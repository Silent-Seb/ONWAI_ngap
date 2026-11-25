//! Spec ingestion: pull the ASN.1 modules out of the 3GPP TS 38.413 Word document.
//!
//! The ASN.1 lives in paragraphs of style `PL` in clauses 9.4.3 - 9.4.8, each module delimited by
//! `-- ASN1START` / `-- ASN1STOP`. The docx is a zip whose `word/document.xml` holds the paragraphs; a small
//! tag scanner is enough (no general XML parser needed).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

/// Number of ASN.1 modules in TS 38.413.
pub const MODULE_COUNT: usize = 6;

/// One extracted ASN.1 module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnModule {
    /// Module name, e.g. `NGAP-IEs`.
    pub name: String,
    /// Full module text from the module header to `END`, `\n`-terminated lines, trailing whitespace trimmed.
    pub text: String,
}

impl AsnModule {
    /// File name used on disk: `<name>.asn`.
    pub fn file_name(&self) -> String {
        format!("{}.asn", self.name)
    }

    /// Number of lines in the module text.
    pub fn line_count(&self) -> usize {
        self.text.lines().count()
    }
}

/// The pinned spec file, as recorded in `codegen/spec-source.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecSource {
    pub file: String,
    pub sha256: String,
}

impl SpecSource {
    /// Parse the contents of `codegen/spec-source.toml`.
    pub fn parse(toml_text: &str) -> Result<Self> {
        let v: toml::Table = toml_text
            .parse()
            .context("spec-source.toml is not valid TOML")?;
        let get = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_owned)
                .with_context(|| format!("spec-source.toml: missing string key `{k}`"))
        };
        Ok(Self {
            file: get("file")?,
            sha256: get("sha256")?,
        })
    }
}

/// Hex SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Read `word/document.xml` out of a docx.
fn read_document_xml(docx: &Path) -> Result<String> {
    let f = std::fs::File::open(docx).with_context(|| format!("open {}", docx.display()))?;
    let mut zip = zip::ZipArchive::new(f).context("not a zip/docx file")?;
    let mut entry = zip
        .by_name("word/document.xml")
        .context("docx has no word/document.xml")?;
    let mut xml = String::with_capacity(entry.size() as usize);
    entry
        .read_to_string(&mut xml)
        .context("word/document.xml is not UTF-8")?;
    Ok(xml)
}

/// A paragraph: its Word style id (empty if none) and its text (`<w:tab/>` -> `\t`, `<w:br/>` -> `\n`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paragraph {
    pub style: String,
    pub text: String,
}

/// Split `document.xml` into paragraphs.
pub fn paragraphs(xml: &str) -> Vec<Paragraph> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = next_paragraph_start(rest) {
        let body_from = &rest[start..];
        let Some(end) = body_from.find("</w:p>") else {
            break;
        };
        out.push(parse_paragraph(&body_from[..end]));
        rest = &body_from[end + "</w:p>".len()..];
    }
    out
}

/// Index of the next `<w:p>` or `<w:p ...>` (not `<w:pPr>`, `<w:pStyle>`, ...).
fn next_paragraph_start(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = s[from..].find("<w:p") {
        let at = from + i;
        match s.as_bytes().get(at + 4) {
            Some(b'>') | Some(b' ') => return Some(at),
            _ => from = at + 4,
        }
    }
    None
}

fn parse_paragraph(p: &str) -> Paragraph {
    let style = p
        .find("<w:pStyle w:val=\"")
        .map(|i| {
            let s = &p[i + "<w:pStyle w:val=\"".len()..];
            s[..s.find('"').unwrap_or(s.len())].to_owned()
        })
        .unwrap_or_default();
    let mut text = String::new();
    let mut i = 0;
    while let Some(lt) = p[i..].find('<') {
        let tag_start = i + lt;
        let Some(gt) = p[tag_start..].find('>') else {
            break;
        };
        let tag = &p[tag_start + 1..tag_start + gt];
        let after = tag_start + gt + 1;
        let name_end = tag.find([' ', '/']).unwrap_or(tag.len());
        match &tag[..name_end] {
            "w:t" if !tag.ends_with('/') => {
                let close = p[after..].find("</w:t>").unwrap_or(p.len() - after);
                text.push_str(&unescape(&p[after..after + close]));
                i = after + close;
                continue;
            }
            // only a bare <w:tab/> is a tab character; <w:tab w:val=".." w:pos=".."/> inside <w:tabs> is a tab stop
            "w:tab" if tag == "w:tab/" => text.push('\t'),
            "w:br" if tag == "w:br/" => text.push('\n'),
            _ => {}
        }
        i = after;
    }
    Paragraph { style, text }
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Extract the ASN.1 modules from the paragraphs of the spec.
///
/// Every `-- ASN1START` ... `-- ASN1STOP` block of `PL` paragraphs is one module. The module starts at the line
/// naming it (`NGAP-xxx {`), which drops the banner comment above it.
pub fn extract_modules(paras: &[Paragraph]) -> Result<Vec<AsnModule>> {
    let mut modules = Vec::new();
    let mut block: Option<Vec<String>> = None;
    for p in paras.iter().filter(|p| p.style == "PL") {
        // Word leaves non-breaking spaces (U+00A0) in a few code lines (e.g. `Foo\u{a0}::= SEQUENCE {`)
        let text = p.text.replace('\u{a0}', " ");
        let line = text.trim_end();
        match (line.trim(), block.as_mut()) {
            ("-- ASN1START", None) => block = Some(Vec::new()),
            ("-- ASN1START", Some(_)) => bail!("nested -- ASN1START"),
            ("-- ASN1STOP", Some(_)) => modules.push(finish_module(block.take().unwrap())?),
            ("-- ASN1STOP", None) => bail!("-- ASN1STOP without -- ASN1START"),
            (_, Some(b)) => b.extend(line.split('\n').map(|l| l.trim_end().to_owned())),
            (_, None) => {}
        }
    }
    ensure!(block.is_none(), "unterminated -- ASN1START block");
    Ok(modules)
}

fn finish_module(lines: Vec<String>) -> Result<AsnModule> {
    let start = lines
        .iter()
        .position(|l| module_name(l).is_some())
        .context("ASN.1 block has no `NGAP-xxx {` module header")?;
    let name = module_name(&lines[start]).unwrap().to_owned();
    let end = lines
        .iter()
        .rposition(|l| l.trim() == "END")
        .with_context(|| format!("module {name} has no END"))?;
    ensure!(end > start, "module {name}: END before header");
    let mut text = lines[start..=end].join("\n");
    text.push('\n');
    Ok(AsnModule { name, text })
}

/// `NGAP-IEs  {` -> `NGAP-IEs`.
fn module_name(line: &str) -> Option<&str> {
    let t = line.trim();
    let name = t.strip_suffix('{')?.trim_end();
    (name.starts_with("NGAP-") && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .then_some(name)
}

/// Full pipeline for a docx file: checks the pinned SHA-256 (if given) and extracts the six modules.
pub fn extract_from_docx(docx: &Path, expected_sha256: Option<&str>) -> Result<Vec<AsnModule>> {
    if let Some(expected) = expected_sha256 {
        let actual = sha256_file(docx)?;
        ensure!(
            actual == expected,
            "{} has SHA-256 {actual}, but codegen/spec-source.toml pins {expected}",
            docx.display()
        );
    }
    let xml = read_document_xml(docx)?;
    let modules = extract_modules(&paragraphs(&xml))?;
    ensure!(
        modules.len() == MODULE_COUNT,
        "expected {MODULE_COUNT} ASN.1 modules, found {}",
        modules.len()
    );
    Ok(modules)
}

/// Read every `*.asn` file of `dir` as `(file name, text)`, sorted by name.
pub fn read_modules_dir(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| {
        format!(
            "read directory {} (run `cargo xtask extract-asn`)",
            dir.display()
        )
    })? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "asn") {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            out.push((name, text));
        }
    }
    out.sort();
    ensure!(!out.is_empty(), "no *.asn files in {}", dir.display());
    Ok(out)
}

/// Write the modules to `dir` as `<name>.asn`, returning the written paths.
pub fn write_modules(modules: &[AsnModule], dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    modules
        .iter()
        .map(|m| {
            let path = dir.join(m.file_name());
            std::fs::write(&path, &m.text).with_context(|| format!("write {}", path.display()))?;
            Ok(path)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pl(t: &str) -> Paragraph {
        Paragraph {
            style: "PL".into(),
            text: t.into(),
        }
    }

    #[test]
    fn paragraph_scanner_handles_styles_text_tabs_and_entities() {
        let xml = r#"<w:body><w:p><w:pPr><w:pStyle w:val="PL"/></w:pPr><w:r><w:t xml:space="preserve">a &lt; b</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>c</w:t></w:r></w:p><w:p w:rsidR="1"><w:r><w:t>plain</w:t></w:r></w:p></w:body>"#;
        let p = paragraphs(xml);
        assert_eq!(p.len(), 2);
        assert_eq!(
            (p[0].style.as_str(), p[0].text.as_str()),
            ("PL", "a < b\tc")
        );
        assert_eq!((p[1].style.as_str(), p[1].text.as_str()), ("", "plain"));
    }

    #[test]
    fn tab_stop_definitions_are_not_tab_characters() {
        let xml = r#"<w:p><w:pPr><w:pStyle w:val="PL"/><w:tabs><w:tab w:val="left" w:pos="568"/></w:tabs></w:pPr><w:r><w:t>x</w:t></w:r></w:p>"#;
        assert_eq!(paragraphs(xml)[0].text, "x");
    }

    #[test]
    fn modules_are_cut_at_header_and_end() {
        let paras = vec![
            pl("-- ASN1START"),
            pl("-- banner comment"),
            pl("NGAP-Foo  {"),
            pl("itu-t (0) }"),
            pl("DEFINITIONS AUTOMATIC TAGS ::="),
            pl("BEGIN"),
            pl("A ::= INTEGER (0..1)   "),
            pl("END"),
            pl("-- ASN1STOP"),
            Paragraph {
                style: "Normal".into(),
                text: "ignored".into(),
            },
        ];
        let m = extract_modules(&paras).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "NGAP-Foo");
        assert_eq!(m[0].line_count(), 6);
        assert!(m[0].text.starts_with("NGAP-Foo  {\n"));
        assert!(m[0].text.ends_with("A ::= INTEGER (0..1)\nEND\n"));
    }

    #[test]
    fn non_breaking_spaces_become_spaces() {
        let paras = vec![
            pl("-- ASN1START"),
            pl("NGAP-A {"),
            pl("Foo\u{a0}::= NULL"),
            pl("END"),
            pl("-- ASN1STOP"),
        ];
        let m = extract_modules(&paras).unwrap();
        assert!(m[0].text.contains("Foo ::= NULL"));
        assert!(m[0].text.is_ascii());
    }

    #[test]
    fn unbalanced_markers_are_errors() {
        assert!(extract_modules(&[pl("-- ASN1START"), pl("NGAP-A {"), pl("END")]).is_err());
        assert!(extract_modules(&[pl("-- ASN1STOP")]).is_err());
    }

    #[test]
    fn spec_source_toml_is_read() {
        let s = SpecSource::parse("file = \"x.docx\"\nsha256 = \"ab\"\n").unwrap();
        assert_eq!((s.file.as_str(), s.sha256.as_str()), ("x.docx", "ab"));
        assert!(SpecSource::parse("file = \"x\"").is_err());
    }
}
