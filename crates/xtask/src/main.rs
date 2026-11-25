//! `cargo xtask <command>` — developer tasks for ONWAI_ngap.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ngap_codegen::spec::{self, SpecSource};
use ngap_codegen::{asn1, emit, ir};

#[derive(Parser)]
#[command(name = "xtask", about = "ONWAI_ngap developer tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract the six NGAP ASN.1 modules from the TS 38.413 docx into `specs/asn1/`.
    ExtractAsn {
        /// The 3GPP TS 38.413 Word document (default: $NGAP_SPEC_DOCX, else `specs/<file in spec-source.toml>`).
        #[arg(long)]
        docx: Option<PathBuf>,
        /// Output directory (default: `specs/asn1`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip the SHA-256 check against `codegen/spec-source.toml` (e.g. for a newer release).
        #[arg(long)]
        no_verify: bool,
    },
    /// Regenerate `crates/ngap-types/src` from the extracted ASN.1 modules.
    Gen {
        /// Directory with the `*.asn` files (default: `specs/asn1`).
        #[arg(long)]
        asn: Option<PathBuf>,
        /// Write the files here instead of `crates/ngap-types/src` (for experiments).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Regenerate in memory and compare with the committed `crates/ngap-types/src`; fails on any difference.
    Check {
        /// Directory with the `*.asn` files (default: `specs/asn1`).
        #[arg(long)]
        asn: Option<PathBuf>,
    },
    /// Regenerate the test vectors `testdata/messages.txt` and `testdata/types.txt` (valid PDUs sampled from the ASN.1).
    Vectors {
        /// Directory with the `*.asn` files (default: `specs/asn1`).
        #[arg(long)]
        asn: Option<PathBuf>,
        /// Write the files here instead of `testdata` (for experiments).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Parse the extracted ASN.1 modules and print a census of their constructs.
    Stats {
        /// Directory with the `*.asn` files (default: `specs/asn1`).
        #[arg(long)]
        asn: Option<PathBuf>,
    },
}

/// Repository root: the directory holding the workspace `Cargo.toml` (parent of `crates/`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask lives in <root>/crates/xtask")
        .to_owned()
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::ExtractAsn {
            docx,
            out,
            no_verify,
        } => extract_asn(docx, out, no_verify),
        Cmd::Stats { asn } => stats(asn),
        Cmd::Gen { asn, out } => gen_types(asn, out),
        Cmd::Check { asn } => check_types(asn),
        Cmd::Vectors { asn, out } => vectors(asn, out),
    }
}

fn extract_asn(docx: Option<PathBuf>, out: Option<PathBuf>, no_verify: bool) -> Result<()> {
    let root = repo_root();
    let source_toml = root.join("codegen/spec-source.toml");
    let source = SpecSource::parse(
        &std::fs::read_to_string(&source_toml)
            .with_context(|| format!("read {}", source_toml.display()))?,
    )?;
    let docx = docx
        .or_else(|| std::env::var_os("NGAP_SPEC_DOCX").map(PathBuf::from))
        .unwrap_or_else(|| root.join("specs").join(&source.file));
    let out = out.unwrap_or_else(|| root.join("specs/asn1"));

    let modules = spec::extract_from_docx(&docx, (!no_verify).then_some(source.sha256.as_str()))?;
    let paths = spec::write_modules(&modules, &out)?;
    for (m, p) in modules.iter().zip(&paths) {
        println!(
            "{:>6} lines  {:<24} -> {}",
            m.line_count(),
            m.name,
            p.display()
        );
    }
    println!(
        "{} modules, {} lines total",
        modules.len(),
        modules.iter().map(|m| m.line_count()).sum::<usize>()
    );
    Ok(())
}

fn stats(asn: Option<PathBuf>) -> Result<()> {
    let dir = asn.unwrap_or_else(|| repo_root().join("specs/asn1"));
    let sources = spec::read_modules_dir(&dir)?;
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    let modules = asn1::parse_modules(&refs)?;
    println!("parsed {} modules from {}\n", modules.len(), dir.display());
    print!("{}", asn1::Census::of(&modules));
    println!("\nresolved IR:");
    let ir = ir::build_ir(&modules)?;
    print!("{}", ir::IrCensus::of(&ir));
    for g in ir::recursive_groups(&ir) {
        println!("  self-containing: {}", g.join(", "));
    }
    Ok(())
}

/// Parse and resolve the ASN.1 modules.
fn load_ir(asn: Option<PathBuf>) -> Result<ir::Ir> {
    let dir = asn.unwrap_or_else(|| repo_root().join("specs/asn1"));
    let sources = spec::read_modules_dir(&dir)?;
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(n, t)| (n.as_str(), t.as_str()))
        .collect();
    let modules = asn1::parse_modules(&refs)?;
    Ok(ir::build_ir(&modules)?)
}

/// Parse, resolve and emit: the files of `ngap-types/src`.
fn generate(asn: Option<PathBuf>) -> Result<Vec<emit::GeneratedFile>> {
    Ok(emit::emit(&load_ir(asn)?)?)
}

fn testdata_dir() -> PathBuf {
    repo_root().join("testdata")
}

fn vectors(asn: Option<PathBuf>, out: Option<PathBuf>) -> Result<()> {
    let v = ngap_testgen::vectors::generate(&load_ir(asn)?)?;
    let dir = out.unwrap_or_else(testdata_dir);
    std::fs::create_dir_all(&dir)?;
    for (name, text) in [("messages.txt", &v.messages), ("types.txt", &v.types)] {
        std::fs::write(dir.join(name), text).with_context(|| format!("write {name}"))?;
        println!(
            "wrote {} ({} vectors, {:.2} MB)",
            dir.join(name).display(),
            text.lines().filter(|l| !l.starts_with('#')).count(),
            text.len() as f64 / 1e6
        );
    }
    Ok(())
}

fn types_dir() -> PathBuf {
    repo_root().join("crates/ngap-types/src")
}

/// Files in `dir` that a previous `gen` wrote (they carry the marker); hand-written files are never touched.
fn existing_generated(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if dir.exists() {
        for e in std::fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "rs")
                && std::fs::read_to_string(&p).is_ok_and(|t| t.contains(emit::GENERATED_MARKER))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn gen_types(asn: Option<PathBuf>, out: Option<PathBuf>) -> Result<()> {
    let files = generate(asn)?;
    let dir = out.unwrap_or_else(types_dir);
    std::fs::create_dir_all(&dir)?;
    let keep: std::collections::HashSet<PathBuf> =
        files.iter().map(|f| dir.join(&f.path)).collect();
    for stale in existing_generated(&dir)? {
        if !keep.contains(&stale) {
            std::fs::remove_file(&stale)?;
            println!("removed stale {}", stale.display());
        }
    }
    let mut bytes = 0;
    for f in &files {
        std::fs::write(dir.join(&f.path), &f.content)
            .with_context(|| format!("write {}", f.path))?;
        bytes += f.content.len();
    }
    println!(
        "wrote {} files ({:.1} MB, {} lines) to {}",
        files.len(),
        bytes as f64 / 1e6,
        files
            .iter()
            .map(|f| f.content.lines().count())
            .sum::<usize>(),
        dir.display()
    );
    Ok(())
}

fn check_types(asn: Option<PathBuf>) -> Result<()> {
    let ir = load_ir(asn)?;
    let files = emit::emit(&ir)?;
    let vectors = ngap_testgen::vectors::generate(&ir)?;
    let dir = types_dir();
    let mut problems = Vec::new();
    for f in &files {
        match std::fs::read_to_string(dir.join(&f.path)) {
            Ok(t) if t == f.content => {}
            Ok(_) => problems.push(format!("differs: {}", f.path)),
            Err(_) => problems.push(format!("missing: {}", f.path)),
        }
    }
    let expected: std::collections::HashSet<PathBuf> =
        files.iter().map(|f| dir.join(&f.path)).collect();
    for p in existing_generated(&dir)? {
        if !expected.contains(&p) {
            problems.push(format!("stale: {}", p.display()));
        }
    }
    for (name, text) in [
        ("messages.txt", &vectors.messages),
        ("types.txt", &vectors.types),
    ] {
        match std::fs::read_to_string(testdata_dir().join(name)) {
            Ok(t) if &t == text => {}
            Ok(_) => problems.push(format!("differs: testdata/{name}")),
            Err(_) => problems.push(format!("missing: testdata/{name}")),
        }
    }
    if problems.is_empty() {
        println!(
            "generated code is up to date ({} files, 2 vector files)",
            files.len()
        );
        Ok(())
    } else {
        for p in problems.iter().take(30) {
            eprintln!("{p}");
        }
        anyhow::bail!(
            "generated code is out of date ({} problems); run `cargo xtask gen` (and `cargo xtask vectors` for testdata/)",
            problems.len()
        )
    }
}
