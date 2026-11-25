//! The committed `crates/ngap-types/src` must be exactly what the generator produces from `specs/asn1`
//! (the same check as `cargo xtask check`). Skips with a message without `specs/asn1`; fails when `CI` is set.

use std::path::PathBuf;

use ngap_codegen::asn1::parse_modules;
use ngap_codegen::emit::emit;
use ngap_codegen::ir::build_ir;

#[test]
fn ngap_types_is_up_to_date() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources = match ngap_codegen::spec::read_modules_dir(&root.join("specs/asn1")) {
        Ok(v) if v.len() == 6 => v,
        other => {
            assert!(
                std::env::var_os("CI").is_none(),
                "specs/asn1 is missing or incomplete: {other:?}"
            );
            eprintln!("SKIPPED: specs/asn1 not found; run `cargo xtask extract-asn`");
            return;
        }
    };
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let ir = build_ir(&parse_modules(&refs).unwrap()).unwrap();
    let files = emit(&ir).unwrap();
    let src = root.join("crates/ngap-types/src");
    for f in &files {
        let on_disk = std::fs::read_to_string(src.join(&f.path)).unwrap_or_default();
        assert!(
            on_disk == f.content,
            "{} is out of date: run `cargo xtask gen`",
            f.path
        );
    }
    let generated: Vec<String> = std::fs::read_dir(&src)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for name in generated {
        assert!(
            files.iter().any(|f| f.path == name),
            "{name} is stale: run `cargo xtask gen`"
        );
    }
}
