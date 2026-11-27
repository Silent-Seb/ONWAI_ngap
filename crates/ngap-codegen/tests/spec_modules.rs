//! The ASN.1 modules committed in `specs/asn1/` are extraction output (`cargo xtask extract-asn`), never edited by hand:
//! their SHA-256 must be the ones pinned in `codegen/spec-source.toml`. Always runs: the files are part of the repository.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_committed_modules_are_the_pinned_extraction() {
    let pins: toml::Table = std::fs::read_to_string(root().join("codegen/spec-source.toml"))
        .expect("codegen/spec-source.toml")
        .parse()
        .expect("valid TOML");
    let modules = pins["modules"].as_table().expect("a [modules] table");
    assert_eq!(modules.len(), 6, "the six modules of clause 9.4");

    for (file, pinned) in modules {
        let bytes = std::fs::read(root().join("specs/asn1").join(file))
            .unwrap_or_else(|e| panic!("specs/asn1/{file} is missing: {e}"));
        let actual = hex(&Sha256::digest(&bytes));
        assert_eq!(
            actual,
            pinned.as_str().expect("a string"),
            "specs/asn1/{file} differs from the pinned extraction: re-run `cargo xtask extract-asn` \
             (never edit it by hand) and update [modules] in codegen/spec-source.toml together with the docx pin"
        );
    }

    // and nothing else sits next to them
    let mut on_disk: Vec<String> = std::fs::read_dir(root().join("specs/asn1"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    on_disk.sort();
    let pinned: Vec<&String> = modules.keys().collect();
    assert_eq!(on_disk.iter().collect::<Vec<_>>(), pinned);
}
