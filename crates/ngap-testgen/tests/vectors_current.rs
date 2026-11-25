//! The committed `testdata/*.txt` must be exactly what `ngap-testgen` produces from `specs/asn1` (the same check as
//! `cargo xtask check`), and the sampler must be deterministic. Skips with a message without `specs/asn1`; fails when
//! `CI` is set.

use std::path::PathBuf;

use ngap_codegen::asn1::parse_modules;
use ngap_codegen::ir::{Ir, build_ir};
use ngap_testgen::{Mode, Sampler, vectors};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn ir() -> Option<Ir> {
    let sources = match ngap_codegen::spec::read_modules_dir(&root().join("specs/asn1")) {
        Ok(v) if v.len() == 6 => v,
        other => {
            assert!(
                std::env::var_os("CI").is_none(),
                "specs/asn1 is missing or incomplete: {other:?}"
            );
            eprintln!("SKIPPED: specs/asn1 not found; run `cargo xtask extract-asn`");
            return None;
        }
    };
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    Some(build_ir(&parse_modules(&refs).unwrap()).unwrap())
}

#[test]
fn testdata_is_up_to_date() {
    let Some(ir) = ir() else { return };
    let v = vectors::generate(&ir).unwrap();
    for (name, text) in [("messages.txt", &v.messages), ("types.txt", &v.types)] {
        let on_disk =
            std::fs::read_to_string(root().join("testdata").join(name)).unwrap_or_default();
        assert!(
            &on_disk == text,
            "testdata/{name} is out of date: run `cargo xtask vectors`"
        );
    }
}

#[test]
fn sampling_is_deterministic_and_the_modes_differ() {
    let Some(ir) = ir() else { return };
    let p = ir
        .procedures
        .get("nGSetup")
        .expect("the NG Setup procedure");
    let sample = |mode, seed| Sampler::new(&ir, mode, seed).pdu(p, 0).unwrap().unwrap().1;
    assert_eq!(sample(Mode::Random, 7), sample(Mode::Random, 7));
    assert_ne!(sample(Mode::Random, 7), sample(Mode::Random, 8));
    let (min, max) = (sample(Mode::Min, 0), sample(Mode::Max, 0));
    assert!(max.len() > min.len(), "min {} max {}", min.len(), max.len());
}

#[test]
fn every_message_has_all_five_shapes() {
    let Some(ir) = ir() else { return };
    let v = vectors::generate(&ir).unwrap();
    let mut shapes = std::collections::BTreeMap::<String, Vec<String>>::new();
    for l in v.messages.lines().filter(|l| !l.starts_with('#')) {
        let (key, _) = l.split_once(" | ").unwrap();
        let (name, tag) = key.rsplit_once('.').unwrap();
        shapes
            .entry(name.to_owned())
            .or_default()
            .push(tag.to_owned());
    }
    assert!(shapes.len() >= 140, "{} messages", shapes.len());
    for (name, tags) in shapes {
        assert_eq!(tags, ["min", "max", "r1", "r2", "r3"], "{name}");
    }
}

#[test]
fn a_set_without_rows_is_reported_not_sampled() {
    let Some(ir) = ir() else { return };
    // PrivateMessage holds a PrivateIE-Container that needs one private IE; the specification defines none
    let mut s = Sampler::new(&ir, Mode::Min, 0);
    assert!(!s.can_sample(&ngap_codegen::ir::IrType::Named("PrivateMessage".into())));
    assert!(s.named("PrivateMessage").is_err());
}
