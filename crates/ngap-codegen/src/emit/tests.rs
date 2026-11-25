//! Emitter tests on a miniature specification: what is generated, and what is refused.

use super::*;
use crate::asn1::parse_modules;
use crate::ir::build_ir;

const PRELUDE: &str = "
M { x } DEFINITIONS AUTOMATIC TAGS ::= BEGIN
maxIEs INTEGER ::= 65535
id-A ProtocolIE-ID ::= 1
id-B-Thing ProtocolIE-ID ::= 2
id-Ext ProtocolExtensionID ::= 7
id-pc ProcedureCode ::= 3
Criticality ::= ENUMERATED { reject, ignore, notify }
Presence ::= ENUMERATED { optional, conditional, mandatory }
ProtocolIE-ID ::= INTEGER (0..65535)
ProtocolExtensionID ::= INTEGER (0..65535)
ProcedureCode ::= INTEGER (0..255)
IES ::= CLASS { &id ProtocolIE-ID UNIQUE, &criticality Criticality, &Value, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality TYPE &Value PRESENCE &presence }
EXT ::= CLASS { &id ProtocolExtensionID UNIQUE, &criticality Criticality, &Extension, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality EXTENSION &Extension PRESENCE &presence }
Container { IES : S } ::= SEQUENCE (SIZE (0..maxIEs)) OF Field {{S}}
Field { IES : S } ::= SEQUENCE { id IES.&id ({S}), criticality IES.&criticality ({S}{@id}), value IES.&Value ({S}{@id}) }
ExtContainer { EXT : S } ::= SEQUENCE (SIZE (1..maxIEs)) OF ExtField {{S}}
ExtField { EXT : S } ::= SEQUENCE { id EXT.&id ({S}), criticality EXT.&criticality ({S}{@id}), extensionValue EXT.&Extension ({S}{@id}) }
";

fn generate_files(body: &str) -> Result<Vec<GeneratedFile>, String> {
    let text = format!("{PRELUDE}\n{body}\nEND\n");
    let modules = parse_modules(&[("t", &text)]).unwrap_or_else(|e| panic!("{e}"));
    let ir = build_ir(&modules).map_err(|e| e.to_string())?;
    emit(&ir).map_err(|e| e.to_string())
}

/// All generated item code, concatenated.
fn code(body: &str) -> String {
    let files = generate_files(body).unwrap_or_else(|e| panic!("{e}"));
    files
        .iter()
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn files_have_the_marker_and_a_lib_that_declares_every_module() {
    let files = generate_files("Foo ::= INTEGER (0..7)").unwrap();
    assert!(files.iter().all(|f| f.content.contains(GENERATED_MARKER)));
    let lib = files.iter().find(|f| f.path == "lib.rs").unwrap();
    for f in files.iter().filter(|f| f.path != "lib.rs") {
        let module = f.path.trim_end_matches(".rs");
        assert!(lib.content.contains(&format!("mod {module};")), "{module}");
    }
    assert!(lib.content.contains("pub use ngap_aper::ie::Criticality;"));
    // Criticality itself is provided by the runtime and not generated
    assert!(!code("Foo ::= INTEGER (0..7)").contains("pub enum Criticality"));
}

#[test]
fn integers_become_the_smallest_fitting_newtype() {
    let c = code(
        "A ::= INTEGER (0..255)\nB ::= INTEGER (0..256)\nC ::= INTEGER (-5..5)\nD ::= INTEGER (0..18446744073709551615)\nE ::= INTEGER (1..65535, ..., 65536..109999)\nF ::= INTEGER (1..30|40, ...)",
    );
    for (name, prim) in [
        ("A", "u8"),
        ("B", "u16"),
        ("C", "i8"),
        ("D", "u64"),
        ("E", "u32"),
    ] {
        assert!(
            c.contains(&format!("pub struct {name}(pub {prim});")),
            "{name}"
        );
    }
    assert!(c.contains(".extensible().with_additions(&[(65536, 109999)])"));
    assert!(c.contains(".with_ranges(&[(1, 30), (40, 40)])"));
}

#[test]
fn enums_get_pascal_variants_and_indices_with_additions_after_the_root() {
    let c = code("E ::= ENUMERATED { not-restricted, a2X, ..., late }");
    assert!(c.contains("#[non_exhaustive]\npub enum E {"));
    assert!(c.contains("NotRestricted,") && c.contains("A2x,") && c.contains("Late,"));
    assert!(c.contains("Self::Late => 2,"));
    assert!(c.contains("w.write_index(index, 2, true)"));
    assert!(c.contains("rt::ErrorKind::InvalidIndex(i)"));
}

#[test]
fn a_message_flattens_its_ies_into_fields_in_spec_order() {
    let c = code(
        "Msg ::= SEQUENCE { protocolIEs Container {{MsgIEs}}, ... }
         MsgIEs IES ::= {
           { ID id-A CRITICALITY reject TYPE Foo PRESENCE mandatory } |
           { ID id-B-Thing CRITICALITY notify TYPE Foo PRESENCE optional }, ... }
         Foo ::= INTEGER (0..7)",
    );
    assert!(c.contains("pub struct Msg {"));
    let a = c.find("pub a: Foo,").expect("mandatory field");
    let b = c.find("pub b_thing: Option<Foo>,").expect("optional field");
    assert!(a < b);
    assert!(c.contains("pub unknown_ies: Vec<rt::ie::RawIe>,"));
    assert!(
        c.contains("pub fn new(a: Foo) -> Self"),
        "only mandatory IEs are constructor arguments"
    );
    assert!(c.contains("rt::ie::RawIe::new(1, rt::ie::Criticality::Reject, x)?"));
    assert!(c.contains("rt::ie::RawIe::new(2, rt::ie::Criticality::Notify, x)?"));
    assert!(c.contains("rt::ie::required(s_a, 1, rt::ie::Criticality::Reject)?"));
    assert!(c.contains("rt::Size::range(0, 65535)"));
}

#[test]
fn extension_containers_become_typed_members_or_the_shared_unknown_type() {
    let c = code(
        "Item ::= SEQUENCE { a INTEGER (0..7), iE-Extensions ExtContainer {{ItemExt}} OPTIONAL, ... }
         ItemExt EXT ::= { { ID id-Ext CRITICALITY ignore EXTENSION INTEGER (0..9) PRESENCE optional }, ... }
         Plain ::= SEQUENCE { iE-Extensions ExtContainer {{NoRows}} OPTIONAL }
         NoRows EXT ::= { ... }",
    );
    assert!(
        c.contains("pub ie_extensions: Option<ItemExt>,"),
        "a set with rows is a struct named after the set"
    );
    assert!(c.contains("pub struct ItemExt {"));
    assert!(
        c.contains("pub ie_extensions: Option<rt::ie::UnknownIes>,"),
        "a set without rows keeps everything raw"
    );
    assert!(c.contains("rt::ie::write_container(w, rt::Size::range(1, 65535), &x.ies)"));
}

#[test]
fn single_ie_fields_become_an_enum_with_an_unknown_fallback() {
    let c = code(
        "Ch ::= CHOICE { a INTEGER (0..3), choice-Extensions Field {{ChIEs}} }
         ChIEs IES ::= { { ID id-A CRITICALITY reject TYPE Foo PRESENCE optional }, ... }
         Foo ::= INTEGER (0..7)
         Empty ::= CHOICE { a INTEGER (0..3), choice-Extensions Field {{NoIEs}} }
         NoIEs IES ::= { ... }",
    );
    assert!(c.contains("pub enum ChIes {") && c.contains("Unknown(rt::ie::RawIe),"));
    assert!(c.contains("ChoiceExtensions(ChIes),"));
    assert!(
        c.contains("ChoiceExtensions(rt::ie::RawIe),"),
        "no rows: the raw IE itself"
    );
}

#[test]
fn inline_enums_are_named_after_their_owner_and_field() {
    let c = code("Parent ::= SEQUENCE { kind ENUMERATED { a, b }, other INTEGER (0..9) }");
    assert!(c.contains("pub enum ParentKind {"));
    assert!(c.contains("pub kind: ParentKind,") && c.contains("pub other: u8,"));
}

#[test]
fn constants_are_emitted_with_the_type_of_their_governor() {
    let files = generate_files("Foo ::= INTEGER (0..7)").unwrap();
    let k = files.iter().find(|f| f.path == "constants.rs").unwrap();
    assert!(k.content.contains("pub const ID_A: u16 = 1;"));
    assert!(k.content.contains("pub const ID_PC: u8 = 3;"));
    assert!(k.content.contains("pub const MAX_IES: u32 = 65535;"));
}

#[test]
fn unsupported_constructs_are_refused_with_a_reason() {
    for (body, needle) in [
        (
            "S ::= SEQUENCE { a INTEGER (0..7), ..., b INTEGER (0..7) OPTIONAL }",
            "SEQUENCE extension additions",
        ),
        (
            "C ::= CHOICE { a INTEGER (0..7), ..., b INTEGER (0..7) }",
            "CHOICE extension additions",
        ),
        (
            "S ::= SEQUENCE { a SEQUENCE { b NULL } }",
            "inline SEQUENCE/CHOICE",
        ),
        ("S ::= IA5String", "strings are not supported"),
        (
            "Msg ::= SEQUENCE { a INTEGER (0..1), protocolIEs Container {{MsgIEs}} }\nMsgIEs IES ::= { ... }",
            "only supported as the sole component",
        ),
        (
            "S ::= SEQUENCE { a ENUMERATED { x, x2 }, b ENUMERATED { y } }\nT ::= SEQUENCE { a ENUMERATED { z } }\nSA ::= INTEGER (0..1)\nS-A ::= INTEGER (0..1)",
            "both map to the Rust name",
        ),
        ("Option ::= INTEGER (0..1)", "reserved name"),
    ] {
        let e = generate_files(body)
            .err()
            .unwrap_or_else(|| panic!("should be refused: {body}"));
        assert!(e.contains(needle), "wanted {needle:?}, got: {e}");
    }
}

#[test]
fn field_names_that_collide_are_refused() {
    let e = generate_files("S ::= SEQUENCE { aB INTEGER (0..1), ab INTEGER (0..1) }")
        .err()
        .unwrap();
    assert!(e.contains("both map to the field `ab`"), "{e}");
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(
        generate_files("Foo ::= INTEGER (0..7)").unwrap(),
        generate_files("Foo ::= INTEGER (0..7)").unwrap()
    );
}
