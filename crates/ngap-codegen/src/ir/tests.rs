//! IR builder tests on a miniature NGAP-like specification.

use super::*;
use crate::asn1::parse_modules;

/// The container family and classes of NGAP-Containers, trimmed, plus a message, a set and two procedures.
const MINI: &str = "
M { x } DEFINITIONS AUTOMATIC TAGS ::= BEGIN
maxIEs INTEGER ::= 65535
maxExt INTEGER ::= 65535
id-A ProtocolIE-ID ::= 1
id-B ProtocolIE-ID ::= 2
id-ext ProtocolExtensionID ::= 7
Criticality ::= ENUMERATED { reject, ignore, notify }
Presence ::= ENUMERATED { optional, conditional, mandatory }
ProtocolIE-ID ::= INTEGER (0..65535)
ProtocolExtensionID ::= INTEGER (0..65535)
ProcedureCode ::= INTEGER (0..255)
IES ::= CLASS { &id ProtocolIE-ID UNIQUE, &criticality Criticality, &Value, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality TYPE &Value PRESENCE &presence }
EXT ::= CLASS { &id ProtocolExtensionID UNIQUE, &criticality Criticality, &Extension, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality EXTENSION &Extension PRESENCE &presence }
EP ::= CLASS { &InitiatingMessage, &SuccessfulOutcome OPTIONAL, &UnsuccessfulOutcome OPTIONAL,
  &procedureCode ProcedureCode UNIQUE, &criticality Criticality DEFAULT ignore }
  WITH SYNTAX { INITIATING MESSAGE &InitiatingMessage [SUCCESSFUL OUTCOME &SuccessfulOutcome]
  [UNSUCCESSFUL OUTCOME &UnsuccessfulOutcome] PROCEDURE CODE &procedureCode [CRITICALITY &criticality] }

Container { IES : S } ::= SEQUENCE (SIZE (0..maxIEs)) OF Field {{S}}
Single { IES : S } ::= Field {{S}}
Field { IES : S } ::= SEQUENCE {
  id IES.&id ({S}),
  criticality IES.&criticality ({S}{@id}),
  value IES.&Value ({S}{@id}) }
ExtContainer { EXT : S } ::= SEQUENCE (SIZE (1..maxExt)) OF ExtField {{S}}
ExtField { EXT : S } ::= SEQUENCE {
  id EXT.&id ({S}),
  criticality EXT.&criticality ({S}{@id}),
  extensionValue EXT.&Extension ({S}{@id}) }
List { INTEGER : lo, INTEGER : hi, IES : S } ::= SEQUENCE (SIZE (lo..hi)) OF Single {{S}}

Foo ::= INTEGER (0..7, ...)
Msg ::= SEQUENCE { protocolIEs Container {{MsgIEs}}, ... }
MsgIEs IES ::= {
  { ID id-A CRITICALITY reject TYPE Foo PRESENCE mandatory } |
  { ID id-B CRITICALITY ignore TYPE OCTET STRING (CONTAINING Foo) PRESENCE optional }, ... }
Item ::= SEQUENCE { a Foo, iE-Extensions ExtContainer {{ItemExt}} OPTIONAL, ... }
ItemExt EXT ::= { { ID id-ext CRITICALITY ignore EXTENSION Foo PRESENCE optional }, ... }
ItemList ::= List { 1, 4, {ItemIEs} }
ItemIEs IES ::= { { ID id-A CRITICALITY reject TYPE Item PRESENCE mandatory } }
procA EP ::= { INITIATING MESSAGE Msg PROCEDURE CODE 3 }
procB EP ::= { INITIATING MESSAGE Msg SUCCESSFUL OUTCOME Msg UNSUCCESSFUL OUTCOME Msg PROCEDURE CODE 4 CRITICALITY reject }
ALL EP ::= { procA | procB, ... }
END
";

fn build(text: &str) -> Result<Ir, IrError> {
    let modules = parse_modules(&[("t", text)]).unwrap_or_else(|e| panic!("{e}"));
    build_ir(&modules)
}

fn mini() -> Ir {
    build(MINI).unwrap_or_else(|e| panic!("{e}"))
}

/// MINI with one textual change; the change must hit.
fn mutated(from: &str, to: &str) -> Result<Ir, IrError> {
    assert!(MINI.contains(from), "test bug: {from:?} not in MINI");
    build(&MINI.replacen(from, to, 1))
}

fn fails(from: &str, to: &str, needle: &str) {
    let e = mutated(from, to).expect_err("should fail");
    assert!(e.message.contains(needle), "wanted {needle:?}, got: {e}");
}

#[test]
fn constants_are_evaluated_with_their_governor() {
    let ir = mini();
    let c = ir.consts.get("id-B").unwrap();
    assert_eq!(
        (c.value, c.ty.as_str(), c.module.as_str()),
        (2, "ProtocolIE-ID", "M")
    );
    assert_eq!(ir.consts.get("maxIEs").unwrap().ty, "INTEGER");
}

#[test]
fn a_message_becomes_a_container_of_a_table() {
    let ir = mini();
    let IrType::Sequence(s) = &ir.types.get("Msg").unwrap().ty else {
        panic!()
    };
    assert!(s.extensible);
    let IrType::SequenceOf { size, element } = &s.root[0].ty else {
        panic!("{:?}", s.root[0].ty)
    };
    assert_eq!(
        *size,
        IrSize {
            lb: 0,
            ub: Some(65535),
            extensible: false
        }
    );
    let IrType::Table(t) = element.as_ref() else {
        panic!()
    };
    assert_eq!((t.class.as_str(), t.set.as_str()), ("IES", "MsgIEs"));
    let roles: Vec<_> = t
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.field.as_str(), c.role))
        .collect();
    assert_eq!(
        roles,
        [
            ("id", "id", TableRole::Key),
            ("criticality", "criticality", TableRole::Criticality),
            ("value", "Value", TableRole::Value)
        ]
    );
}

#[test]
fn a_single_container_is_the_table_itself_and_lists_get_their_bounds() {
    let ir = mini();
    let IrType::SequenceOf { size, element } = &ir.types.get("ItemList").unwrap().ty else {
        panic!()
    };
    assert_eq!((size.lb, size.ub), (1, Some(4)));
    assert!(matches!(element.as_ref(), IrType::Table(t) if t.set == "ItemIEs"));
    let IrType::Sequence(item) = &ir.types.get("Item").unwrap().ty else {
        panic!()
    };
    let ext = &item.root[1];
    assert!(ext.optional);
    let IrType::SequenceOf { size, element } = &ext.ty else {
        panic!()
    };
    assert_eq!((size.lb, size.ub), (1, Some(65535)));
    assert!(matches!(element.as_ref(), IrType::Table(t) if t.class == "EXT" && t.set == "ItemExt"));
}

#[test]
fn object_sets_become_rows_in_spec_order() {
    let ir = mini();
    let s = ir.sets.get("MsgIEs").unwrap();
    assert_eq!(
        (s.kind, s.extensible, s.rows.len()),
        (SetKind::ProtocolIes, true, 2)
    );
    assert_eq!(
        (s.rows[0].id, s.rows[0].criticality, s.rows[0].presence),
        (1, Criticality::Reject, Presence::Mandatory)
    );
    assert_eq!(s.rows[0].ty, IrType::Named("Foo".into()));
    assert_eq!((s.rows[1].id, s.rows[1].presence), (2, Presence::Optional));
    assert!(
        matches!(&s.rows[1].ty, IrType::OctetString { contained: Some(c), .. } if **c == IrType::Named("Foo".into()))
    );
    let e = ir.sets.get("ItemExt").unwrap();
    assert_eq!((e.kind, e.rows[0].id), (SetKind::ProtocolExtensions, 7));
}

#[test]
fn procedures_get_class_code_and_default_criticality() {
    let ir = mini();
    let a = ir.procedures.get("procA").unwrap();
    assert_eq!(
        (a.code, a.criticality, a.class, a.initiating.as_str()),
        (3, Criticality::Ignore, ProcedureClass::Class2, "Msg")
    );
    assert!(a.successful.is_none());
    let b = ir.procedures.get("procB").unwrap();
    assert_eq!(
        (b.code, b.criticality, b.class),
        (4, Criticality::Reject, ProcedureClass::Class1)
    );
    assert_eq!(
        (b.successful.as_deref(), b.unsuccessful.as_deref()),
        (Some("Msg"), Some("Msg"))
    );
    assert_eq!(ir.sets.get("ALL").unwrap().procedures, ["procA", "procB"]);
}

#[test]
fn integer_constraints_are_evaluated() {
    let ir = mutated("Foo ::= INTEGER (0..7, ...)", "Foo ::= INTEGER (1..30|40|181, ...)\nBar ::= INTEGER (-5..maxExt)\nBaz ::= INTEGER\nQux ::= INTEGER (0..MAX)").unwrap();
    let int = |n: &str| match &ir.types.get(n).unwrap().ty {
        IrType::Integer(r) => r.clone(),
        t => panic!("{t:?}"),
    };
    let foo = int("Foo");
    assert_eq!((foo.lb, foo.ub, foo.extensible), (Some(1), Some(181), true));
    assert_eq!(foo.ranges, [(1, 30), (40, 40), (181, 181)]);
    let bar = int("Bar");
    assert_eq!(
        (bar.lb, bar.ub, bar.extensible, bar.ranges.len()),
        (Some(-5), Some(65535), false, 1)
    );
    assert_eq!(int("Baz"), IntRange::default());
    assert_eq!(
        (int("Qux").lb, int("Qux").ub, int("Qux").ranges.len()),
        (Some(0), None, 0)
    );
}

#[test]
fn sizes_use_constants_and_extension_markers() {
    let ir = mutated("Foo ::=", "S1 ::= OCTET STRING (SIZE (1..maxExt, ...))\nS2 ::= BIT STRING (SIZE (8, ..., 16))\nS3 ::= UTF8String (SIZE (1..150, ...))\nS4 ::= OCTET STRING\nFoo ::=").unwrap();
    assert!(
        matches!(&ir.types.get("S1").unwrap().ty, IrType::OctetString { size, contained: None } if *size == IrSize { lb: 1, ub: Some(65535), extensible: true })
    );
    assert!(
        matches!(&ir.types.get("S2").unwrap().ty, IrType::BitString(s) if *s == IrSize { lb: 8, ub: Some(8), extensible: true })
    );
    assert!(
        matches!(&ir.types.get("S3").unwrap().ty, IrType::CharString { size, .. } if size.ub == Some(150) && size.extensible)
    );
    assert!(
        matches!(&ir.types.get("S4").unwrap().ty, IrType::OctetString { size, .. } if *size == IrSize::UNBOUNDED)
    );
}

#[test]
fn enumerations_are_numbered_and_indexed() {
    let ir = mutated(
        "Foo ::=",
        "E ::= ENUMERATED { c(5), a, b, ..., d, e }\nFoo ::=",
    )
    .unwrap();
    let IrType::Enumerated(e) = &ir.types.get("E").unwrap().ty else {
        panic!()
    };
    let root: Vec<_> = e
        .root
        .iter()
        .map(|i| (i.name.as_str(), i.value, i.index))
        .collect();
    assert_eq!(root, [("c", 5, 2), ("a", 0, 0), ("b", 1, 1)]);
    let adds: Vec<_> = e
        .additions
        .iter()
        .map(|i| (i.name.as_str(), i.value, i.index))
        .collect();
    assert_eq!(adds, [("d", 2, 0), ("e", 3, 1)]);
    assert!(e.extensible);
    // plain enumeration: declaration order is the PER index
    let IrType::Enumerated(c) = &ir.types.get("Criticality").unwrap().ty else {
        panic!()
    };
    assert_eq!(
        c.root
            .iter()
            .map(|i| (i.name.as_str(), i.index))
            .collect::<Vec<_>>(),
        [("reject", 0), ("ignore", 1), ("notify", 2)]
    );
    assert!(!c.extensible);
}

#[test]
fn choices_and_nested_types() {
    let ir = mutated(
        "Foo ::=",
        "Ch ::= CHOICE { a Foo, b SEQUENCE (SIZE(1..3)) OF Foo, ..., c NULL }\nFoo ::=",
    )
    .unwrap();
    let IrType::Choice(c) = &ir.types.get("Ch").unwrap().ty else {
        panic!()
    };
    assert_eq!(
        (c.root.len(), c.extensible, c.additions.len()),
        (2, true, 1)
    );
    assert!(
        matches!(&c.root[1].ty, IrType::SequenceOf { size, element } if size.ub == Some(3) && **element == IrType::Named("Foo".into()))
    );
    assert_eq!(c.additions[0].ty, IrType::Null);
}

#[test]
fn resolve_follows_aliases() {
    let ir = mutated("Foo ::=", "Alias ::= Foo2\nFoo2 ::= Foo\nFoo ::=").unwrap();
    assert!(matches!(
        ir.resolve(&IrType::Named("Alias".into())),
        Some(IrType::Integer(_))
    ));
    assert!(ir.resolve(&IrType::Named("Nope".into())).is_none());
}

#[test]
fn errors_name_the_problem() {
    fails(
        "TYPE Foo PRESENCE mandatory",
        "TYPE Nope PRESENCE mandatory",
        "`Nope` is not defined or imported",
    );
    fails(
        "ID id-B CRITICALITY",
        "ID id-A CRITICALITY",
        "appears twice",
    );
    fails(
        "Container {{MsgIEs}}",
        "Container {{Missing}}",
        "not a visible object set",
    );
    fails(
        "ExtContainer {{ItemExt}}",
        "ExtContainer {{MsgIEs}}",
        "not of class EXT",
    );
    fails(
        "Container {{MsgIEs}}",
        "Container {{MsgIEs}, 3}",
        "takes 1 parameters, 2 given",
    );
    fails(
        "List { 1, 4, {ItemIEs} }",
        "List { {ItemIEs}, 4, {ItemIEs} }",
        "wrong kind",
    );
    fails(
        "List { 1, 4, {ItemIEs} }",
        "List { 1, nope, {ItemIEs} }",
        "unknown constant `nope`",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nD ::= SEQUENCE { a INTEGER DEFAULT 3 }",
        "DEFAULT component",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nD ::= SEQUENCE { a Foo, a Foo }",
        "duplicate component",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nE ::= ENUMERATED { a, a }",
        "duplicate enumeration item",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nR ::= Foo (0..3)",
        "constraint on the reference",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nR ::= Container",
        "without arguments",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nR ::= INTEGER (7..3)",
        "empty range",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nR ::= OCTET STRING (SIZE (-1..3))",
        "negative size",
    );
    fails("PROCEDURE CODE 4", "PROCEDURE CODE 3", "also used by");
    fails(
        "PROCEDURE CODE 4",
        "PROCEDURE CODE 300",
        "outside the range of ProcedureCode",
    );
    fails(
        "id-A ProtocolIE-ID ::= 1",
        "id-A ProtocolIE-ID ::= 70000",
        "outside the range of ProtocolIE-ID",
    );
    fails(
        "INITIATING MESSAGE Msg PROCEDURE CODE 3",
        "INITIATING MESSAGE Foo PROCEDURE CODE 3",
        "must be a SEQUENCE with an IE container",
    );
    fails(
        "Foo ::= INTEGER (0..7, ...)",
        "Foo ::= INTEGER (0..7, ...)\nField2 ::= SEQUENCE { id IES.&id ({MsgIEs}), value IES.&Value ({MsgIEs}{@id}) }\nBad ::= SEQUENCE { x IES.&id }",
        "table-constrained",
    );
}

#[test]
fn names_must_be_unique_across_modules_and_imports_must_resolve() {
    let a = "A { x } DEFINITIONS ::= BEGIN T ::= INTEGER END";
    let b = "B { y } DEFINITIONS ::= BEGIN T ::= INTEGER END";
    let m = parse_modules(&[("a", a), ("b", b)]).unwrap();
    assert!(
        build_ir(&m)
            .unwrap_err()
            .message
            .contains("also defined in module")
    );
    let c = "C { z } DEFINITIONS ::= BEGIN IMPORTS Nope FROM A; U ::= INTEGER END";
    let m = parse_modules(&[("a", a), ("c", c)]).unwrap();
    assert!(
        build_ir(&m)
            .unwrap_err()
            .message
            .contains("`Nope` is not defined in A")
    );
    // a type that exists in another module but is not imported is out of scope
    let d = "D { w } DEFINITIONS ::= BEGIN V ::= SEQUENCE { t T } END";
    let m = parse_modules(&[("a", a), ("d", d)]).unwrap();
    assert!(
        build_ir(&m)
            .unwrap_err()
            .message
            .contains("not defined or imported")
    );
}

#[test]
fn self_containing_types_are_reported() {
    let ir = mutated("Foo ::=", "Tree ::= SEQUENCE { kids SEQUENCE OF Tree OPTIONAL }\nA1 ::= SEQUENCE { b B1 }\nB1 ::= CHOICE { a A1, n NULL }\nFoo ::=").unwrap();
    let mut groups = recursive_groups(&ir);
    groups.iter_mut().for_each(|g| g.sort());
    groups.sort();
    assert_eq!(
        groups,
        [
            vec!["A1".to_owned(), "B1".to_owned()],
            vec!["Tree".to_owned()]
        ]
    );
    // CONTAINING is raw bytes: not an edge
    let ir = mutated(
        "Foo ::=",
        "Cn ::= SEQUENCE { raw OCTET STRING (CONTAINING Cn) }\nFoo ::=",
    )
    .unwrap();
    assert!(recursive_groups(&ir).is_empty());
}
