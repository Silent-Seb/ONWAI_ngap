//! Builds the IR of the six real NGAP modules and checks it. Needs `specs/asn1` (see `parse_ngap.rs`).

use std::path::PathBuf;

use ngap_codegen::asn1::{CharStringKind, parse_modules};
use ngap_codegen::ir::*;

fn load() -> Option<Ir> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/asn1");
    let sources = match ngap_codegen::spec::read_modules_dir(&dir) {
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
    let modules = parse_modules(&refs).unwrap_or_else(|e| panic!("{e}"));
    Some(build_ir(&modules).unwrap_or_else(|e| panic!("{e}")))
}

fn named<'a>(ir: &'a Ir, n: &str) -> &'a IrType {
    &ir.types.get(n).unwrap_or_else(|| panic!("no type {n}")).ty
}

/// The numbers of the pinned release `38413-j40`; the AST census already cross-checks the parser, these pin the
/// resolver (every row, constant and procedure is accounted for).
#[test]
fn census_of_38413_j40() {
    let Some(ir) = load() else { return };
    let c = IrCensus::of(&ir);
    println!("{c}");
    assert_eq!(
        (
            c.consts,
            c.consts_ie_ids,
            c.consts_procedure_codes,
            c.consts_other
        ),
        (686, 491, 87, 108)
    );
    assert_eq!(
        c.named_types,
        1308 - 11,
        "every non-parameterized type assignment"
    );
    assert_eq!(
        (
            c.sets,
            c.ie_sets,
            c.extension_sets,
            c.procedure_sets,
            c.private_sets
        ),
        (700, 227, 469, 3, 1)
    );
    assert_eq!(
        c.ie_rows + c.extension_rows,
        1127,
        "every inline object of the AST is a row"
    );
    assert_eq!((c.ie_rows, c.extension_rows), (898, 229));
    assert_eq!((c.procedures, c.class1, c.class2), (87, 36, 51));
    assert_eq!(c.enumerations, 230);
    assert_eq!(c.choices, 79);
    assert_eq!(c.contained + contained_in_rows(&ir), 60);
    assert_eq!(
        c.recursive_groups, 0,
        "no type contains itself, so no indirection is needed"
    );
}

fn contained_in_rows(ir: &Ir) -> usize {
    ir.sets
        .iter()
        .flat_map(|s| &s.rows)
        .filter(|r| {
            matches!(
                &r.ty,
                IrType::OctetString {
                    contained: Some(_),
                    ..
                }
            )
        })
        .count()
}

/// Every table node of the IR, by class, counting the rows' inline types too: the parameterized container uses
/// plus the three procedure wrappers of the PDU.
#[test]
fn every_container_use_became_a_table() {
    let Some(ir) = load() else { return };
    let mut by_class = std::collections::BTreeMap::<String, usize>::new();
    let mut count = |t: &IrType| {
        fn go(t: &IrType, m: &mut std::collections::BTreeMap<String, usize>) {
            match t {
                IrType::Table(x) => *m.entry(x.class.clone()).or_default() += 1,
                IrType::Sequence(s) => s.root.iter().chain(&s.additions).for_each(|c| go(&c.ty, m)),
                IrType::Choice(c) => c.root.iter().chain(&c.additions).for_each(|a| go(&a.ty, m)),
                IrType::SequenceOf { element, .. } => go(element, m),
                IrType::OctetString {
                    contained: Some(c), ..
                } => go(c, m),
                _ => {}
            }
        }
        go(t, &mut by_class);
    };
    for t in &ir.types {
        count(&t.ty);
    }
    for s in &ir.sets {
        for r in &s.rows {
            count(&r.ty);
        }
    }
    // 150 `ProtocolIE-Container` + 77 `ProtocolIE-SingleContainer` uses (the 78th reference is inside the unused
    // `ProtocolIE-ContainerList` template)
    assert_eq!(by_class["NGAP-PROTOCOL-IES"], 150 + 77);
    assert_eq!(by_class["NGAP-PROTOCOL-EXTENSION"], 469);
    assert_eq!(by_class["NGAP-PRIVATE-IES"], 1);
    assert_eq!(by_class["NGAP-ELEMENTARY-PROCEDURE"], 3);
}

#[test]
fn constants() {
    let Some(ir) = load() else { return };
    let v = |n: &str| {
        ir.consts
            .get(n)
            .unwrap_or_else(|| panic!("no const {n}"))
            .value
    };
    assert_eq!(v("id-NGSetup"), 21);
    assert_eq!(v("id-GlobalRANNodeID"), 27);
    assert_eq!(v("id-SupportedTAList"), 102);
    assert_eq!(v("maxProtocolIEs"), 65535);
    assert_eq!(ir.consts.get("id-NGSetup").unwrap().ty, "ProcedureCode");
}

#[test]
fn constrained_types_are_evaluated() {
    let Some(ir) = load() else { return };
    let IrType::Integer(r) = named(&ir, "ExpectedActivityPeriod") else {
        panic!()
    };
    assert_eq!((r.lb, r.ub, r.extensible), (Some(1), Some(181), true));
    assert_eq!(r.ranges.len(), 10, "1..30 and nine single values");
    assert_eq!(r.ranges[0], (1, 30));
    let IrType::Integer(r) = named(&ir, "ExtendedPacketDelayBudget") else {
        panic!()
    };
    assert_eq!(
        (r.lb, r.ub, r.extensible, r.ranges.clone()),
        (Some(1), Some(65535), true, vec![(1, 65535)])
    );
    assert_eq!(
        r.additions,
        [(65536, 109999)],
        "values defined after the extension marker"
    );
    let IrType::Integer(r) = named(&ir, "AMF-UE-NGAP-ID") else {
        panic!()
    };
    assert_eq!(
        (r.lb, r.ub, r.extensible),
        (Some(0), Some(1_099_511_627_775), false)
    );
    assert!(
        matches!(named(&ir, "AMFName"), IrType::CharString { kind: CharStringKind::Printable, size } if *size == IrSize { lb: 1, ub: Some(150), extensible: true })
    );
    assert!(
        matches!(named(&ir, "TAC"), IrType::OctetString { size, .. } if *size == IrSize { lb: 3, ub: Some(3), extensible: false })
    );
    assert!(
        matches!(named(&ir, "URI-address"), IrType::CharString { kind: CharStringKind::Visible, size } if *size == IrSize::UNBOUNDED)
    );
    let IrType::Enumerated(e) = named(&ir, "Criticality") else {
        panic!()
    };
    assert_eq!(
        e.root.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
        ["reject", "ignore", "notify"]
    );
}

#[test]
fn ng_setup_request_is_resolved() {
    let Some(ir) = load() else { return };
    let IrType::Sequence(s) = named(&ir, "NGSetupRequest") else {
        panic!()
    };
    assert!(s.extensible);
    assert_eq!(s.root.len(), 1);
    let IrType::SequenceOf { size, element } = &s.root[0].ty else {
        panic!()
    };
    assert_eq!((size.lb, size.ub), (0, Some(65535)));
    let IrType::Table(t) = element.as_ref() else {
        panic!()
    };
    assert_eq!(
        (t.class.as_str(), t.set.as_str()),
        ("NGAP-PROTOCOL-IES", "NGSetupRequestIEs")
    );
    let set = ir.sets.get("NGSetupRequestIEs").unwrap();
    assert!(set.extensible);
    let ids: Vec<u32> = set.rows.iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), 9);
    assert_eq!(
        &ids[..4],
        [27, 82, 102, 21],
        "rows keep the spec order (the required wire order)"
    );
    let first = &set.rows[0];
    assert_eq!(
        (first.criticality, first.presence),
        (Criticality::Reject, Presence::Mandatory)
    );
    assert_eq!(first.ty, IrType::Named("GlobalRANNodeID".into()));
    assert_eq!(set.rows[1].presence, Presence::Optional);
}

#[test]
fn procedures_and_the_pdu_wrapper() {
    let Some(ir) = load() else { return };
    let p = ir.procedures.get("nGSetup").unwrap();
    assert_eq!(
        (p.code, p.criticality, p.class),
        (21, Criticality::Reject, ProcedureClass::Class1)
    );
    assert_eq!(
        (
            p.initiating.as_str(),
            p.successful.as_deref(),
            p.unsuccessful.as_deref()
        ),
        (
            "NGSetupRequest",
            Some("NGSetupResponse"),
            Some("NGSetupFailure")
        )
    );
    let p = ir.procedures.get("aMFStatusIndication").unwrap();
    assert_eq!(
        (p.criticality, p.class, p.successful.clone()),
        (Criticality::Ignore, ProcedureClass::Class2, None)
    );
    // handover cancel: a response but no failure message
    let p = ir.procedures.get("handoverCancel").unwrap();
    assert_eq!(
        (p.successful.as_deref(), p.unsuccessful.as_deref()),
        (Some("HandoverCancelAcknowledge"), None)
    );

    let all = ir.sets.get("NGAP-ELEMENTARY-PROCEDURES").unwrap();
    assert_eq!(
        all.procedures.len(),
        87,
        "class 1 and class 2 sets are flattened, in order"
    );
    assert_eq!(all.procedures[0], "aMFConfigurationUpdate");
    let IrType::Choice(pdu) = named(&ir, "NGAP-PDU") else {
        panic!()
    };
    assert_eq!(
        pdu.root.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
        [
            "initiatingMessage",
            "successfulOutcome",
            "unsuccessfulOutcome"
        ]
    );
    let IrType::Table(t) = named(&ir, "InitiatingMessage") else {
        panic!()
    };
    assert_eq!(
        (
            t.class.as_str(),
            t.set.as_str(),
            t.components[2].field.as_str()
        ),
        (
            "NGAP-ELEMENTARY-PROCEDURE",
            "NGAP-ELEMENTARY-PROCEDURES",
            "InitiatingMessage"
        )
    );
}

#[test]
fn n2_transfer_containers_stay_raw_bytes() {
    let Some(ir) = load() else { return };
    let IrType::Sequence(s) = named(&ir, "PDUSessionResourceSetupItemSUReq") else {
        panic!()
    };
    let c = s
        .root
        .iter()
        .find(|c| c.name == "pDUSessionResourceSetupRequestTransfer")
        .expect("component");
    let IrType::OctetString {
        contained: Some(inner),
        ..
    } = &c.ty
    else {
        panic!("{:?}", c.ty)
    };
    assert_eq!(
        **inner,
        IrType::Named("PDUSessionResourceSetupRequestTransfer".into())
    );
    // the transfer type itself is a normal message-like SEQUENCE with its own IE table
    let IrType::Sequence(t) = ir.resolve(inner).unwrap() else {
        panic!()
    };
    assert!(
        matches!(&t.root[0].ty, IrType::SequenceOf { element, .. } if matches!(element.as_ref(), IrType::Table(tab) if tab.set == "PDUSessionResourceSetupRequestTransferIEs"))
    );
}

#[test]
fn private_message_uses_the_private_class() {
    let Some(ir) = load() else { return };
    let IrType::Sequence(s) = named(&ir, "PrivateMessage") else {
        panic!()
    };
    let IrType::SequenceOf { size, element } = &s.root[0].ty else {
        panic!()
    };
    assert_eq!((size.lb, size.ub), (1, Some(65535)));
    assert!(matches!(element.as_ref(), IrType::Table(t) if t.class == "NGAP-PRIVATE-IES"));
    let set = ir.sets.get("PrivateMessageIEs").unwrap();
    assert_eq!(
        (set.kind, set.rows.len(), set.extensible),
        (SetKind::PrivateIes, 0, true)
    );
}
