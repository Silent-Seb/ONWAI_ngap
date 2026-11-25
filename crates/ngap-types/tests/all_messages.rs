//! Every message of the specification, in five sampled shapes each (`testdata/messages.txt`, produced by
//! `cargo xtask vectors` from the resolved ASN.1 without using the generated types): the generated types must decode
//! each PDU and encode it back to the same octets.

use std::collections::BTreeSet;

use ngap_types::*;

pub fn vectors() -> Vec<(String, String, Vec<u8>)> {
    include_str!("../../../testdata/messages.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(" | "))
        .map(|(k, v)| {
            let (name, tag) = k.rsplit_once('.').expect("name.tag");
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (name.to_owned(), tag.to_owned(), bytes)
        })
        .collect()
}

#[test]
fn every_sampled_pdu_round_trips_octet_for_octet() {
    let all = vectors();
    assert!(all.len() >= 700, "only {} vectors", all.len());
    for (name, tag, bytes) in &all {
        let pdu: NgapPdu = ngap_aper::from_slice(bytes)
            .unwrap_or_else(|e| panic!("{name}.{tag}: decode failed: {e}"));
        let again =
            ngap_aper::to_vec(&pdu).unwrap_or_else(|e| panic!("{name}.{tag}: encode failed: {e}"));
        assert_eq!(&again, bytes, "{name}.{tag}: re-encoding differs");
    }
}

#[test]
fn the_decoded_message_is_the_one_that_was_sampled() {
    for (name, tag, bytes) in vectors() {
        let pdu: NgapPdu = ngap_aper::from_slice(&bytes).unwrap();
        assert_eq!(pdu.message_name(), name, "{name}.{tag}");
        // the sampler writes only IEs the specification defines for the message
        assert!(pdu.unknown_ies().is_empty(), "{name}.{tag}");
        // and in the order the specification requires
        let ids = match &pdu {
            NgapPdu::InitiatingMessage(m) => {
                InitiatingMessage::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            NgapPdu::SuccessfulOutcome(m) => {
                SuccessfulOutcome::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            NgapPdu::UnsuccessfulOutcome(m) => {
                UnsuccessfulOutcome::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            _ => unreachable!(),
        };
        let ids = ids.unwrap().unwrap();
        let known = pdu.ie_ids();
        let positions: Vec<usize> = ids
            .iter()
            .map(|id| known.iter().position(|k| k == id).expect("a known IE"))
            .collect();
        assert!(
            positions.windows(2).all(|p| p[0] < p[1]),
            "{name}.{tag}: {ids:?}"
        );
    }
}

/// The message inside the procedure wrapper.
fn content(bytes: &[u8]) -> Vec<u8> {
    let mut r = ngap_aper::BitReader::new(bytes);
    r.read_index(3, true).unwrap();
    ngap_aper::ie::read_procedure(&mut r).unwrap().2
}

#[test]
fn every_message_of_every_procedure_is_covered() {
    let seen: BTreeSet<String> = vectors().into_iter().map(|(n, _, _)| n).collect();
    // each wrapper enum has one variant per message; `PrivateMessage` cannot be sampled (the spec defines no private IE)
    let expected = InitiatingMessage::PROCEDURE_CODES.len()
        + SuccessfulOutcome::PROCEDURE_CODES.len()
        + UnsuccessfulOutcome::PROCEDURE_CODES.len()
        - 1;
    assert_eq!(seen.len(), expected, "{seen:?}");
}

#[test]
fn the_maximal_pdu_has_every_ie_the_minimal_one_leaves_out() {
    let mut max_ids = 0;
    let mut min_ids = 0;
    for (_, tag, bytes) in vectors() {
        let pdu: NgapPdu = ngap_aper::from_slice(&bytes).unwrap();
        let n = match &pdu {
            NgapPdu::InitiatingMessage(m) => {
                InitiatingMessage::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            NgapPdu::SuccessfulOutcome(m) => {
                SuccessfulOutcome::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            NgapPdu::UnsuccessfulOutcome(m) => {
                UnsuccessfulOutcome::wire_ie_ids(m.procedure_code(), &content(&bytes))
            }
            _ => unreachable!(),
        }
        .unwrap()
        .unwrap()
        .len();
        match tag.as_str() {
            "max" => max_ids += n,
            "min" => min_ids += n,
            _ => {}
        }
        if tag == "max" {
            // everything defined is present (except what cannot be sampled: rows whose type needs an empty set)
            assert!(
                n >= pdu.ie_ids().len() * 9 / 10,
                "{}: {n} of {}",
                pdu.message_name(),
                pdu.ie_ids().len()
            );
        }
    }
    assert!(max_ids > 2 * min_ids, "max {max_ids} min {min_ids}");
}
