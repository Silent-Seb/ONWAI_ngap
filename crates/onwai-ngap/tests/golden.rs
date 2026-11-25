//! The PDUs that the independent `asn1tools` encoder produced (shared with the `ngap-types` tests) go through
//! `decode_pdu` / `encode_pdu`: no issues, and the same octets come back.

use onwai_ngap::{PduInfo, decode_pdu, encode_pdu};

fn vectors() -> Vec<(String, Vec<u8>)> {
    include_str!("../../ngap-types/tests/vectors.txt")
        .lines()
        .filter_map(|l| l.split_once(" | "))
        .map(|(k, v)| {
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (k.to_owned(), bytes)
        })
        .collect()
}

#[test]
fn oracle_pdus_decode_cleanly_and_re_encode_identically() {
    let all = vectors();
    assert!(all.len() >= 10);
    for (name, bytes) in all {
        let decoded = decode_pdu(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(decoded.issues.is_empty(), "{name}: {:?}", decoded.issues);
        assert_eq!(encode_pdu(&decoded.pdu).unwrap(), bytes, "{name}");
        // the envelope facts agree with the message
        assert_eq!(decoded.context.procedure_code, decoded.pdu.procedure_code());
        assert_eq!(decoded.context.message_type, decoded.pdu.message_type());
        assert_eq!(
            decoded.context.procedure_criticality,
            decoded.pdu.procedure_criticality()
        );
    }
}

#[test]
fn every_corrupted_oracle_pdu_gives_an_error_or_a_value_never_a_panic() {
    for (_, bytes) in vectors() {
        for i in 0..bytes.len() * 8 {
            let mut b = bytes.clone();
            b[i / 8] ^= 0x80 >> (i % 8);
            if let Err(e) = decode_pdu(&b) {
                let _ = (e.to_string(), e.reaction(), e.cause(), e.error_indication());
            }
        }
    }
}

fn sampled() -> Vec<(String, Vec<u8>)> {
    include_str!("../../../testdata/messages.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(" | "))
        .map(|(k, v)| {
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (k.to_owned(), bytes)
        })
        .collect()
}

#[test]
fn every_sampled_message_decodes_through_the_facade_without_issues() {
    let all = sampled();
    assert!(all.len() >= 700);
    for (name, bytes) in all {
        let decoded = decode_pdu(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(decoded.issues.is_empty(), "{name}: {:?}", decoded.issues);
        assert_eq!(encode_pdu(&decoded.pdu).unwrap(), bytes, "{name}");
    }
}
