//! Same properties as `crates/onwai-ngap/tests/mutation.rs`, with coverage-guided input:
//! `decode_pdu` never panics; whatever it accepts is a fixed point of encode/decode; the diagnostics API is total and
//! the Error Indication it builds can be encoded.
#![no_main]

use libfuzzer_sys::fuzz_target;
use onwai_ngap::{DecodeOptions, NgapPdu, decode_pdu, decode_pdu_with, encode_pdu, types};

fuzz_target!(|data: &[u8]| {
    match decode_pdu(data) {
        Ok(decoded) => {
            let again = encode_pdu(&decoded.pdu).expect("a decoded PDU must encode");
            let back = decode_pdu(&again).expect("a re-encoded PDU must decode");
            assert_eq!(back.pdu, decoded.pdu, "not a fixed point");
            assert!(
                decode_pdu_with(data, &DecodeOptions::default().enforce_ie_order(false)).is_ok(),
                "the lenient decoder rejects what the strict one accepts"
            );
        }
        Err(e) => {
            let _ = (
                e.to_string(),
                e.reaction(),
                e.cause(),
                e.criticality_diagnostics(),
            );
            if let Some(ei) = e.error_indication() {
                let pdu = NgapPdu::InitiatingMessage(types::InitiatingMessage::ErrorIndication(ei));
                encode_pdu(&pdu).expect("the Error Indication built from an error must encode");
            }
        }
    }
});
