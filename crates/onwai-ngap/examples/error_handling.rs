//! What `decode_pdu` tells you about a faulty PDU. Run with `cargo run -p onwai-ngap --example error_handling`.

use onwai_ngap::{Reaction, decode_pdu, encode_pdu, types::*};

fn main() {
    // a PDU whose procedure code (200) this version of the specification does not define, criticality "reject"
    let unknown_procedure = [0x00, 200, 0x00, 0x00];
    // random octets
    let garbage = [0xff, 0x13, 0x37];

    for (what, bytes) in [
        ("unknown procedure", &unknown_procedure[..]),
        ("garbage", &garbage[..]),
    ] {
        let Err(e) = decode_pdu(bytes) else {
            println!("{what}: decoded");
            continue;
        };
        println!("{what}: {e}");
        match e.reaction() {
            Reaction::ErrorIndication => {
                // the caller fills in the AP IDs it knows and sends the message
                let ei = e.error_indication().expect("clause 10 asks for one");
                let wire = encode_pdu(&NgapPdu::InitiatingMessage(
                    InitiatingMessage::ErrorIndication(ei),
                ))
                .unwrap();
                println!("  -> send Error Indication, {} octets", wire.len());
            }
            other => println!("  -> {other:?}"),
        }
    }
}
