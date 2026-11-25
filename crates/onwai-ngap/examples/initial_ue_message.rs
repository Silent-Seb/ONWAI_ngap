//! Take the NAS PDU out of an Initial UE Message. Run with `cargo run -p onwai-ngap --example initial_ue_message`.
//!
//! The NAS PDU is TS 24.501 and out of scope: the codec hands over the octets.

use onwai_ngap::{decode_pdu, types::*};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    // an Initial UE Message from the oracle-checked test vectors of `ngap-types`
    let pdu = hex(
        "000f403e00000500550002000100260014137e004179000d0100f1100000000000000000010079000f4000f110000000010000f110000001005a4001180070400100",
    );
    let decoded = decode_pdu(&pdu).expect("a valid PDU");
    let NgapPdu::InitiatingMessage(InitiatingMessage::InitialUeMessage(m)) = decoded.pdu else {
        panic!("not an Initial UE Message");
    };
    println!("RAN UE NGAP ID {}", m.ran_ue_ngap_id.0);
    println!("user location: {:?}", m.user_location_information);
    println!(
        "NAS PDU ({} octets): {:02x?}",
        m.nas_pdu.0.len(),
        m.nas_pdu.0
    );
    println!("RRC establishment cause: {:?}", m.rrc_establishment_cause);
}
