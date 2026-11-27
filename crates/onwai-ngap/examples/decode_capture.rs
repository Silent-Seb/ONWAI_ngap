//! Decode a real N2 conversation: the 14 NGAP PDUs of a UE registration and PDU session set-up between a simulated
//! gNB and a 5G core AMF (`tests/captures/attach.txt`, extracted from `tests/captures/5g_attach.pcap`).
//! Run with `cargo run -p onwai-ngap --example decode_capture`.

use onwai_ngap::{decode_pdu, encode_pdu};

fn main() {
    let capture = include_str!("../tests/captures/attach.txt");
    for line in capture.lines().filter(|l| !l.starts_with('#')) {
        let Some((head, hex)) = line.split_once(" | ") else {
            continue;
        };
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        match decode_pdu(&bytes) {
            Ok(d) => {
                let same = encode_pdu(&d.pdu).is_ok_and(|again| again == bytes);
                println!(
                    "{head:<8} {:>4} octets  {}{}",
                    bytes.len(),
                    d.pdu.message_name(),
                    if same { "" } else { "  (re-encoding differs!)" },
                );
            }
            Err(e) => println!("{head}: {e}"),
        }
    }
}
