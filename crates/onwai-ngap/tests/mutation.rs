//! Robustness: damaged PDUs must never panic, hang or allocate wildly, and whatever still decodes must be a
//! fixed point (`decode(encode(x)) == x`).
//!
//! The corpus is `testdata/messages.txt`; each PDU is mutated `NGAP_MUTATIONS` times (default 12; the nightly-style
//! run is `NGAP_MUTATIONS=2000 cargo test -p onwai-ngap --release --test mutation`). Deterministic: the seed is
//! `NGAP_SEED` (default 1), and a failure prints the PDU and the mutation.

use std::time::{Duration, Instant};

use onwai_ngap::{DecodeOptions, decode_pdu, decode_pdu_with, encode_pdu};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn corpus() -> Vec<(String, Vec<u8>)> {
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

fn mutate(rng: &mut Rng, original: &[u8], donor: &[u8]) -> (Vec<u8>, String) {
    let mut b = original.to_vec();
    let what = match rng.below(9) {
        0 => {
            let n = 1 + rng.below(4);
            for _ in 0..n {
                let i = rng.below(b.len() * 8);
                b[i / 8] ^= 0x80 >> (i % 8);
            }
            format!("flip {n} bit(s)")
        }
        1 => {
            let i = rng.below(b.len());
            b[i] = rng.next() as u8;
            format!("replace byte {i}")
        }
        2 => {
            let n = rng.below(b.len());
            b.truncate(n);
            format!("truncate to {n}")
        }
        3 => {
            let i = rng.below(b.len() + 1);
            let extra: Vec<u8> = (0..1 + rng.below(8)).map(|_| rng.next() as u8).collect();
            b.splice(i..i, extra);
            format!("insert at {i}")
        }
        4 => {
            let i = rng.below(b.len());
            let n = 1 + rng.below(b.len() - i);
            b.drain(i..i + n);
            format!("delete {n} at {i}")
        }
        5 => {
            let i = rng.below(b.len());
            let n = 1 + rng.below((b.len() - i).min(6));
            let fill = if rng.below(2) == 0 { 0x00 } else { 0xff };
            b[i..i + n].fill(fill);
            format!("fill {n} at {i} with {fill:#x}")
        }
        6 => {
            // splice the tail of another PDU onto this one
            let i = rng.below(b.len());
            let j = rng.below(donor.len());
            b.truncate(i);
            b.extend_from_slice(&donor[j..]);
            format!("splice donor tail at {i}/{j}")
        }
        7 => {
            // a huge length determinant somewhere
            let i = rng.below(b.len());
            b[i] = 0xff;
            if i + 1 < b.len() {
                b[i + 1] = 0xff;
            }
            format!("0xffff at {i}")
        }
        _ => {
            let i = rng.below(b.len());
            let n = 1 + rng.below(b.len() - i);
            let copy = b[i..i + n].to_vec();
            let at = rng.below(b.len() + 1);
            b.splice(at..at, copy);
            format!("duplicate {n} from {i} at {at}")
        }
    };
    (b, what)
}

#[test]
fn damaged_pdus_never_panic_and_survivors_are_fixed_points() {
    let rounds: usize = std::env::var("NGAP_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let seed: u64 = std::env::var("NGAP_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let corpus = corpus();
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let (mut decoded, mut rejected) = (0u64, 0u64);
    let mut slowest = Duration::ZERO;
    for (name, original) in &corpus {
        for _ in 0..rounds {
            let donor = &corpus[rng.below(corpus.len())].1;
            let (bytes, what) = mutate(&mut rng, original, donor);
            let start = Instant::now();
            let result = decode_pdu(&bytes);
            let lenient =
                decode_pdu_with(&bytes, &DecodeOptions::default().enforce_ie_order(false));
            slowest = slowest.max(start.elapsed());
            match result {
                Ok(d) => {
                    decoded += 1;
                    let again = encode_pdu(&d.pdu).unwrap_or_else(|e| {
                        panic!(
                            "{name}: {what}: decoded value does not encode: {e}\n{}",
                            hex(&bytes)
                        )
                    });
                    let back = decode_pdu(&again).unwrap_or_else(|e| {
                        panic!(
                            "{name}: {what}: re-encoding does not decode: {e}\n{}",
                            hex(&bytes)
                        )
                    });
                    assert_eq!(
                        back.pdu,
                        d.pdu,
                        "{name}: {what}: not a fixed point\n{}",
                        hex(&bytes)
                    );
                    assert!(
                        lenient.is_ok(),
                        "{name}: {what}: the lenient decoder rejects what the strict one accepts"
                    );
                }
                Err(e) => {
                    rejected += 1;
                    // the diagnostics API must be total
                    let _ = (
                        e.to_string(),
                        e.reaction(),
                        e.cause(),
                        e.error_indication(),
                        e.criticality_diagnostics(),
                    );
                    if let Some(ei) = e.error_indication() {
                        // and what it builds must be encodable
                        let pdu = onwai_ngap::NgapPdu::InitiatingMessage(
                            onwai_ngap::types::InitiatingMessage::ErrorIndication(ei),
                        );
                        encode_pdu(&pdu).unwrap_or_else(|x| {
                            panic!("{name}: {what}: Error Indication does not encode: {x}")
                        });
                    }
                }
            }
        }
    }
    eprintln!("{decoded} still decoded, {rejected} rejected, slowest decode {slowest:?}");
    assert!(rejected > 0, "the mutations are too weak");
    assert!(
        slowest < Duration::from_secs(2),
        "a decode took {slowest:?}"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
