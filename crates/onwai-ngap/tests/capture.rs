//! NGAP PDUs captured on a real N2 link (a simulated gNB and a 5G core AMF: one UE registration and PDU session
//! set-up), see `tests/captures/attach.txt`. This is the check against a foreign implementation: bytes produced by
//! other encoders must decode without any diagnostics and encode back to exactly the same octets.

use onwai_ngap::{Context, MessageType, decode_pdu, encode_pdu, types::*};

fn capture() -> Vec<(String, bool, Vec<u8>)> {
    include_str!("captures/attach.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (head, hex) = l.split_once(" | ")?;
            let (frame, dir) = head.split_once(' ')?;
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            Some((frame.to_owned(), dir == "->", bytes))
        })
        .collect()
}

#[test]
fn the_captured_conversation_is_what_we_expect() {
    let names: Vec<_> = capture()
        .iter()
        .map(|(frame, _, bytes)| {
            decode_pdu(bytes)
                .unwrap_or_else(|e| panic!("frame {frame}: {e}"))
                .pdu
                .message_name()
        })
        .collect();
    assert_eq!(
        names,
        [
            "NGSetupRequest",
            "NGSetupResponse",
            "InitialUEMessage",
            "DownlinkNASTransport",
            "UplinkNASTransport",
            "DownlinkNASTransport",
            "UplinkNASTransport",
            "InitialContextSetupRequest",
            "InitialContextSetupResponse",
            "UplinkNASTransport",
            "UplinkNASTransport",
            "DownlinkNASTransport",
            "PDUSessionResourceSetupRequest",
            "PDUSessionResourceSetupResponse",
        ]
    );
}

#[test]
fn every_captured_pdu_decodes_cleanly_and_re_encodes_to_the_same_octets() {
    let all = capture();
    assert_eq!(all.len(), 14);
    for (frame, _, bytes) in &all {
        let decoded = decode_pdu(bytes).unwrap_or_else(|e| panic!("frame {frame}: {e}"));
        assert!(
            decoded.issues.is_empty(),
            "frame {frame}: unexpected issues {:?}",
            decoded.issues
        );
        assert!(decoded.pdu.unknown_ies().is_empty(), "frame {frame}");
        let again = encode_pdu(&decoded.pdu).unwrap_or_else(|e| panic!("frame {frame}: {e}"));
        assert_eq!(&again, bytes, "frame {frame}: re-encoding differs");
    }
}

#[test]
fn the_direction_matches_the_message_type() {
    for (frame, _, bytes) in capture() {
        let d = decode_pdu(&bytes).unwrap();
        let Context { message_type, .. } = d.context;
        // setup, NAS and context/session requests from the AMF are initiating; the responses are successful outcomes
        let name = d.pdu.message_name();
        let expect = if name.ends_with("Response") {
            MessageType::Successful
        } else {
            MessageType::Initiating
        };
        assert_eq!(message_type, expect, "frame {frame} ({name})");
    }
}

#[test]
fn the_ng_setup_exchange_carries_the_expected_values() {
    let all = capture();
    let request = decode_pdu(&all[0].2).unwrap().pdu;
    let NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(r)) = request else {
        panic!("not an NG Setup Request")
    };
    assert_eq!(r.ran_node_name.unwrap().0, "UERANSIM-gnb-999-70-1");
    let GlobalRanNodeId::GlobalGnbId(g) = r.global_ran_node_id else {
        panic!("not a gNB")
    };
    assert_eq!(g.plmn_identity.0, [0x99, 0xf9, 0x07]);
    assert_eq!(r.supported_ta_list.0.len(), 1);

    let response = decode_pdu(&all[1].2).unwrap().pdu;
    let NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(r)) = response else {
        panic!("not an NG Setup Response")
    };
    assert_eq!(r.amf_name.0, "example-amf0");
    assert!(!r.served_guami_list.0.is_empty());
    assert!(!r.plmn_support_list.0.is_empty());
}

#[test]
fn the_nas_pdus_are_opaque_octets_that_start_with_a_5gs_header() {
    // 5GMM messages carry the extended protocol discriminator 0x7e; the codec does not interpret them
    let mut seen = 0;
    for (_, _, bytes) in capture() {
        match decode_pdu(&bytes).unwrap().pdu {
            NgapPdu::InitiatingMessage(InitiatingMessage::InitialUeMessage(m)) => {
                assert_eq!(m.nas_pdu.0[0], 0x7e);
                seen += 1;
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::UplinkNasTransport(m)) => {
                assert_eq!(m.nas_pdu.0[0], 0x7e);
                seen += 1;
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::DownlinkNasTransport(m)) => {
                assert_eq!(m.nas_pdu.0[0], 0x7e);
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(
        seen, 8,
        "1 Initial UE Message, 4 uplink and 3 downlink NAS transports"
    );
}
