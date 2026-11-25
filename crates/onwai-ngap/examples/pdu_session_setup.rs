//! PDU Session Resource Setup Request carrying an N2 SM container the SMF built.
//! Run with `cargo run -p onwai-ngap --example pdu_session_setup`.
//!
//! The AMF forwards the SMF's octets without decoding them (`Contained::from_raw`), and a receiver decodes one
//! only when it needs to look inside.

use onwai_ngap::{Contained, decode_pdu, encode_pdu, types::*};

fn main() {
    // N2 SM information from the SMF (N11): opaque octets (this made-up one is not a valid transfer)
    let from_smf = vec![0x00, 0x00, 0x03, 0x00, 0x8b];
    let item = PduSessionResourceSetupItemSuReq::new(
        PduSessionId(5),
        SNssai::new(Sst(vec![1])),
        Contained::from_raw(from_smf.clone()),
    );
    let request = PduSessionResourceSetupRequest::new(
        AmfUeNgapId(1),
        RanUeNgapId(2),
        PduSessionResourceSetupListSuReq(vec![item]),
    );
    let bytes = encode_pdu(&NgapPdu::InitiatingMessage(
        InitiatingMessage::PduSessionResourceSetupRequest(request),
    ))
    .unwrap();
    println!("{} octets on the wire", bytes.len());

    // the gNB side
    let NgapPdu::InitiatingMessage(InitiatingMessage::PduSessionResourceSetupRequest(m)) =
        decode_pdu(&bytes).unwrap().pdu
    else {
        unreachable!()
    };
    let transfer =
        &m.pdu_session_resource_setup_list_su_req.0[0].pdu_session_resource_setup_request_transfer;
    assert_eq!(transfer.raw(), &from_smf[..]);
    match transfer.decode() {
        Ok(t) => println!("transfer: {t:?}"),
        Err(e) => println!("the transfer is not decodable: {e}"),
    }
}
