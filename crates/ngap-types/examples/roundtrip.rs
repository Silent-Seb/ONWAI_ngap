//! Build an NG Setup Response and a PDU Session Resource Setup Request, encode them, decode them again, and look
//! inside. Run with `cargo run -p ngap-types --example roundtrip`.

use ngap_aper::{BitString, Contained, from_slice, to_vec};
use ngap_types::*;

fn main() -> ngap_aper::Result<()> {
    let plmn = PlmnIdentity(vec![0x00, 0xf1, 0x10]);
    let slice = SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]);

    // --- the AMF answers an NG Setup Request
    let guami = Guami::new(
        plmn.clone(),
        AmfRegionId(BitString::new(vec![1], 8)?),
        AmfSetId(BitString::new(vec![0, 0x40], 10)?),
        AmfPointer(BitString::new(vec![4], 6)?),
    );
    let mut response = NgSetupResponse::new(
        AmfName("amf-1".into()),
        ServedGuamiList(vec![ServedGuamiItem::new(guami)]),
        RelativeAmfCapacity(255),
        PlmnSupportList(vec![PlmnSupportItem::new(plmn, slice)]),
    );
    response.extended_amf_name = None; // optional IEs are `Option`s
    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(response));
    let bytes = to_vec(&pdu)?; // the complete APER encoding: what goes into the SCTP message
    println!(
        "NG Setup Response: {} octets: {:02x?}",
        bytes.len(),
        &bytes[..12]
    );

    // --- the peer's bytes come back in
    match from_slice::<NgapPdu>(&bytes)? {
        NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(r)) => {
            println!(
                "AMF name {:?}, capacity {}, {} GUAMI(s)",
                r.amf_name.0,
                r.relative_amf_capacity.0,
                r.served_guami_list.0.len()
            );
            println!("IEs this version does not know: {}", r.unknown_ies.len());
        }
        other => println!("something else: {other:?}"),
    }

    // --- N2 SM information is an opaque container: an AMF forwards the SMF's bytes without decoding them
    let transfer_from_smf: Vec<u8> = vec![0x00, 0x00, 0x03, 0x00, 0x8b]; // pretend this came over N11
    let item = PduSessionResourceSetupItemSuReq::new(
        PduSessionId(5),
        SNssai::new(Sst(vec![1])),
        Contained::from_raw(transfer_from_smf.clone()),
    );
    assert_eq!(
        item.pdu_session_resource_setup_request_transfer.raw(),
        &transfer_from_smf[..]
    );
    // ... and decodes one only when it needs to look inside (this made-up one is not valid, so it says so)
    println!(
        "decoding the pretend transfer: {:?}",
        item.pdu_session_resource_setup_request_transfer
            .decode()
            .map(|_| "ok")
            .map_err(|e| e.to_string())
    );
    Ok(())
}
