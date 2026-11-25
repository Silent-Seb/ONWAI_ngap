//! An AMF answers an NG Setup Request. Run with `cargo run -p onwai-ngap --example ng_setup`.
//!
//! Decoding what the gNB sent, picking the facts the AMF needs, building the reply and encoding it.

use ngap_aper::BitString;
use onwai_ngap::{PduInfo, decode_pdu, encode_pdu, types::*};

fn main() {
    // --- what arrives on the SCTP association (here: built, so that the example needs no capture)
    let plmn = PlmnIdentity(vec![0x00, 0xf1, 0x10]);
    let slices = SliceSupportList(vec![SliceSupportItem::new(SNssai::new(Sst(vec![1])))]);
    let mut request = NgSetupRequest::new(
        GlobalRanNodeId::GlobalGnbId(GlobalGnbId::new(
            plmn.clone(),
            GnbId::GnbId(BitString::new(vec![0x00, 0x00, 0x40], 22).unwrap()),
        )),
        SupportedTaList(vec![SupportedTaItem::new(
            Tac(vec![0, 0, 1]),
            BroadcastPlmnList(vec![BroadcastPlmnItem::new(plmn.clone(), slices.clone())]),
        )]),
        PagingDrx::V128,
    );
    request.ran_node_name = Some(RanNodeName("gnb-1".into()));
    let received = encode_pdu(&NgapPdu::InitiatingMessage(
        InitiatingMessage::NgSetupRequest(request),
    ))
    .unwrap();

    // --- decode it
    let decoded = match decode_pdu(&received) {
        Ok(d) => d,
        Err(e) => {
            // `e.reaction()` says what clause 10 requires; `e.error_indication()` is the message to send
            println!("cannot use the PDU: {e} -> {:?}", e.reaction());
            return;
        }
    };
    println!(
        "received {} (procedure {}, {:?})",
        decoded.pdu.message_name(),
        decoded.pdu.procedure_code(),
        decoded.pdu.message_type()
    );
    let NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(request)) = decoded.pdu else {
        return;
    };
    println!(
        "gNB {:?} serves {} tracking area(s), default paging DRX {:?}",
        request.ran_node_name.map(|n| n.0),
        request.supported_ta_list.0.len(),
        request.default_paging_drx
    );

    // --- the AMF accepts: NG Setup Response
    let guami = Guami::new(
        plmn.clone(),
        AmfRegionId(BitString::new(vec![1], 8).unwrap()),
        AmfSetId(BitString::new(vec![0, 0x40], 10).unwrap()),
        AmfPointer(BitString::new(vec![4], 6).unwrap()),
    );
    let response = NgSetupResponse::new(
        AmfName("amf-1".into()),
        ServedGuamiList(vec![ServedGuamiItem::new(guami)]),
        RelativeAmfCapacity(255),
        PlmnSupportList(vec![PlmnSupportItem::new(plmn, slices)]),
    );
    let reply = encode_pdu(&NgapPdu::SuccessfulOutcome(
        SuccessfulOutcome::NgSetupResponse(response),
    ))
    .unwrap();
    println!("reply: {} octets: {:02x?}", reply.len(), &reply[..8]);
}
