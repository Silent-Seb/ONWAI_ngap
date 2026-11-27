//! The AMF pages a UE: build a Paging message, encode it, and read it back as the gNB would.
//! Run with `cargo run -p onwai-ngap --example paging`.

use ngap_aper::BitString;
use onwai_ngap::{decode_pdu, encode_pdu, types::*};

fn main() {
    let paging = Paging::new(
        UePagingIdentity::FiveGSTmsi(FiveGSTmsi::new(
            AmfSetId(BitString::new(vec![0, 0x40], 10).unwrap()),
            AmfPointer(BitString::new(vec![4], 6).unwrap()),
            FiveGTmsi(vec![0xde, 0xad, 0xbe, 0xef]),
        )),
        TaiListForPaging(vec![TaiListForPagingItem::new(Tai::new(
            PlmnIdentity(vec![0x00, 0xf1, 0x10]),
            Tac(vec![0, 0, 1]),
        ))]),
    );
    // optional IEs are plain `Option` fields
    let mut paging = paging;
    paging.paging_drx = Some(PagingDrx::V64);

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage::Paging(paging));
    let wire = encode_pdu(&pdu).expect("a Paging message that was built from valid parts encodes");
    println!("Paging, {} octets: {}", wire.len(), hex(&wire));

    let decoded = decode_pdu(&wire).expect("what we encode, we decode");
    println!(
        "decoded: {} (procedure {}, {:?})",
        decoded.pdu.message_name(),
        decoded.context.procedure_code,
        decoded.context.message_type,
    );
    assert_eq!(decoded.pdu, pdu);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
