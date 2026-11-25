//! Real NGAP PDUs: the generated types must produce exactly the bytes the independent `asn1tools` encoder
//! produces for the same value (`tools/gen_ngap_vectors.py`), and decoding those bytes must give the value back.

use std::collections::BTreeMap;

use ngap_aper::{BitString, from_slice, to_vec};
use ngap_types::*;

fn vectors() -> BTreeMap<String, Vec<u8>> {
    include_str!("vectors.txt")
        .lines()
        .filter_map(|l| l.split_once(" | "))
        .map(|(k, v)| {
            (
                k.to_owned(),
                (0..v.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                    .collect(),
            )
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Encode == oracle, decode(oracle) == value, re-encode(decode) == oracle.
fn check(name: &str, pdu: NgapPdu) {
    let expected = &vectors()[name];
    let got = to_vec(&pdu).unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
    assert_eq!(
        hex(&got),
        hex(expected),
        "{name}: encoding differs from the oracle"
    );
    let back: NgapPdu =
        from_slice(expected).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    assert_eq!(back, pdu, "{name}: decoded value differs");
    assert_eq!(
        to_vec(&back).unwrap(),
        *expected,
        "{name}: re-encoding differs"
    );
}

fn bits(bytes: &[u8], n: usize) -> BitString {
    BitString::new(bytes.to_vec(), n).unwrap()
}

fn plmn() -> PlmnIdentity {
    PlmnIdentity(vec![0x00, 0xf1, 0x10])
}

fn tai() -> Tai {
    Tai::new(plmn(), Tac(vec![0, 0, 1]))
}

fn nr_cgi() -> NrCgi {
    NrCgi::new(plmn(), NrCellIdentity(bits(&[0, 0, 0, 1, 0], 36)))
}

fn uli() -> UserLocationInformation {
    UserLocationInformation::UserLocationInformationNr(UserLocationInformationNr::new(
        nr_cgi(),
        tai(),
    ))
}

fn snssai1() -> SNssai {
    SNssai::new(Sst(vec![1]))
}

fn snssai2() -> SNssai {
    let mut s = SNssai::new(Sst(vec![1]));
    s.sd = Some(Sd(vec![1, 2, 3]));
    s
}

fn nas() -> NasPdu {
    NasPdu(vec![
        0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x00, 0xf1, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ])
}

fn guami() -> Guami {
    Guami::new(
        plmn(),
        AmfRegionId(bits(&[1], 8)),
        AmfSetId(bits(&[0, 0x40], 10)),
        AmfPointer(bits(&[4], 6)),
    )
}

fn init(m: InitiatingMessage) -> NgapPdu {
    NgapPdu::InitiatingMessage(m)
}

#[test]
fn ng_setup_request() {
    let global = GlobalRanNodeId::GlobalGnbId(GlobalGnbId::new(
        plmn(),
        GnbId::GnbId(bits(&[0x12, 0x34, 0x56], 24)),
    ));
    let ta = SupportedTaItem::new(
        Tac(vec![0, 0, 1]),
        BroadcastPlmnList(vec![BroadcastPlmnItem::new(
            plmn(),
            SliceSupportList(vec![
                SliceSupportItem::new(snssai1()),
                SliceSupportItem::new(snssai2()),
            ]),
        )]),
    );
    let mut m = NgSetupRequest::new(global, SupportedTaList(vec![ta]), PagingDrx::V128);
    m.ran_node_name = Some(RanNodeName("gnb-1".into()));
    check(
        "ng_setup_request",
        init(InitiatingMessage::NgSetupRequest(m)),
    );
}

#[test]
fn ng_setup_response() {
    let m = NgSetupResponse::new(
        AmfName("amf-1".into()),
        ServedGuamiList(vec![ServedGuamiItem::new(guami())]),
        RelativeAmfCapacity(255),
        PlmnSupportList(vec![PlmnSupportItem::new(
            plmn(),
            SliceSupportList(vec![SliceSupportItem::new(snssai1())]),
        )]),
    );
    check(
        "ng_setup_response",
        NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(m)),
    );
}

#[test]
fn ng_setup_failure() {
    let mut m = NgSetupFailure::new(Cause::Misc(CauseMisc::Unspecified));
    m.time_to_wait = Some(TimeToWait::V10s);
    check(
        "ng_setup_failure",
        NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::NgSetupFailure(m)),
    );
}

#[test]
fn initial_ue_message() {
    let mut m = InitialUeMessage::new(
        RanUeNgapId(1),
        nas(),
        uli(),
        RrcEstablishmentCause::MoSignalling,
    );
    m.ue_context_request = Some(UeContextRequest::Requested);
    check(
        "initial_ue_message",
        init(InitiatingMessage::InitialUeMessage(m)),
    );
}

#[test]
fn downlink_nas_transport() {
    let m = DownlinkNasTransport::new(AmfUeNgapId(0x12_3456_789A), RanUeNgapId(7), nas());
    check(
        "downlink_nas_transport",
        init(InitiatingMessage::DownlinkNasTransport(m)),
    );
}

#[test]
fn uplink_nas_transport() {
    let m = UplinkNasTransport::new(AmfUeNgapId(5), RanUeNgapId(7), nas(), uli());
    check(
        "uplink_nas_transport",
        init(InitiatingMessage::UplinkNasTransport(m)),
    );
}

#[test]
fn ue_context_release_command() {
    let ids = UeNgapIds::UeNgapIdPair(UeNgapIdPair::new(AmfUeNgapId(5), RanUeNgapId(7)));
    let m =
        UeContextReleaseCommand::new(ids, Cause::RadioNetwork(CauseRadioNetwork::UserInactivity));
    check(
        "ue_context_release_command",
        init(InitiatingMessage::UeContextReleaseCommand(m)),
    );
}

#[test]
fn paging() {
    let id = UePagingIdentity::FiveGSTmsi(FiveGSTmsi::new(
        AmfSetId(bits(&[0, 0x40], 10)),
        AmfPointer(bits(&[4], 6)),
        FiveGTmsi(vec![0, 0, 0, 1]),
    ));
    let m = Paging::new(id, TaiListForPaging(vec![TaiListForPagingItem::new(tai())]));
    check("paging", init(InitiatingMessage::Paging(m)));
}

#[test]
fn error_indication() {
    let mut diag = CriticalityDiagnostics::new();
    diag.procedure_code = Some(ProcedureCode(21));
    diag.triggering_message = Some(TriggeringMessage::InitiatingMessage);
    diag.procedure_criticality = Some(Criticality::Reject);
    diag.ies_criticality_diagnostics = Some(CriticalityDiagnosticsIeList(vec![
        CriticalityDiagnosticsIeItem::new(
            Criticality::Reject,
            ProtocolIeId(27),
            TypeOfError::Missing,
        ),
    ]));
    let mut m = ErrorIndication::new();
    m.amf_ue_ngap_id = Some(AmfUeNgapId(9));
    m.ran_ue_ngap_id = Some(RanUeNgapId(3));
    m.cause = Some(Cause::Protocol(CauseProtocol::SemanticError));
    m.criticality_diagnostics = Some(diag);
    check(
        "error_indication",
        init(InitiatingMessage::ErrorIndication(m)),
    );
}

#[test]
fn pdu_session_resource_setup_request_with_a_contained_transfer() {
    let tunnel = UpTransportLayerInformation::GtpTunnel(GtpTunnel::new(
        TransportLayerAddress(bits(&[0xc0, 0xa8, 0, 1], 32)),
        GtpTeid(vec![0, 0, 0, 0x10]),
    ));
    let flow = QosFlowSetupRequestItem::new(
        QosFlowIdentifier(1),
        QosFlowLevelQosParameters::new(
            QosCharacteristics::NonDynamic5Qi(NonDynamic5QiDescriptor::new(FiveQi(9))),
            AllocationAndRetentionPriority::new(
                PriorityLevelArp(8),
                PreEmptionCapability::ShallNotTriggerPreEmption,
                PreEmptionVulnerability::NotPreEmptable,
            ),
        ),
    );
    let transfer = PduSessionResourceSetupRequestTransfer::new(
        tunnel,
        PduSessionType::Ipv4,
        QosFlowSetupRequestList(vec![flow]),
    );
    let mut item = PduSessionResourceSetupItemSuReq::new(
        PduSessionId(5),
        snssai1(),
        ngap_aper::Contained::encode_from(&transfer).unwrap(),
    );
    item.pdu_session_nas_pdu = Some(nas());
    let m = PduSessionResourceSetupRequest::new(
        AmfUeNgapId(5),
        RanUeNgapId(7),
        PduSessionResourceSetupListSuReq(vec![item]),
    );
    // the transfer container is opaque bytes until asked for
    let raw = m.pdu_session_resource_setup_list_su_req.0[0]
        .pdu_session_resource_setup_request_transfer
        .raw()
        .to_vec();
    assert_eq!(
        from_slice::<PduSessionResourceSetupRequestTransfer>(&raw).unwrap(),
        transfer
    );
    check(
        "pdu_session_resource_setup_request",
        init(InitiatingMessage::PduSessionResourceSetupRequest(m)),
    );
}

#[test]
fn initial_context_setup_request() {
    let alg = |_: ()| bits(&[0xe0, 0x00], 16);
    let sec = UeSecurityCapabilities::new(
        NRencryptionAlgorithms(alg(())),
        NRintegrityProtectionAlgorithms(alg(())),
        EutrAencryptionAlgorithms(alg(())),
        EutrAintegrityProtectionAlgorithms(alg(())),
    );
    let key = SecurityKey(bits(&(0..32).collect::<Vec<u8>>(), 256));
    let mut m = InitialContextSetupRequest::new(
        AmfUeNgapId(5),
        RanUeNgapId(7),
        guami(),
        AllowedNssai(vec![
            AllowedNssaiItem::new(snssai1()),
            AllowedNssaiItem::new(snssai2()),
        ]),
        sec,
        key,
    );
    m.nas_pdu = Some(nas());
    check(
        "initial_context_setup_request",
        init(InitiatingMessage::InitialContextSetupRequest(m)),
    );
}
