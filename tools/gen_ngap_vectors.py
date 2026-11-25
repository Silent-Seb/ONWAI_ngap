#!/usr/bin/env python3
"""Golden NGAP PDUs encoded by the independent `asn1tools` library, for crates/ngap-types/tests/golden.rs.

    python3 -I tools/oracle_asn.py specs/asn1 /tmp/oracle_asn
    ASN1TOOLS_PATH=<dir containing asn1tools> python3 -I tools/gen_ngap_vectors.py specs/asn1 /tmp/oracle_asn \
        > crates/ngap-types/tests/vectors.txt

Line format: `name | hex` of the complete APER encoding of an `NGAP-PDU`. Id, criticality and type of every IE are
read from the object sets of the specification text, so this script cannot drift from the spec.
"""
import glob
import os
import re
import sys

if os.environ.get("ASN1TOOLS_PATH"):
    sys.path.insert(0, os.environ["ASN1TOOLS_PATH"])
import asn1tools

SPEC_DIR, ORACLE_DIR = sys.argv[1], sys.argv[2]
SPEC = "\n".join(open(f).read() for f in sorted(glob.glob(SPEC_DIR + "/*.asn")))
conv = asn1tools.compile_files(sorted(glob.glob(ORACLE_DIR + "/*.asn")), "per")

IDS = {m.group(1): int(m.group(2)) for m in re.finditer(r"^\s*(id-[\w-]+)\s+(?:ProtocolIE-ID|ProcedureCode)\s*::=\s*(\d+)", SPEC, flags=re.M)}


def rows(set_name):
    m = re.search(r"^" + re.escape(set_name) + r"\s+NGAP-PROTOCOL-IES\s*::=\s*\{(.*?)^\}", SPEC, flags=re.M | re.S)
    assert m, set_name
    out = {}
    for r in re.finditer(r"\{\s*ID\s+(id-[\w-]+)\s+CRITICALITY\s+(\w+)\s+TYPE\s+(.+?)\s+PRESENCE\s+(\w+)\s*\}", m.group(1), flags=re.S):
        t = re.sub(r"\s+", " ", r.group(3)).strip()
        c = re.fullmatch(r"OCTET STRING \(CONTAINING (\S+)\s*\)", t)
        out[r.group(1)] = (IDS[r.group(1)], r.group(2), f"CONTAINING-OF-{c.group(1)}" if c else t)
    return out


def message(set_name, **ies):
    """`{'protocolIEs': [...]}` with the IEs in the order of the set (as the spec requires)."""
    table = rows(set_name)
    order = list(table)
    out = []
    for id_name in sorted(ies, key=lambda k: order.index(k.replace("_", "-"))):
        pass
    for id_name in order:
        key = id_name.replace("-", "_")
        if key in ies:
            i, crit, typ = table[id_name]
            out.append({"id": i, "criticality": crit, "value": conv.encode(typ, ies[key])})
    assert len(out) == len(ies), f"unknown IE in {set_name}: {set(k.replace('_', '-') for k in ies) - set(order)}"
    return {"protocolIEs": out}


def procedure(obj):
    m = re.search(r"^" + obj + r"\s+NGAP-ELEMENTARY-PROCEDURE\s*::=\s*\{(.*?)\}", SPEC, flags=re.M | re.S)
    body = m.group(1)
    code = IDS[re.search(r"PROCEDURE CODE\s+(id-\w+)", body).group(1)]
    crit = re.search(r"CRITICALITY\s+(\w+)", body)
    return code, crit.group(1) if crit else "ignore"


def pdu(kind, obj, msg_type, value):
    code, crit = procedure(obj)
    return (kind, {"procedureCode": code, "criticality": crit, "value": conv.encode(msg_type, value)})


PLMN = b"\x00\xf1\x10"
SNSSAI1 = {"s-NSSAI": {"sST": b"\x01"}}
SNSSAI2 = {"s-NSSAI": {"sST": b"\x01", "sD": b"\x01\x02\x03"}}
TAI = {"pLMNIdentity": PLMN, "tAC": b"\x00\x00\x01"}
NRCGI = {"pLMNIdentity": PLMN, "nRCellIdentity": (b"\x00\x00\x00\x01\x00", 36)}
ULI_NR = ("userLocationInformationNR", {"nR-CGI": NRCGI, "tAI": TAI})
NAS = b"\x7e\x00\x41\x79\x00\x0d\x01\x00\xf1\x10\x00\x00\x00\x00\x00\x00\x00\x00\x01"
GUAMI = {"pLMNIdentity": PLMN, "aMFRegionID": (b"\x01", 8), "aMFSetID": (b"\x00\x40", 10), "aMFPointer": (b"\x04", 6)}

CASES = {}

CASES["ng_setup_request"] = pdu("initiatingMessage", "nGSetup", "NGSetupRequest", message(
    "NGSetupRequestIEs",
    id_GlobalRANNodeID=("globalGNB-ID", {"pLMNIdentity": PLMN, "gNB-ID": ("gNB-ID", (b"\x12\x34\x56", 24))}),
    id_RANNodeName="gnb-1",
    id_SupportedTAList=[{"tAC": b"\x00\x00\x01", "broadcastPLMNList": [{"pLMNIdentity": PLMN, "tAISliceSupportList": [SNSSAI1, SNSSAI2]}]}],
    id_DefaultPagingDRX="v128",
))

CASES["ng_setup_response"] = pdu("successfulOutcome", "nGSetup", "NGSetupResponse", message(
    "NGSetupResponseIEs",
    id_AMFName="amf-1",
    id_ServedGUAMIList=[{"gUAMI": GUAMI}],
    id_RelativeAMFCapacity=255,
    id_PLMNSupportList=[{"pLMNIdentity": PLMN, "sliceSupportList": [SNSSAI1]}],
))

CASES["ng_setup_failure"] = pdu("unsuccessfulOutcome", "nGSetup", "NGSetupFailure", message(
    "NGSetupFailureIEs", id_Cause=("misc", "unspecified"), id_TimeToWait="v10s",
))

CASES["initial_ue_message"] = pdu("initiatingMessage", "initialUEMessage", "InitialUEMessage", message(
    "InitialUEMessage-IEs",
    id_RAN_UE_NGAP_ID=1, id_NAS_PDU=NAS, id_UserLocationInformation=ULI_NR,
    id_RRCEstablishmentCause="mo-Signalling", id_UEContextRequest="requested",
))

CASES["downlink_nas_transport"] = pdu("initiatingMessage", "downlinkNASTransport", "DownlinkNASTransport", message(
    "DownlinkNASTransport-IEs", id_AMF_UE_NGAP_ID=0x123456789A, id_RAN_UE_NGAP_ID=7, id_NAS_PDU=NAS,
))

CASES["uplink_nas_transport"] = pdu("initiatingMessage", "uplinkNASTransport", "UplinkNASTransport", message(
    "UplinkNASTransport-IEs", id_AMF_UE_NGAP_ID=5, id_RAN_UE_NGAP_ID=7, id_NAS_PDU=NAS, id_UserLocationInformation=ULI_NR,
))

CASES["ue_context_release_command"] = pdu("initiatingMessage", "uEContextRelease", "UEContextReleaseCommand", message(
    "UEContextReleaseCommand-IEs",
    id_UE_NGAP_IDs=("uE-NGAP-ID-pair", {"aMF-UE-NGAP-ID": 5, "rAN-UE-NGAP-ID": 7}),
    id_Cause=("radioNetwork", "user-inactivity"),
))

CASES["paging"] = pdu("initiatingMessage", "paging", "Paging", message(
    "PagingIEs",
    id_UEPagingIdentity=("fiveG-S-TMSI", {"aMFSetID": (b"\x00\x40", 10), "aMFPointer": (b"\x04", 6), "fiveG-TMSI": b"\x00\x00\x00\x01"}),
    id_TAIListForPaging=[{"tAI": TAI}],
))

CASES["error_indication"] = pdu("initiatingMessage", "errorIndication", "ErrorIndication", message(
    "ErrorIndicationIEs",
    id_AMF_UE_NGAP_ID=9, id_RAN_UE_NGAP_ID=3, id_Cause=("protocol", "semantic-error"),
    id_CriticalityDiagnostics={"procedureCode": 21, "triggeringMessage": "initiating-message", "procedureCriticality": "reject",
                               "iEsCriticalityDiagnostics": [{"iECriticality": "reject", "iE-ID": 27, "typeOfError": "missing"}]},
))

TRANSFER = message(
    "PDUSessionResourceSetupRequestTransferIEs",
    id_UL_NGU_UP_TNLInformation=("gTPTunnel", {"transportLayerAddress": (b"\xc0\xa8\x00\x01", 32), "gTP-TEID": b"\x00\x00\x00\x10"}),
    id_PDUSessionType="ipv4",
    id_QosFlowSetupRequestList=[{"qosFlowIdentifier": 1, "qosFlowLevelQosParameters": {
        "qosCharacteristics": ("nonDynamic5QI", {"fiveQI": 9}),
        "allocationAndRetentionPriority": {"priorityLevelARP": 8, "pre-emptionCapability": "shall-not-trigger-pre-emption", "pre-emptionVulnerability": "not-pre-emptable"}}}],
)
CASES["pdu_session_resource_setup_request"] = pdu("initiatingMessage", "pDUSessionResourceSetup", "PDUSessionResourceSetupRequest", message(
    "PDUSessionResourceSetupRequestIEs",
    id_AMF_UE_NGAP_ID=5, id_RAN_UE_NGAP_ID=7,
    id_PDUSessionResourceSetupListSUReq=[{
        "pDUSessionID": 5, "pDUSessionNAS-PDU": NAS, "s-NSSAI": SNSSAI1["s-NSSAI"],
        "pDUSessionResourceSetupRequestTransfer": conv.encode("PDUSessionResourceSetupRequestTransfer", TRANSFER)}],
))

CASES["initial_context_setup_request"] = pdu("initiatingMessage", "initialContextSetup", "InitialContextSetupRequest", message(
    "InitialContextSetupRequestIEs",
    id_AMF_UE_NGAP_ID=5, id_RAN_UE_NGAP_ID=7, id_GUAMI=GUAMI,
    id_AllowedNSSAI=[SNSSAI1, SNSSAI2],
    id_UESecurityCapabilities={"nRencryptionAlgorithms": (b"\xe0\x00", 16), "nRintegrityProtectionAlgorithms": (b"\xe0\x00", 16),
                               "eUTRAencryptionAlgorithms": (b"\xe0\x00", 16), "eUTRAintegrityProtectionAlgorithms": (b"\xe0\x00", 16)},
    id_SecurityKey=(bytes(range(32)), 256),
    id_NAS_PDU=NAS,
))

for name, (kind, value) in CASES.items():
    enc = conv.encode("NGAP-PDU", (kind, value))
    assert conv.decode("NGAP-PDU", enc)[0] == kind
    print(f"{name} | {enc.hex()}")
