#!/usr/bin/env python3
"""Generate independent ALIGNED-PER test vectors for the `ngap-aper` runtime primitives.

The vectors come from the Python `asn1tools` library (codec "per" = ALIGNED PER, X.691), so the Rust runtime is
checked against an implementation that shares no code with it. Output: crates/ngap-aper/tests/vectors.txt (committed).

    ASN1TOOLS_PATH=/dir/containing/asn1tools python3 -I tools/gen_aper_vectors.py > crates/ngap-aper/tests/vectors.txt

Line format:  <name> | <hex of the complete encoding>          (bare value)
              <name>@w | <hex>                                  (value wrapped as SEQUENCE { 3 bits 101, value, 3 bits 110 },
                                                                 exposes octet-alignment behaviour)
              <name> | big:<len>:<fnv1a64>:<first 16 octets>    (large encodings, too long to list)
"""
import os
import sys

if os.environ.get("ASN1TOOLS_PATH"):
    sys.path.insert(0, os.environ["ASN1TOOLS_PATH"])
import asn1tools

SPEC = r"""
T DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Pre ::= BIT STRING (SIZE(3))
I1 ::= INTEGER (5..5)
I3 ::= INTEGER (0..7)
I8 ::= INTEGER (0..255)
I9 ::= INTEGER (0..256)
I16 ::= INTEGER (0..65535)
I17 ::= INTEGER (0..65536)
I32 ::= INTEGER (0..4294967295)
I64 ::= INTEGER (0..18446744073709551615)
IS ::= INTEGER (-127..127)
IX1 ::= INTEGER (-420..10000, ...)
IX2 ::= INTEGER (1..65535, ..., 65536..109999)
IU ::= INTEGER
-- semi-constrained INTEGER (lb..MAX) is deliberately absent: asn1tools encodes it as an unconstrained (two's
-- complement) integer, contradicting X.691 10.7; the Rust tests use hand-derived vectors for it. NGAP has none.
B8 ::= BIT STRING (SIZE(8))
B16 ::= BIT STRING (SIZE(16))
B17 ::= BIT STRING (SIZE(17))
B28 ::= BIT STRING (SIZE(28))
B0 ::= BIT STRING (SIZE(0..4))
BV ::= BIT STRING (SIZE(1..1024, ...))
BU ::= BIT STRING
BF ::= BIT STRING (SIZE(8, ...))
BG ::= BIT STRING (SIZE(8, ..., 16))
BS ::= BIT STRING (SIZE(1..16))
O1 ::= OCTET STRING (SIZE(1))
O2 ::= OCTET STRING (SIZE(2))
O3 ::= OCTET STRING (SIZE(3))
O32 ::= OCTET STRING (SIZE(32))
OV ::= OCTET STRING (SIZE(1..255))
OW ::= OCTET STRING (SIZE(0..2))
OX ::= OCTET STRING (SIZE(1..150, ...))
OM ::= OCTET STRING (SIZE(1..65535))
OU ::= OCTET STRING
OC ::= OCTET STRING (CONTAINING I8)
PS ::= PrintableString (SIZE(1..150, ...))
VS ::= VisibleString (SIZE(1..150, ...))
VU ::= VisibleString
US ::= UTF8String (SIZE(1..150, ...))
UU ::= UTF8String
EN ::= ENUMERATED { a, b, c }
E1 ::= ENUMERATED { only }
EX ::= ENUMERATED { a, b, c, ..., d, e }
EB ::= ENUMERATED { e0, e1, e2, e3, e4, e5, e6, e7, e8, e9 }
OID ::= OBJECT IDENTIFIER
NL ::= NULL
CH ::= CHOICE { a INTEGER (0..7), b NULL, c OCTET STRING (SIZE(2)) }
CX ::= CHOICE { a INTEGER (0..7), b NULL, ..., c INTEGER (0..255), d OCTET STRING (SIZE(2)) }
C1 ::= CHOICE { only INTEGER (0..7) }
SX ::= SEQUENCE { a INTEGER (0..7), ..., b INTEGER (0..255) OPTIONAL, c INTEGER (0..1) OPTIONAL }
SY ::= SEQUENCE { a INTEGER (0..7), ... }
SO1 ::= SEQUENCE (SIZE(1..4)) OF INTEGER (0..7)
SO2 ::= SEQUENCE (SIZE(0..65535)) OF INTEGER (0..255)
SO3 ::= SEQUENCE OF INTEGER (0..255)
SO4 ::= SEQUENCE (SIZE(3)) OF INTEGER (0..7)
SO5 ::= SEQUENCE (SIZE(1..4, ...)) OF INTEGER (0..7)
SO6 ::= SEQUENCE (SIZE(1..256)) OF INTEGER (0..7)
W-I3 ::= SEQUENCE { p Pre, x I3, q Pre }
END
"""

conv = asn1tools.compile_string(SPEC, "per")
wrapped = {}


def pat(n):
    return bytes((i * 7 + 3) % 251 for i in range(n))


def fnv(b):
    h = 0xCBF29CE484222325
    for x in b:
        h = ((h ^ x) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def bits(s):
    """'101' -> (bytes, nbits)"""
    n = len(s)
    v = int(s, 2) << ((-n) % 8) if n else 0
    return (v.to_bytes((n + 7) // 8, "big"), n)


# (case name, type, value, wrap?)
CASES = []


def case(name, typ, value, wrap=True, big=False):
    CASES.append((name, typ, value, wrap, big))


for v in (5,): case("i1", "I1", v)
for v in (0, 1, 7): case(f"i3_{v}", "I3", v)
for v in (0, 1, 255): case(f"i8_{v}", "I8", v)
for v in (0, 255, 256): case(f"i9_{v}", "I9", v)
for v in (0, 1, 256, 65535): case(f"i16_{v}", "I16", v)
for v in (0, 255, 256, 65535, 65536): case(f"i17_{v}", "I17", v)
for v in (0, 1, 255, 256, 65535, 65536, 0xFFFFFF, 0x1000000, 0xFFFFFFFF): case(f"i32_{v}", "I32", v)
for v in (0, 0xFFFFFFFF, 0x100000000, 0x123456789ABC, 2**64 - 1): case(f"i64_{v}", "I64", v)
for v in (-127, 0, 127): case(f"is_{v}", "IS", v)
for v in (-420, 0, 10000, 10001, -421, 1000000, -100000): case(f"ix1_{v}", "IX1", v)
for v in (1, 65535, 65536, 109999, 110000, 0, 5000000): case(f"ix2_{v}", "IX2", v)
for v in (0, 1, 127, 128, -1, -128, -129, 255, 256, 32767, 32768, -32768, -32769, 2**63, -(2**63), 2**100): case(f"iu_{v}", "IU", v)

case("b8", "B8", (b"\xa5", 8))
case("b16", "B16", (b"\xa5\x5a", 16))
case("b17", "B17", (b"\xa5\x5a\x80", 17))
case("b28", "B28", (b"\x12\x34\x56\x70", 28))
for n in (0, 1, 3, 4): case(f"b0_{n}", "B0", bits("1011"[:n]))
for n in (1, 8, 9, 1024): case(f"bv_{n}", "BV", (pat((n + 7) // 8), n) if n % 8 == 0 else (bytes(pat((n + 7) // 8)[:-1]) + bytes([pat((n + 7) // 8)[-1] & (0xFF << (-n % 8)) & 0xFF]), n))
case("bv_1025", "BV", (pat(129)[:-1] + bytes([pat(129)[-1] & 0x80]), 1025))
for n in (0, 1, 7, 8, 100): case(f"bu_{n}", "BU", (pat(n // 8) if n % 8 == 0 else pat(n // 8 + 1)[:-1] + bytes([pat(n // 8 + 1)[-1] & (0xFF << (-n % 8)) & 0xFF]), n))
case("bf_8", "BF", (b"\x5a", 8))
case("bf_9", "BF", (b"\x5a\x80", 9))
case("bg_8", "BG", (b"\x5a", 8))
case("bg_16", "BG", (b"\x5a\xa5", 16))
case("bg_12", "BG", (b"\x5a\xa0", 12))
for n in (1, 5, 16): case(f"bs_{n}", "BS", bits(("1011001110001011"[:n])))

case("o1", "O1", b"\x42")
case("o2", "O2", b"\x42\x43")
case("o3", "O3", b"\x42\x43\x44")
case("o32", "O32", pat(32))
for n in (1, 2, 255): case(f"ov_{n}", "OV", pat(n))
for n in (0, 1, 2): case(f"ow_{n}", "OW", pat(n))
for n in (1, 150, 151, 300): case(f"ox_{n}", "OX", pat(n))
for n in (1, 256, 65535): case(f"om_{n}", "OM", pat(n))
for n in (0, 1, 127, 128, 16383): case(f"ou_{n}", "OU", pat(n))
for n in (16384, 20000, 32768, 49152, 65536, 70000): case(f"ou_{n}", "OU", pat(n), wrap=False, big=True)
case("oc", "OC", b"\x07")
for s in ("a", "hello"): case(f"ps_{s}", "PS", s)
case("ps_150", "PS", "A" * 150)
case("ps_151", "PS", "B" * 151)
for s in ("a", "http://x.y/z"): case(f"vs_{s}", "VS", s)
case("vu_0", "VU", "")
case("vu_5", "VU", "abcde")
case("us_a", "US", "a")
case("us_utf8", "US", "héllo €")
case("uu_utf8", "UU", "héllo €")
case("uu_empty", "UU", "")

case("en_a", "EN", "a"); case("en_c", "EN", "c")
case("e1", "E1", "only")
for s in ("a", "c", "d", "e"): case(f"ex_{s}", "EX", s)
for s in ("e0", "e9"): case(f"eb_{s}", "EB", s)
case("oid_1", "OID", "1.2.840.113549")
case("oid_2", "OID", "0.4.0.0.22.3.1.1.0")
case("oid_3", "OID", "2.999.3")
case("nl", "NL", None)
case("ch_a", "CH", ("a", 5)); case("ch_b", "CH", ("b", None)); case("ch_c", "CH", ("c", b"\x01\x02"))
case("cx_a", "CX", ("a", 5)); case("cx_b", "CX", ("b", None))
case("cx_c", "CX", ("c", 200)); case("cx_d", "CX", ("d", b"\x01\x02"))
case("c1", "C1", ("only", 3))
case("sx_a", "SX", {"a": 3}); case("sx_ab", "SX", {"a": 3, "b": 200}); case("sx_ac", "SX", {"a": 3, "c": 1})
case("sx_abc", "SX", {"a": 3, "b": 200, "c": 1})
case("sy_a", "SY", {"a": 3})
for n in (1, 4): case(f"so1_{n}", "SO1", [i % 8 for i in range(n)])
for n in (0, 1, 300): case(f"so2_{n}", "SO2", [i % 256 for i in range(n)])
for n in (0, 5, 127, 128, 200, 16383): case(f"so3_{n}", "SO3", [i % 256 for i in range(n)])
for n in (16384, 20000, 70000): case(f"so3_{n}", "SO3", [i % 256 for i in range(n)], wrap=False, big=True)
case("so4", "SO4", [1, 2, 3])
for n in (1, 4, 6): case(f"so5_{n}", "SO5", [i % 8 for i in range(n)])
for n in (1, 256): case(f"so6_{n}", "SO6", [i % 8 for i in range(n)])

# wrapped variants: SEQUENCE { p 3 bits, x T, q 3 bits } built by hand-defining a one-off module per type
def wrap_conv(typ):
    if typ not in wrapped:
        spec = SPEC.replace("W-I3 ::= SEQUENCE { p Pre, x I3, q Pre }", f"W ::= SEQUENCE {{ p Pre, x {typ}, q Pre }}")
        wrapped[typ] = asn1tools.compile_string(spec, "per")
    return wrapped[typ]



# ---- IE container machinery of NGAP-Containers / NGAP-PDU-Descriptions, in miniature
SPEC2 = r"""
N DEFINITIONS AUTOMATIC TAGS ::= BEGIN
maxIEs INTEGER ::= 65535
Criticality ::= ENUMERATED { reject, ignore, notify }
Presence ::= ENUMERATED { optional, conditional, mandatory }
ProtocolIE-ID ::= INTEGER (0..65535)
ProtocolExtensionID ::= INTEGER (0..65535)
ProcedureCode ::= INTEGER (0..255)
IES ::= CLASS { &id ProtocolIE-ID UNIQUE, &criticality Criticality, &Value, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality TYPE &Value PRESENCE &presence }
EXT ::= CLASS { &id ProtocolExtensionID UNIQUE, &criticality Criticality, &Extension, &presence Presence }
  WITH SYNTAX { ID &id CRITICALITY &criticality EXTENSION &Extension PRESENCE &presence }
EP ::= CLASS { &InitiatingMessage, &SuccessfulOutcome OPTIONAL, &UnsuccessfulOutcome OPTIONAL,
  &procedureCode ProcedureCode UNIQUE, &criticality Criticality DEFAULT ignore }
  WITH SYNTAX { INITIATING MESSAGE &InitiatingMessage [SUCCESSFUL OUTCOME &SuccessfulOutcome]
  [UNSUCCESSFUL OUTCOME &UnsuccessfulOutcome] PROCEDURE CODE &procedureCode [CRITICALITY &criticality] }
-- asn1tools cannot pass a template parameter on to another template, so the field is written inline here
Container {IES : S} ::= SEQUENCE (SIZE (0..maxIEs)) OF SEQUENCE { id IES.&id ({S}), criticality IES.&criticality ({S}{@id}), value IES.&Value ({S}{@id}) }
Field {IES : S} ::= SEQUENCE { id IES.&id ({S}), criticality IES.&criticality ({S}{@id}), value IES.&Value ({S}{@id}) }
ExtContainer {EXT : S} ::= SEQUENCE (SIZE (1..maxIEs)) OF SEQUENCE { id EXT.&id ({S}), criticality EXT.&criticality ({S}{@id}), extensionValue EXT.&Extension ({S}{@id}) }
TI ::= INTEGER (0..255)
TO ::= OCTET STRING (SIZE(2))
TE ::= ENUMERATED { a, b, c }
Msg ::= SEQUENCE { protocolIEs Container {{MsgIEs}}, ... }
MsgIEs IES ::= {
  { ID 1 CRITICALITY reject TYPE TI PRESENCE mandatory } |
  { ID 2 CRITICALITY ignore TYPE TO PRESENCE optional } |
  { ID 300 CRITICALITY notify TYPE TE PRESENCE optional }, ... }
Item ::= SEQUENCE { a INTEGER (0..7), iE-Extensions ExtContainer {{ItemExt}} OPTIONAL, ... }
ItemExt EXT ::= { { ID 7 CRITICALITY ignore EXTENSION TI PRESENCE optional }, ... }
Ch ::= CHOICE { x INTEGER (0..7), choice-Extensions Field {{ChIEs}} }
ChIEs IES ::= { { ID 5 CRITICALITY reject TYPE TI PRESENCE optional }, ... }
Rsp ::= SEQUENCE { protocolIEs Container {{RspIEs}}, ... }
RspIEs IES ::= { { ID 1 CRITICALITY ignore TYPE TI PRESENCE mandatory }, ... }
InitiatingMessage ::= SEQUENCE {
  procedureCode EP.&procedureCode ({EPs}),
  criticality EP.&criticality ({EPs}{@procedureCode}),
  value EP.&InitiatingMessage ({EPs}{@procedureCode}) }
SuccessfulOutcome ::= SEQUENCE {
  procedureCode EP.&procedureCode ({EPs}),
  criticality EP.&criticality ({EPs}{@procedureCode}),
  value EP.&SuccessfulOutcome ({EPs}{@procedureCode}) }
Pdu ::= CHOICE { initiatingMessage InitiatingMessage, successfulOutcome SuccessfulOutcome, ... }
EPs EP ::= { procA | procB, ... }
procA EP ::= { INITIATING MESSAGE Msg SUCCESSFUL OUTCOME Rsp PROCEDURE CODE 21 CRITICALITY reject }
procB EP ::= { INITIATING MESSAGE Item PROCEDURE CODE 200 }
END
"""
conv2 = asn1tools.compile_string(SPEC2, "per")
def oc(t, v):
    """Open type contents: the complete encoding of the value (asn1tools takes bytes here)."""
    return conv2.encode(t, v)


IE_CASES = [
    ("ie_msg_empty", "Msg", {"protocolIEs": []}),
    ("ie_msg_1", "Msg", {"protocolIEs": [{"id": 1, "criticality": "reject", "value": oc("TI", 200)}]}),
    ("ie_msg_12", "Msg", {"protocolIEs": [{"id": 1, "criticality": "reject", "value": oc("TI", 7)}, {"id": 2, "criticality": "ignore", "value": oc("TO", b"ab")}]}),
    ("ie_msg_123", "Msg", {"protocolIEs": [{"id": 1, "criticality": "reject", "value": oc("TI", 255)}, {"id": 2, "criticality": "ignore", "value": oc("TO", b"zz")}, {"id": 300, "criticality": "notify", "value": oc("TE", "c")}]}),
    ("ie_item_noext", "Item", {"a": 3}),
    ("ie_item_ext", "Item", {"a": 3, "iE-Extensions": [{"id": 7, "criticality": "ignore", "extensionValue": oc("TI", 9)}]}),
    ("ie_choice_x", "Ch", ("x", 5)),
    ("ie_choice_ext", "Ch", ("choice-Extensions", {"id": 5, "criticality": "reject", "value": oc("TI", 77)})),
    ("ie_pdu_init_a", "Pdu", ("initiatingMessage", {"procedureCode": 21, "criticality": "reject", "value": oc("Msg", {"protocolIEs": [{"id": 1, "criticality": "reject", "value": oc("TI", 7)}]})})),
    ("ie_pdu_init_b", "Pdu", ("initiatingMessage", {"procedureCode": 200, "criticality": "ignore", "value": oc("Item", {"a": 6})})),
    ("ie_pdu_succ_a", "Pdu", ("successfulOutcome", {"procedureCode": 21, "criticality": "reject", "value": oc("Rsp", {"protocolIEs": [{"id": 1, "criticality": "ignore", "value": oc("TI", 1)}]})})),
]

out = []
for name, typ, value, wrap, big in CASES:
    variants = [(name, conv, typ, value)]
    if wrap:
        variants.append((name + "@w", wrap_conv(typ), "W", {"p": bits("101"), "x": value, "q": bits("110")}))
    for n, c, t, v in variants:
        try:
            enc = c.encode(t, v)
        except Exception as e:  # value not encodable by the oracle (e.g. out of root range): skip, with a note
            print(f"# skipped {n}: {e}", file=sys.stderr)
            continue
        c.decode(t, enc)  # must decode without error
        if big:
            out.append(f"{n} | big:{len(enc)}:{fnv(enc):016x}:{enc[:16].hex()}")
        else:
            out.append(f"{n} | {enc.hex()}")
for n, t, v in IE_CASES:
    out.append(f"{n} | {conv2.encode(t, v).hex()}")
print("\n".join(out))
