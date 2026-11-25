#!/usr/bin/env python3
"""Rewrite the extracted NGAP ASN.1 modules into a form the Python `asn1tools` library can compile.

`asn1tools` is the independent encoder used to check the generated codec. It stumbles over three constructs of
the NGAP modules, both rewritable without changing the wire format:

 1. a parameterized type whose body instantiates another parameterized type with its own parameter
    (`ProtocolIE-Container {S} ::= SEQUENCE OF ProtocolIE-Field {{S}}`): the field SEQUENCE is written inline;
 2. an inline `OCTET STRING (CONTAINING X)` as the type of an information object field: it gets a name;
 3. an INTEGER constrained by a union of values (`1..30|40|181`) is given the span of the union (`1..181`): same PER
    encoding, see `span_value_sets`.

The unused container templates (`...ContainerList`, `...ContainerPair`, `...ContainerPairList`) are dropped.

    python3 -I tools/oracle_asn.py specs/asn1 OUT_DIR
"""
import re
import sys
from pathlib import Path

FIELD = "SEQUENCE {{ id {c}.&id ({{S}}), criticality {c}.&criticality ({{S}}{{@id}}), {v} {c}.&{t} ({{S}}{{@id}}) }}"


def rewrite_containers(text, consts):
    ies = FIELD.format(c="NGAP-PROTOCOL-IES", v="value", t="Value").replace("{S}", "{IEsSetParam}")
    ext = FIELD.format(c="NGAP-PROTOCOL-EXTENSION", v="extensionValue", t="Extension").replace("{S}", "{ExtensionSetParam}")
    prv = FIELD.format(c="NGAP-PRIVATE-IES", v="value", t="Value").replace("{S}", "{IEsSetParam}")
    # drop the unused templates (everything from the template name to the next top-level blank-line-separated item)
    for name in ("ProtocolIE-ContainerList", "ProtocolIE-ContainerPairList", "ProtocolIE-ContainerPair"):
        text = re.sub(r"\n" + re.escape(name) + r" \{.*?\n\n", "\n\n", text, flags=re.S)
    text = re.sub(
        r"ProtocolIE-Container \{NGAP-PROTOCOL-IES : IEsSetParam\} ::=.*?\n\n",
        "ProtocolIE-Container {NGAP-PROTOCOL-IES : IEsSetParam} ::= SEQUENCE (SIZE (0.." + str(consts["maxProtocolIEs"]) + ")) OF " + ies + "\n\n",
        text, flags=re.S)
    text = re.sub(
        r"ProtocolIE-SingleContainer \{NGAP-PROTOCOL-IES : IEsSetParam\} ::=.*?\n\n",
        "ProtocolIE-SingleContainer {NGAP-PROTOCOL-IES : IEsSetParam} ::= " + ies + "\n\n", text, flags=re.S)
    text = re.sub(
        r"ProtocolExtensionContainer \{NGAP-PROTOCOL-EXTENSION : ExtensionSetParam\} ::=.*?\n\n",
        "ProtocolExtensionContainer {NGAP-PROTOCOL-EXTENSION : ExtensionSetParam} ::= SEQUENCE (SIZE (1.." + str(consts["maxProtocolExtensions"]) + ")) OF " + ext + "\n\n",
        text, flags=re.S)
    text = re.sub(
        r"PrivateIE-Container \{NGAP-PRIVATE-IES : IEsSetParam ?\} ::=.*?\n\n",
        "PrivateIE-Container {NGAP-PRIVATE-IES : IEsSetParam} ::= SEQUENCE (SIZE (1.." + str(consts["maxPrivateIEs"]) + ")) OF " + prv + "\n\n", text, flags=re.S)
    return text


def rewrite_imports(text):
    for name in ("ProtocolIE-ContainerList", "ProtocolIE-ContainerPairList", "ProtocolIE-ContainerPair"):
        text = re.sub(r"\n\t" + re.escape(name) + r"\{\},?", "", text)
    return text


def name_containing(text):
    """`TYPE OCTET STRING (CONTAINING X)` -> `TYPE CONTAINING-OF-X`, plus the definition at the end of the module."""
    found = {}

    def repl(m):
        found[m.group(2)] = True
        return f"{m.group(1)} CONTAINING-OF-{m.group(2)}"

    text = re.sub(r"(TYPE|EXTENSION)\s+OCTET STRING\s*\(CONTAINING\s+([A-Za-z0-9-]+)\s*\)", repl, text)
    defs = "".join(f"\nCONTAINING-OF-{n} ::= OCTET STRING (CONTAINING {n})\n" for n in sorted(found))
    return re.sub(r"\nEND\s*$", defs + "\nEND\n", text.rstrip() + "\n")


def span_value_sets(text):
    """`INTEGER (1..30|40|181, ...)` -> `INTEGER (1..181, ...)`.

    PER encodes an INTEGER with the span of its constraint (X.691 10.5: lb = smallest, ub = largest value of the set);
    the gaps only restrict which values are valid. `asn1tools` does not do that for a union of values (it encodes
    `1..30|40|181` differently from `1..181`), so the oracle gets the span, which has the same encoding.
    """
    def repl(m):
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        return f"INTEGER ({min(nums)}..{max(nums)}{m.group(2) or ''})"

    return re.sub(r"INTEGER\s*\(([\d.]+(?:\s*\|\s*[\d.]+)+)(\s*,\s*\.\.\.)?\s*\)", repl, text)


def read_consts(src):
    text = (Path(src) / "NGAP-Constants.asn").read_text()
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^(max\w+)\s+INTEGER ::= (\d+)", text, flags=re.M)}


def main(src, out):
    consts = read_consts(src)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for f in sorted(Path(src).glob("*.asn")):
        t = f.read_text()
        if f.name == "NGAP-Containers.asn":
            t = rewrite_containers(t, consts)
        t = rewrite_imports(t)
        t = name_containing(t)
        t = span_value_sets(t)
        (out / f.name).write_text(t)
        print(f"wrote {out / f.name}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
