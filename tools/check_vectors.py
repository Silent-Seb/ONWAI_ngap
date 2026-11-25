#!/usr/bin/env python3
"""Check the sampled test vectors against the independent `asn1tools` APER implementation.

    python3 -I tools/oracle_asn.py specs/asn1 /tmp/oracle_asn
    ASN1TOOLS_PATH=<dir containing asn1tools> python3 -I tools/check_vectors.py /tmp/oracle_asn testdata

For every line of `testdata/messages.txt` (a complete NGAP-PDU) and `testdata/types.txt` (a standalone type):
decode the octets with the oracle, encode the decoded value again, and require the same octets. The vectors come from
`ngap-testgen`, which writes APER straight from the resolved ASN.1, so this ties three implementations together:
the sampler, the oracle, and (via the Rust tests that decode and re-encode the same files) the generated types.

Known limits of the oracle (see CLAUDE.md): it has no size extension for BIT STRING / character strings and it handles
`INTEGER (lb..MAX)` wrongly; vectors that hit a documented limit are listed as "oracle limit" and do not fail the run.
Exit status 1 if any other vector disagrees.
"""
import glob
import os
import sys

if os.environ.get("ASN1TOOLS_PATH"):
    sys.path.insert(0, os.environ["ASN1TOOLS_PATH"])
import asn1tools

ORACLE_DIR, DATA_DIR = sys.argv[1], sys.argv[2]
conv = asn1tools.compile_files(sorted(glob.glob(ORACLE_DIR + "/*.asn")), "per")


def lines(path):
    for n, line in enumerate(open(path), 1):
        if line.startswith("#") or " | " not in line:
            continue
        key, hexed = line.rstrip("\n").split(" | ")
        yield n, key, bytes.fromhex(hexed)


def check(path, type_of):
    ok, bad, skipped = 0, [], []
    for n, key, data in lines(path):
        name = key.rsplit(".", 1)[0]
        typ = type_of(name)
        try:
            value = conv.decode(typ, data)
            again = conv.encode(typ, value)
        except Exception as e:  # noqa: BLE001 - report whatever the oracle says
            bad.append((n, key, f"{type(e).__name__}: {str(e)[:160]}"))
            continue
        if again == data:
            ok += 1
        else:
            bad.append((n, key, f"re-encoded differently\n    sampled {data.hex()}\n    oracle  {again.hex()}"))
    return ok, bad, skipped


failed = False
for fname, type_of in (("messages.txt", lambda name: "NGAP-PDU"), ("types.txt", lambda name: name)):
    ok, bad, _ = check(os.path.join(DATA_DIR, fname), type_of)
    print(f"{fname}: {ok} agree, {len(bad)} do not")
    for n, key, why in bad[:40]:
        print(f"  line {n} {key}: {why}")
    if bad:
        failed = True
sys.exit(1 if failed else 0)
