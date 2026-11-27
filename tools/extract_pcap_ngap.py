#!/usr/bin/env python3
"""Extract the NGAP PDUs of a capture as hex, one per line, for crates/onwai-ngap/tests/captures/*.txt.

    python3 -I tools/extract_pcap_ngap.py CAPTURE.pcap [--replace OLD_IP=NEW_IP ...] [--replace-text OLD=NEW ...] > crates/onwai-ngap/tests/captures/NAME.txt

Standard library only. Reads classic pcap (Ethernet, Linux cooked v1/v2, raw IP), IPv4, SCTP; every DATA chunk with
payload protocol identifier 60 (NGAP, TS 38.412) is one PDU. Fragmented chunks are not reassembled (they are reported
and skipped). Each output line is `<frame>.<n> <direction> | <hex>`; the direction is `->` for the sender of the first
NG Setup Request (the RAN node) and `<-` for the other side.

`--replace OLD=NEW` swaps an IPv4 address (4 octets) inside the PDUs for another, e.g. a public address for an RFC 5737
documentation address: transport layer addresses are fixed-size bit strings, so the encoding stays valid. `--replace-text OLD=NEW` does the same for an ASCII string of equal length (e.g. a node name). The script
fails if an address or string is not found, so a typo cannot go unnoticed.
"""
import ipaddress
import struct
import sys

NGAP_PPID = 60


def packets(data):
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        end = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        end = ">"
    else:
        sys.exit("not a classic pcap file (pcapng is not supported: save as pcap)")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    pos = 24
    n = 0
    while pos + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[pos : pos + 16])
        n += 1
        yield n, linktype, data[pos + 16 : pos + 16 + incl]
        pos += 16 + incl


def ip_payload(linktype, pkt):
    if linktype == 1:  # Ethernet
        if pkt[12:14] != b"\x08\x00":
            return None
        pkt = pkt[14:]
    elif linktype == 113:  # Linux cooked v1
        if pkt[14:16] != b"\x08\x00":
            return None
        pkt = pkt[16:]
    elif linktype == 276:  # Linux cooked v2
        if pkt[0:2] != b"\x08\x00":
            return None
        pkt = pkt[20:]
    elif linktype != 101:  # raw IP
        sys.exit(f"unsupported link type {linktype}")
    if pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0xF) * 4
    if pkt[9] != 132:  # SCTP
        return None
    total = struct.unpack(">H", pkt[2:4])[0]
    return pkt[12:16], pkt[16:20], pkt[ihl:total]


def chunks(sctp):
    pos = 12  # common header
    while pos + 4 <= len(sctp):
        ctype, flags, length = struct.unpack(">BBH", sctp[pos : pos + 4])
        if length < 4:
            break
        yield ctype, flags, sctp[pos + 4 : pos + length]
        pos += (length + 3) & ~3


def main(argv):
    replace = []
    files = []
    it = iter(argv)
    for a in it:
        if a == "--replace":
            old, new = next(it).split("=")
            replace.append((ipaddress.ip_address(old).packed, ipaddress.ip_address(new).packed, old))
        elif a == "--replace-text":
            old, new = next(it).split("=")
            if len(old) != len(new):
                sys.exit("--replace-text needs strings of equal length")
            replace.append((old.encode("ascii"), new.encode("ascii"), old))
        else:
            files.append(a)
    if len(files) != 1:
        sys.exit(__doc__)
    data = open(files[0], "rb").read()
    out = []
    ran = None
    for frame, linktype, pkt in packets(data):
        parsed = ip_payload(linktype, pkt)
        if parsed is None:
            continue
        src, _, sctp = parsed
        k = 0
        for ctype, flags, body in chunks(sctp):
            if ctype != 0 or len(body) < 12:
                continue
            ppid = struct.unpack(">I", body[8:12])[0]
            if ppid != NGAP_PPID:
                continue
            if flags & 0x03 != 0x03:  # B and E bits: an unfragmented message
                print(f"# frame {frame}: fragmented DATA chunk skipped", file=sys.stderr)
                continue
            k += 1
            out.append((frame, k, src, body[12:]))
    if not out:
        sys.exit("no NGAP DATA chunks found")
    # the RAN node is the sender of the first PDU (the NG Setup Request)
    ran = out[0][2]
    used = {old: 0 for _, _, old in replace}
    lines = []
    for frame, k, src, pdu in out:
        for a, b, old in replace:
            used[old] += pdu.count(a)
            pdu = pdu.replace(a, b)
        lines.append(f"{frame}.{k} {'->' if src == ran else '<-'} | {pdu.hex()}")
    for old, n in used.items():
        if n == 0:
            sys.exit(f"address {old} does not occur in any PDU")
        print(f"# {old}: replaced {n} time(s)", file=sys.stderr)
    print("\n".join(lines))


main(sys.argv[1:])
