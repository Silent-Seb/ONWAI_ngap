# ONWAI_ngap

A Rust **NGAP codec** for the AMF side of the 5G **N2 interface** — typed Rust definitions of every message and
information element in **3GPP TS 38.413 (NG Application Protocol), Rel-19 v19.4.0**, with ASN.1 **Aligned PER**
encoding and decoding.

The library is **generated from the ASN.1 embedded in the specification** (clause 9.4), not transcribed by hand,
so it can follow each 3GPP release by re-running the generator. It is a sibling of
[ONWAI_sbi](../ONWAI_sbi) and follows the same conventions (generated code is committed, never hand-edited, and
`cargo xtask check` proves it is up to date).

> **Status: working codec, pre-alpha.** All steps of the [plan](#implementation-steps) are done: the spec is extracted, parsed and
> resolved; `ngap-types` (1,446 generated types with APER encode/decode) is verified against an independent APER implementation
> on 715 sampled PDUs (every message, five shapes each), 3,876 sampled types and 10 hand-built real PDUs; the `onwai-ngap` facade
> (`decode_pdu` / `encode_pdu` with clause-10 diagnostics) is mutation-tested. Nothing is published to crates.io. CI
> (`build-and-test`: fmt, clippy `-D warnings`, `cargo test --workspace`) is green on every push so far (checked 2026-11-28); the `spec`
> and `oracle` jobs are skipped until the repository variable `NGAP_SPEC_URL` is set.

**Scope (decided):** codec only — typed NGAP PDUs, APER encode/decode, and the decode-time diagnostics that clause 10
needs. **Not in scope:** SCTP transport (PPID 60, port 38412), per-gNB / per-UE state and AP-ID handling (§10.6),
procedure state machines and timers, logical-error handling (§10.4), NAS (TS 24.501) decoding of `NAS-PDU`, serde/JSON.
Those are later layers that sit on top of this crate.

---

## Source of the definitions

| | |
|---|---|
| Specification | 3GPP TS 38.413 *NG-RAN; NG Application Protocol (NGAP)* |
| Release / version | Rel-19, v19.4.0 (file `38413-j40.docx`) |
| SHA-256 of the pinned file | `fb2cd9b8c2606da79aa0008faaedcc01ecd1de3ea1595242c35674215c7d66ef` |
| ASN.1 location | clause 9.4.3 – 9.4.8 (six modules, 14,685 lines) |
| Download | <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/> |

The spec is **not vendored** (git-ignored `specs/`; see [`codegen/spec-source.toml`](codegen/spec-source.toml) and
[`NOTICE.md`](NOTICE.md)). © 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). Where this README
and the specification disagree, **the specification wins**.

### What the ASN.1 contains (measured)

| Module (clause) | Lines | Content |
|---|---:|---|
| `NGAP-CommonDataTypes` (9.4.6) | 26 | `Criticality`, `Presence`, `ProcedureCode` (0..255), `ProtocolIE-ID` (0..65535), `PrivateIE-ID`, `TriggeringMessage` |
| `NGAP-Constants` (9.4.7) | 743 | 87 procedure codes, 491 `id-*` IE ids, 108 `max*` bounds |
| `NGAP-Containers` (9.4.8) | 192 | 4 information-object classes; parameterized `ProtocolIE-Container`, `-SingleContainer`, `-Field`, `-ContainerList`, `-ContainerPair(List)`, `ProtocolExtensionContainer/-Field`, `PrivateIE-Container/-Field` |
| `NGAP-PDU-Descriptions` (9.4.3) | 1,006 | `NGAP-PDU` CHOICE; `InitiatingMessage` / `SuccessfulOutcome` / `UnsuccessfulOutcome` as open types selected by procedure code through the `NGAP-ELEMENTARY-PROCEDURE` class; class-1 and class-2 object sets |
| `NGAP-PDU-Contents` (9.4.4) | 4,020 | the message SEQUENCEs and 227 `NGAP-PROTOCOL-IES` object sets (their IE tables) |
| `NGAP-IEs` (9.4.5) | 8,698 | the IE types (~1,140 type assignments); 469 `NGAP-PROTOCOL-EXTENSION` object sets (the per-type `iE-Extensions`) |

Construct census of the parsed AST (`cargo xtask stats`; every figure is cross-checked against an independent count of
the lexer's tokens, see [ASN.1 front end](#asn1-front-end-ngap-codegen---implemented)):

| | | | |
|---|---:|---|---:|
| assignments | 2,786 | SEQUENCE (components / OPTIONAL) | 627 (1,668 / 794) |
| ↳ type assignments (11 parameterized) | 1,308 | SEQUENCE OF | 240 |
| ↳ value assignments (`id-*`, `max*`, …) | 686 | CHOICE (alternatives) | 79 (249) |
| ↳ information-object classes | 5 | ENUMERATED (items) | 230 (843) |
| ↳ object sets: IES 227, EXTENSION 469, PRIVATE-IES 1, ELEMENTARY-PROCEDURE 3 | 700 | INTEGER / BIT STRING / OCTET STRING | 241 / 62 / 132 |
| ↳ information objects (the 87 elementary procedures) | 87 | `OCTET STRING (CONTAINING X)` | 60 |
| inline objects in object sets (the IE rows) | 1,127 | character strings (2 Printable, 4 Visible, 3 UTF8) | 9 |
| table constraints `({Set}{@id})` | 23 | NULL / OBJECT IDENTIFIER | 6 / 1 |
| extension markers `...` | 1,634 | no BOOLEAN, REAL, SET, named numbers, `DEFAULT` components | |

Notable values: one `INTEGER (0..18446744073709551615)`, one extension *range* `INTEGER (1..65535, ..., 65536..109999)`,
two value-set unions `INTEGER (1..30|40|…|181, ...)`; all character strings are `SIZE(1..150, ...)` except
`URI-address`.

### Wire format

Clause 9.4.1: *"NGAP ASN.1 definition conforms to ITU-T Rec. X.691 [PER], X.680 and X.681."* NGAP is carried in
**ALIGNED PER** (APER). The spec text does not repeat the word "aligned"; APER is the NGAP convention (as in
Wireshark). The codec is checked against an independent ALIGNED PER encoder (`asn1tools`, see
[Verification](#verification)), and against a real capture of a gNB and an AMF (verification item 12), but only that one attach/session trace.

Rules from clause 9.4.1 and 10 that the codec honours:

- IEs in a container follow the order of the object-set definition; a *mandatory* IE appears exactly once, an
  *optional/conditional* IE at most once.
- **Transfer-syntax error** (§10.2): the PDU cannot be ASN.1-decoded (range violation, missing mandatory SEQUENCE
  component, wrong order inside a SEQUENCE).
- **Abstract-syntax error** (§10.3): unknown IE id, missing mandatory IE, IEs in the wrong order / too many occurrences,
  each handled by the IE's **criticality** (`reject` / `ignore` / `notify`). The codec reports these precisely so a later
  AMF layer can build Error Indication, failure messages and `CriticalityDiagnostics`.

---

## Repository structure

```
ONWAI_ngap/
├── Cargo.toml  rust-toolchain.toml  rustfmt.toml     workspace; toolchain pinned to 1.100.0 like ONWAI_sbi
├── .cargo/config.toml                                `cargo xtask …` alias
├── README.md  CLAUDE.md  LICENSE  NOTICE.md
├── fuzz/                         cargo-fuzz target for decode_pdu (nightly; own workspace, see fuzz/README.md)
├── codegen/
│   └── spec-source.toml          pinned spec file name, release, SHA-256, transfer syntax
├── tools/                        oracle scripts (Python + asn1tools; only needed to regenerate test vectors)
│   ├── gen_aper_vectors.py       crates/ngap-aper/tests/vectors.txt: primitives and IE containers
│   ├── oracle_asn.py             rewrites the NGAP modules so asn1tools can compile them
│   ├── gen_ngap_vectors.py       crates/ngap-types/tests/vectors.txt: real NGAP PDUs
│   └── check_vectors.py          testdata/*.txt vs the oracle: decode, re-encode, same octets
├── specs/                        GIT-IGNORED: 38413-j40.docx and the extracted specs/asn1/*.asn
├── testdata/                     GENERATED, committed: messages.txt (every message, 5 sampled shapes), types.txt (every type)
├── .github/workflows/ci.yml      fmt, clippy, tests; spec-based regeneration and oracle jobs when NGAP_SPEC_URL is set
├── docs/
│   ├── architecture.md           pipeline, crates, why it is built this way
│   ├── mapping-rules.md          ASN.1 → Rust rules and decode semantics
│   └── regenerating.md           new spec release, regeneration, oracle checks, robustness runs
└── crates/
    ├── xtask/          hand-written   `cargo xtask extract-asn | stats | gen | vectors | check`
    ├── ngap-testgen/   hand-written   samples valid PDUs/types from the IR (min / max / random) → testdata/
    ├── ngap-aper/      hand-written   APER runtime: BitReader/BitWriter, Size, BitString, Contained<T>, traits, errors
    ├── ngap-codegen/   hand-written   ASN.1 lexer → parser → resolver/IR → Rust emitter
    ├── ngap-types/     GENERATED      every ASN.1 type + APER impls (committed, never hand-edited)
    └── onwai-ngap/     hand-written   facade: NgapPdu, decode_pdu / encode_pdu, Contained<T>, diagnostics, examples
```

Hand-written crates are linted with `-D warnings`; `unsafe` is forbidden workspace-wide.

---

## Design

### Generated types (`ngap-types`) — implemented

Full rules: [`docs/mapping-rules.md`](docs/mapping-rules.md). In short: names are Rust-style (`NGSetupRequest` →
`NgSetupRequest`, `pDUSessionID` → `pdu_session_id`); **the IEs of a message are its fields** (mandatory → `T`, optional →
`Option<T>`, in spec order) plus `unknown_ies: Vec<RawIe>` for IEs the spec version does not define; every struct has
`new(<mandatory fields>)`; `OCTET STRING (CONTAINING T)` is `Contained<T>`, raw bytes that are only decoded on request;
`iE-Extensions` are typed where the spec defines members and raw otherwise; `NgapPdu` is the CHOICE of
`InitiatingMessage` / `SuccessfulOutcome` / `UnsuccessfulOutcome`, enums with one variant per procedure message.
1,446 types, each with `AperEncode` + `AperDecode`, 70k lines, no proc-macros and no serde.

### APER runtime (`ngap-aper`) — implemented

Fully safe Rust, no dependencies. Every encoder is a `write_*` method on `BitWriter`, every decoder a `read_*` method
on `BitReader` (generated code calls them with the constants of each ASN.1 type). Errors are `AperError { kind,
bit_offset }`; decoding never panics, and lengths are validated against the remaining input before allocating.

| ASN.1 construct | API |
|---|---|
| INTEGER `(lo..hi)` (any range up to the u64 range; `i128` arithmetic) | `write/read_constrained_int` |
| INTEGER `(lo..hi, ...)` incl. extension *ranges* (`ExtendedPacketDelayBudget`) | `write/read_ext_constrained_int` |
| INTEGER unconstrained / `(lb..MAX)` / normally-small numbers | `*_unconstrained_int`, `*_semi_constrained_int`, `*_normally_small` |
| SIZE constraints, incl. extensible and unbounded | `Size::{UNBOUNDED, fixed, range, extensible}` |
| OCTET STRING, BIT STRING (`BitString`), PrintableString / VisibleString (`CharSet`), UTF8String | `*_octet_string`, `*_bit_string`, `*_char_string`, `*_utf8_string` |
| OBJECT IDENTIFIER (`ObjectIdentifier`), NULL (no bits) | `*_object_identifier` |
| CHOICE index, ENUMERATED index (root + extension additions) | `write_index(idx, root_count, extensible)` / `read_index` |
| SEQUENCE extension additions, open types | `write_extension_additions` / `read_extension_additions`, `write/read_open_type` |
| SEQUENCE OF | `write_seq_of` / `read_seq_of` |
| `OCTET STRING (CONTAINING T)` | `Contained<T>`: `raw()`, `from_raw`, `decode()`, `encode_from(&T)` |
| whole values | `AperEncode` / `AperDecode`, `to_vec` (complete encoding, ≥ 1 octet), `from_slice` |

Long strings and lists use X.691 16K fragmentation (tested through 128K). A zero-bit element guard bounds SEQUENCE OF
decoding (NGAP has no unbounded lists, so this is defence in depth).

Rules confirmed against the oracle (and easy to get wrong): constrained lengths follow the integer range rules (a
1024-value range takes two aligned octets); variable-length strings/bit strings are aligned after the length *even when
empty*; fixed-size strings are unaligned only up to 2 octets / 16 bits; `UTF8String`'s SIZE is not PER-visible; an
ENUMERATED / CHOICE addition is `normally small` indexed from the first addition; the SEQUENCE extension-additions
bitmap has one bit per addition the sender knows.

#### Test vectors from an independent implementation

`crates/ngap-aper/tests/vectors.txt` (committed, 339 lines ≈ 170 values, each bare and wrapped between two 3-bit
fields to expose alignment) is produced by `tools/gen_aper_vectors.py` with the Python library
[`asn1tools`](https://github.com/eerimoq/asn1tools) (codec `per` = ALIGNED PER). It is **not** needed to run the tests;
only to regenerate the vectors: `ASN1TOOLS_PATH=<dir containing asn1tools> python3 -I tools/gen_aper_vectors.py >
crates/ngap-aper/tests/vectors.txt` (pure Python plus `pyparsing`, `bitstruct`).
`tests/vectors.rs` checks encode == vector, decode(vector) == value, the wrapped form, and decoding of every truncated
prefix. `tests/behaviour.rs` covers error paths, 16K fragmentation boundaries, extension additions (incl. > 64),
`Contained`, and 30,000 rounds of pseudo-random garbage into every decoder.

Known oracle gaps (covered by hand-derived vectors from X.691 instead): `asn1tools` does not implement size extension for
BIT STRING and character strings, and encodes `INTEGER (lb..MAX)` as an unconstrained integer, contradicting X.691 10.7
(NGAP has no such type). `asn1tools` also fails to *parse* the full NGAP modules (`EXTENSION OCTET STRING (CONTAINING …)`
inside an object set), so using it as the whole-PDU oracle in step 7 needs a small preprocessing step or another oracle.

### ASN.1 front end (`ngap-codegen`) — implemented

`ngap_codegen::asn1` turns the six modules into a typed AST that the resolver (step 4) consumes. It is hand-written and
deliberately limited to the dialect TS 38.413 uses (X.680 / X.681 / X.683 subset): a construct outside it — `BOOLEAN`,
`REAL`, `SET`, `EXPORTS`, named numbers or bits, a second extension marker — is a parse **error with `module:line:col`**,
never a silent gap.

| Stage | What it does |
|---|---|
| `lexer` | tokens with positions; `--` comments (to the next `--` or end of line); hyphenated names; negative numbers; `::=` `...` `..` `.&field` `@` |
| `parser` | modules (OID, tag default), `IMPORTS` incl. `Name{}`, type / value / class / object / object-set assignments, parameterized types, constraints (ranges, unions, `SIZE`, `CONTAINING`, extension markers with additions, table constraints `({Set}{@id})`), ENUMERATED / CHOICE / SEQUENCE / SEQUENCE OF |
| `ast` | `Module`, `Assignment`, `Type` (+ `constraints`), `ClassAssignment`, `ObjectSet`, … ; `Type::walk` visits nested types |
| `census` | construct counts (`Census::of`), used by `cargo xtask stats` and by the tests |

Information objects such as `{ ID id-X CRITICALITY reject TYPE T PRESENCE mandatory }` can only be read with the
`WITH SYNTAX` of their class, and the classes live in other modules (`NGAP-Containers`, `NGAP-PDU-Descriptions`) than
their users. `parse_modules` therefore **pre-scans every source for class definitions**, then parses each module against
that registry; the objects come out as `field → type | value` pairs and an object that lacks a mandatory field is an error.

Gates (`crates/ngap-codegen/tests/parse_ngap.rs`, need `specs/asn1`; they skip with a message if it is absent and fail
when `CI` is set): token counts of `ENUMERATED`, `CHOICE`, `SEQUENCE`, `OF`, `NULL`, `INTEGER`, `BIT`, `OCTET`, `OBJECT`,
`CONTAINING`, `SIZE`, character-string keywords, `CLASS`, `OPTIONAL`, `FROM`, `...`, `::=`, `@`, `:`, `;` and `[` equal the
corresponding AST counts; every imported symbol is defined by the module it comes from (and `Name{}` marks exactly the
parameterized ones); every object-set reference names something defined. A second test pins the census of the
pinned release (`38413-j40`).

### Resolver / IR (`ngap_codegen::ir`) — implemented

`build_ir(&modules) -> Result<Ir, IrError>` turns the AST into what the emitter reads, then validates it
(errors carry `module:line (item)`):

| IR part | Content |
|---|---|
| `consts` | 686 integers (`id-*` IE ids and procedure codes, `max*`) with their governor type and module |
| `types` | the 1,297 non-parameterized type assignments as `IrType`: `Integer(IntRange)`, `Enumerated`, `BitString(size)`, `OctetString { size, contained }`, `CharString`, `Sequence`, `SequenceOf { size, element }`, `Choice`, `Named(name)`, `Table` |
| `sets` | the 700 object sets as rows `(id, criticality, presence, type)` in spec order — which is also the required wire order — plus whether the set is extensible (`...`) |
| `procedures` | the 87 elementary procedures: code, criticality (class default `ignore` applied), class 1 / 2, initiating / successful / unsuccessful message type names |

Rules worth knowing (all pinned by tests):

- **Parameterized containers are instantiated, not special-cased by name.** Actual parameters are substituted into the
  template (`ProtocolIE-Container {{NGSetupRequestIEs}}` → `SEQUENCE (SIZE (0..65535)) OF ProtocolIE-Field {{…}}` → …).
  A SEQUENCE whose components are `CLASS.&field ({Set}{@key})` becomes one `Table { class, set, components: Key |
  Criticality | Value }`, so an IE container is `SequenceOf { Table }` (or a bare `Table` for `ProtocolIE-SingleContainer`),
  and the PDU's `InitiatingMessage` / `SuccessfulOutcome` / `UnsuccessfulOutcome` are tables over the procedure set.
  The wire layout (id, criticality, open-type value) is therefore *derived from the spec's own definitions*, and an
  unexpected shape is an error instead of a guess. Uses in the pinned release: 150 `Container` + 77 `SingleContainer`
  (IE tables), 469 extension containers, 1 private container, 3 PDU wrappers. `ContainerList` and the `Pair` family are
  defined but never used.
- **PER-visible constraints only.** A union like `1..30|40|…|181` has the effective range `1..=181` (`lb`/`ub`) and keeps the
  written `ranges` for logical validation; an extension marker only sets `extensible`; `SIZE(8, ..., 16)` is fixed 8 +
  extensible; sizes use the constants (`SIZE(1..maxnoofTAIs)`). Constraints on a *reference* (`Foo (SIZE(2))`) do not
  occur and are an error.
- **Enumerations are numbered** as X.680 says (explicit values honoured, then the lowest unused); each item carries its PER
  `index` (rank among the root values, or position among the additions).
- **Scoping is checked**: a name must be defined in, or imported into, the module using it; names must be unique across
  modules (they are, which lets the IR use one flat namespace).
- **Validation**: no dangling type or set reference; every table's set exists and has the table's class; unique IE ids per
  set and within `ProtocolIE-ID`; unique procedure codes within `ProcedureCode`; every message type is a SEQUENCE with an
  IE container; class-1/class-2 membership agrees with `NGAP-ELEMENTARY-PROCEDURES-CLASS-1`; the union set lists
  exactly the 87 procedures; `NGAP-PDU` has the expected three alternatives.
- **Recursion**: `recursive_groups(&ir)` finds types that contain themselves by value (`OCTET STRING (CONTAINING T)` holds raw
  bytes and is not an edge). In 38413-j40 there are none, so the generated Rust needs no `Box`.

`cargo xtask stats` prints this census after the AST one.

### Decode diagnostics (the only clause-10 piece in scope)

`onwai_ngap::decode_pdu(&[u8]) -> Result<Decoded, DecodeError>` reads the envelope first (message type, procedure code
and criticality), so even a PDU whose body is broken is reported with the procedure it belongs to.

| What is wrong | Clause | `DecodeError` | `reaction()` | `cause()` |
|---|---|---|---|---|
| not valid APER; message type unreadable; trailing octets | 10.2, 10.3.4.1A | `TransferSyntax { error, context }` | `ErrorIndication` | transfer-syntax-error |
| procedure code not defined | 10.3.4.1 | `UnknownProcedure` | reject / notify → `ErrorIndication`, ignore → `Ignore` | abstract-syntax-error-reject / -ignore-and-notify |
| unknown IE with criticality *reject* (the message's own IEs) | 10.3.4.2 | `AbstractSyntax { issues }` | initiating, procedure has a failure message → `UnsuccessfulOutcome`; without → `ErrorIndication`; response → `LocalErrorHandling` | abstract-syntax-error-reject |
| mandatory IE missing (any depth) | 10.3.5 | `AbstractSyntax { issues: [Missing] }` | as above | reject / ignore-and-notify by the IE's criticality |
| IEs in the wrong order (top level), IE twice (any depth) | 10.3.6 | `AbstractSyntax { construction }` | as above | falsely-constructed-message |
| unknown IE with criticality *notify* / *ignore* | 10.3.4.2 | **not an error**: `Decoded.issues`; `needs_report()` / `criticality_diagnostics()` for *notify* | | |

Whatever the cause, an error inside an Error Indication message is `LocalErrorHandling` (10.5). `DecodeError::error_indication()`
builds the Error Indication message (cause + Criticality Diagnostics: procedure code, triggering message, procedure
criticality, one item per IE); `criticality_diagnostics()` and `cause()` serve a failure message the same way. The codec sends
nothing: the caller fills in the AP IDs it knows and transmits.

Limits, on purpose and stated: the first problem found is reported (clause 10.3.1 wants all of them); a missing mandatory IE is
an error whatever its criticality (clause 10.3.5 wants "Ignore" and "Ignore and Notify" ones tolerated: 125 of the 350 mandatory
IEs are "Ignore"), because the typed message cannot hold an absent mandatory field, and `reaction()` then asks for the failure
message or an Error Indication all the same; conditional IEs that are
erroneously present (10.3.3) and logical errors (10.4) need state or semantics and are not detected. Unknown IEs are examined at
any depth (message, list items, extension containers): the generated decoders call `ngap_aper::ie::note_unknown` for each one and
the facade collects them with `record_unknown_ies` (a thread-local scope); the diagnostics list each distinct problem once,
at most 256 (`maxnoofErrors`). `DecodeOptions::enforce_ie_order(false)` accepts known IEs in any
order for a sloppy peer.

---

## Usage

```rust
use ngap_aper::{from_slice, to_vec, Contained};
use ngap_types::*;

// build a message: `new` takes the mandatory IEs, optional ones are `Option` fields
let mut m = NgSetupResponse::new(AmfName("amf-1".into()), served_guami_list, RelativeAmfCapacity(255), plmn_support_list);
m.extended_amf_name = None;
let bytes: Vec<u8> = to_vec(&NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(m)))?;   // APER, for SCTP PPID 60

// read what the gNB sent
match from_slice::<NgapPdu>(&bytes)? {
    NgapPdu::InitiatingMessage(InitiatingMessage::InitialUeMessage(m)) => {
        let nas: &[u8] = &m.nas_pdu.0;                     // opaque NAS-PDU
        let id = m.ran_ue_ngap_id;
        for ie in &m.unknown_ies { /* id, criticality, content: apply clause 10.3.4 */ }
    }
    _ => {}
}

// N2 SM containers are opaque until you look inside
let forwarded: &[u8] = item.pdu_session_resource_setup_request_transfer.raw();
let transfer = item.pdu_session_resource_setup_request_transfer.decode()?;      // PduSessionResourceSetupRequestTransfer
let built = Contained::encode_from(&transfer)?;
```

The same through the facade, with clause-10 diagnostics:

```rust
use onwai_ngap::{decode_pdu, encode_pdu, Reaction, types::*};

match decode_pdu(&bytes) {
    Ok(decoded) => {
        // decoded.pdu: NgapPdu; decoded.context: message type + procedure code + criticality
        if decoded.needs_report() { /* put decoded.criticality_diagnostics() in the response */ }
    }
    Err(e) => match e.reaction() {
        Reaction::ErrorIndication => { let ei = e.error_indication().unwrap(); /* fill in AP IDs, encode_pdu, send */ }
        Reaction::UnsuccessfulOutcome => { /* send the procedure's failure message with e.cause(), e.criticality_diagnostics() */ }
        Reaction::LocalErrorHandling | Reaction::Ignore => {}
    },
}
```

Runnable programs (`cargo run -p onwai-ngap --example <name>`): [`ng_setup`](crates/onwai-ngap/examples/ng_setup.rs) (decode a
request, answer with NG Setup Response), [`initial_ue_message`](crates/onwai-ngap/examples/initial_ue_message.rs) (NAS-PDU out of
an Initial UE Message), [`pdu_session_setup`](crates/onwai-ngap/examples/pdu_session_setup.rs) (forward a pre-encoded N2 SM
container), [`error_handling`](crates/onwai-ngap/examples/error_handling.rs) (what a faulty PDU turns into),
[`paging`](crates/onwai-ngap/examples/paging.rs) (build a Paging message), [`decode_capture`](crates/onwai-ngap/examples/decode_capture.rs)
(decode the 14 PDUs of a real attach). The lower-level
[`ngap-types` example](crates/ngap-types/examples/roundtrip.rs) uses `ngap_aper::{to_vec, from_slice}` directly (decode errors are then
`ngap_aper::AperError` with a specific `ErrorKind`: `MissingIe { id, criticality }`, `DuplicateIe`, `UnknownProcedure`, …).

## Regenerating from the spec

```bash
# 1. put the pinned spec at specs/38413-j40.docx (git-ignored); or export NGAP_SPEC_DOCX=/path/to/38413-j40.docx
cargo xtask extract-asn          # docx → specs/asn1/NGAP-*.asn  (6 files); checks SHA-256 against spec-source.toml
cargo xtask stats                # parse the .asn files and print the construct census (compare with the table above)
cargo xtask gen                  # regenerate crates/ngap-types/src (32 files)
cargo xtask check                # regenerate in memory and diff against committed files (CI gate)
cargo test --workspace            # all tests; the ones needing specs/asn1 skip with a message if it is absent
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings   # the generated crate opts out
```

Moving to a new 3GPP release: replace the docx, update `codegen/spec-source.toml` (file, version, SHA-256) and
`NOTICE.md`, run `extract-asn` → `stats` → `gen` → `check`; review new constructs reported by the generator.

---

## Implementation steps

- [x] **0. Bootstrap** — workspace, toolchain pin, lints, `.cargo` alias, LICENSE/NOTICE, `spec-source.toml`, this README.
- [x] **1. Spec ingestion** — `cargo xtask extract-asn` (`ngap_codegen::spec`): unzip the docx, walk `word/document.xml`
      paragraphs, take `PL`-style paragraphs between `-- ASN1START` / `-- ASN1STOP` (exactly six blocks = six modules),
      write six `.asn` files, verify the SHA-256 pinned in `spec-source.toml`. Verified: 14,685 lines total. Word
      artefacts handled: tab-stop definitions are not tabs; U+00A0 non-breaking spaces in 6 code lines become spaces.
- [x] **2. `ngap-aper` runtime** — all primitives above, 16 tests: 339 oracle vectors (independent `asn1tools`), hand-derived
      vectors where the oracle is wrong or incomplete, error paths, fragmentation, 30k-round garbage-input test.
- [x] **3. ASN.1 front end** (`ngap_codegen::asn1`) — lexer, typed AST, parser, census; all six modules parse, and every
      count is proven equal to an independent token count (21 unit tests + 3 integration tests). Details below.
- [x] **4. Resolver / IR** (`ngap_codegen::ir`) — constants, constraints, enumerations, container instantiation, object-set
      rows, procedures, validation; the real spec resolves with 0 errors and no self-containing types (34 unit tests on a
      mini spec + 8 integration tests). Details below.
- [x] **5. Rust emitter** (`ngap_codegen::emit`, `cargo xtask gen | check`) — `ngap-types`: 1,446 types with
      `AperEncode`/`AperDecode`, 70k lines in 32 files, type-checks in 53 s at 660 MB peak. Verified byte-for-byte against
      the independent `asn1tools` encoder on 10 real PDUs. Rules in [`docs/mapping-rules.md`](docs/mapping-rules.md).
- [x] **6. Facade `onwai-ngap`** — `decode_pdu` / `decode_pdu_with` / `encode_pdu`, `Decoded`, `DecodeError` with
      `reaction()` / `cause()` / `criticality_diagnostics()` / `error_indication()`, IE-order check, `Contained<T>` re-export, four
      runnable examples. The generator now also emits, per message, `IE_IDS` and `wire_ie_ids`, and per procedure wrapper (and
      `NgapPdu`) `procedure_code()`, `criticality()`, `message_name()`, `unknown_ies()`, `ie_ids()`. 18 tests (16 hand-built
      defect PDUs, the 10 oracle PDUs through the facade, corruption sweep) + 1 doctest.
- [x] **7. Verification suite + CI + docs** — `ngap-testgen` (random valid PDUs sampled from the IR, independent of the emitter),
      `testdata/` (715 message vectors: all 143 messages × min / max / r1 / r2 / r3, and 3,876 standalone type vectors),
      Rust round-trip tests over them, `tools/check_vectors.py` (the same octets against `asn1tools`: 715/715 and 3,876/3,876
      agree), a seeded mutation test (found and fixed one bug, below), `.github/workflows/ci.yml`, `docs/architecture.md`,
      `docs/regenerating.md`. `cargo xtask check` now also checks `testdata/`.

## Verification

What exists today (all green; `cargo test --workspace` runs about 140 tests):

1. `extract-asn` yields the six modules (14,685 lines); `ngap_codegen` parses them and the AST counts equal independent
   token counts (`tests/parse_ngap.rs`); the IR counts are pinned (`tests/ir_ngap.rs`: 1,297 types, 227 IE sets, 469 extension
   sets, 87 procedures, 1,127 rows).
2. `cargo xtask check` → "generated code is up to date" (also enforced by `tests/generated_is_current.rs`).
3. `cargo fmt --all --check` + `cargo clippy --workspace --all-targets -- -D warnings`.
4. **Primitives vs the oracle** (`ngap-aper`): 350 vectors from `asn1tools` — integers, strings, enumerations, choices,
   extension additions, fragmentation, IE containers, extension containers, the procedure wrapper.
5. **Golden PDUs vs the oracle** (`ngap-types/tests/golden.rs`): NG Setup Request / Response / Failure, Initial UE Message,
   Downlink / Uplink NAS Transport, UE Context Release Command, Paging, Error Indication (with Criticality Diagnostics), PDU
   Session Resource Setup Request (with a contained transfer), Initial Context Setup Request. Bytes must equal the oracle's,
   decoding must give the value back, and re-encoding must reproduce the bytes.
6. **Behaviour** (`ngap-types/tests/behaviour.rs`): unknown IEs kept and re-emitted; IEs accepted in any order; missing and
   duplicate IEs; unknown procedure; typed extension members; range checks; every truncated prefix of every vector is an
   error and every single-bit corruption is an error or a value, never a panic.

7. **Diagnostics** (`onwai-ngap/tests/diagnostics.rs`): unknown IE with each criticality, missing mandatory IE, duplicate, wrong order,
    unknown procedure code with each criticality, truncation at every length, trailing octets, errors inside Error Indication and in
    responses, the Error Indication built from an error encodes and decodes.
8. **Facade on the oracle PDUs** (`onwai-ngap/tests/golden.rs`): the 10 `asn1tools` PDUs decode with no issues and re-encode to the
    same octets; every single-bit corruption is an error or a value.

9. **Every message type** (`ngap-types/tests/all_messages.rs`, `onwai-ngap/tests/golden.rs`): the 715 sampled PDUs
   (`testdata/messages.txt`: each of the 143 messages minimal, maximal and three random ones; written by `ngap-testgen` from the
   resolved ASN.1, not from the generated types) decode, carry only IEs the spec defines for them in spec order, and re-encode to the same
   octets; the facade decodes them with no issues. `PrivateMessage` is the one message that cannot be sampled (its container
   needs one private IE and the specification defines none).
10. **Independent oracle** (`tools/check_vectors.py`): every vector of `testdata/messages.txt` and `testdata/types.txt` is
    decoded by `asn1tools`, encoded again, and must give the same octets: 715/715 and 3,876/3,876. This covers each named type
    standalone, including the extension values of INTEGERs and ENUMERATEDs that the random mode draws. Needs Python; the vectors are committed,
    so the Rust tests do not.
11. **Robustness** (`onwai-ngap/tests/mutation.rs`): seeded mutations (bit flips, byte replacement, truncation, insertion, deletion,
    fills, splices from other PDUs, huge length determinants, duplicated chunks) of all 715 PDUs. No panic, no decode slower than
    15 ms in any run; a mutant that still decodes is a fixed point (`decode(encode(x)) == x`), the lenient decoder accepts whatever the strict
    one does, and the Error Indication built from a rejection encodes. About 1.4 million mutants (seeds 2–7, 300–400 per PDU) pass. The first
    long run found a real defect: an open type of length 0 was accepted although X.691 11.2 makes its minimum one octet, so the
    value did not survive a re-encode; `read_open_type` now rejects it.
12. **A real capture** (`onwai-ngap/tests/capture.rs`, `tests/captures/attach.txt`): 14 NGAP PDUs of one UE registration and PDU session
    set-up between a simulated gNB (UERANSIM) and a 5G core AMF in a lab network — NG Setup, Initial UE Message, NAS transport,
    Initial Context Setup, PDU Session Resource Setup — produced by encoders other than ours. All decode with no diagnostics and
    encode back to the same octets, which confirms ALIGNED PER against the field. The capture itself is committed (`tests/captures/5g_attach.pcap`, 111 packets: the AMF name was replaced by a same-size text and
    the checksum of that SCTP packet recomputed); the PDUs are extracted with `tools/extract_pcap_ngap.py`, with the two public N3 addresses
    swapped for documentation addresses.
13. **Coverage-guided fuzzing** (`fuzz/`, needs nightly + `cargo-fuzz`, see `fuzz/README.md`): the same properties as the mutation test,
    seeded with the 715 PDUs. Not part of `cargo test --workspace` (own workspace). A 10-minute run (4.65 million executions, corpus grown from 715 to about 7,000 inputs) found no crash and no property violation.
14. **Every named type in Rust** (`ngap-types/tests/all_types.rs`): the 3,876 standalone type vectors decode and re-encode to the same
    octets through the generated types, selected by ASN.1 name with the generated `round_trip_by_name` (`by_name.rs`, test support).

## Risks and notes

- **Build memory — resolved.** The first development host had only 1.85 GB RAM (ONWAI_sbi could not compile its generated
  crates whole there). `ngap-types` avoids proc-macro derives and keeps the per-type code small (the shared work is in
  `ngap-aper`), so the whole 70k-line crate type-checks in **53 s at 660 MB** (`cargo check -j1`) and the full workspace test
  suite runs on this host. No slicing, feature splitting or deferred CI work is needed.
- **Open types and ordering.** IE values are open types: the decoder slices by length and decodes against the sub-slice;
  unknown ids are skipped via the length prefix — this is what makes §10.3.4 implementable.
- **Spec drift.** The docx is pinned by SHA-256; regeneration against a newer 38.413 should be a one-command diff.
- Own generator versus hampi / rasn was decided deliberately (full control of information-object-class handling,
  criticality, and `CONTAINING` pass-through; consistency with ONWAI_sbi). Their NGAP output can still serve as an extra
  cross-check.

## Licence

Apache-2.0 for the code in this repository (see [`LICENSE`](LICENSE)); the 3GPP specification text and the ASN.1
derived from it remain © 3GPP (see [`NOTICE.md`](NOTICE.md)).
