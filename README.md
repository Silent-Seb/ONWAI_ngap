# ONWAI_ngap

A Rust **NGAP codec** for the AMF side of the 5G **N2 interface** — typed Rust definitions of every message and
information element in **3GPP TS 38.413 (NG Application Protocol), Rel-19 v19.4.0**, with ASN.1 **Aligned PER**
encoding and decoding.

The library is **generated from the ASN.1 embedded in the specification** (clause 9.4), not transcribed by hand,
so it can follow each 3GPP release by re-running the generator. It is a sibling of
[ONWAI_sbi](../ONWAI_sbi) and follows the same conventions (generated code is committed, never hand-edited, and
`cargo xtask check` proves it is up to date).

> **Status: planning → bootstrap.** This README is the project plan. The checklist under
> [Implementation steps](#implementation-steps) shows what exists. Nothing is published.

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
| `NGAP-PDU-Contents` (9.4.4) | 4,020 | ~140 top-level SEQUENCEs (messages and list items), 228 `NGAP-PROTOCOL-IES` object sets |
| `NGAP-IEs` (9.4.5) | 8,698 | ~1,140 type assignments; 468 `NGAP-PROTOCOL-EXTENSION` object sets (the per-type `iE-Extensions`) |

Construct census (this is what the runtime and generator must support): 627 SEQUENCE, 240 SEQUENCE OF, 79 CHOICE,
230 ENUMERATED (98 extensible), 239 INTEGER (67 extensible; one `0..18446744073709551615`; one extension *range*
`1..65535, ..., 65536..109999`; two value-set unions `1..30|40|…|181, ...`), 62 BIT STRING, 132 OCTET STRING,
**60 `OCTET STRING (CONTAINING X)`**, 6 UTF8String, 2 PrintableString, 6 NULL, 1 OBJECT IDENTIFIER, 9 information-object
classes, 11 parameterized-type uses, 1 `IES-PAIR` set, no BOOLEAN / REAL / `COMPONENTS OF`.

### Wire format

Clause 9.4.1: *"NGAP ASN.1 definition conforms to ITU-T Rec. X.691 [PER], X.680 and X.681."* NGAP is carried in
**ALIGNED PER** (APER). The spec text does not repeat the word "aligned", so APER is confirmed by interop vectors
(see [Verification](#verification)), not assumed.

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
├── codegen/
│   └── spec-source.toml          pinned spec file name, release, SHA-256, transfer syntax
├── specs/                        GIT-IGNORED: 38413-j40.docx and the extracted specs/asn1/*.asn
├── docs/
│   ├── architecture.md           pipeline: docx → ASN.1 → AST → IR → Rust
│   ├── mapping-rules.md          ASN.1 → Rust mapping (naming, optionality, CHOICE, CONTAINING, …)
│   └── regenerating.md           regenerate / verify / move to a new 3GPP release
└── crates/
    ├── xtask/          hand-written   `cargo xtask extract-asn | gen | check | verify | stats`
    ├── ngap-aper/      hand-written   APER runtime: BitReader/BitWriter, encode/decode traits, error type
    ├── ngap-codegen/   hand-written   ASN.1 lexer → parser → resolver/IR → Rust emitter
    ├── ngap-types/     GENERATED      every ASN.1 type + APER impls (committed, never hand-edited)
    └── onwai-ngap/     hand-written   facade: NgapPdu, decode_pdu / encode_pdu, Contained<T>, diagnostics, examples
```

Hand-written crates are linted with `-D warnings`; `unsafe` is forbidden workspace-wide.

---

## Design

### Generated type model (rules to be written down in `docs/mapping-rules.md`)

- ASN.1 names → Rust idiom: `NGSetupRequest` → `NgSetupRequest`; fields snake_case; enum variants CamelCase.
- **Messages are flattened.** The `protocolIEs` container becomes a plain `#[non_exhaustive]` struct:
  `mandatory` → `T`, `optional` / `conditional` → `Option<T>`. On decode each message also keeps
  `unknown_ies: Vec<UnknownIe { id, criticality, raw }>` so nothing is silently dropped.
- `ProtocolIE-ContainerList` → `Vec<Item>`; `iE-Extensions` → typed known extensions plus raw unknowns.
- `NgapPdu` = `Initiating | Successful | Unsuccessful`, each an enum with one variant per message, dispatched through a
  generated elementary-procedure table (procedure code → messages, criticality, class 1 / class 2).
- ENUMERATED → `enum` (an unknown *extension* value is a decode error, never UB); CHOICE → `enum`; BIT STRING →
  length-checked newtype; bounded INTEGER → smallest fitting integer newtype with range checks on encode and decode;
  strings → `String` / `Vec<u8>` newtypes. Value-set constraints (`1..30|40|…|181`) are checked as their PER-visible
  range `1..181`.
- **`OCTET STRING (CONTAINING X)`** (all N2 SM / transparent containers; an AMF mostly forwards these opaquely) →
  `Contained<X>`: raw bytes with `.raw()` for zero-cost pass-through, `.decode()` to parse on demand, and
  `Contained::encode_from(&x)` to build. Decoding a message never eagerly decodes contained transfers.
- Derives are `Debug, Clone, PartialEq, Eq` only — no proc-macro derives and no serde in the first cut, to keep compile
  memory low (the generated crate is large).

### APER runtime (`ngap-aper`)

Bit-level reader/writer with octet alignment; extension bit + optional-bitmap preamble; constrained whole numbers
(≤255 bit-field, =256 one octet, ≤64K two octets, >64K length-prefixed, including the u64 range); extension-range and
unconstrained integers; normally-small non-negative numbers; length determinants (constrained, unconstrained,
fragmentation ≥16K); BIT STRING and OCTET STRING (fixed, ranged, extensible); known-multiplier character strings;
NULL; OBJECT IDENTIFIER; ENUMERATED; CHOICE index (+ extension); SEQUENCE OF; SEQUENCE extension additions (unknown
additions skipped as open types); **open types** (length-prefixed, which makes skipping an unknown IE possible).
Fully safe Rust; malformed input yields an error with a bit offset and never panics or over-allocates.

### Decode diagnostics (the only clause-10 piece in scope)

```text
decode_pdu(&[u8]) -> Result<Decoded, DecodeError>

Decoded { pdu, issues }                      non-fatal: unknown `ignore` / `notify` IEs
DecodeError::Transfer(..)                    §10.2, with bit offset
DecodeError::AbstractSyntax { procedure_code, message_kind, criticality, issues }
                                             §10.3: missing/unknown `reject` IE, duplicate, wrong order
issues_to_criticality_diagnostics(..)        pure data mapping to the CriticalityDiagnostics IE
```

Sending Error Indication / failure messages is the caller's job.

---

## Usage (planned API — available once step 6 lands)

```rust
use onwai_ngap::{decode_pdu, encode_pdu, NgapPdu};

// decode what the gNB sent
let decoded = decode_pdu(&bytes)?;
if let NgapPdu::Initiating(init) = decoded.pdu {
    match init {
        InitiatingMessage::InitialUeMessage(m) => {
            let nas: &[u8] = m.nas_pdu.as_ref();              // opaque NAS-PDU
            let ran_ue_ngap_id = m.ran_ue_ngap_id;
        }
        _ => {}
    }
}
for issue in &decoded.issues { /* unknown ignore/notify IEs */ }

// pass an N2 SM transfer container through untouched, or build one
let transfer: Contained<PduSessionResourceSetupRequestTransfer> = Contained::from_raw(bytes_from_smf);
let msg = PduSessionResourceSetupRequest { /* … */ };
let out: Vec<u8> = encode_pdu(&NgapPdu::from(msg))?;
```

## Regenerating from the spec (planned commands)

```bash
# 1. put the pinned spec at specs/38413-j40.docx (git-ignored); or export NGAP_SPEC_DOCX=/path/to/38413-j40.docx
cargo xtask extract-asn          # docx → specs/asn1/NGAP-*.asn  (6 files); checks SHA-256 against spec-source.toml
cargo xtask stats                # constructs census; must match the table above
cargo xtask gen                  # regenerate crates/ngap-types
cargo xtask check                # regenerate in memory and diff against committed files (CI gate)
cargo xtask verify               # type-check ngap-types in memory-sized slices (for small machines)
cargo test -p ngap-aper -p ngap-codegen
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings   # hand-written crates
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
- [ ] **2. `ngap-aper` runtime** + unit tests from X.691 worked examples and hand-built vectors for every primitive.
- [ ] **3. ASN.1 front end** (`ngap-codegen`): lexer (`--` comments, hyphenated names), recursive-descent parser for the
      dialect (modules, IMPORTS, type/value assignments, constraints incl. extension `...`, ENUMERATED / CHOICE /
      SEQUENCE with `...`, `CLASS … WITH SYNTAX`, information object sets, parameterized types, field references
      `CLASS.&f ({Set}{@id})`). Gate: all six modules parse and counts equal the census.
- [ ] **4. Resolver / IR**: cross-module imports, constant evaluation (`maxnoof*`, `id-*`), instantiate parameterized
      containers per object set into concrete IE tables (id, criticality, type, presence, order), effective PER
      constraints, elementary-procedure table.
- [ ] **5. Rust emitter**: direct `impl AperEncode/AperDecode` per type (no derives), output split into many small
      files / modules per procedure family; write `docs/mapping-rules.md`; zero generator warnings.
- [ ] **6. Facade `onwai-ngap`**: `NgapPdu`, `decode_pdu` / `encode_pdu`, `Contained<T>`, diagnostics, runnable
      `examples/` (NG Setup round trip; Initial UE Message → NAS-PDU; PDU Session Resource Setup with a pre-encoded transfer).
- [ ] **7. Verification suite + CI + docs** (below).

## Verification

1. `extract-asn` yields six modules whose counts match the census.
2. `cargo test -p ngap-aper -p ngap-codegen`: primitive vectors; parser reads all six modules; IR counts
   (~1,140 types, 228 IE sets, 468 extension sets, 87 procedures).
3. `cargo xtask gen && cargo xtask check` → "generated code is up to date", zero generator warnings.
4. `fmt` + `clippy -D warnings` on hand-written crates; `cargo xtask verify` type-checks `ngap-types` slices.
5. **Round trip** for every message type (generated fixtures, minimal and maximal): encode → decode → equal.
6. **Golden vectors** — real APER NGAP hex from public sources (Wireshark sample captures, other public NGAP traces) for NG Setup, Initial UE Message, Initial Context Setup, PDU Session Resource Setup, Handover Required,
   Paging: decode, re-encode must be byte-identical.
7. **Independent oracle** — compile the same `.asn` with Python `asn1tools` (aligned PER) in a dev-only script; random
   values encoded by the oracle must decode and re-encode byte-identically in Rust, and the reverse. This is the main
   guard against APER mistakes (fallback: `asn1c -gen-APER`). Special attention: the extension-range INTEGER
   (`ExtendedPacketDelayBudget`), value-set constraints, and the u64 range.
8. **Robustness** — proptest / `cargo-fuzz` on `decode_pdu`: random and truncated bytes never panic or allocate
   unboundedly (lengths are bounded by constraints and remaining input).
9. **Diagnostics tests** — hand-crafted PDUs with an unknown ignore / notify / reject IE, a missing mandatory IE, a
   duplicate IE and a wrong order; check `issues` / `AbstractSyntax` against clause 10.3.

## Risks and notes

- **Build memory.** The development host has 1.85 GB RAM (ONWAI_sbi could not compile its generated crates whole
  here). Mitigations: no proc-macro derives, many small modules, `ngap-types` split into cargo features per procedure
  family (all on by default), and `cargo xtask verify` slices as in ONWAI_sbi. Full-workspace `cargo test
  --all-features` may have to wait for a bigger machine.
- **Open types and ordering.** IE values are open types: the decoder slices by length and decodes against the sub-slice;
  unknown ids are skipped via the length prefix — this is what makes §10.3.4 implementable.
- **Spec drift.** The docx is pinned by SHA-256; regeneration against a newer 38.413 should be a one-command diff.
- Own generator versus hampi / rasn was decided deliberately (full control of information-object-class handling,
  criticality, and `CONTAINING` pass-through; consistency with ONWAI_sbi). Their NGAP output can still serve as an extra
  cross-check.

## Licence

Apache-2.0 for the code in this repository (see [`LICENSE`](LICENSE)); the 3GPP specification text and the ASN.1
derived from it remain © 3GPP (see [`NOTICE.md`](NOTICE.md)).
