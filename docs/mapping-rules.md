# ASN.1 → Rust mapping rules

How `ngap-codegen` turns the ASN.1 of TS 38.413 into the `ngap-types` crate. Everything here is implemented in
`crates/ngap-codegen/src/emit/` and pinned by tests (`emit/tests.rs`, `crates/ngap-types/tests/`).

## Names

| ASN.1 | Rust | Rule |
|---|---|---|
| type `NGSetupRequest` | `NgSetupRequest` | split into words at `-`, at lower→UPPER, and at the end of an acronym (`PDUSession` → `pdu`, `session`); capitalise each word |
| field / IE `pDUSessionID`, `id-AMF-UE-NGAP-ID` | `pdu_session_id`, `amf_ue_ngap_id` | same words, snake_case; a lone lowercase first letter belongs to the following acronym (`aMFName` → `amf_name`); the `id-` prefix of an IE id is dropped; Rust keywords get a trailing `_` |
| enumeration item `not-restricted` | `NotRestricted` | PascalCase |
| constant `id-NGSetup`, `maxnoofTAIs` | `ID_NGSETUP`, `MAXNOOF_TAIS` | upper-case, `_` at `-` and lower→UPPER only |
| inline ENUMERATED in field `a2X-Range` of `Parent` | `ParentA2xRange` | owner name + field name |
| extension set `Foo-ExtIEs`, single-IE set | `FooExtIes` | the set's own name |

`QoS`, `QoE`, `IoT`, `AIoT`, `ProSe`, `A2X`, `V2X` stay one word (`qos`, `aiot`, `prose`, `a2x`). Two ASN.1 names that map to
the same Rust name, a name that is a Rust prelude name (`Option`, `Result`, …), or two fields of one struct that collide,
stop generation with a message naming both.

All names live in one flat namespace (`ngap_types::*`); the six ASN.1 modules only decide which source file an item is in.

## Types

| ASN.1 | Rust |
|---|---|
| `INTEGER (lb..ub)` (named) | `struct X(pub uN/iN)`: the smallest primitive holding the root **and** any extension-addition ranges (`ExtendedPacketDelayBudget` is `u32`); `Copy`, `Ord` |
| `INTEGER` field | the primitive itself |
| `ENUMERATED` | `enum`, one variant per item, root then additions; `#[non_exhaustive]` if it has `...`; `Copy` |
| `BIT STRING (SIZE ..)` | `struct X(pub BitString)` / field `BitString` (`ngap_aper::BitString`: bytes + bit length) |
| `OCTET STRING (SIZE ..)` | `struct X(pub Vec<u8>)` / `Vec<u8>` |
| `OCTET STRING (CONTAINING T)` | `Contained<T>`: the raw bytes of the encoded `T`. `raw()`, `decode()`, `Contained::encode_from(&t)`; forwarding never decodes |
| `PrintableString`, `VisibleString`, `UTF8String` | `String` (alphabet checked; UTF-8 checked) |
| `NULL` | unit struct / `()`; a CHOICE alternative of `NULL` is a unit variant |
| `OBJECT IDENTIFIER` | `ngap_aper::ObjectIdentifier` |
| `SEQUENCE { .. }` | `struct` with `pub` fields; `OPTIONAL` → `Option<T>`; `new(<mandatory fields>)` sets the optional ones to `None` |
| `SEQUENCE (SIZE ..) OF T` | `struct X(pub Vec<T>)` (named) / `Vec<T>` (field) |
| `CHOICE { .. }` | `enum`; `#[non_exhaustive]` if it has `...`; decoding an alternative the spec does not define (extension) is an error |
| `X ::= Y` | `struct X(pub Y)` |

Generated types derive `Debug, Clone, PartialEq, Eq` (+ `Copy`, `Hash` on integer/enum newtypes). No serde, no proc-macros.

## Messages and information elements

A message (`NGSetupRequest ::= SEQUENCE { protocolIEs ProtocolIE-Container {{NGSetupRequestIEs}}, ... }`) is a struct whose
**fields are the IEs**, in the order of the object set (the order they must be written in):

* `mandatory` → `T`, `optional` / `conditional` → `Option<T>`;
* `unknown_ies: Vec<RawIe>`: IEs whose id the set does not list, kept as `{ id, criticality, content }` so nothing is lost
  and the receiver can apply the criticality rules of clause 10.3.4;
* `new(<mandatory IEs>)`; the same shape serves the N2 transfer containers (`PDUSessionResourceSetupRequestTransfer`, …).

The wire layout (count, then per IE: id 0..65535, criticality, open type) comes from the runtime (`ngap_aper::ie`), which
follows `NGAP-Containers`; the IR derives that layout from the spec's own templates.

**Extension containers** (`iE-Extensions ProtocolExtensionContainer {{X-ExtIEs}} OPTIONAL`, 469 uses): if the set has rows, a
struct named after the set (same shape as a message: fields + `unknown_ies`, `Default`); if it has none (381 sets), the shared
`ngap_aper::ie::UnknownIes { ies: Vec<RawIe> }`. An extension container must hold at least one member, so `Some` of an
empty one cannot be encoded.

**`choice-Extensions`** (a single IE field, `ProtocolIE-SingleContainer`, 77 uses): if the set has rows, an enum with one
variant per row plus `Unknown(RawIe)`; otherwise `RawIe` itself.

**Procedures.** `InitiatingMessage`, `SuccessfulOutcome`, `UnsuccessfulOutcome` are enums with one variant per procedure
message (variant = message type name). The procedure code and criticality on the wire are implied by the variant
(`NgapPdu` is the CHOICE of the three).

## Decoding semantics

| Situation | Result |
|---|---|
| IE order differs from the spec | accepted (the encoder always writes spec order) |
| IE id not in the set | kept in `unknown_ies` (any criticality) |
| IE appears twice | `ErrorKind::DuplicateIe { id }` |
| mandatory IE missing | `ErrorKind::MissingIe { id, criticality }` — an error whatever the criticality, because the struct cannot hold it |
| procedure code unknown | `ErrorKind::UnknownProcedure { code, criticality }` |
| CHOICE / ENUMERATED extension value undefined here | `ErrorKind::InvalidIndex` |
| SEQUENCE extension additions present | skipped (NGAP-j40 defines none) |
| IE value does not decode / has whole spare octets | the inner error / `TrailingData` |
| open type of length 0 | `ErrorKind::InvalidLength` (X.691 11.2: an empty encoding is sent as one zero octet) |
| criticality received for a procedure | not kept (implied by the variant) |

Extensible constraints: a **size** outside the root is encoded/decoded in the extension form (a `String` or `Vec` can hold
it); an **integer** outside the root must lie in a range written after the marker, otherwise `ValueOutOfRange` (the Rust integer
cannot represent undefined values); values in a gap of a union (`1..30|40`) are rejected.

Reacting to these results (building Error Indication, failure messages, Criticality Diagnostics) is the caller's job; the
facade crate maps them in step 6.

## Not supported (the generator stops with a message)

SEQUENCE / CHOICE **extension additions**; an inline SEQUENCE / CHOICE (NGAP has none); IA5 / Numeric / BMP strings; an IE
container (`SEQUENCE OF Table`) anywhere but as the sole component of a message; `DEFAULT` components; named numbers/bits;
constraints on a type reference. A new spec release using one of these must extend the parser, IR, emitter and their tests.

## Accessors for the facade

For `onwai-ngap`, the generator adds (all derived from the IR, nothing hard-coded):

* on every message struct (a SEQUENCE holding only the IE container): `IE_IDS: &[u32]`, the ids of the IEs the spec defines for it in
  wire order, and `wire_ie_ids(content) -> Result<Vec<u32>>`, the ids of the IEs of an encoded message in the order received;
* on every procedure wrapper enum (`InitiatingMessage`, `SuccessfulOutcome`, `UnsuccessfulOutcome`): `PROCEDURE_CODES`,
  `procedure_code()`, `criticality()`, `message_name()`, `unknown_ies()`, `ie_ids()`, `wire_ie_ids(code, content)`
  (`PrivateMessage`, whose container holds private IEs, reports none);
* on `NgapPdu`: `procedure_code()`, `criticality()`, `message_name()`, `unknown_ies()`, `ie_ids()` forwarding to the wrapper. They exist
  because `NgapPdu` is `#[non_exhaustive]` (its CHOICE is extensible), so other crates cannot match it exhaustively.
