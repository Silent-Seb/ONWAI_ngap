# Architecture

```text
 38413-j40.docx ──xtask extract-asn──▶ specs/asn1/*.asn (6 modules, git-ignored)
                                            │ ngap_codegen::asn1   lexer → parser → AST
                                            ▼
                                       ngap_codegen::ir           resolver: constants, constraints, enumerations,
                                            │                      container instantiation, object-set rows, procedures
                       ┌────────────────────┼────────────────────────┐
                       ▼                    ▼                        ▼
            ngap_codegen::emit        ngap-testgen             xtask stats
            (Rust source)             (random valid APER,
                       │               straight from the IR)
                       ▼                    ▼
        crates/ngap-types/src        testdata/{messages,types}.txt
        (GENERATED, committed)       (committed)
                       │                    │
   uses ngap-aper ◀────┘                    ├──▶ Rust tests: decode → encode must reproduce the octets
   (APER runtime)                           └──▶ tools/check_vectors.py: the same octets vs. Python asn1tools
                       ▼
               crates/onwai-ngap  (decode_pdu / encode_pdu, clause-10 diagnostics)
```

## Crates

| Crate | Kind | Role |
|---|---|---|
| `ngap-aper` | hand-written | ALIGNED PER primitives (`BitReader` / `BitWriter`, integers, strings, extension additions, open types, 16K fragmentation), the IE-container machinery (`ie`), `Contained<T>`. No knowledge of NGAP types. |
| `ngap-codegen` | hand-written | `spec` (docx → ASN.1), `asn1` (parser), `ir` (resolver), `emit` (Rust). Never depends on `ngap-aper`: the generator only writes text. |
| `ngap-types` | **generated** | 1,446 types with `AperEncode` / `AperDecode`; per-message `IE_IDS`, per-procedure accessors. Hand-written parts: `tests/`, `examples/`. |
| `ngap-testgen` | hand-written, dev tool | Samples valid values from the IR and writes their APER with `ngap-aper`: min / max / random PDUs for every message, every named type standalone. Independent of the emitter. |
| `onwai-ngap` | hand-written | The API an AMF uses: `decode_pdu`, `encode_pdu`, `DecodeError` with the clause-10 reaction, cause, Criticality Diagnostics and Error Indication. |
| `xtask` | hand-written | `extract-asn`, `stats`, `gen`, `vectors`, `check`. |

## Why it is built this way

* **Generated, committed, never edited.** The ASN.1 of the spec is the single source. A newer 3GPP release means re-running the
  pipeline; `cargo xtask check` (and `tests/generated_is_current.rs`) fail when the committed code or vectors differ from what
  the generator produces.
* **The generator is not trusted, so it is checked three ways.**
  1. `ngap-aper` primitives against vectors from an independent encoder (`tools/gen_aper_vectors.py`);
  2. real PDUs built with that encoder (`tools/gen_ngap_vectors.py`) against the generated types, byte for byte;
  3. `ngap-testgen` samples every message from the *IR* (a different code path from the emitter) and the generated types must
     round-trip each one; the same octets are also decoded and re-encoded by the independent oracle.
* **IE-container machinery lives in the runtime**, so each message's generated code is small (the whole 70k-line crate
  type-checks in about a minute at under 700 MB).
* **The facade reads the envelope first** (message type, procedure code, criticality) and decodes the body second, so every
  failure can say which procedure it belongs to, which is what clause 10 needs.

## Scope

Codec only: no SCTP, no per-UE or per-gNB state, no procedure state machines, no NAS. Clause 10 is handled as far as a single
message allows (see the table in the README); logical errors (10.4) and AP-ID handling (10.6) need state and belong to a layer
above.
