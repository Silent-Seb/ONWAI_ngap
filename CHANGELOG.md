# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project is pre-alpha and not published to crates.io (`publish = false`), so there are no releases yet and the version stays at 0.0.1.

## [Unreleased]

### Added
- **Step 0, bootstrap:** Cargo workspace (edition 2024, `unsafe` forbidden, clippy `all`), pinned toolchain 1.100.0, `cargo xtask` alias.
- **Step 1, spec ingestion:** `cargo xtask extract-asn` pulls the six ASN.1 modules of clause 9.4 out of TS 38.413 v19.4.0
  (`38413-j40.docx`, SHA-256 pinned in `codegen/spec-source.toml`; the spec itself is not vendored).
- **Step 2, `ngap-aper`:** the ALIGNED PER (X.691) runtime — integers, length determinants with fragmentation, strings, OID,
  extension additions, open types, `Contained<T>`, IE containers — checked against an independent encoder (`asn1tools`).
- **Steps 3 and 4, `ngap-codegen`:** ASN.1 front end (lexer, parser, census gates) and the resolver/IR (container instantiation per
  object set, effective PER constraints, elementary-procedure table).
- **Step 5, `ngap-types`:** 1,446 generated types with APER encode/decode, committed; `cargo xtask gen | check` keeps them current.
- **Step 6, `onwai-ngap`:** facade with `decode_pdu` / `encode_pdu`, `PduInfo`, and the clause 10 diagnostics
  (`DecodeError::reaction()`, `cause()`, `error_indication()`, Criticality Diagnostics); four examples.
- **Step 7, verification:** `ngap-testgen` (715 sampled PDUs and 3,876 type vectors, all agreeing with `asn1tools`), a seeded mutation
  test (about 1.4 million mutants), the CI workflow, `docs/architecture.md`, `docs/regenerating.md`.
- `fuzz/`: a cargo-fuzz target for `decode_pdu` (nightly; own workspace).
- `ngap-types`: generated `round_trip_by_name` (test support) and `tests/all_types.rs` checking all 3,876 type vectors in Rust.
- A real capture, `crates/onwai-ngap/tests/captures/5g_attach.pcap` (gNB/AMF attach and PDU session set-up): its 14 NGAP PDUs decode
  with no diagnostics and re-encode byte-identically (`tests/capture.rs`); `tools/extract_pcap_ngap.py` extracts PDUs from a pcap.
- Examples `paging` and `decode_capture`; package metadata (repository, keywords, categories); this changelog and `CONTRIBUTING.md`;
  `deny.toml` and a `deny` CI job (`cargo deny check`: licences, advisories, sources, bans).

### Changed
- Unknown IEs are examined at any depth (message, list items, extension containers), not only at the top level of a message
  (clause 10.3.4.2). `ngap_aper::ie::note_unknown` / `record_unknown_ies` carry them from the generated decoders to the facade.
- The Criticality Diagnostics built from a decode problem lists each distinct problem once, at most 256 (`maxnoofErrors`).

### Fixed
- An open type of length 0 was accepted although X.691 11.2 makes its minimum one octet, so the value did not survive a re-encode
  (found by the mutation test); `read_open_type` now rejects it.
