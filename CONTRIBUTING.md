# Contributing

Thanks for looking. This is a small, focused codec; please read [`README.md`](README.md) (plan, layout, verification) and
[`CLAUDE.md`](CLAUDE.md) (the rules of the repo, written for any contributor, human or not) first. The short version:

## Scope
**Codec only**: typed NGAP PDUs, APER encode/decode and the decode-time diagnostics of clause 10. No SCTP, no per-UE or
per-gNB state, no procedure state machines, no NAS. If you want to grow the scope, open an issue first.

## The one big rule: generated code is never edited
`crates/ngap-types` is generated from the ASN.1 of TS 38.413 and committed. To change it, change the generator
(`crates/ngap-codegen`) or the runtime (`crates/ngap-aper`), run `cargo xtask gen`, and commit both. `cargo xtask check` must say
*generated code is up to date*. The same goes for `testdata/` (`cargo xtask vectors`). See [`docs/regenerating.md`](docs/regenerating.md).

## Before you open a pull request
```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask check
cargo deny check        # optional locally: `cargo install cargo-deny --locked`; CI runs it
```
On a host with about 2 GB of RAM add `-j2`. CI runs the first three on every push. The extracted ASN.1 modules are committed in `specs/asn1/` (never edit them by hand); the 3GPP
Word document itself is not part of the repository (see `codegen/spec-source.toml` for the pinned file and its SHA-256) and is needed only
to re-extract them or for the optional CI jobs.

## Tests
- A change to the APER runtime needs a unit test, and a vector from an independent encoder where one exists
  (`tools/gen_aper_vectors.py`, Python + `asn1tools`; the vectors are committed, so the tests do not need Python). When a test and the
  oracle disagree, check ITU-T X.691 before changing either.
- A change to the clause 10 behaviour changes the table in the README, `crates/onwai-ngap/tests/diagnostics.rs` and the code together.
- Robustness: `onwai-ngap/tests/mutation.rs` (`NGAP_SEED`, `NGAP_MUTATIONS`) and `fuzz/` (nightly, see `fuzz/README.md`). A failure
  there is a decoder bug: fix the decoder, do not weaken the property.

## Adding a real capture
Captures are the most valuable tests: they come from implementations other than this one. Extract the PDUs with
`tools/extract_pcap_ngap.py`, add them under `crates/onwai-ngap/tests/captures/`, and decode them in a test as `tests/capture.rs` does.
**Check what you commit**: a pcap can hold subscriber identities (SUPI/SUCI/IMSI/IMEI), public IP addresses and the names of nodes
or products. Use only lab data, and swap anything that should not be public for same-size dummies (the script has `--replace` and
`--replace-text`; a changed byte inside a pcap needs the SCTP CRC32c of that packet recomputed).

## Style
Rust 2024, `unsafe` is forbidden, generated code uses no proc-macro derives beyond `Debug, Clone, PartialEq, Eq`. Commit messages say
what changed and why in a short summary line plus a paragraph when it is not obvious.

## Licence
Apache-2.0 (see [`LICENSE`](LICENSE)); contributions are accepted under the same licence. The 3GPP specification is not covered by it
(see [`NOTICE.md`](NOTICE.md)).
