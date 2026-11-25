# Regenerating: new spec release, changed generator, new vectors

Everything under `crates/ngap-types/src` and `testdata/` is produced, not written. Never edit those files.

## Prerequisites

* The 3GPP document at `specs/38413-j40.docx` (git-ignored), or point `NGAP_SPEC_DOCX` at it. The expected SHA-256 is pinned in
  `codegen/spec-source.toml`; `extract-asn` refuses a different file unless you pass `--no-verify`.
* Rust 1.100 (`rust-toolchain.toml`). The development host is small (1.85 GB): add `-j2`.
* Python 3 with `asn1tools` only for the oracle checks (below); nothing else needs Python.

## After changing `ngap-codegen`, `ngap-aper` or the sampler

```bash
cargo xtask gen          # rewrite crates/ngap-types/src (only files carrying the @generated marker)
cargo xtask vectors      # rewrite testdata/messages.txt and testdata/types.txt
cargo xtask check        # both must say "up to date"
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

`cargo test` also fails if the committed files are stale (`ngap-codegen/tests/generated_is_current.rs`,
`ngap-testgen/tests/vectors_current.rs`), unless `specs/asn1` is absent, in which case those tests skip (they fail if `CI` is set).

## Moving to a newer TS 38.413

1. Put the new docx in `specs/`, update `codegen/spec-source.toml` (file, version, SHA-256) and `NOTICE.md`.
2. `cargo xtask extract-asn` then `cargo xtask stats`: compare the census with the tables in the README. A construct the parser
   does not know stops here with a line number; extend the lexer/parser/AST *and* the census cross-checks in
   `crates/ngap-codegen/tests/parse_ngap.rs` rather than loosening them.
3. `cargo xtask gen`. The emitter stops on anything it does not support (see "Not supported" in `docs/mapping-rules.md`).
4. `cargo xtask vectors`, then `cargo test --workspace`. New messages are covered automatically (the vectors enumerate the IR's
   procedures); the pinned counts in `tests/ir_ngap.rs` will tell you what changed and must be updated deliberately.
5. Run the oracle checks.

## Oracle checks (independent APER implementation)

`asn1tools` cannot compile the raw NGAP modules, so `tools/oracle_asn.py` rewrites them first (see its header for the three
rewrites; none changes the wire format).

```bash
pip install asn1tools==0.169.0                     # or unzip the wheels and set ASN1TOOLS_PATH=<dir>
python3 -I tools/oracle_asn.py specs/asn1 /tmp/oracle_asn
python3 -I tools/check_vectors.py /tmp/oracle_asn testdata         # sampled PDUs and types vs the oracle
python3 -I tools/gen_aper_vectors.py ...                           # regenerate the ngap-aper primitive vectors
python3 -I tools/gen_ngap_vectors.py specs/asn1 /tmp/oracle_asn > crates/ngap-types/tests/vectors.txt
```

`check_vectors.py` decodes every committed vector with the oracle, encodes the value again and requires the same octets; it exits
non-zero on any disagreement. When the oracle and a test disagree, read X.691 before changing either side: the oracle is wrong for
`INTEGER (lb..MAX)` and lacks size extension for BIT STRING / character strings, and encodes a union of values
(`1..30|40|181`) differently from the span `1..181` that X.691 prescribes, which is why the rewrite replaces unions by their span.

## Robustness runs

```bash
cargo test -p onwai-ngap --test mutation                                   # 12 mutations per vector, about a second
NGAP_SEED=7 NGAP_MUTATIONS=2000 cargo test -p onwai-ngap --release --test mutation -- --nocapture
```

Each mutated PDU must decode or be rejected without panicking; those that decode must be a fixed point
(`decode(encode(x)) == x`), and the diagnostics built from a rejection must themselves encode.
