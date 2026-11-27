# Coverage-guided fuzzing of `decode_pdu`

Needs a nightly toolchain and `cargo-fuzz` (neither is part of the pinned stable toolchain):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

Seed the corpus from the generated vectors (one file per PDU), then run:

```sh
mkdir -p fuzz/corpus/decode_pdu
grep -v '^#' testdata/messages.txt | awk -F' [|] ' '{print $2 > sprintf("fuzz/corpus/decode_pdu/%04d.hex", NR)}'
for f in fuzz/corpus/decode_pdu/*.hex; do xxd -r -p "$f" "${f%.hex}.bin" && rm "$f"; done
cargo +nightly fuzz run decode_pdu -- -max_total_time=300
```

The target checks the same properties as `crates/onwai-ngap/tests/mutation.rs` (no panic, accepted input is an
encode/decode fixed point, diagnostics are total, the Error Indication it builds encodes). A crash is saved in
`fuzz/artifacts/`; reproduce with `cargo +nightly fuzz run decode_pdu fuzz/artifacts/decode_pdu/<file>`, fix the decoder and
add the input as a unit test. Do not weaken the property.
