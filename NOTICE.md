# NOTICE

ONWAI_ngap
Copyright 2026 the ONWAI_ngap contributors. The code in this repository is licensed under the
Apache License, Version 2.0 (see [`LICENSE`](LICENSE)).

## Third-party material: 3GPP TS 38.413

The generated crate (`ngap-types`) is derived from the ASN.1 definitions published in:

- 3GPP TS 38.413, "NG-RAN; NG Application Protocol (NGAP)", Release 19, version 19.4.0 (`38413-j40`)
- Source: <https://www.3gpp.org/ftp/Specs/archive/38_series/38.413/>
- Location: not vendored; the generator reads a local, unmodified copy (default `specs/38413-j40.docx`, git-ignored; see
  `codegen/spec-source.toml`, which also records the SHA-256 of the pinned file)

> © 2026, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.

The specification is not covered by this repository's Apache-2.0 licence and remains subject to the terms stated by
3GPP. Rust code generated from it (`@generated` files) carries this notice and the 3GPP attribution. Where this
repository and the specification disagree, the specification wins.
