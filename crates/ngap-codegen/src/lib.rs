//! Generator for the NGAP codec (3GPP TS 38.413).
//!
//! Pipeline: spec `.docx` -> [`spec`] (six ASN.1 modules) -> [`asn1`] (lexer, parser, AST) -> [`ir`] (resolver) -> Rust
//! emitter. The first three stages exist so far.

pub mod asn1;
pub mod emit;
pub mod ir;
pub mod spec;
