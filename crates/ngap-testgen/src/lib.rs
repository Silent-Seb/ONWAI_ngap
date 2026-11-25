//! Valid NGAP encodings sampled from the **resolved ASN.1** (the IR of `ngap-codegen`), independently of the generated
//! Rust types.
//!
//! [`Sampler`] walks an [`IrType`], decides every choice (which optional component is present, how long a list is, which
//! alternative) and writes the APER encoding directly with the `ngap-aper` primitives. It therefore knows the structure
//! of the spec but shares no code with the emitter, which makes its output a test of the emitter: the generated types
//! must decode every sample and re-encode it to the same octets. The Python oracle (`tools/check_vectors.py`) checks the
//! same octets against an independent APER implementation.
//!
//! [`vectors`] turns this into the committed files `testdata/messages.txt` (a complete `NGAP-PDU` per message, in several
//! modes) and `testdata/types.txt` (every named type standalone).

mod rng;
mod sampler;
pub mod vectors;

pub use rng::Rng;
pub use sampler::{Mode, SampleError, Sampler};
