//! OBJECT IDENTIFIER (X.691 clause 24): the BER-style content octets as an octet string with unconstrained length.

use crate::error::{AperError, ErrorKind, Result};
use crate::size::Size;
use crate::{BitReader, BitWriter};

/// An OBJECT IDENTIFIER value as its arcs, e.g. `[1, 2, 840, 113549]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(Vec<u64>);

impl ObjectIdentifier {
    /// At least two arcs; the first is 0, 1 or 2, and the second is below 40 unless the first is 2.
    pub fn new(arcs: Vec<u64>) -> Result<Self> {
        let ok = arcs.len() >= 2 && arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] < 40);
        if ok {
            Ok(Self(arcs))
        } else {
            Err(AperError::new(ErrorKind::InvalidObjectIdentifier, 0))
        }
    }

    pub fn arcs(&self) -> &[u64] {
        &self.0
    }

    fn to_content(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let first = u128::from(self.0[0]) * 40 + u128::from(self.0[1]);
        push_base128(&mut out, first);
        for &a in &self.0[2..] {
            push_base128(&mut out, u128::from(a));
        }
        out
    }

    fn from_content(c: &[u8]) -> Option<Self> {
        let mut subs: Vec<u128> = Vec::new();
        let mut cur: u128 = 0;
        let mut pending = false;
        for &b in c {
            if !pending && b == 0x80 {
                return None; // non-minimal subidentifier
            }
            cur = cur.checked_mul(128)?.checked_add(u128::from(b & 0x7F))?;
            if cur > u128::from(u64::MAX) + 80 {
                return None;
            }
            if b & 0x80 == 0 {
                subs.push(cur);
                cur = 0;
                pending = false;
            } else {
                pending = true;
            }
        }
        if pending || subs.is_empty() {
            return None;
        }
        let (a0, a1) = match subs[0] {
            s if s < 40 => (0, s),
            s if s < 80 => (1, s - 40),
            s => (2, s - 80),
        };
        let mut arcs = vec![a0, u64::try_from(a1).ok()?];
        for &s in &subs[1..] {
            arcs.push(u64::try_from(s).ok()?);
        }
        Some(Self(arcs))
    }
}

fn push_base128(out: &mut Vec<u8>, v: u128) {
    let mut groups = [0u8; 19];
    let mut n = 0;
    let mut x = v;
    loop {
        groups[n] = (x & 0x7F) as u8;
        n += 1;
        x >>= 7;
        if x == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(groups[i] | if i > 0 { 0x80 } else { 0 });
    }
}

impl BitWriter {
    pub fn write_object_identifier(&mut self, oid: &ObjectIdentifier) -> Result<()> {
        self.write_octet_string(&oid.to_content(), Size::UNBOUNDED)
    }
}

impl<'a> BitReader<'a> {
    pub fn read_object_identifier(&mut self) -> Result<ObjectIdentifier> {
        let content = self.read_octet_string(Size::UNBOUNDED)?;
        ObjectIdentifier::from_content(&content)
            .ok_or_else(|| self.error(ErrorKind::InvalidObjectIdentifier))
    }
}
