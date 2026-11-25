use std::collections::HashMap;
use std::fmt;

use ngap_aper::{BitString, BitWriter, CharSet, IntSpec, ObjectIdentifier, Size};
use ngap_codegen::asn1::CharStringKind;
use ngap_codegen::ir::{
    Criticality, IntRange, Ir, IrChoice, IrEnum, IrSequence, IrSize, IrType, ObjectSetIr, Presence,
    Procedure, SetKind, TableSeq,
};

use crate::rng::Rng;

/// How the choices are made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The smallest valid value: no optional component, shortest lists, lowest values.
    Min,
    /// Everything present, lists of a few elements, highest values.
    Max,
    /// Pseudo-random choices (also extension values of INTEGERs and ENUMERATEDs).
    Random,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleError(pub String);

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SampleError {}

type R<T> = Result<T, SampleError>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(SampleError(msg.into()))
}

fn aper<T>(r: ngap_aper::Result<T>) -> R<T> {
    r.map_err(|e| SampleError(format!("APER writer: {e}")))
}

/// How many elements / characters at most a list or string grows to in `Max` and `Random` mode.
const LIST_CAP: u64 = 2;
const STRING_CAP: u64 = 24;
const DEPTH_LIMIT: u32 = 80;

#[derive(Debug)]
pub struct Sampler<'a> {
    ir: &'a Ir,
    rng: Rng,
    mode: Mode,
    sampleable: HashMap<String, bool>,
}

impl<'a> Sampler<'a> {
    pub fn new(ir: &'a Ir, mode: Mode, seed: u64) -> Self {
        Sampler {
            ir,
            rng: Rng::new(seed),
            mode,
            sampleable: HashMap::new(),
        }
    }

    /// The complete encoding of a sample of the named type, as a standalone value (padded to whole octets).
    pub fn named(&mut self, name: &str) -> R<Vec<u8>> {
        let mut w = BitWriter::new();
        self.encode(&IrType::Named(name.to_owned()), &mut w, 0)?;
        Ok(w.into_complete_bytes())
    }

    /// A complete `NGAP-PDU`: `role` 0/1/2 = initiating message / successful outcome / unsuccessful outcome of `p`.
    /// `None` if the procedure has no message in that role.
    pub fn pdu(&mut self, p: &Procedure, role: usize) -> R<Option<(String, Vec<u8>)>> {
        let msg = match role {
            0 => Some(&p.initiating),
            1 => p.successful.as_ref(),
            2 => p.unsuccessful.as_ref(),
            _ => return err("role must be 0, 1 or 2"),
        };
        let Some(msg) = msg else { return Ok(None) };
        let content = self.named(msg)?;
        let mut w = BitWriter::new();
        aper(w.write_index(role as u64, 3, true))?;
        aper(w.write_constrained_int(i128::from(p.code), 0, 255))?;
        aper(w.write_index(crit_index(p.criticality), 3, false))?;
        aper(w.write_open_type(&content))?;
        Ok(Some((msg.clone(), w.into_complete_bytes())))
    }

    /// Whether a value of `ty` can be produced: an extension container or IE set without rows cannot hold an element.
    pub fn can_sample(&mut self, ty: &IrType) -> bool {
        self.can(ty, 0)
    }

    fn can(&mut self, ty: &IrType, depth: u32) -> bool {
        if depth > DEPTH_LIMIT {
            return false;
        }
        match ty {
            IrType::Named(n) => {
                if let Some(&v) = self.sampleable.get(n) {
                    return v;
                }
                // a reference cycle would be a spec feature we do not handle: treat as not sampleable while computing
                self.sampleable.insert(n.clone(), false);
                let ir = self.ir;
                let v = ir.types.get(n).is_some_and(|t| self.can(&t.ty, depth + 1));
                self.sampleable.insert(n.clone(), v);
                v
            }
            IrType::Table(t) => self.table_rows(t, depth).is_some_and(|r| !r.is_empty()),
            IrType::SequenceOf { size, element } => {
                size.lb == 0
                    || match element.as_ref() {
                        IrType::Table(t) => {
                            self.table_rows(t, depth).is_some_and(|r| !r.is_empty())
                        }
                        e => self.can(e, depth + 1),
                    }
            }
            IrType::Sequence(s) => s
                .root
                .iter()
                .all(|c| c.optional || self.can(&c.ty, depth + 1)),
            IrType::Choice(c) => c.root.iter().any(|a| self.can(&a.ty, depth + 1)),
            _ => true,
        }
    }

    /// The rows of the table's set that can be sampled, as indices into `ObjectSetIr::rows`; `None` for a set kind
    /// that has none (the procedure wrappers).
    fn table_rows(&mut self, t: &TableSeq, depth: u32) -> Option<Vec<usize>> {
        let ir = self.ir;
        let set = ir.sets.get(&t.set)?;
        if !matches!(set.kind, SetKind::ProtocolIes | SetKind::ProtocolExtensions) {
            return None;
        }
        Some(
            (0..set.rows.len())
                .filter(|&i| self.can(&set.rows[i].ty, depth + 1))
                .collect(),
        )
    }

    // ---- the walk

    fn encode(&mut self, ty: &IrType, w: &mut BitWriter, depth: u32) -> R<()> {
        if depth > DEPTH_LIMIT {
            return err("type nesting too deep (a recursive type?)");
        }
        match ty {
            IrType::Null => Ok(()),
            IrType::Integer(r) => self.integer(r, w),
            IrType::Enumerated(e) => self.enumerated(e, w),
            IrType::BitString(size) => {
                let n = self.size(*size, STRING_CAP);
                let bits: Vec<bool> = (0..n).map(|_| self.rng.chance(2)).collect();
                aper(w.write_bit_string(&BitString::from_bits(&bits), to_size(*size)))
            }
            IrType::OctetString { size, contained } => {
                let data = match contained {
                    Some(inner) => {
                        let mut iw = BitWriter::new();
                        self.encode(inner, &mut iw, depth + 1)?;
                        iw.into_complete_bytes()
                    }
                    None => {
                        let n = self.size(*size, STRING_CAP);
                        (0..n).map(|_| self.rng.next_u64() as u8).collect()
                    }
                };
                let size = if contained.is_some() {
                    Size::UNBOUNDED
                } else {
                    to_size(*size)
                };
                aper(w.write_octet_string(&data, size))
            }
            IrType::ObjectIdentifier => {
                let first = self.rng.below(3) as u64;
                let second = if first == 2 {
                    self.rng.below(100)
                } else {
                    self.rng.below(40)
                } as u64;
                let mut arcs = vec![first, second];
                for _ in 0..self.pick(0, 4) {
                    arcs.push(self.rng.below(100_000) as u64);
                }
                aper(w.write_object_identifier(&aper(ObjectIdentifier::new(arcs))?))
            }
            IrType::CharString { kind, size } => self.chars(*kind, *size, w),
            IrType::Sequence(s) => self.sequence(s, w, depth),
            IrType::SequenceOf { size, element } => self.sequence_of(*size, element, w, depth),
            IrType::Choice(c) => self.choice(c, w, depth),
            IrType::Named(n) => {
                let ir = self.ir;
                match ir.types.get(n) {
                    Some(t) => self.encode(&t.ty, w, depth + 1),
                    None => err(format!("unknown type `{n}`")),
                }
            }
            IrType::Table(t) => {
                // a single IE field (`ProtocolIE-SingleContainer`): one row of the set
                let rows = self.table_rows(t, depth).unwrap_or_default();
                if rows.is_empty() {
                    return err(format!("set `{}` has no row to sample", t.set));
                }
                let pick = rows[self.pick_index(rows.len())];
                let ir = self.ir;
                match ir.sets.get(&t.set) {
                    Some(set) => self.ie_field(set, pick, w, depth),
                    None => err(format!("unknown set `{}`", t.set)),
                }
            }
        }
    }

    /// `index` of a choice among `n` alternatives, by mode.
    fn pick_index(&mut self, n: usize) -> usize {
        match self.mode {
            Mode::Min => 0,
            Mode::Max => n - 1,
            Mode::Random => self.rng.below(n as u128) as usize,
        }
    }

    fn pick(&mut self, lo: u64, hi: u64) -> u64 {
        match self.mode {
            Mode::Min => lo,
            Mode::Max => hi,
            Mode::Random => self.rng.between(i128::from(lo), i128::from(hi)) as u64,
        }
    }

    /// A length within `size`, by mode; `cap` bounds how far above the lower bound it goes.
    fn size(&mut self, size: IrSize, cap: u64) -> u64 {
        let hi = size.ub.map_or(size.lb + cap, |ub| ub.min(size.lb + cap));
        self.pick(size.lb, hi)
    }

    fn integer(&mut self, r: &IntRange, w: &mut BitWriter) -> R<()> {
        let in_additions = self.mode == Mode::Random
            && r.extensible
            && !r.additions.is_empty()
            && self.rng.chance(5);
        let v = if in_additions {
            let (lo, hi) = r.additions[self.rng.below(r.additions.len() as u128) as usize];
            self.rng.between(lo, hi)
        } else {
            self.root_int(r)
        };
        let leak = |v: &[(i128, i128)]| -> &'static [(i128, i128)] {
            Box::leak(v.to_vec().into_boxed_slice())
        };
        let spec = IntSpec {
            lb: r.lb,
            ub: r.ub,
            extensible: r.extensible,
            ranges: if r.ranges.len() > 1 {
                leak(&r.ranges)
            } else {
                &[]
            },
            additions: leak(&r.additions),
        };
        aper(w.write_int(v, &spec))
    }

    fn root_int(&mut self, r: &IntRange) -> i128 {
        let segments: Vec<(i128, i128)> = match (r.lb, r.ub) {
            (Some(lb), Some(ub)) if r.ranges.is_empty() => vec![(lb, ub)],
            (Some(_), Some(_)) => r.ranges.clone(),
            (Some(lb), None) => vec![(lb, lb.saturating_add(1 << 40))],
            (None, Some(ub)) => vec![(ub.saturating_sub(1 << 40), ub)],
            (None, None) => vec![(-(1 << 40), 1 << 40)],
        };
        match self.mode {
            Mode::Min => {
                let (lo, hi) = segments[0];
                0.clamp(lo, hi).min(if r.lb.is_some() { lo } else { hi })
            }
            Mode::Max => segments[segments.len() - 1].1,
            Mode::Random => {
                let (lo, hi) = segments[self.rng.below(segments.len() as u128) as usize];
                if self.rng.chance(4) {
                    // the edges are where encoders go wrong
                    if self.rng.chance(2) { lo } else { hi }
                } else {
                    self.rng.between(lo, hi)
                }
            }
        }
    }

    fn enumerated(&mut self, e: &IrEnum, w: &mut BitWriter) -> R<()> {
        let root = e.root.len() as u64;
        let index = if self.mode == Mode::Random && !e.additions.is_empty() && self.rng.chance(5) {
            root + e.additions[self.rng.below(e.additions.len() as u128) as usize].index
        } else {
            e.root[self.pick_index(e.root.len())].index
        };
        aper(w.write_index(index, root, e.extensible))
    }

    fn chars(&mut self, kind: CharStringKind, size: IrSize, w: &mut BitWriter) -> R<()> {
        const PRINTABLE: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
        let n = self.size(size, STRING_CAP) as usize;
        match kind {
            CharStringKind::Printable | CharStringKind::Visible => {
                let (set, alphabet): (CharSet, Vec<u8>) = if kind == CharStringKind::Printable {
                    (CharSet::Printable, PRINTABLE.to_vec())
                } else {
                    (CharSet::Visible, (0x20..=0x7e).collect())
                };
                let s: String = (0..n)
                    .map(|_| alphabet[self.rng.below(alphabet.len() as u128) as usize] as char)
                    .collect();
                aper(w.write_char_string(&s, to_size(size), set))
            }
            CharStringKind::Utf8 => {
                let pool = ['a', 'Z', '0', '-', ' ', 'é', 'ß', '日', '本', '€'];
                let s: String = (0..n)
                    .map(|i| {
                        if self.mode == Mode::Random {
                            pool[self.rng.below(pool.len() as u128) as usize]
                        } else {
                            pool[i % 5]
                        }
                    })
                    .collect();
                aper(w.write_utf8_string(&s))
            }
            other => err(format!("character string kind {other:?} is not supported")),
        }
    }

    fn sequence(&mut self, s: &IrSequence, w: &mut BitWriter, depth: u32) -> R<()> {
        if !s.additions.is_empty() {
            return err("SEQUENCE extension additions are not supported");
        }
        if s.extensible {
            w.write_bit(false);
        }
        let mut present = Vec::with_capacity(s.root.len());
        for c in &s.root {
            let p = if !c.optional {
                true
            } else if !self.can(&c.ty, depth + 1) {
                false
            } else {
                match self.mode {
                    Mode::Min => false,
                    Mode::Max => true,
                    Mode::Random => self.rng.chance(2),
                }
            };
            if c.optional {
                w.write_bit(p);
            }
            present.push(p);
        }
        for (c, p) in s.root.iter().zip(present) {
            if p {
                self.encode(&c.ty, w, depth + 1)?;
            }
        }
        Ok(())
    }

    fn sequence_of(
        &mut self,
        size: IrSize,
        element: &IrType,
        w: &mut BitWriter,
        depth: u32,
    ) -> R<()> {
        // the IE container: the rows of the set, in the order of the specification
        if let IrType::Table(t) = element {
            return self.container(size, t, w, depth);
        }
        let n = self.size(size, LIST_CAP);
        if n > 0 && !self.can(element, depth + 1) {
            return err("list element cannot be sampled");
        }
        let items = vec![(); n as usize];
        let mut failure = None;
        let r = w.write_seq_of(&items, to_size(size), |w, ()| {
            self.encode(element, w, depth + 1).map_err(|e| {
                failure = Some(e);
                w.error(ngap_aper::ErrorKind::ValueOutOfRange)
            })
        });
        match failure {
            Some(e) => Err(e),
            None => aper(r),
        }
    }

    fn container(&mut self, size: IrSize, t: &TableSeq, w: &mut BitWriter, depth: u32) -> R<()> {
        let ir = self.ir;
        let Some(set) = ir.sets.get(&t.set) else {
            return err(format!("unknown set `{}`", t.set));
        };
        let usable = self.table_rows(t, depth).unwrap_or_default();
        let mut chosen = Vec::new();
        for &i in &usable {
            let take = match set.rows[i].presence {
                Presence::Mandatory => true,
                _ => match self.mode {
                    Mode::Min => false,
                    Mode::Max => true,
                    Mode::Random => self.rng.chance(2),
                },
            };
            if take {
                chosen.push(i);
            }
        }
        for (i, row) in set.rows.iter().enumerate() {
            if row.presence == Presence::Mandatory && !usable.contains(&i) {
                return err(format!(
                    "mandatory IE {} of `{}` cannot be sampled",
                    row.id, set.name
                ));
            }
        }
        while (chosen.len() as u64) < size.lb {
            match usable.iter().find(|i| !chosen.contains(i)) {
                Some(&i) => chosen.push(i),
                None => {
                    return err(format!(
                        "set `{}` has too few rows for SIZE({}..)",
                        set.name, size.lb
                    ));
                }
            }
        }
        chosen.sort_unstable(); // the order of the set is the order on the wire
        if size.ub.is_some_and(|ub| chosen.len() as u64 > ub) {
            return err("more rows than the container allows");
        }
        let mut failure = None;
        let r = w.write_seq_of(&chosen, to_size(size), |w, &i| {
            self.ie_field(set, i, w, depth).map_err(|e| {
                failure = Some(e);
                w.error(ngap_aper::ErrorKind::ValueOutOfRange)
            })
        });
        match failure {
            Some(e) => Err(e),
            None => aper(r),
        }
    }

    /// `SEQUENCE { id, criticality, value OPEN TYPE }` for row `i` of `set`.
    fn ie_field(&mut self, set: &ObjectSetIr, i: usize, w: &mut BitWriter, depth: u32) -> R<()> {
        let row = &set.rows[i];
        aper(w.write_constrained_int(i128::from(row.id), 0, 65535))?;
        aper(w.write_index(crit_index(row.criticality), 3, false))?;
        let mut vw = BitWriter::new();
        self.encode(&row.ty, &mut vw, depth + 1)?;
        aper(w.write_open_type(&vw.into_complete_bytes()))
    }

    fn choice(&mut self, c: &IrChoice, w: &mut BitWriter, depth: u32) -> R<()> {
        if !c.additions.is_empty() {
            return err("CHOICE extension additions are not supported");
        }
        let usable: Vec<usize> = (0..c.root.len())
            .filter(|&i| self.can(&c.root[i].ty, depth + 1))
            .collect();
        if usable.is_empty() {
            return err("no alternative of the CHOICE can be sampled");
        }
        let i = usable[self.pick_index(usable.len())];
        aper(w.write_index(i as u64, c.root.len() as u64, c.extensible))?;
        self.encode(&c.root[i].ty, w, depth + 1)
    }
}

fn crit_index(c: Criticality) -> u64 {
    match c {
        Criticality::Reject => 0,
        Criticality::Ignore => 1,
        Criticality::Notify => 2,
    }
}

fn to_size(s: IrSize) -> Size {
    let base = match s.ub {
        Some(ub) if ub == s.lb => Size::fixed(s.lb),
        Some(ub) => Size::range(s.lb, ub),
        None => Size {
            lb: s.lb,
            ub: None,
            ext: false,
        },
    };
    if s.extensible {
        base.extensible()
    } else {
        base
    }
}
