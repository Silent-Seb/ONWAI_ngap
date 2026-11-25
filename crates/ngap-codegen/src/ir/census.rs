//! Census of the IR (printed by `cargo xtask stats`, pinned by tests).

use core::fmt;

use super::validate::{recursive_groups, walk};
use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IrCensus {
    pub consts: usize,
    pub consts_ie_ids: usize,
    pub consts_procedure_codes: usize,
    pub consts_other: usize,
    pub named_types: usize,
    /// Type nodes below the named types (and below IE rows), counted by kind.
    pub integers: usize,
    pub enumerations: usize,
    pub sequences: usize,
    pub sequence_ofs: usize,
    pub choices: usize,
    pub tables: usize,
    pub contained: usize,
    pub sets: usize,
    pub ie_sets: usize,
    pub extension_sets: usize,
    pub procedure_sets: usize,
    pub private_sets: usize,
    pub ie_rows: usize,
    pub extension_rows: usize,
    pub procedures: usize,
    pub class1: usize,
    pub class2: usize,
    pub recursive_groups: usize,
}

impl IrCensus {
    pub fn of(ir: &Ir) -> IrCensus {
        let mut c = IrCensus {
            consts: ir.consts.len(),
            named_types: ir.types.len(),
            procedures: ir.procedures.len(),
            ..Default::default()
        };
        for k in &ir.consts {
            match k.ty.as_str() {
                "ProtocolIE-ID" => c.consts_ie_ids += 1,
                "ProcedureCode" => c.consts_procedure_codes += 1,
                _ => c.consts_other += 1,
            }
        }
        let node = |n: &IrType, c: &mut IrCensus| match n {
            IrType::Integer(_) => c.integers += 1,
            IrType::Enumerated(_) => c.enumerations += 1,
            IrType::Sequence(_) => c.sequences += 1,
            IrType::SequenceOf { .. } => c.sequence_ofs += 1,
            IrType::Choice(_) => c.choices += 1,
            IrType::Table(_) => c.tables += 1,
            IrType::OctetString {
                contained: Some(_), ..
            } => c.contained += 1,
            _ => {}
        };
        for t in &ir.types {
            walk(&t.ty, &mut |n| node(n, &mut c));
        }
        c.sets = ir.sets.len();
        for s in &ir.sets {
            match s.kind {
                SetKind::ProtocolIes => {
                    c.ie_sets += 1;
                    c.ie_rows += s.rows.len();
                }
                SetKind::ProtocolExtensions => {
                    c.extension_sets += 1;
                    c.extension_rows += s.rows.len();
                }
                SetKind::ElementaryProcedures => c.procedure_sets += 1,
                SetKind::PrivateIes | SetKind::ProtocolIesPair => c.private_sets += 1,
            }
        }
        for p in &ir.procedures {
            match p.class {
                ProcedureClass::Class1 => c.class1 += 1,
                ProcedureClass::Class2 => c.class2 += 1,
            }
        }
        c.recursive_groups = recursive_groups(ir).len();
        c
    }
}

impl fmt::Display for IrCensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rows: [(&str, usize); 23] = [
            ("constants", self.consts),
            ("  IE ids (ProtocolIE-ID)", self.consts_ie_ids),
            ("  procedure codes", self.consts_procedure_codes),
            ("  other (max*)", self.consts_other),
            ("named types", self.named_types),
            ("  INTEGER nodes", self.integers),
            ("  ENUMERATED nodes", self.enumerations),
            ("  SEQUENCE nodes", self.sequences),
            ("  SEQUENCE OF nodes", self.sequence_ofs),
            ("  CHOICE nodes", self.choices),
            (
                "  table SEQUENCEs (IE fields, procedure wrappers)",
                self.tables,
            ),
            ("  OCTET STRING (CONTAINING ..)", self.contained),
            ("object sets", self.sets),
            ("  IE sets", self.ie_sets),
            ("  extension sets", self.extension_sets),
            ("  procedure sets", self.procedure_sets),
            ("  private / pair sets (empty)", self.private_sets),
            ("IE rows", self.ie_rows),
            ("extension rows", self.extension_rows),
            ("elementary procedures", self.procedures),
            ("  class 1 (with response)", self.class1),
            ("  class 2", self.class2),
            ("self-containing type groups", self.recursive_groups),
        ];
        for (name, n) in rows {
            writeln!(f, "{n:>7}  {name}")?;
        }
        Ok(())
    }
}
