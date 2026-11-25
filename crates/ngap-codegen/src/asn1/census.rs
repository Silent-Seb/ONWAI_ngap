//! Census of the constructs in parsed modules.
//!
//! Serves two purposes: `cargo xtask stats` prints it, and the tests cross-check it against an independent count of
//! tokens, so a construct the parser silently dropped cannot go unnoticed.

use core::fmt;
use std::collections::BTreeMap;

use super::ast::*;

/// Counts over a set of modules. "Types" are counted at every nesting level, including the types of value
/// assignments, parameter governors and class fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Census {
    pub modules: usize,
    pub imports_symbols: usize,
    // assignments
    pub type_assignments: usize,
    pub parameterized_type_assignments: usize,
    pub value_assignments: usize,
    pub class_assignments: usize,
    pub object_set_assignments: usize,
    pub object_assignments: usize,
    /// Object set assignments per class name.
    pub object_sets_by_class: BTreeMap<String, usize>,
    // information objects
    pub inline_objects_in_sets: usize,
    pub object_set_references: usize,
    pub object_set_extension_markers: usize,
    // type constructs
    pub null: usize,
    pub integer: usize,
    pub enumerated: usize,
    pub enumerated_items: usize,
    pub bit_string: usize,
    pub octet_string: usize,
    pub object_identifier: usize,
    pub char_strings: usize,
    pub sequence: usize,
    pub sequence_of: usize,
    pub choice: usize,
    pub references: usize,
    pub parameterized_references: usize,
    pub field_references: usize,
    pub components: usize,
    pub optional_components: usize,
    pub default_components: usize,
    pub alternatives: usize,
    // constraints
    pub subtype_constraints: usize,
    pub table_constraints: usize,
    pub size_constraints: usize,
    pub containing: usize,
    /// Every `...` in a SEQUENCE, CHOICE, ENUMERATED, element set (also inside SIZE) or object set.
    pub extension_markers: usize,
}

impl Census {
    pub fn of(modules: &[Module]) -> Census {
        let mut c = Census {
            modules: modules.len(),
            ..Census::default()
        };
        for m in modules {
            c.imports_symbols += m.imports.iter().map(|i| i.symbols.len()).sum::<usize>();
            for a in &m.assignments {
                c.assignment(a);
            }
        }
        c
    }

    fn assignment(&mut self, a: &Assignment) {
        match a {
            Assignment::Type(t) => {
                self.type_assignments += 1;
                if !t.params.is_empty() {
                    self.parameterized_type_assignments += 1;
                }
                for p in &t.params {
                    if let Some(Governor::Type(ty)) = &p.governor {
                        self.ty(ty);
                    }
                }
                self.ty(&t.ty);
            }
            Assignment::Value(v) => {
                self.value_assignments += 1;
                self.ty(&v.ty);
            }
            Assignment::Class(c) => {
                self.class_assignments += 1;
                for f in &c.fields {
                    if let FieldKind::FixedTypeValue(t) = &f.kind {
                        self.ty(t);
                    }
                }
            }
            Assignment::ObjectSet(s) => {
                self.object_set_assignments += 1;
                *self
                    .object_sets_by_class
                    .entry(s.class.clone())
                    .or_default() += 1;
                self.object_set(&s.set);
            }
            Assignment::Object(o) => {
                self.object_assignments += 1;
                self.object(&o.object);
            }
        }
    }

    fn object(&mut self, o: &Object) {
        for f in &o.fields {
            if let FieldValue::Type(t) = &f.value {
                self.ty(t);
            }
        }
    }

    fn object_set(&mut self, s: &ObjectSet) {
        for e in &s.elements {
            match e {
                ObjectSetElement::Reference(_) => self.object_set_references += 1,
                ObjectSetElement::Object(o) => {
                    self.inline_objects_in_sets += 1;
                    self.object(o);
                }
                ObjectSetElement::Extension => {
                    self.object_set_extension_markers += 1;
                    self.extension_markers += 1;
                }
            }
        }
    }

    fn ty(&mut self, t: &Type) {
        // `walk` visits this type and all nested ones; count each node once, then constraints of every node
        t.walk(&mut |n| self.node(n));
    }

    fn node(&mut self, t: &Type) {
        match &t.kind {
            TypeKind::Null => self.null += 1,
            TypeKind::Integer => self.integer += 1,
            TypeKind::Enumerated(e) => {
                self.enumerated += 1;
                self.enumerated_items += e.root.len() + e.additions.iter().flatten().count();
                self.extension_markers += usize::from(e.additions.is_some());
            }
            TypeKind::BitString => self.bit_string += 1,
            TypeKind::OctetString => self.octet_string += 1,
            TypeKind::ObjectIdentifier => self.object_identifier += 1,
            TypeKind::CharString(_) => self.char_strings += 1,
            TypeKind::Sequence(s) => {
                self.sequence += 1;
                self.components += s.root.len() + s.additions.len();
                for c in s.root.iter().chain(&s.additions) {
                    self.optional_components += usize::from(c.optional);
                    self.default_components += usize::from(c.default.is_some());
                }
                self.extension_markers += usize::from(s.additions_marker);
            }
            TypeKind::SequenceOf(_) => self.sequence_of += 1,
            TypeKind::Choice(c) => {
                self.choice += 1;
                self.alternatives += c.root.len() + c.additions.len();
                self.extension_markers += usize::from(c.additions_marker);
            }
            TypeKind::Reference(r) => {
                self.references += 1;
                if !r.args.is_empty() {
                    self.parameterized_references += 1;
                    for a in &r.args {
                        if let ActualParam::ObjectSet(s) = a {
                            self.object_set(s);
                        }
                    }
                }
            }
            TypeKind::FieldRef { .. } => self.field_references += 1,
        }
        for c in &t.constraints {
            match c {
                Constraint::Subtype(set) => {
                    self.subtype_constraints += 1;
                    self.element_set(set);
                }
                Constraint::Table(t) => {
                    self.table_constraints += 1;
                    self.object_set(&t.set);
                }
            }
        }
    }

    fn element_set(&mut self, s: &ElementSet) {
        self.extension_markers += usize::from(s.additions.is_some());
        for e in s.root.iter().chain(s.additions.iter().flatten()) {
            match e {
                Elem::Size(inner) => {
                    self.size_constraints += 1;
                    self.element_set(inner);
                }
                Elem::Containing(_) => self.containing += 1,
                Elem::Value(_) | Elem::Range(..) => {}
            }
        }
    }

    /// Total number of `::=` assignments (excluding the module headers).
    pub fn assignments(&self) -> usize {
        self.type_assignments
            + self.value_assignments
            + self.class_assignments
            + self.object_set_assignments
            + self.object_assignments
    }
}

impl fmt::Display for Census {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rows: [(&str, usize); 36] = [
            ("modules", self.modules),
            ("imported symbols", self.imports_symbols),
            ("assignments", self.assignments()),
            ("  type assignments", self.type_assignments),
            (
                "    of which parameterized",
                self.parameterized_type_assignments,
            ),
            ("  value assignments", self.value_assignments),
            ("  class assignments", self.class_assignments),
            ("  object set assignments", self.object_set_assignments),
            ("  object assignments", self.object_assignments),
            ("inline objects in object sets", self.inline_objects_in_sets),
            ("object set references", self.object_set_references),
            ("NULL", self.null),
            ("INTEGER", self.integer),
            ("ENUMERATED", self.enumerated),
            ("  enumeration items", self.enumerated_items),
            ("BIT STRING", self.bit_string),
            ("OCTET STRING", self.octet_string),
            ("OBJECT IDENTIFIER", self.object_identifier),
            ("character strings", self.char_strings),
            ("SEQUENCE", self.sequence),
            ("  components", self.components),
            ("  OPTIONAL components", self.optional_components),
            ("  DEFAULT components", self.default_components),
            ("SEQUENCE OF", self.sequence_of),
            ("CHOICE", self.choice),
            ("  alternatives", self.alternatives),
            ("type references", self.references),
            ("  parameterized", self.parameterized_references),
            ("class field references", self.field_references),
            ("subtype constraints", self.subtype_constraints),
            ("table constraints", self.table_constraints),
            ("SIZE constraints", self.size_constraints),
            ("CONTAINING constraints", self.containing),
            ("extension markers `...`", self.extension_markers),
            ("  in object sets", self.object_set_extension_markers),
            ("(end)", 0),
        ];
        for (name, n) in rows.iter().take(rows.len() - 1) {
            writeln!(f, "{n:>7}  {name}")?;
        }
        writeln!(f, "object sets by class:")?;
        for (class, n) in &self.object_sets_by_class {
            writeln!(f, "{n:>7}    {class}")?;
        }
        Ok(())
    }
}
