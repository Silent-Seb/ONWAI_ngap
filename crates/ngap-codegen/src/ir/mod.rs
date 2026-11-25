//! The resolved intermediate representation (IR) the Rust emitter consumes.
//!
//! [`build_ir`] takes the parsed modules and produces:
//!
//! * every constant (`id-*`, `max*`) evaluated to an integer;
//! * every named type with its PER-visible constraints evaluated (ranges, sizes, extension markers), enumerations
//!   numbered, and the parameterized `ProtocolIE-Container {{Set}}` family *instantiated*: a SEQUENCE of class-field
//!   references constrained by an object set becomes a [`TableSeq`] bound to that set by name;
//! * every information object set as concrete rows (id, criticality, presence, type), in the order the spec lists them;
//! * every elementary procedure (code, criticality, class 1/2, message types).
//!
//! [`validate`](validate::validate) then checks the whole IR for consistency (dangling references, duplicate ids, ...).

mod build;
mod census;
mod validate;

use std::collections::HashMap;
use std::fmt;

use crate::asn1::CharStringKind;

pub use build::build_ir;
pub use census::IrCensus;
pub use validate::recursive_groups;

/// A map that remembers insertion (= declaration) order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordered<T> {
    items: Vec<T>,
    index: HashMap<String, usize>,
}

impl<T> Default for Ordered<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            index: HashMap::new(),
        }
    }
}

impl<T> Ordered<T> {
    /// Insert; returns false (and keeps the old value) if `name` already exists.
    pub fn insert(&mut self, name: &str, value: T) -> bool {
        if self.index.contains_key(name) {
            return false;
        }
        self.index.insert(name.to_owned(), self.items.len());
        self.items.push(value);
        true
    }

    pub fn get(&self, name: &str) -> Option<&T> {
        self.index.get(name).map(|&i| &self.items[i])
    }

    pub fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<'a, T> IntoIterator for &'a Ordered<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

/// The whole resolved specification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ir {
    pub consts: Ordered<Const>,
    pub types: Ordered<NamedType>,
    pub sets: Ordered<ObjectSetIr>,
    pub procedures: Ordered<Procedure>,
}

/// An integer constant: `id-NGSetup ProcedureCode ::= 21`, `maxnoofTAIs INTEGER ::= 256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Const {
    pub name: String,
    pub module: String,
    /// The governing type's name (`INTEGER`, `ProcedureCode`, `ProtocolIE-ID`).
    pub ty: String,
    pub value: i128,
}

/// A non-parameterized type assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedType {
    pub name: String,
    pub module: String,
    pub line: u32,
    pub ty: IrType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrType {
    Null,
    Integer(IntRange),
    Enumerated(IrEnum),
    BitString(IrSize),
    OctetString {
        size: IrSize,
        /// `OCTET STRING (CONTAINING T)`.
        contained: Option<Box<IrType>>,
    },
    ObjectIdentifier,
    CharString {
        kind: CharStringKind,
        size: IrSize,
    },
    Sequence(IrSequence),
    SequenceOf {
        size: IrSize,
        element: Box<IrType>,
    },
    Choice(IrChoice),
    /// A reference to a named type.
    Named(String),
    /// A SEQUENCE of (key, criticality, open type) bound to an object set: an IE field or a procedure wrapper.
    Table(TableSeq),
}

/// The PER-visible constraint of an INTEGER.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntRange {
    /// `None`: unbounded below.
    pub lb: Option<i128>,
    /// `None`: unbounded above.
    pub ub: Option<i128>,
    /// An extension marker `...` follows the root: values outside the root are allowed.
    pub extensible: bool,
    /// The root as written, a union of closed ranges (`1..30|40|181` has three). Empty if any end is unbounded.
    /// PER encodes the span `lb..=ub`; this keeps the gaps for logical validation.
    pub ranges: Vec<(i128, i128)>,
    /// Closed ranges written after the extension marker (`(1..65535, ..., 65536..109999)`): values outside the
    /// root that are still defined.
    pub additions: Vec<(i128, i128)>,
}

/// A SIZE constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrSize {
    pub lb: u64,
    pub ub: Option<u64>,
    pub extensible: bool,
}

impl IrSize {
    pub const UNBOUNDED: IrSize = IrSize {
        lb: 0,
        ub: None,
        extensible: false,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrEnum {
    /// Root items in declaration order.
    pub root: Vec<IrEnumItem>,
    pub extensible: bool,
    /// Extension additions in declaration order.
    pub additions: Vec<IrEnumItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrEnumItem {
    pub name: String,
    /// The ASN.1 value (`name(5)`, else automatic).
    pub value: i128,
    /// The PER index: rank of the value among the root values, or the position among the additions.
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrSequence {
    pub root: Vec<IrComponent>,
    pub extensible: bool,
    pub additions: Vec<IrComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrComponent {
    pub name: String,
    pub ty: IrType,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrChoice {
    pub root: Vec<IrAlternative>,
    pub extensible: bool,
    pub additions: Vec<IrAlternative>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrAlternative {
    pub name: String,
    pub ty: IrType,
}

/// `SEQUENCE { id CLASS.&id ({Set}), criticality CLASS.&criticality ({Set}{@id}), value CLASS.&Value ({Set}{@id}) }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSeq {
    /// The information object class (e.g. `NGAP-PROTOCOL-IES`).
    pub class: String,
    /// The object set the table is bound to (a key of [`Ir::sets`]).
    pub set: String,
    pub components: Vec<TableComponent>,
}

impl TableSeq {
    /// The key component (the first one).
    pub fn key(&self) -> &TableComponent {
        &self.components[0]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableComponent {
    pub name: String,
    /// The class field it reads, without the `&`.
    pub field: String,
    pub role: TableRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableRole {
    /// Selects the object in the set (`id`, `procedureCode`).
    Key,
    /// A `Criticality` taken from the selected object.
    Criticality,
    /// An open type whose actual type is given by the selected object.
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    Reject,
    Ignore,
    Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Optional,
    Conditional,
    Mandatory,
}

/// What an information object class is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    /// `NGAP-PROTOCOL-IES`: message IEs.
    ProtocolIes,
    /// `NGAP-PROTOCOL-EXTENSION`: the `iE-Extensions` of a type.
    ProtocolExtensions,
    /// `NGAP-PRIVATE-IES`.
    PrivateIes,
    /// `NGAP-PROTOCOL-IES-PAIR`.
    ProtocolIesPair,
    /// `NGAP-ELEMENTARY-PROCEDURE`.
    ElementaryProcedures,
}

/// An information object set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSetIr {
    pub name: String,
    pub module: String,
    pub line: u32,
    pub class: String,
    pub kind: SetKind,
    /// The set has an extension marker: unknown members may appear on the wire.
    pub extensible: bool,
    /// Rows of an IE / extension set, in the order of the spec (which is also the required wire order).
    pub rows: Vec<IeRow>,
    /// Procedure names of an elementary-procedure set (sets of sets are flattened), in spec order.
    pub procedures: Vec<String>,
}

/// One IE (or extension) of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IeRow {
    pub id: u32,
    /// The name of the `id-*` constant the spec used (`id-GlobalRANNodeID`), if it used one.
    pub id_name: Option<String>,
    pub criticality: Criticality,
    pub presence: Presence,
    pub ty: IrType,
}

/// An elementary procedure object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Procedure {
    /// The object's name, e.g. `nGSetup`.
    pub name: String,
    pub module: String,
    pub line: u32,
    pub code: u16,
    pub criticality: Criticality,
    pub class: ProcedureClass,
    /// Message type names (keys of [`Ir::types`]).
    pub initiating: String,
    pub successful: Option<String>,
    pub unsuccessful: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcedureClass {
    /// Request with a response (successful and/or unsuccessful outcome).
    Class1,
    /// Initiating message only.
    Class2,
}

impl Ir {
    /// Follow `Named` references until a constructed type is reached. `None` on a dangling name or a reference cycle.
    pub fn resolve<'a>(&'a self, mut ty: &'a IrType) -> Option<&'a IrType> {
        for _ in 0..64 {
            match ty {
                IrType::Named(n) => ty = &self.types.get(n)?.ty,
                other => return Some(other),
            }
        }
        None
    }
}

/// An error while building the IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrError {
    pub module: String,
    /// The assignment being processed.
    pub item: String,
    pub line: u32,
    pub message: String,
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} (`{}`): {}",
            self.module, self.line, self.item, self.message
        )
    }
}

impl std::error::Error for IrError {}

#[cfg(test)]
mod tests;
