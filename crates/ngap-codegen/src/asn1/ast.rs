//! Abstract syntax tree for the NGAP ASN.1 dialect.
//!
//! Only constructs TS 38.413 uses are represented; anything else is a parse error rather than a silent gap.

/// One ASN.1 module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    /// The module's object identifier, e.g. `itu-t (0) identified-organization (4) ...`.
    pub oid: Vec<OidArc>,
    pub tag_default: TagDefault,
    pub extensibility_implied: bool,
    pub imports: Vec<Import>,
    pub assignments: Vec<Assignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidArc {
    pub name: Option<String>,
    pub number: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagDefault {
    Explicit,
    Implicit,
    Automatic,
}

/// `Sym1, Sym2 FROM Module`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub symbols: Vec<ImportSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSymbol {
    pub name: String,
    /// Written `Name{}`: a parameterized type.
    pub parameterized: bool,
}

/// A top-level assignment (`... ::= ...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assignment {
    Type(TypeAssignment),
    Value(ValueAssignment),
    Class(ClassAssignment),
    ObjectSet(ObjectSetAssignment),
    Object(ObjectAssignment),
}

impl Assignment {
    pub fn name(&self) -> &str {
        match self {
            Assignment::Type(a) => &a.name,
            Assignment::Value(a) => &a.name,
            Assignment::Class(a) => &a.name,
            Assignment::ObjectSet(a) => &a.name,
            Assignment::Object(a) => &a.name,
        }
    }

    /// Source line of the assignment's name (1-based).
    pub fn line(&self) -> u32 {
        match self {
            Assignment::Type(a) => a.line,
            Assignment::Value(a) => a.line,
            Assignment::Class(a) => a.line,
            Assignment::ObjectSet(a) => a.line,
            Assignment::Object(a) => a.line,
        }
    }
}

/// `Name ::= Type` or `Name {params} ::= Type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAssignment {
    pub name: String,
    pub params: Vec<Param>,
    pub ty: Type,
    pub line: u32,
}

/// A formal parameter of a parameterized type: `NGAP-PROTOCOL-IES : IEsSetParam`, `INTEGER : lowerBound`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub governor: Option<Governor>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Governor {
    /// An information object (set) parameter of this class.
    Class(String),
    /// A value parameter of this type.
    Type(Type),
}

/// `name Type ::= value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueAssignment {
    pub name: String,
    pub ty: Type,
    pub value: Value,
    pub line: u32,
}

/// `NAME ::= CLASS { &field ... } WITH SYNTAX { ... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassAssignment {
    pub name: String,
    pub fields: Vec<ClassField>,
    pub syntax: Vec<SyntaxItem>,
    pub line: u32,
}

impl ClassAssignment {
    pub fn field(&self, name: &str) -> Option<&ClassField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassField {
    /// Without the `&`.
    pub name: String,
    pub kind: FieldKind,
    pub unique: bool,
    pub optional: bool,
    pub default: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// `&Value`: holds a type.
    Type,
    /// `&id ProtocolIE-ID`: holds a value of the given type.
    FixedTypeValue(Type),
}

/// An item of a `WITH SYNTAX` clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyntaxItem {
    /// A keyword such as `ID` or `CRITICALITY`.
    Literal(String),
    /// A field reference such as `&id` (name without `&`).
    Field(String),
    /// `[ ... ]`
    Optional(Vec<SyntaxItem>),
}

/// `name CLASS ::= { ... }`: one information object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAssignment {
    pub name: String,
    pub class: String,
    pub object: Object,
    pub line: u32,
}

/// `Name CLASS ::= { obj | obj, ... }`: an information object set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSetAssignment {
    pub name: String,
    pub class: String,
    pub set: ObjectSet,
    pub line: u32,
}

/// An information object: its field settings in `WITH SYNTAX` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub fields: Vec<ObjectField>,
}

impl Object {
    pub fn field(&self, name: &str) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| &f.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectField {
    /// Without the `&`.
    pub name: String,
    pub value: FieldValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Type(Type),
    Value(Value),
}

/// `{ a | { inline object } , ... }`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectSet {
    pub elements: Vec<ObjectSetElement>,
}

impl ObjectSet {
    /// True if the set contains the extension marker `...`.
    pub fn is_extensible(&self) -> bool {
        self.elements
            .iter()
            .any(|e| matches!(e, ObjectSetElement::Extension))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSetElement {
    /// A reference to an object or object set by name.
    Reference(String),
    /// An inline object `{ ID ... }`.
    Object(Object),
    /// `...`
    Extension,
}

/// A value: an integer or an identifier (value reference, enumeration item, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i128),
    Ident(String),
}

/// A type with the constraints written after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type {
    pub kind: TypeKind,
    pub constraints: Vec<Constraint>,
}

impl Type {
    pub fn new(kind: TypeKind) -> Self {
        Self {
            kind,
            constraints: Vec::new(),
        }
    }

    /// Visit this type and every type nested in it (components, alternatives, elements, `CONTAINING`, ...).
    pub fn walk(&self, f: &mut impl FnMut(&Type)) {
        f(self);
        match &self.kind {
            TypeKind::Sequence(s) => s.root.iter().chain(&s.additions).for_each(|c| c.ty.walk(f)),
            TypeKind::Choice(c) => c.root.iter().chain(&c.additions).for_each(|a| a.ty.walk(f)),
            TypeKind::SequenceOf(t) => t.walk(f),
            _ => {}
        }
        for c in &self.constraints {
            if let Constraint::Subtype(set) = c {
                set.walk_types(f);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Null,
    Integer,
    Enumerated(Enumerated),
    BitString,
    OctetString,
    ObjectIdentifier,
    CharString(CharStringKind),
    Sequence(Sequence),
    /// `SEQUENCE [(SIZE ...)] OF element` (the size constraint is in `Type::constraints`).
    SequenceOf(Box<Type>),
    Choice(Choice),
    /// A reference to a (possibly parameterized) type, e.g. `ProtocolIE-Container { {NGSetupRequestIEs} }`.
    Reference(TypeRef),
    /// `CLASS.&Field`: the type held by a class field.
    FieldRef {
        class: String,
        field: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharStringKind {
    Printable,
    Visible,
    Utf8,
    Ia5,
    Numeric,
    Bmp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumerated {
    pub root: Vec<EnumItem>,
    /// `Some` if there is an extension marker; the items after it.
    pub additions: Option<Vec<EnumItem>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumItem {
    pub name: String,
    /// Explicit `name(5)` value, if written.
    pub value: Option<i128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sequence {
    pub root: Vec<Component>,
    /// True if there is an extension marker `...`; `additions` are the components after it.
    pub additions_marker: bool,
    pub additions: Vec<Component>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub ty: Type,
    pub optional: bool,
    pub default: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub root: Vec<Alternative>,
    pub additions_marker: bool,
    pub additions: Vec<Alternative>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternative {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRef {
    pub name: String,
    /// Actual parameters of a parameterized type (empty for an ordinary reference).
    pub args: Vec<ActualParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActualParam {
    Value(Value),
    /// `{ NGSetupRequestIEs }`
    ObjectSet(ObjectSet),
}

/// A constraint in parentheses after a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// `(0..7)`, `(SIZE(1..4, ...))`, `(CONTAINING T)`
    Subtype(ElementSet),
    /// `({IEsSetParam})` or `({Set}{@id})`
    Table(TableConstraint),
}

/// `root_elements [, ... [, additional_elements]]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementSet {
    /// A union (`a | b | c`) of elements.
    pub root: Vec<Elem>,
    /// `Some` if there is an extension marker; the elements after it.
    pub additions: Option<Vec<Elem>>,
}

impl ElementSet {
    fn walk_types(&self, f: &mut impl FnMut(&Type)) {
        for e in self.root.iter().chain(self.additions.iter().flatten()) {
            match e {
                Elem::Containing(t) => t.walk(f),
                Elem::Size(s) => s.walk_types(f),
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elem {
    Value(Value),
    Range(Bound, Bound),
    Size(ElementSet),
    Containing(Box<Type>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Value(Value),
    Min,
    Max,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableConstraint {
    pub set: ObjectSet,
    /// The `{@id}` component relation: the referenced component names (empty if absent).
    pub at: Vec<String>,
}
