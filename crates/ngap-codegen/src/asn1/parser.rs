//! Recursive-descent parser for the NGAP ASN.1 dialect.
//!
//! Object bodies (`{ ID id-X CRITICALITY reject TYPE T PRESENCE mandatory }`) can only be parsed with the
//! `WITH SYNTAX` of their class, and classes are defined in other modules than the ones using them, so
//! [`parse_modules`] first pre-scans all sources for class definitions.

use core::fmt;
use std::collections::HashMap;

use super::ast::*;
use super::lexer::{Tok, Token, lex};

/// A syntax error, with the module label it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub module: String,
    pub line: u32,
    pub col: u32,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.module, self.line, self.col, self.message
        )
    }
}

impl std::error::Error for ParseError {}

type R<T> = Result<T, ParseError>;

/// Parse a set of ASN.1 modules given as `(label, text)` pairs (the label, usually the file name, is only used in
/// error messages). The modules may reference classes defined in each other.
pub fn parse_modules(sources: &[(&str, &str)]) -> R<Vec<Module>> {
    let mut lexed = Vec::new();
    for (label, text) in sources {
        let toks = lex(text).map_err(|e| ParseError {
            module: (*label).to_owned(),
            line: e.line,
            col: e.col,
            message: e.message,
        })?;
        lexed.push((*label, toks));
    }

    let mut classes: HashMap<String, ClassAssignment> = HashMap::new();
    for (label, toks) in &lexed {
        for class in prescan_classes(label, toks)? {
            classes.insert(class.name.clone(), class);
        }
    }

    lexed
        .iter()
        .map(|(label, toks)| {
            Parser {
                toks,
                pos: 0,
                label,
                classes: &classes,
            }
            .module()
        })
        .collect()
}

/// Find `Name ::= CLASS {` at any position and parse those class definitions.
fn prescan_classes(label: &str, toks: &[Token]) -> R<Vec<ClassAssignment>> {
    let empty = HashMap::new();
    let mut out = Vec::new();
    for i in 0..toks.len().saturating_sub(2) {
        if let (Tok::Ident(name), Tok::Assign, Tok::Ident(kw)) =
            (&toks[i].tok, &toks[i + 1].tok, &toks[i + 2].tok)
            && kw == "CLASS"
            && is_upper(name)
        {
            let mut p = Parser {
                toks,
                pos: i + 2,
                label,
                classes: &empty,
            };
            out.push(p.class(name.clone(), toks[i].line)?);
        }
    }
    Ok(out)
}

fn is_upper(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

/// ASN.1 type keywords this dialect does not support; reported instead of being mistaken for type references.
const UNSUPPORTED_TYPES: &[&str] = &[
    "BOOLEAN",
    "REAL",
    "SET",
    "ANY",
    "EXTERNAL",
    "EMBEDDED",
    "UTCTime",
    "GeneralizedTime",
];

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
    label: &'a str,
    classes: &'a HashMap<String, ClassAssignment>,
}

impl<'a> Parser<'a> {
    // ---- token helpers

    fn peek(&self) -> Option<&'a Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_at(&self, n: usize) -> Option<&'a Tok> {
        self.toks.get(self.pos + n).map(|t| &t.tok)
    }

    fn here(&self) -> (u32, u32) {
        self.toks
            .get(self.pos)
            .or(self.toks.last())
            .map_or((1, 1), |t| (t.line, t.col))
    }

    fn line(&self) -> u32 {
        self.here().0
    }

    fn err<T>(&self, message: impl Into<String>) -> R<T> {
        let (line, col) = self.here();
        Err(ParseError {
            module: self.label.to_owned(),
            line,
            col,
            message: message.into(),
        })
    }

    fn found(&self) -> String {
        self.peek()
            .map_or_else(|| "end of input".to_owned(), |t| t.to_string())
    }

    fn bump(&mut self) -> R<&'a Tok> {
        match self.toks.get(self.pos) {
            Some(t) => {
                self.pos += 1;
                Ok(&t.tok)
            }
            None => self.err("unexpected end of input"),
        }
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Tok) -> R<()> {
        if self.eat(t) {
            Ok(())
        } else {
            self.err(format!("expected {t}, found {}", self.found()))
        }
    }

    fn is_ident(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(i)) if i == s)
    }

    fn eat_ident(&mut self, s: &str) -> bool {
        let hit = self.is_ident(s);
        if hit {
            self.pos += 1;
        }
        hit
    }

    fn expect_kw(&mut self, s: &str) -> R<()> {
        if self.eat_ident(s) {
            Ok(())
        } else {
            self.err(format!("expected `{s}`, found {}", self.found()))
        }
    }

    fn ident(&mut self) -> R<String> {
        match self.peek() {
            Some(Tok::Ident(s)) => {
                self.pos += 1;
                Ok(s.clone())
            }
            _ => self.err(format!("expected an identifier, found {}", self.found())),
        }
    }

    // ---- module

    fn module(&mut self) -> R<Module> {
        let name = self.ident()?;
        let oid = self.oid()?;
        self.expect_kw("DEFINITIONS")?;
        let tag_default = if self.eat_ident("EXPLICIT") {
            self.expect_kw("TAGS")?;
            TagDefault::Explicit
        } else if self.eat_ident("IMPLICIT") {
            self.expect_kw("TAGS")?;
            TagDefault::Implicit
        } else if self.eat_ident("AUTOMATIC") {
            self.expect_kw("TAGS")?;
            TagDefault::Automatic
        } else {
            TagDefault::Explicit
        };
        let extensibility_implied = self.eat_ident("EXTENSIBILITY");
        if extensibility_implied {
            self.expect_kw("IMPLIED")?;
        }
        self.expect(&Tok::Assign)?;
        self.expect_kw("BEGIN")?;
        if self.is_ident("EXPORTS") {
            return self.err("EXPORTS is not supported");
        }
        let mut imports = Vec::new();
        if self.eat_ident("IMPORTS") {
            loop {
                imports.push(self.import()?);
                if self.eat(&Tok::Semi) {
                    break;
                }
            }
        }
        let mut assignments = Vec::new();
        while !self.is_ident("END") {
            if self.peek().is_none() {
                return self.err("missing `END`");
            }
            assignments.push(self.assignment()?);
        }
        self.pos += 1; // END
        if self.peek().is_some() {
            return self.err(format!("unexpected {} after `END`", self.found()));
        }
        Ok(Module {
            name,
            oid,
            tag_default,
            extensibility_implied,
            imports,
            assignments,
        })
    }

    fn oid(&mut self) -> R<Vec<OidArc>> {
        self.expect(&Tok::LBrace)?;
        let mut arcs = Vec::new();
        while !self.eat(&Tok::RBrace) {
            match self.bump()? {
                Tok::Number(n) => arcs.push(OidArc {
                    name: None,
                    number: u64::try_from(*n).ok(),
                }),
                Tok::Ident(name) => {
                    let number = if self.eat(&Tok::LParen) {
                        let Tok::Number(n) = self.bump()? else {
                            return self.err("expected an arc number");
                        };
                        self.expect(&Tok::RParen)?;
                        u64::try_from(*n).ok()
                    } else {
                        None
                    };
                    arcs.push(OidArc {
                        name: Some(name.clone()),
                        number,
                    });
                }
                t => return self.err(format!("unexpected {t} in an object identifier")),
            }
        }
        Ok(arcs)
    }

    fn import(&mut self) -> R<Import> {
        let mut symbols = Vec::new();
        loop {
            let name = self.ident()?;
            let parameterized =
                self.peek() == Some(&Tok::LBrace) && self.peek_at(1) == Some(&Tok::RBrace);
            if parameterized {
                self.pos += 2;
            }
            symbols.push(ImportSymbol {
                name,
                parameterized,
            });
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect_kw("FROM")?;
        let module = self.ident()?;
        if self.peek() == Some(&Tok::LBrace) {
            return self
                .err("an object identifier after the module name in IMPORTS is not supported");
        }
        Ok(Import { module, symbols })
    }

    // ---- assignments

    fn is_class(&self, t: Option<&Tok>) -> bool {
        matches!(t, Some(Tok::Ident(n)) if self.classes.contains_key(n))
    }

    fn assignment(&mut self) -> R<Assignment> {
        let line = self.line();
        let name = self.ident()?;
        if !is_upper(&name) {
            // value or object assignment: `name Type ::= value` / `name CLASS ::= { ... }`
            if self.is_class(self.peek()) && self.peek_at(1) == Some(&Tok::Assign) {
                let class = self.ident()?;
                self.expect(&Tok::Assign)?;
                let object = self.object(&self.classes[&class])?;
                return Ok(Assignment::Object(ObjectAssignment {
                    name,
                    class,
                    object,
                    line,
                }));
            }
            let ty = self.ty()?;
            self.expect(&Tok::Assign)?;
            let value = self.value()?;
            return Ok(Assignment::Value(ValueAssignment {
                name,
                ty,
                value,
                line,
            }));
        }
        if self.peek() == Some(&Tok::LBrace) {
            let params = self.params()?;
            self.expect(&Tok::Assign)?;
            let ty = self.ty()?;
            return Ok(Assignment::Type(TypeAssignment {
                name,
                params,
                ty,
                line,
            }));
        }
        if self.is_class(self.peek()) && self.peek_at(1) == Some(&Tok::Assign) {
            let class = self.ident()?;
            self.expect(&Tok::Assign)?;
            let set = self.object_set(Some(&self.classes[&class]))?;
            return Ok(Assignment::ObjectSet(ObjectSetAssignment {
                name,
                class,
                set,
                line,
            }));
        }
        self.expect(&Tok::Assign)?;
        if self.is_ident("CLASS") {
            return Ok(Assignment::Class(self.class(name, line)?));
        }
        let ty = self.ty()?;
        Ok(Assignment::Type(TypeAssignment {
            name,
            params: Vec::new(),
            ty,
            line,
        }))
    }

    fn params(&mut self) -> R<Vec<Param>> {
        self.expect(&Tok::LBrace)?;
        let mut params = Vec::new();
        loop {
            let first = self.ty()?;
            let param = if self.eat(&Tok::Colon) {
                let name = self.ident()?;
                let governor = match &first {
                    Type {
                        kind: TypeKind::Reference(r),
                        constraints,
                    } if r.args.is_empty()
                        && constraints.is_empty()
                        && self.classes.contains_key(&r.name) =>
                    {
                        Governor::Class(r.name.clone())
                    }
                    _ => Governor::Type(first),
                };
                Param {
                    governor: Some(governor),
                    name,
                }
            } else {
                match first {
                    Type {
                        kind: TypeKind::Reference(r),
                        ..
                    } if r.args.is_empty() => Param {
                        governor: None,
                        name: r.name,
                    },
                    _ => return self.err("expected a parameter name"),
                }
            };
            params.push(param);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(params)
    }

    fn value(&mut self) -> R<Value> {
        match self.bump()? {
            Tok::Number(n) => Ok(Value::Integer(*n)),
            Tok::Ident(s) => Ok(Value::Ident(s.clone())),
            t => self.err(format!("expected a value, found {t}")),
        }
    }

    // ---- classes and objects

    /// At the `CLASS` keyword.
    fn class(&mut self, name: String, line: u32) -> R<ClassAssignment> {
        self.expect_kw("CLASS")?;
        self.expect(&Tok::LBrace)?;
        let mut fields = Vec::new();
        loop {
            let Tok::Amp(fname) = self.bump()? else {
                return self.err("expected a class field `&name`");
            };
            let kind = if is_upper(fname) {
                FieldKind::Type
            } else {
                FieldKind::FixedTypeValue(self.ty()?)
            };
            let (mut unique, mut optional, mut default) = (false, false, None);
            loop {
                if self.eat_ident("UNIQUE") {
                    unique = true;
                } else if self.eat_ident("OPTIONAL") {
                    optional = true;
                } else if self.eat_ident("DEFAULT") {
                    default = Some(self.value()?);
                } else {
                    break;
                }
            }
            fields.push(ClassField {
                name: fname.clone(),
                kind,
                unique,
                optional,
                default,
            });
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        let mut syntax = Vec::new();
        if self.eat_ident("WITH") {
            self.expect_kw("SYNTAX")?;
            self.expect(&Tok::LBrace)?;
            syntax = self.syntax_items(&Tok::RBrace)?;
        }
        Ok(ClassAssignment {
            name,
            fields,
            syntax,
            line,
        })
    }

    /// Items up to and including the closing token.
    fn syntax_items(&mut self, close: &Tok) -> R<Vec<SyntaxItem>> {
        let mut items = Vec::new();
        while !self.eat(close) {
            match self.bump()? {
                Tok::Ident(w) => items.push(SyntaxItem::Literal(w.clone())),
                Tok::Amp(f) => items.push(SyntaxItem::Field(f.clone())),
                Tok::LBracket => {
                    items.push(SyntaxItem::Optional(self.syntax_items(&Tok::RBracket)?))
                }
                t => return self.err(format!("unexpected {t} in WITH SYNTAX")),
            }
        }
        Ok(items)
    }

    /// `{ ... }` holding the fields of one object, per the class `WITH SYNTAX`.
    fn object(&mut self, class: &ClassAssignment) -> R<Object> {
        self.expect(&Tok::LBrace)?;
        let mut fields = Vec::new();
        self.object_syntax(class, &class.syntax, &mut fields)?;
        self.expect(&Tok::RBrace)?;
        for f in &class.fields {
            if !f.optional
                && f.default.is_none()
                && !fields.iter().any(|x: &ObjectField| x.name == f.name)
            {
                return self.err(format!(
                    "object of class {} lacks the required field &{}",
                    class.name, f.name
                ));
            }
        }
        Ok(Object { fields })
    }

    fn object_syntax(
        &mut self,
        class: &ClassAssignment,
        items: &[SyntaxItem],
        out: &mut Vec<ObjectField>,
    ) -> R<()> {
        if items.is_empty() {
            return self.err(format!(
                "class {} has no WITH SYNTAX; the default syntax is not supported",
                class.name
            ));
        }
        for item in items {
            match item {
                SyntaxItem::Literal(w) => self.expect_kw(w)?,
                SyntaxItem::Field(f) => {
                    let Some(field) = class.field(f) else {
                        return self.err(format!(
                            "WITH SYNTAX of {} names unknown field &{f}",
                            class.name
                        ));
                    };
                    let value = match field.kind {
                        FieldKind::Type => FieldValue::Type(self.ty()?),
                        FieldKind::FixedTypeValue(_) => FieldValue::Value(self.value()?),
                    };
                    out.push(ObjectField {
                        name: f.clone(),
                        value,
                    });
                }
                SyntaxItem::Optional(group) => match group.first() {
                    Some(SyntaxItem::Literal(first)) => {
                        if self.is_ident(first) {
                            self.object_syntax(class, group, out)?;
                        }
                    }
                    _ => {
                        return self.err("an optional WITH SYNTAX group must start with a keyword");
                    }
                },
            }
        }
        Ok(())
    }

    /// `{ elem | elem , ... }`. Inline objects need the class of the set (`None`: references only).
    fn object_set(&mut self, class: Option<&ClassAssignment>) -> R<ObjectSet> {
        self.expect(&Tok::LBrace)?;
        let mut elements = Vec::new();
        if self.eat(&Tok::RBrace) {
            return Ok(ObjectSet { elements });
        }
        loop {
            match self.peek() {
                Some(Tok::Ellipsis) => {
                    self.pos += 1;
                    elements.push(ObjectSetElement::Extension);
                }
                Some(Tok::LBrace) => match class {
                    Some(c) => elements.push(ObjectSetElement::Object(self.object(c)?)),
                    None => return self.err("an inline object needs a known class here"),
                },
                Some(Tok::Ident(_)) => elements.push(ObjectSetElement::Reference(self.ident()?)),
                _ => return self.err(format!("unexpected {} in an object set", self.found())),
            }
            if !(self.eat(&Tok::Pipe) || self.eat(&Tok::Comma)) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(ObjectSet { elements })
    }

    // ---- types

    fn ty(&mut self) -> R<Type> {
        let Some(Tok::Ident(kw)) = self.peek() else {
            return self.err(format!("expected a type, found {}", self.found()));
        };
        let kw = kw.as_str();
        if UNSUPPORTED_TYPES.contains(&kw) {
            return self.err(format!("the ASN.1 type {kw} is not supported"));
        }
        let kind = match kw {
            "NULL" => {
                self.pos += 1;
                TypeKind::Null
            }
            "INTEGER" => {
                self.pos += 1;
                if self.peek() == Some(&Tok::LBrace) {
                    return self.err("INTEGER with named numbers is not supported");
                }
                TypeKind::Integer
            }
            "ENUMERATED" => {
                self.pos += 1;
                TypeKind::Enumerated(self.enumerated()?)
            }
            "BIT" => {
                self.pos += 1;
                self.expect_kw("STRING")?;
                if self.peek() == Some(&Tok::LBrace) {
                    return self.err("BIT STRING with named bits is not supported");
                }
                TypeKind::BitString
            }
            "OCTET" => {
                self.pos += 1;
                self.expect_kw("STRING")?;
                TypeKind::OctetString
            }
            "OBJECT" => {
                self.pos += 1;
                self.expect_kw("IDENTIFIER")?;
                TypeKind::ObjectIdentifier
            }
            "PrintableString" | "VisibleString" | "UTF8String" | "IA5String" | "NumericString"
            | "BMPString" => {
                self.pos += 1;
                TypeKind::CharString(match kw {
                    "PrintableString" => CharStringKind::Printable,
                    "VisibleString" => CharStringKind::Visible,
                    "UTF8String" => CharStringKind::Utf8,
                    "IA5String" => CharStringKind::Ia5,
                    "NumericString" => CharStringKind::Numeric,
                    _ => CharStringKind::Bmp,
                })
            }
            "SEQUENCE" => {
                self.pos += 1;
                return self.sequence_or_of();
            }
            "CHOICE" => {
                self.pos += 1;
                TypeKind::Choice(self.choice()?)
            }
            _ => self.type_reference()?,
        };
        let constraints = self.constraints()?;
        Ok(Type { kind, constraints })
    }

    fn constraints(&mut self) -> R<Vec<Constraint>> {
        let mut out = Vec::new();
        while self.peek() == Some(&Tok::LParen) {
            out.push(self.constraint()?);
        }
        Ok(out)
    }

    /// After `SEQUENCE`.
    fn sequence_or_of(&mut self) -> R<Type> {
        match self.peek() {
            Some(Tok::LBrace) => {
                let seq = self.sequence_body()?;
                let constraints = self.constraints()?;
                Ok(Type {
                    kind: TypeKind::Sequence(seq),
                    constraints,
                })
            }
            Some(Tok::LParen | Tok::Ident(_)) => {
                let constraints = self.constraints()?;
                self.expect_kw("OF")?;
                let element = self.ty()?;
                Ok(Type {
                    kind: TypeKind::SequenceOf(Box::new(element)),
                    constraints,
                })
            }
            _ => self.err(format!(
                "expected `{{`, `(` or `OF` after SEQUENCE, found {}",
                self.found()
            )),
        }
    }

    fn sequence_body(&mut self) -> R<Sequence> {
        self.expect(&Tok::LBrace)?;
        let mut seq = Sequence {
            root: Vec::new(),
            additions_marker: false,
            additions: Vec::new(),
        };
        loop {
            if self.eat(&Tok::Ellipsis) {
                if seq.additions_marker {
                    return self.err("a second extension marker in a SEQUENCE is not supported");
                }
                seq.additions_marker = true;
            } else {
                let name = self.ident()?;
                let ty = self.ty()?;
                let (mut optional, mut default) = (false, None);
                if self.eat_ident("OPTIONAL") {
                    optional = true;
                } else if self.eat_ident("DEFAULT") {
                    default = Some(self.value()?);
                }
                let c = Component {
                    name,
                    ty,
                    optional,
                    default,
                };
                if seq.additions_marker {
                    seq.additions.push(c)
                } else {
                    seq.root.push(c)
                }
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(seq)
    }

    fn choice(&mut self) -> R<Choice> {
        self.expect(&Tok::LBrace)?;
        let mut ch = Choice {
            root: Vec::new(),
            additions_marker: false,
            additions: Vec::new(),
        };
        loop {
            if self.eat(&Tok::Ellipsis) {
                if ch.additions_marker {
                    return self.err("a second extension marker in a CHOICE is not supported");
                }
                ch.additions_marker = true;
            } else {
                let name = self.ident()?;
                let ty = self.ty()?;
                let alt = Alternative { name, ty };
                if ch.additions_marker {
                    ch.additions.push(alt)
                } else {
                    ch.root.push(alt)
                }
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(ch)
    }

    fn enumerated(&mut self) -> R<Enumerated> {
        self.expect(&Tok::LBrace)?;
        let mut e = Enumerated {
            root: Vec::new(),
            additions: None,
        };
        loop {
            if self.eat(&Tok::Ellipsis) {
                if e.additions.is_some() {
                    return self.err("a second extension marker in an ENUMERATED is not supported");
                }
                e.additions = Some(Vec::new());
            } else {
                let name = self.ident()?;
                let value = if self.eat(&Tok::LParen) {
                    let Tok::Number(n) = self.bump()? else {
                        return self.err("expected a number");
                    };
                    self.expect(&Tok::RParen)?;
                    Some(*n)
                } else {
                    None
                };
                let item = EnumItem { name, value };
                match &mut e.additions {
                    Some(a) => a.push(item),
                    None => e.root.push(item),
                }
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBrace)?;
        Ok(e)
    }

    /// `Name`, `Name { actual params }` or `CLASS.&field`.
    fn type_reference(&mut self) -> R<TypeKind> {
        let name = self.ident()?;
        if !is_upper(&name) {
            return self.err(format!("`{name}` is not a type name"));
        }
        if self.peek() == Some(&Tok::Dot) {
            self.pos += 1;
            let Tok::Amp(field) = self.bump()? else {
                return self.err("expected a class field `&name` after `.`");
            };
            return Ok(TypeKind::FieldRef {
                class: name,
                field: field.clone(),
            });
        }
        let mut args = Vec::new();
        if self.eat(&Tok::LBrace) {
            loop {
                args.push(match self.peek() {
                    Some(Tok::LBrace) => ActualParam::ObjectSet(self.object_set(None)?),
                    _ => ActualParam::Value(self.value()?),
                });
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
            self.expect(&Tok::RBrace)?;
        }
        Ok(TypeKind::Reference(TypeRef { name, args }))
    }

    // ---- constraints

    fn constraint(&mut self) -> R<Constraint> {
        self.expect(&Tok::LParen)?;
        if self.peek() == Some(&Tok::LBrace) {
            let set = self.object_set(None)?;
            let mut at = Vec::new();
            if self.eat(&Tok::LBrace) {
                loop {
                    self.expect(&Tok::At)?;
                    at.push(self.ident()?);
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                self.expect(&Tok::RBrace)?;
            }
            self.expect(&Tok::RParen)?;
            return Ok(Constraint::Table(TableConstraint { set, at }));
        }
        let set = self.element_set()?;
        self.expect(&Tok::RParen)?;
        Ok(Constraint::Subtype(set))
    }

    /// `a | b [, ... [, c | d]]` up to (not including) the closing parenthesis.
    fn element_set(&mut self) -> R<ElementSet> {
        let root = self.elements()?;
        let mut additions = None;
        if self.peek() == Some(&Tok::Comma) && self.peek_at(1) == Some(&Tok::Ellipsis) {
            self.pos += 2;
            additions = Some(if self.eat(&Tok::Comma) {
                self.elements()?
            } else {
                Vec::new()
            });
        }
        Ok(ElementSet { root, additions })
    }

    fn elements(&mut self) -> R<Vec<Elem>> {
        let mut v = vec![self.element()?];
        while self.eat(&Tok::Pipe) {
            v.push(self.element()?);
        }
        Ok(v)
    }

    fn element(&mut self) -> R<Elem> {
        if self.eat_ident("SIZE") {
            self.expect(&Tok::LParen)?;
            let inner = self.element_set()?;
            self.expect(&Tok::RParen)?;
            return Ok(Elem::Size(inner));
        }
        if self.eat_ident("CONTAINING") {
            return Ok(Elem::Containing(Box::new(self.ty()?)));
        }
        let lo = self.bound()?;
        if self.eat(&Tok::DotDot) {
            let hi = self.bound()?;
            return Ok(Elem::Range(lo, hi));
        }
        match lo {
            Bound::Value(v) => Ok(Elem::Value(v)),
            _ => self.err("MIN/MAX must be part of a range"),
        }
    }

    fn bound(&mut self) -> R<Bound> {
        match self.peek() {
            Some(Tok::Ident(s)) if s == "MIN" => {
                self.pos += 1;
                Ok(Bound::Min)
            }
            Some(Tok::Ident(s)) if s == "MAX" => {
                self.pos += 1;
                Ok(Bound::Max)
            }
            _ => Ok(Bound::Value(self.value()?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module with the NGAP-style classes, so object syntax can be tested.
    const PRELUDE: &str = "
        NGAP-IES ::= CLASS { &id INTEGER UNIQUE, &criticality Criticality, &Value, &presence Presence }
        WITH SYNTAX { ID &id CRITICALITY &criticality TYPE &Value PRESENCE &presence }
        PROC ::= CLASS { &Init, &Succ OPTIONAL, &code INTEGER UNIQUE, &crit Criticality DEFAULT ignore }
        WITH SYNTAX { INITIATING MESSAGE &Init [SUCCESSFUL OUTCOME &Succ] CODE &code [CRITICALITY &crit] }
    ";

    fn module(body: &str) -> Module {
        let text =
            format!("M {{ a (1) b }} DEFINITIONS AUTOMATIC TAGS ::= BEGIN {PRELUDE} {body} END");
        match parse_modules(&[("t", &text)]) {
            Ok(mut v) => v.remove(0),
            Err(e) => panic!("{e}"),
        }
    }

    fn last_type(body: &str) -> Type {
        match module(body).assignments.pop().unwrap() {
            Assignment::Type(t) => t.ty,
            a => panic!("not a type assignment: {a:?}"),
        }
    }

    fn fails(body: &str) -> ParseError {
        let text = format!("M {{ a }} DEFINITIONS ::= BEGIN {PRELUDE} {body} END");
        parse_modules(&[("t", &text)]).expect_err("should not parse")
    }

    #[test]
    fn module_header_and_imports() {
        let text = "NGAP-X { itu-t (0) etsi (0) 3 } DEFINITIONS AUTOMATIC TAGS ::= BEGIN
            IMPORTS A, b, C{} FROM M1 D FROM M2; END";
        let m = parse_modules(&[("t", text)]).unwrap().remove(0);
        assert_eq!(m.name, "NGAP-X");
        assert_eq!(m.oid.len(), 3);
        assert_eq!(
            (
                m.oid[0].name.as_deref(),
                m.oid[0].number,
                m.oid[2].name.as_deref(),
                m.oid[2].number
            ),
            (Some("itu-t"), Some(0), None, Some(3))
        );
        assert_eq!(m.tag_default, TagDefault::Automatic);
        assert_eq!(m.imports.len(), 2);
        assert_eq!(m.imports[0].module, "M1");
        let syms: Vec<_> = m.imports[0]
            .symbols
            .iter()
            .map(|s| (s.name.as_str(), s.parameterized))
            .collect();
        assert_eq!(syms, [("A", false), ("b", false), ("C", true)]);
    }

    #[test]
    fn simple_types_and_constraints() {
        let t = last_type("T ::= INTEGER (0..7)");
        assert_eq!(t.kind, TypeKind::Integer);
        assert_eq!(
            t.constraints,
            [Constraint::Subtype(ElementSet {
                root: vec![Elem::Range(
                    Bound::Value(Value::Integer(0)),
                    Bound::Value(Value::Integer(7))
                )],
                additions: None
            })]
        );
        // union with extension and extension additions
        let t = last_type("T ::= INTEGER (1..30|40|181, ..., 200..300)");
        let Constraint::Subtype(s) = &t.constraints[0] else {
            panic!()
        };
        assert_eq!(s.root.len(), 3);
        assert_eq!(s.additions.as_ref().unwrap().len(), 1);
        // SIZE with symbolic bound, extensible, nested extension marker with additions
        let t = last_type("T ::= BIT STRING (SIZE(8, ..., 16))");
        let Constraint::Subtype(s) = &t.constraints[0] else {
            panic!()
        };
        let Elem::Size(inner) = &s.root[0] else {
            panic!()
        };
        assert_eq!(
            (inner.root.len(), inner.additions.as_ref().map(Vec::len)),
            (1, Some(1))
        );
        let t = last_type("T ::= OCTET STRING (SIZE(1..maxX, ...))");
        let Constraint::Subtype(s) = &t.constraints[0] else {
            panic!()
        };
        let Elem::Size(inner) = &s.root[0] else {
            panic!()
        };
        assert_eq!(
            inner.root,
            [Elem::Range(
                Bound::Value(Value::Integer(1)),
                Bound::Value(Value::Ident("maxX".into()))
            )]
        );
        assert_eq!(inner.additions, Some(vec![]));
        // negative bounds, MIN/MAX, CONTAINING
        assert!(
            matches!(&last_type("T ::= INTEGER (-127..127)").constraints[0], Constraint::Subtype(s) if s.root == [Elem::Range(Bound::Value(Value::Integer(-127)), Bound::Value(Value::Integer(127)))])
        );
        assert!(
            matches!(&last_type("T ::= INTEGER (0..MAX)").constraints[0], Constraint::Subtype(s) if matches!(&s.root[0], Elem::Range(_, Bound::Max)))
        );
        let t = last_type("T ::= OCTET STRING (CONTAINING Other)");
        assert!(
            matches!(&t.constraints[0], Constraint::Subtype(s) if matches!(&s.root[0], Elem::Containing(t) if matches!(&t.kind, TypeKind::Reference(r) if r.name == "Other")))
        );
        assert_eq!(
            last_type("T ::= UTF8String (SIZE(1..150, ...))").kind,
            TypeKind::CharString(CharStringKind::Utf8)
        );
        assert_eq!(
            last_type("T ::= OBJECT IDENTIFIER").kind,
            TypeKind::ObjectIdentifier
        );
    }

    #[test]
    fn enumerated_choice_sequence() {
        let TypeKind::Enumerated(e) = last_type("T ::= ENUMERATED {a, b, ..., c(5)}").kind else {
            panic!()
        };
        assert_eq!(
            e.root.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        let add = e.additions.unwrap();
        assert_eq!((add[0].name.as_str(), add[0].value), ("c", Some(5)));
        let TypeKind::Enumerated(e) = last_type("T ::= ENUMERATED {a, ...}").kind else {
            panic!()
        };
        assert_eq!(e.additions, Some(vec![]));

        let TypeKind::Choice(c) =
            last_type("T ::= CHOICE { x INTEGER (0..1), y NULL, ..., z Foo }").kind
        else {
            panic!()
        };
        assert_eq!(
            (c.root.len(), c.additions_marker, c.additions.len()),
            (2, true, 1)
        );

        let TypeKind::Sequence(s) = last_type(
            "T ::= SEQUENCE { a Foo, b Bar OPTIONAL, c Baz DEFAULT reject, ..., d Qux OPTIONAL }",
        )
        .kind
        else {
            panic!()
        };
        assert_eq!(
            (s.root.len(), s.additions.len(), s.additions_marker),
            (3, 1, true)
        );
        assert!(s.root[1].optional && s.root[2].default == Some(Value::Ident("reject".into())));
        // empty extensible sequence
        let TypeKind::Sequence(s) = last_type("T ::= SEQUENCE { ... }").kind else {
            panic!()
        };
        assert!(s.root.is_empty() && s.additions_marker);
    }

    #[test]
    fn sequence_of_variants() {
        let t = last_type("T ::= SEQUENCE (SIZE(1..4)) OF Foo (SIZE(2))");
        let TypeKind::SequenceOf(el) = &t.kind else {
            panic!()
        };
        assert_eq!(
            t.constraints.len(),
            1,
            "size constraint belongs to the list"
        );
        assert_eq!(el.constraints.len(), 1, "the trailing one to the element");
        let t = last_type("T ::= SEQUENCE OF INTEGER (0..7)");
        assert!(t.constraints.is_empty() && matches!(t.kind, TypeKind::SequenceOf(_)));
    }

    #[test]
    fn references_parameters_and_table_constraints() {
        let TypeKind::Reference(r) = last_type("T ::= ProtocolIE-Container { {SetIEs} }").kind
        else {
            panic!()
        };
        assert_eq!(
            r.args,
            [ActualParam::ObjectSet(ObjectSet {
                elements: vec![ObjectSetElement::Reference("SetIEs".into())]
            })]
        );
        let TypeKind::Reference(r) = last_type("T ::= List { 1, maxN, {SetIEs} }").kind else {
            panic!()
        };
        assert_eq!(r.args.len(), 3);
        assert_eq!(r.args[0], ActualParam::Value(Value::Integer(1)));
        assert_eq!(r.args[1], ActualParam::Value(Value::Ident("maxN".into())));

        let TypeKind::Sequence(s) =
            last_type("T ::= SEQUENCE { id NGAP-IES.&id ({S}), value NGAP-IES.&Value ({S}{@id}) }")
                .kind
        else {
            panic!()
        };
        assert_eq!(
            s.root[0].ty.kind,
            TypeKind::FieldRef {
                class: "NGAP-IES".into(),
                field: "id".into()
            }
        );
        let Constraint::Table(t) = &s.root[1].ty.constraints[0] else {
            panic!()
        };
        assert_eq!(t.at, ["id"]);
        let Constraint::Table(t) = &s.root[0].ty.constraints[0] else {
            panic!()
        };
        assert!(t.at.is_empty());
    }

    #[test]
    fn parameterized_type_assignment() {
        let m = module(
            "C { NGAP-IES : Set, INTEGER : lo } ::= SEQUENCE (SIZE (lo..10)) OF F { {Set} }",
        );
        let Some(Assignment::Type(t)) = m.assignments.last() else {
            panic!()
        };
        assert_eq!(t.params.len(), 2);
        assert_eq!(
            t.params[0],
            Param {
                governor: Some(Governor::Class("NGAP-IES".into())),
                name: "Set".into()
            }
        );
        assert!(matches!(
            &t.params[1].governor,
            Some(Governor::Type(Type {
                kind: TypeKind::Integer,
                ..
            }))
        ));
    }

    #[test]
    fn classes_objects_and_object_sets() {
        let m = module(
            "idA INTEGER ::= 27
             procA PROC ::= { INITIATING MESSAGE Req SUCCESSFUL OUTCOME Ack CODE idA }
             procB PROC ::= { INITIATING MESSAGE Req2 CODE 7 CRITICALITY reject }
             Ies NGAP-IES ::= {
                { ID idA CRITICALITY reject TYPE Foo PRESENCE mandatory } |
                { ID 2 CRITICALITY ignore TYPE OCTET STRING (CONTAINING Bar) PRESENCE optional },
                ...
             }
             Procs PROC ::= { procA | procB, ... }
             Empty NGAP-IES ::= { ... }",
        );
        let classes: Vec<_> = m
            .assignments
            .iter()
            .filter_map(|a| {
                if let Assignment::Class(c) = a {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(classes.len(), 2);
        assert_eq!(
            classes[1]
                .fields
                .iter()
                .map(|f| (f.name.as_str(), f.optional, f.default.is_some()))
                .collect::<Vec<_>>(),
            [
                ("Init", false, false),
                ("Succ", true, false),
                ("code", false, false),
                ("crit", false, true)
            ]
        );
        assert!(classes[0].fields[0].unique);
        assert_eq!(
            classes[1].syntax.len(),
            7,
            "INITIATING MESSAGE &Init [..] CODE &code [..]: 2 + 1 + 1(opt) + 1 + 1 + 1(opt)... as items"
        );
        let objs: Vec<_> = m
            .assignments
            .iter()
            .filter_map(|a| {
                if let Assignment::Object(o) = a {
                    Some(o)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(objs.len(), 2);
        assert_eq!(
            objs[0]
                .object
                .fields
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["Init", "Succ", "code"]
        );
        assert_eq!(
            objs[1].object.field("crit"),
            Some(&FieldValue::Value(Value::Ident("reject".into())))
        );
        let sets: Vec<_> = m
            .assignments
            .iter()
            .filter_map(|a| {
                if let Assignment::ObjectSet(s) = a {
                    Some(s)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0].set.elements.len(), 3);
        assert!(matches!(
            sets[0].set.elements[2],
            ObjectSetElement::Extension
        ));
        assert!(
            matches!(&sets[0].set.elements[1], ObjectSetElement::Object(o) if matches!(o.field("Value"), Some(FieldValue::Type(t)) if t.kind == TypeKind::OctetString))
        );
        assert_eq!(
            sets[1].set.elements,
            [
                ObjectSetElement::Reference("procA".into()),
                ObjectSetElement::Reference("procB".into()),
                ObjectSetElement::Extension
            ]
        );
        assert_eq!(sets[2].set.elements, [ObjectSetElement::Extension]);
    }

    #[test]
    fn errors_have_positions_and_clear_messages() {
        let e = fails("T ::= BOOLEAN");
        assert!(e.message.contains("BOOLEAN"), "{e}");
        assert!(
            fails("T ::= INTEGER { a(1) }")
                .message
                .contains("named numbers")
        );
        assert!(
            fails("T ::= BIT STRING { a(1) }")
                .message
                .contains("named bits")
        );
        assert!(
            fails("T ::= SEQUENCE { a Foo, ..., b Bar, ... }")
                .message
                .contains("second extension marker")
        );
        assert!(
            fails("T ::= SEQUENCE { a }")
                .message
                .contains("expected a type"),
            "{}",
            fails("T ::= SEQUENCE { a }")
        );
        assert!(fails("t ::= 5 x").message.contains("expected a type"));
        // a mandatory WITH SYNTAX keyword is missing
        let e = fails("o PROC ::= { INITIATING MESSAGE Req }");
        assert!(e.message.contains("expected `CODE`"), "{e}");
        // a mandatory class field that the object leaves out (its syntax group is optional)
        let text = "M { a } DEFINITIONS ::= BEGIN K ::= CLASS { &a INTEGER, &b INTEGER } WITH SYNTAX { A &a [B &b] } o K ::= { A 1 } END";
        let e = parse_modules(&[("t", text)]).unwrap_err();
        assert!(e.message.contains("lacks the required field &b"), "{e}");
        // an object of a class without WITH SYNTAX
        let text = "M { a } DEFINITIONS ::= BEGIN K ::= CLASS { &a INTEGER } o K ::= { 1 } END";
        assert!(
            parse_modules(&[("t", text)])
                .unwrap_err()
                .message
                .contains("WITH SYNTAX")
        );
        // structure errors
        let no_end = "M { a } DEFINITIONS ::= BEGIN T ::= NULL";
        assert!(
            parse_modules(&[("t", no_end)])
                .unwrap_err()
                .message
                .contains("END")
        );
        let trailing = "M { a } DEFINITIONS ::= BEGIN T ::= NULL END X";
        assert!(
            parse_modules(&[("t", trailing)])
                .unwrap_err()
                .message
                .contains("after `END`")
        );
        let exports = "M { a } DEFINITIONS ::= BEGIN EXPORTS T; END";
        assert!(
            parse_modules(&[("t", exports)])
                .unwrap_err()
                .message
                .contains("EXPORTS")
        );
        // lexical error is reported with the module label and a position
        let bad = "M { a } DEFINITIONS ::= BEGIN\n T ::= \"x\" END";
        let e = parse_modules(&[("file.asn", bad)]).unwrap_err();
        assert_eq!((e.module.as_str(), e.line), ("file.asn", 2));
        assert!(e.to_string().starts_with("file.asn:2:"));
    }

    #[test]
    fn classes_may_be_defined_in_another_module() {
        let a = "A { x } DEFINITIONS ::= BEGIN K ::= CLASS { &id INTEGER UNIQUE } WITH SYNTAX { ID &id } END";
        let b = "B { y } DEFINITIONS ::= BEGIN IMPORTS K FROM A; o K ::= { ID 5 } S K ::= { o | { ID 6 } } END";
        let m = parse_modules(&[("b", b), ("a", a)]).unwrap();
        assert_eq!(m[0].assignments.len(), 2);
    }
}
