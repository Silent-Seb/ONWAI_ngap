//! The generator proper: walks the IR and produces one [`Item`] (a Rust type with its APER impls) per type.

use std::collections::HashMap;
use std::fmt::Write as _;

use super::names::{Names, pascal, screaming, snake};
use crate::asn1::CharStringKind;
use crate::ir::*;

/// An error that stops generation, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitError(pub String);

impl core::fmt::Display for EmitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EmitError {}

pub(super) type Res<T> = Result<T, EmitError>;

fn bail<T>(msg: impl Into<String>) -> Res<T> {
    Err(EmitError(msg.into()))
}

/// Replace `@KEY@` placeholders.
fn tpl(text: &str, vars: &[(&str, &str)]) -> String {
    let mut out = text.to_owned();
    for (k, v) in vars {
        out = out.replace(&format!("@{k}@"), v);
    }
    out
}

/// One generated Rust type (with impls), grouped by the ASN.1 module it came from.
pub(super) struct Item {
    pub group: String,
    pub code: String,
}

/// A type as the generated Rust sees it: how to name it, encode it and decode it.
#[derive(Clone)]
enum RTy {
    /// Anything with `AperEncode` / `AperDecode` impls (generated types, `Contained<T>`, `RawIe`, ...).
    Named(String),
    Int {
        prim: &'static str,
        spec: String,
    },
    Bits(String),
    Octets(String),
    Chars {
        size: String,
        set: &'static str,
    },
    Utf8,
    Oid,
    Null,
    List(Box<RTy>, String),
    /// An extension container with no defined members: `ngap_aper::ie::UnknownIes` (no trait impls: needs the size).
    UnknownExt(String),
}

impl RTy {
    fn ty(&self) -> String {
        match self {
            RTy::Named(n) => n.clone(),
            RTy::Int { prim, .. } => (*prim).to_owned(),
            RTy::Bits(_) => "rt::BitString".into(),
            RTy::Octets(_) => "Vec<u8>".into(),
            RTy::Chars { .. } | RTy::Utf8 => "String".into(),
            RTy::Oid => "rt::ObjectIdentifier".into(),
            RTy::Null => "()".into(),
            RTy::List(e, _) => format!("Vec<{}>", e.ty()),
            RTy::UnknownExt(_) => "rt::ie::UnknownIes".into(),
        }
    }

    /// A `Result<()>` expression writing `x` (a `&T` identifier) to the writer `w`.
    fn enc(&self, x: &str) -> String {
        match self {
            RTy::Named(_) => format!("{x}.aper_encode(w)"),
            RTy::Int { spec, .. } => format!("w.write_int(i128::from(*{x}), &{spec})"),
            RTy::Bits(sz) => format!("w.write_bit_string({x}, {sz})"),
            RTy::Octets(sz) => format!("w.write_octet_string({x}, {sz})"),
            RTy::Chars { size, set } => {
                format!("w.write_char_string({x}, {size}, rt::CharSet::{set})")
            }
            RTy::Utf8 => format!("w.write_utf8_string({x})"),
            RTy::Oid => format!("w.write_object_identifier({x})"),
            RTy::Null => "Ok(())".into(),
            RTy::List(e, sz) => format!("w.write_seq_of({x}, {sz}, |w, x| {})", e.enc("x")),
            RTy::UnknownExt(sz) => format!("rt::ie::write_container(w, {sz}, &{x}.ies)"),
        }
    }

    /// A `Result<T>` expression reading a value from the reader `r`.
    fn dec(&self) -> String {
        match self {
            RTy::Named(n) => format!("<{n}>::aper_decode(r)"),
            RTy::Int { prim, spec } => format!("r.read_int_as::<{prim}>(&{spec})"),
            RTy::Bits(sz) => format!("r.read_bit_string({sz})"),
            RTy::Octets(sz) => format!("r.read_octet_string({sz})"),
            RTy::Chars { size, set } => format!("r.read_char_string({size}, rt::CharSet::{set})"),
            RTy::Utf8 => "r.read_utf8_string()".into(),
            RTy::Oid => "r.read_object_identifier()".into(),
            RTy::Null => "Ok(())".into(),
            RTy::List(e, sz) => format!("r.read_seq_of({sz}, |r| {})", e.dec()),
            RTy::UnknownExt(sz) => {
                format!("rt::ie::read_container(r, {sz}).map(|ies| rt::ie::UnknownIes {{ ies }})")
            }
        }
    }

    /// True if values are written by `RawIe::new` (a plain trait call) rather than a closure.
    fn is_trait_backed(&self) -> bool {
        matches!(self, RTy::Named(_))
    }
}

fn size_expr(sz: &IrSize) -> String {
    let base = match (sz.lb, sz.ub) {
        (0, None) => "rt::Size::UNBOUNDED".to_owned(),
        (lb, Some(ub)) if lb == ub => format!("rt::Size::fixed({lb})"),
        (lb, Some(ub)) => format!("rt::Size::range({lb}, {ub})"),
        (lb, None) => format!("rt::Size {{ lb: {lb}, ub: None, ext: false }}"),
    };
    if sz.extensible {
        format!("{base}.extensible()")
    } else {
        base
    }
}

fn int_spec(r: &IntRange) -> String {
    let mut s = match (r.lb, r.ub) {
        (Some(lb), Some(ub)) => format!("rt::IntSpec::range({lb}, {ub})"),
        (Some(lb), None) => format!("rt::IntSpec::semi({lb})"),
        (None, _) => "rt::IntSpec::UNCONSTRAINED".to_owned(),
    };
    if r.ranges.len() > 1 {
        let list: Vec<String> = r
            .ranges
            .iter()
            .map(|(a, b)| format!("({a}, {b})"))
            .collect();
        let _ = write!(s, ".with_ranges(&[{}])", list.join(", "));
    }
    if r.extensible {
        s.push_str(".extensible()");
    }
    if !r.additions.is_empty() {
        let list: Vec<String> = r
            .additions
            .iter()
            .map(|(a, b)| format!("({a}, {b})"))
            .collect();
        let _ = write!(s, ".with_additions(&[{}])", list.join(", "));
    }
    s
}

/// The smallest Rust integer type holding every defined value (root and additions).
fn int_prim(r: &IntRange, what: &str) -> Res<&'static str> {
    let (mut lo, mut hi) = (r.lb, r.ub);
    for &(a, b) in &r.additions {
        lo = lo.map(|l| l.min(a));
        hi = hi.map(|h| h.max(b));
    }
    Ok(match (lo, hi) {
        (Some(lo), Some(hi)) if lo >= 0 => match hi {
            0..=255 => "u8",
            256..=65535 => "u16",
            65536..=4294967295 => "u32",
            4294967296..=18446744073709551615 => "u64",
            _ => return bail(format!("{what}: integer range above u64")),
        },
        (Some(lo), Some(hi)) => {
            if lo >= i128::from(i8::MIN) && hi <= i128::from(i8::MAX) {
                "i8"
            } else if lo >= i128::from(i16::MIN) && hi <= i128::from(i16::MAX) {
                "i16"
            } else if lo >= i128::from(i32::MIN) && hi <= i128::from(i32::MAX) {
                "i32"
            } else if lo >= i128::from(i64::MIN) && hi <= i128::from(i64::MAX) {
                "i64"
            } else {
                return bail(format!("{what}: integer range beyond i64"));
            }
        }
        (Some(lo), None) if lo >= 0 => "u64",
        _ => "i64",
    })
}

pub(super) struct Generator<'a> {
    ir: &'a Ir,
    /// ASN.1 type name -> Rust name.
    type_names: HashMap<&'a str, String>,
    names: Names,
    pub items: Vec<Item>,
    group: String,
    /// Extension set name -> (Rust struct name, size expression it was generated with).
    ext_structs: HashMap<String, (String, String)>,
    ie_choices: HashMap<String, String>,
    private_ie: bool,
}

impl<'a> Generator<'a> {
    pub fn new(ir: &'a Ir) -> Res<Self> {
        let mut names = Names::default();
        let mut type_names = HashMap::new();
        for t in &ir.types {
            let rust = pascal(&t.name);
            names.claim(&rust, &t.name).map_err(EmitError)?;
            type_names.insert(t.name.as_str(), rust);
        }
        Ok(Self {
            ir,
            type_names,
            names,
            items: Vec::new(),
            group: String::new(),
            ext_structs: HashMap::new(),
            ie_choices: HashMap::new(),
            private_ie: false,
        })
    }

    pub fn run(&mut self) -> Res<()> {
        for t in &self.ir.types {
            self.group = t.module.clone();
            self.gen_named(t)
                .map_err(|e| EmitError(format!("{}: {}: {}", t.module, t.name, e.0)))?;
        }
        Ok(())
    }

    fn push(&mut self, _name: &str, code: String) {
        self.items.push(Item {
            group: self.group.clone(),
            code,
        });
    }

    /// `(ASN.1 name, Rust name)` of every named type, in specification order.
    pub fn type_table(&self) -> Vec<(&str, &str)> {
        self.ir
            .types
            .iter()
            .filter_map(|t| {
                self.type_names
                    .get(t.name.as_str())
                    .map(|r| (t.name.as_str(), r.as_str()))
            })
            .collect()
    }

    fn rust_name(&self, asn: &str) -> Res<String> {
        self.type_names
            .get(asn)
            .cloned()
            .map_or_else(|| bail(format!("unknown type `{asn}`")), Ok)
    }

    fn doc(&self, asn: &str) -> String {
        format!("/// ASN.1 `{asn}` ({}).\n", self.group)
    }

    // ---- types as fields

    /// The Rust-level description of `ty` used as a field/element/payload of `owner` (named `field` there).
    /// Generates helper types (inline enums, extension structs, ...) on first use.
    fn lower(&mut self, ty: &IrType, owner: &str, field: &str) -> Res<RTy> {
        Ok(match ty {
            IrType::Named(n) => RTy::Named(self.rust_name(n)?),
            IrType::Integer(r) => RTy::Int {
                prim: int_prim(r, &format!("{owner}.{field}"))?,
                spec: int_spec(r),
            },
            IrType::Enumerated(e) => {
                let name = format!("{owner}{}", pascal(field));
                self.names
                    .claim(&name, &format!("{owner}.{field} (inline ENUMERATED)"))
                    .map_err(EmitError)?;
                let code = self.enum_code(&name, "an inline ENUMERATED", e)?;
                self.push(&name, code);
                RTy::Named(name)
            }
            IrType::BitString(sz) => RTy::Bits(size_expr(sz)),
            IrType::OctetString {
                size,
                contained: None,
            } => RTy::Octets(size_expr(size)),
            IrType::OctetString {
                size,
                contained: Some(inner),
            } => {
                if *size != IrSize::UNBOUNDED {
                    return bail(format!(
                        "{owner}.{field}: OCTET STRING with both SIZE and CONTAINING"
                    ));
                }
                let RTy::Named(n) = self.lower(inner, owner, field)? else {
                    return bail(format!("{owner}.{field}: CONTAINING needs a named type"));
                };
                RTy::Named(format!("rt::Contained<{n}>"))
            }
            IrType::CharString { kind, size } => match kind {
                CharStringKind::Printable => RTy::Chars {
                    size: size_expr(size),
                    set: "Printable",
                },
                CharStringKind::Visible => RTy::Chars {
                    size: size_expr(size),
                    set: "Visible",
                },
                CharStringKind::Utf8 => RTy::Utf8,
                other => {
                    return bail(format!(
                        "{owner}.{field}: {other:?} strings are not supported"
                    ));
                }
            },
            IrType::ObjectIdentifier => RTy::Oid,
            IrType::Null => RTy::Null,
            IrType::SequenceOf { size, element } => match element.as_ref() {
                IrType::Table(tab) => self.lower_table_list(tab, size, owner, field)?,
                other => RTy::List(
                    Box::new(self.lower(other, owner, &format!("{field}Item"))?),
                    size_expr(size),
                ),
            },
            IrType::Table(tab) => self.lower_single_ie(tab, owner, field)?,
            IrType::Sequence(_) | IrType::Choice(_) => {
                return bail(format!(
                    "{owner}.{field}: an inline SEQUENCE/CHOICE is not supported"
                ));
            }
        })
    }

    fn set(&self, name: &str) -> Res<&'a ObjectSetIr> {
        self.ir
            .sets
            .get(name)
            .map_or_else(|| bail(format!("unknown object set `{name}`")), Ok)
    }

    /// `SEQUENCE (SIZE ..) OF Table`: an extension container or the private IE container.
    fn lower_table_list(
        &mut self,
        tab: &TableSeq,
        size: &IrSize,
        owner: &str,
        field: &str,
    ) -> Res<RTy> {
        let set = self.set(&tab.set)?;
        match set.kind {
            SetKind::ProtocolExtensions => {
                let sz = size_expr(size);
                if set.rows.is_empty() {
                    return Ok(RTy::UnknownExt(sz));
                }
                let name = self.ensure_ext_struct(set, &sz)?;
                Ok(RTy::Named(name))
            }
            SetKind::PrivateIes => {
                self.ensure_private_ie(owner)?;
                Ok(RTy::List(
                    Box::new(RTy::Named("PrivateIe".into())),
                    size_expr(size),
                ))
            }
            _ => bail(format!(
                "{owner}.{field}: an IE container of class {} is only supported as the sole component of a message",
                tab.class
            )),
        }
    }

    /// `ProtocolIE-SingleContainer`: exactly one IE field.
    fn lower_single_ie(&mut self, tab: &TableSeq, owner: &str, field: &str) -> Res<RTy> {
        let set = self.set(&tab.set)?;
        if !matches!(set.kind, SetKind::ProtocolIes | SetKind::ProtocolExtensions) {
            return bail(format!(
                "{owner}.{field}: a single IE field over a {:?} set is not supported",
                set.kind
            ));
        }
        if set.rows.is_empty() {
            return Ok(RTy::Named("rt::ie::RawIe".into()));
        }
        if let Some(n) = self.ie_choices.get(&set.name) {
            return Ok(RTy::Named(n.clone()));
        }
        let name = pascal(&set.name);
        self.names.claim(&name, &set.name).map_err(EmitError)?;
        self.ie_choices.insert(set.name.clone(), name.clone());
        let code = self.ie_choice_code(&name, set)?;
        self.push(&name, code);
        Ok(RTy::Named(name))
    }

    fn ensure_ext_struct(&mut self, set: &ObjectSetIr, size: &str) -> Res<String> {
        if let Some((n, sz)) = self.ext_structs.get(&set.name) {
            if sz != size {
                return bail(format!(
                    "extension set `{}` is used with different container sizes",
                    set.name
                ));
            }
            return Ok(n.clone());
        }
        let name = pascal(&set.name);
        self.names.claim(&name, &set.name).map_err(EmitError)?;
        self.ext_structs
            .insert(set.name.clone(), (name.clone(), size.to_owned()));
        let code = self.ie_struct_code(&name, &set.name, set, size, None)?;
        self.push(&name, code);
        Ok(name)
    }

    fn ensure_private_ie(&mut self, owner: &str) -> Res<()> {
        if self.private_ie {
            return Ok(());
        }
        self.private_ie = true;
        self.names
            .claim("PrivateIe", "PrivateIe (private IE field)")
            .map_err(EmitError)?;
        let id = self
            .rust_name("PrivateIE-ID")
            .map_err(|_| EmitError(format!("{owner}: PrivateIE-ID is not defined")))?;
        let code = tpl(
            r#"/// One member of the private IE container: `SEQUENCE { id PrivateIE-ID, criticality, value OPEN TYPE }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateIe {
    pub id: @ID@,
    pub criticality: rt::ie::Criticality,
    /// The complete APER encoding of the value.
    pub content: Vec<u8>,
}

impl rt::AperEncode for PrivateIe {
    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {
        self.id.aper_encode(w)?;
        self.criticality.aper_encode(w)?;
        w.write_open_type(&self.content)
    }
}

impl rt::AperDecode for PrivateIe {
    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {
        let id = <@ID@>::aper_decode(r)?;
        let criticality = rt::ie::Criticality::aper_decode(r)?;
        let content = r.read_open_type()?;
        Ok(Self { id, criticality, content })
    }
}
"#,
            &[("ID", &id)],
        );
        self.push("PrivateIe", code);
        Ok(())
    }

    // ---- named types

    fn gen_named(&mut self, t: &NamedType) -> Res<()> {
        let name = self.rust_name(&t.name)?;
        let doc = self.doc(&t.name);
        // ENUMERATED Criticality is provided by the runtime (the IE machinery needs it)
        if t.name == "Criticality" {
            let IrType::Enumerated(e) = &t.ty else {
                return bail("Criticality must be an ENUMERATED");
            };
            let items: Vec<&str> = e.root.iter().map(|i| i.name.as_str()).collect();
            if items != ["reject", "ignore", "notify"] || e.extensible {
                return bail(
                    "Criticality is not ENUMERATED { reject, ignore, notify }: update ngap_aper::ie::Criticality",
                );
            }
            return Ok(());
        }
        let code = match &t.ty {
            IrType::Integer(r) => self.int_newtype(&name, &doc, r)?,
            IrType::Enumerated(e) => format!("{doc}{}", self.enum_code(&name, "", e)?),
            IrType::Null => tpl(
                "@DOC@#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]\npub struct @N@;\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, _w: &mut rt::BitWriter) -> rt::Result<()> {\n        Ok(())\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(_r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        Ok(Self)\n    }\n}\n",
                &[("DOC", &doc), ("N", &name)],
            ),
            IrType::Named(_)
            | IrType::BitString(_)
            | IrType::OctetString { .. }
            | IrType::CharString { .. }
            | IrType::ObjectIdentifier => {
                let r = self.lower(&t.ty, &name, "Value")?;
                self.newtype(&name, &doc, &r)
            }
            IrType::SequenceOf { size, element } => {
                if matches!(element.as_ref(), IrType::Table(_)) {
                    return bail("a named list of IE fields is not supported");
                }
                let r = self.lower(&t.ty, &name, "Item")?;
                let _ = size;
                self.newtype(&name, &doc, &r)
            }
            IrType::Sequence(s) => match self.message_shape(s) {
                Some((size, set_name)) => {
                    let set = self.set(set_name)?;
                    self.ie_struct_code(&name, &t.name, set, &size_expr(size), Some(s.extensible))?
                }
                None => self.struct_code(&name, &t.name, &doc, s)?,
            },
            IrType::Choice(c) => self.choice_code(&name, &doc, c)?,
            IrType::Table(tab) => self.procedure_enum_code(&name, &doc, tab)?,
        };
        self.push(&name, code);
        Ok(())
    }

    /// A type whose only component is the IE container of a message: `(size, set name)`.
    fn message_shape<'s>(&self, s: &'s IrSequence) -> Option<(&'s IrSize, &'s str)> {
        if s.root.len() != 1 || !s.additions.is_empty() || s.root[0].optional {
            return None;
        }
        match &s.root[0].ty {
            IrType::SequenceOf { size, element } => match element.as_ref() {
                IrType::Table(t)
                    if self
                        .ir
                        .sets
                        .get(&t.set)
                        .is_some_and(|set| set.kind == SetKind::ProtocolIes) =>
                {
                    Some((size, t.set.as_str()))
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn int_newtype(&mut self, name: &str, doc: &str, r: &IntRange) -> Res<String> {
        let prim = int_prim(r, name)?;
        Ok(tpl(
            "@DOC@#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]\npub struct @N@(pub @P@);\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        w.write_int(i128::from(self.0), &@S@)\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        Ok(Self(r.read_int_as::<@P@>(&@S@)?))\n    }\n}\n",
            &[("DOC", doc), ("N", name), ("P", prim), ("S", &int_spec(r))],
        ))
    }

    /// `pub struct N(pub T);` delegating to the representation.
    fn newtype(&self, name: &str, doc: &str, r: &RTy) -> String {
        tpl(
            "@DOC@#[derive(Debug, Clone, PartialEq, Eq)]\npub struct @N@(pub @T@);\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        let x = &self.0;\n        @E@\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        Ok(Self(@D@?))\n    }\n}\n",
            &[
                ("DOC", doc),
                ("N", name),
                ("T", &r.ty()),
                ("E", &r.enc("x")),
                ("D", &r.dec()),
            ],
        )
    }

    // ---- enumerations

    fn variant_names(&self, e: &IrEnum, owner: &str) -> Res<Vec<String>> {
        let mut seen = HashMap::new();
        let mut out = Vec::new();
        for i in e.root.iter().chain(&e.additions) {
            let mut v = pascal(&i.name);
            if v == "Self" {
                v.push('_');
            }
            if let Some(other) = seen.insert(v.clone(), i.name.clone()) {
                return bail(format!(
                    "{owner}: enumeration items `{other}` and `{}` both map to `{v}`",
                    i.name
                ));
            }
            out.push(v);
        }
        Ok(out)
    }

    fn enum_code(&mut self, name: &str, what: &str, e: &IrEnum) -> Res<String> {
        let variants = self.variant_names(e, name)?;
        let root = e.root.len();
        let all: Vec<(&IrEnumItem, u64)> = e
            .root
            .iter()
            .map(|i| (i, i.index))
            .chain(e.additions.iter().map(|i| (i, root as u64 + i.index)))
            .collect();
        let mut decl = String::new();
        let mut enc = String::new();
        let mut dec = String::new();
        for ((item, index), v) in all.iter().zip(&variants) {
            let kind = if *index >= root as u64 {
                " (extension addition)"
            } else {
                ""
            };
            let _ = writeln!(decl, "    /// `{}`{kind}", item.name);
            let _ = writeln!(decl, "    {v},");
            let _ = writeln!(enc, "            Self::{v} => {index},");
            let _ = writeln!(dec, "            {index} => Self::{v},");
        }
        let attr = if e.extensible {
            "#[non_exhaustive]\n"
        } else {
            ""
        };
        let intro = if what.is_empty() {
            String::new()
        } else {
            format!("/// {what} of this module.\n")
        };
        Ok(tpl(
            "@INTRO@#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n@ATTR@pub enum @N@ {\n@DECL@}\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        let index: u64 = match self {\n@ENC@        };\n        w.write_index(index, @ROOT@, @EXT@)\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        Ok(match r.read_index(@ROOT@, @EXT@)? {\n@DEC@            i => return Err(r.error(rt::ErrorKind::InvalidIndex(i))),\n        })\n    }\n}\n",
            &[
                ("INTRO", &intro),
                ("ATTR", attr),
                ("N", name),
                ("DECL", &decl),
                ("ENC", &enc),
                ("DEC", &dec),
                ("ROOT", &root.to_string()),
                ("EXT", &e.extensible.to_string()),
            ],
        ))
    }

    // ---- sequences

    fn field_name(
        &self,
        asn: &str,
        owner: &str,
        seen: &mut HashMap<String, String>,
    ) -> Res<String> {
        let f = snake(asn);
        match seen.insert(f.clone(), asn.to_owned()) {
            Some(other) => bail(format!(
                "{owner}: `{other}` and `{asn}` both map to the field `{f}`"
            )),
            None => Ok(f),
        }
    }

    fn struct_code(&mut self, name: &str, asn: &str, doc: &str, s: &IrSequence) -> Res<String> {
        if !s.additions.is_empty() {
            return bail("SEQUENCE extension additions are not supported (NGAP-j40 has none)");
        }
        struct F {
            field: String,
            r: RTy,
            optional: bool,
            asn: String,
        }
        let mut seen = HashMap::new();
        let mut fields = Vec::new();
        for c in &s.root {
            let field = self.field_name(&c.name, name, &mut seen)?;
            let r = self.lower(&c.ty, name, &c.name)?;
            fields.push(F {
                field,
                r,
                optional: c.optional,
                asn: c.name.clone(),
            });
        }
        let mut decl = String::new();
        let mut enc = String::new();
        let mut dec = String::new();
        let mut init = String::new();
        let mut args = String::new();
        let mut ctor = String::new();
        for f in &fields {
            let ty = f.r.ty();
            let ty = if f.optional {
                format!("Option<{ty}>")
            } else {
                ty
            };
            let _ = writeln!(decl, "    /// `{}`", f.asn);
            let _ = writeln!(decl, "    pub {}: {ty},", f.field);
            if f.optional {
                let _ = writeln!(ctor, "            {}: None,", f.field);
            } else {
                let _ = write!(args, "{}: {}, ", f.field, f.r.ty());
                let _ = writeln!(ctor, "            {},", f.field);
            }
            let _ = writeln!(init, "            {0}: v_{0},", f.field);
        }
        if s.extensible {
            enc.push_str("        w.write_bit(false); // extension marker: no additions\n");
            dec.push_str("        let extension = r.read_bit()?;\n");
        }
        for f in fields.iter().filter(|f| f.optional) {
            let _ = writeln!(enc, "        w.write_bit(self.{}.is_some());", f.field);
            let _ = writeln!(dec, "        let p_{0} = r.read_bit()?;", f.field);
        }
        for f in &fields {
            if f.optional {
                let _ = writeln!(
                    enc,
                    "        if let Some(x) = &self.{} {{\n            {}?;\n        }}",
                    f.field,
                    f.r.enc("x")
                );
                let _ = writeln!(
                    dec,
                    "        let v_{0} = if p_{0} {{ Some({1}?) }} else {{ None }};",
                    f.field,
                    f.r.dec()
                );
            } else {
                let _ = writeln!(
                    enc,
                    "        {{\n            let x = &self.{};\n            {}?;\n        }}",
                    f.field,
                    f.r.enc("x")
                );
                let _ = writeln!(dec, "        let v_{0} = {1}?;", f.field, f.r.dec());
            }
        }
        if s.extensible {
            dec.push_str(
                "        if extension {\n            r.read_extension_additions()?;\n        }\n",
            );
        }
        let args = args.trim_end_matches([',', ' ']).to_owned();
        Ok(tpl(
            "@DOC@#[derive(Debug, Clone, PartialEq, Eq)]\npub struct @N@ {\n@DECL@}\n\nimpl @N@ {\n    /// A value with the mandatory components given and every optional one absent.\n    pub fn new(@ARGS@) -> Self {\n        Self {\n@CTOR@        }\n    }\n}\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n@ENC@        Ok(())\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n@DEC@        Ok(Self {\n@INIT@        })\n    }\n}\n",
            &[("DOC", doc), ("N", name), ("DECL", &decl), ("ARGS", &args), ("CTOR", &ctor), ("ENC", &enc), ("DEC", &dec), ("INIT", &init)],
        )
        .replace("@ASN@", asn))
    }

    // ---- IE sets

    /// The struct of a message (`message_ext = Some(extensible)`) or of an extension set (`None`): one field per row.
    fn ie_struct_code(
        &mut self,
        name: &str,
        asn: &str,
        set: &ObjectSetIr,
        size: &str,
        message_ext: Option<bool>,
    ) -> Res<String> {
        struct F {
            field: String,
            r: RTy,
            optional: bool,
            id: u32,
            crit: &'static str,
            doc: String,
        }
        let mut seen = HashMap::new();
        seen.insert("unknown_ies".to_owned(), "(the unknown IE list)".to_owned());
        let mut fields = Vec::new();
        for row in &set.rows {
            let base = row
                .id_name
                .clone()
                .unwrap_or_else(|| format!("ie-{}", row.id));
            let base = base.strip_prefix("id-").unwrap_or(&base).to_owned();
            let field = self.field_name(&base, name, &mut seen)?;
            let r = self.lower(&row.ty, name, &base)?;
            let crit = crit_variant(row.criticality);
            let doc = format!(
                "`{}` (id {}, {:?}, {:?})",
                row.id_name.as_deref().unwrap_or("-"),
                row.id,
                row.criticality,
                row.presence
            );
            fields.push(F {
                field,
                r,
                optional: row.presence != Presence::Mandatory,
                id: row.id,
                crit,
                doc,
            });
        }
        let (mut decl, mut ctor, mut args, mut enc, mut slots, mut arms, mut build) =
            Default::default();
        let (decl, ctor, args, enc, slots, arms, build): (
            &mut String,
            &mut String,
            &mut String,
            &mut String,
            &mut String,
            &mut String,
            &mut String,
        ) = (
            &mut decl, &mut ctor, &mut args, &mut enc, &mut slots, &mut arms, &mut build,
        );
        for f in &fields {
            let ty = f.r.ty();
            let _ = writeln!(decl, "    /// {}", f.doc);
            let _ = writeln!(
                decl,
                "    pub {}: {},",
                f.field,
                if f.optional {
                    format!("Option<{ty}>")
                } else {
                    ty.clone()
                }
            );
            if f.optional {
                let _ = writeln!(ctor, "            {}: None,", f.field);
            } else {
                let _ = write!(args, "{}: {}, ", f.field, ty);
                let _ = writeln!(ctor, "            {},", f.field);
            }
            // encode
            let make = |x: &str| {
                if f.r.is_trait_backed() {
                    format!(
                        "rt::ie::RawIe::new({}, rt::ie::Criticality::{}, {x})?",
                        f.id, f.crit
                    )
                } else {
                    format!(
                        "rt::ie::RawIe::with({}, rt::ie::Criticality::{}, |w| {})?",
                        f.id,
                        f.crit,
                        f.r.enc(x)
                    )
                }
            };
            if f.optional {
                let _ = writeln!(
                    enc,
                    "        if let Some(x) = &self.{} {{\n            ies.push({});\n        }}",
                    f.field,
                    make("x")
                );
            } else {
                let _ = writeln!(
                    enc,
                    "        {{\n            let x = &self.{};\n            ies.push({});\n        }}",
                    f.field,
                    make("x")
                );
            }
            // decode
            let _ = writeln!(
                slots,
                "        let mut s_{}: Option<{}> = None;",
                f.field,
                f.r.ty()
            );
            let value = if f.r.is_trait_backed() {
                "ie.decode()?".to_owned()
            } else {
                format!("ie.decode_with(|r| {})?", f.r.dec())
            };
            let _ = writeln!(
                arms,
                "                {0} => rt::ie::set_once(&mut s_{1}, {0}, {2})?,",
                f.id, f.field, value
            );
            if f.optional {
                let _ = writeln!(build, "            {0}: s_{0},", f.field);
            } else {
                let _ = writeln!(
                    build,
                    "            {0}: rt::ie::required(s_{0}, {1}, rt::ie::Criticality::{2})?,",
                    f.field, f.id, f.crit
                );
            }
        }
        let args = args.trim_end_matches([',', ' ']).to_owned();
        let (pre_enc, pre_dec, post_dec, derive, intro) = match message_ext {
            Some(true) => (
                "        w.write_bit(false); // extension marker: no additions\n",
                "        let extension = r.read_bit()?;\n",
                "        if extension {\n            r.read_extension_additions()?;\n        }\n",
                "#[derive(Debug, Clone, PartialEq, Eq)]\n",
                format!(
                    "/// ASN.1 `{asn}` ({}): the IEs of the message are the fields.\n",
                    self.group
                ),
            ),
            Some(false) => (
                "",
                "",
                "",
                "#[derive(Debug, Clone, PartialEq, Eq)]\n",
                format!(
                    "/// ASN.1 `{asn}` ({}): the IEs of the message are the fields.\n",
                    self.group
                ),
            ),
            None => (
                "",
                "",
                "",
                "#[derive(Debug, Clone, Default, PartialEq, Eq)]\n",
                format!(
                    "/// The extension IEs of `{asn}` ({}). IEs not defined here are kept in `unknown_ies`.\n",
                    self.group
                ),
            ),
        };
        let ctor_fn = if message_ext.is_some() || fields.iter().all(|f| f.optional) {
            tpl(
                "impl @N@ {\n    /// A value with the mandatory IEs given and every optional one absent.\n    pub fn new(@ARGS@) -> Self {\n        Self {\n@CTOR@            unknown_ies: Vec::new(),\n        }\n    }\n}\n\n",
                &[("N", name), ("ARGS", &args), ("CTOR", ctor)],
            )
        } else {
            String::new()
        };
        let message_impl = match message_ext {
            Some(ext) => {
                let ids: Vec<String> = fields.iter().map(|f| f.id.to_string()).collect();
                tpl(
                    "\nimpl @N@ {\n    /// The ids of the IEs this version of the specification defines for the message, in the order the\n    /// specification requires them on the wire.\n    pub const IE_IDS: &'static [u32] = &[@IDS@];\n\n    /// The ids of the IEs in the encoded message `content`, in the order received (known or not).\n    pub fn wire_ie_ids(content: &[u8]) -> rt::Result<Vec<u32>> {\n        rt::ie::wire_ie_ids(content, @EXT@, @SIZE@)\n    }\n}\n",
                    &[
                        ("N", name),
                        ("IDS", &ids.join(", ")),
                        ("EXT", &ext.to_string()),
                        ("SIZE", size),
                    ],
                )
            }
            None => String::new(),
        };
        let mut code = tpl(
            "@INTRO@@DERIVE@pub struct @N@ {\n@DECL@    /// IEs this version of the specification does not define here, as received (id, criticality, encoded value).\n    pub unknown_ies: Vec<rt::ie::RawIe>,\n}\n\n@CTORFN@impl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n@PREENC@        let mut ies: Vec<rt::ie::RawIe> = Vec::new();\n@ENC@        ies.extend(self.unknown_ies.iter().cloned());\n        rt::ie::write_container(w, @SIZE@, &ies)\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n@PREDEC@@SLOTS@        let mut unknown_ies = Vec::new();\n        for ie in rt::ie::read_container(r, @SIZE@)? {\n            match ie.id {\n@ARMS@                _ => unknown_ies.push(ie),\n            }\n        }\n@POSTDEC@        Ok(Self {\n@BUILD@            unknown_ies,\n        })\n    }\n}\n",
            &[
                ("INTRO", &intro),
                ("DERIVE", derive),
                ("N", name),
                ("DECL", decl),
                ("CTORFN", &ctor_fn),
                ("PREENC", pre_enc),
                ("ENC", enc),
                ("SIZE", size),
                ("PREDEC", pre_dec),
                ("SLOTS", slots),
                ("ARMS", arms),
                ("POSTDEC", post_dec),
                ("BUILD", build),
            ],
        );
        code.push_str(&message_impl);
        Ok(code)
    }

    /// An enum for a single IE field (`ProtocolIE-SingleContainer`) over a set that defines rows.
    fn ie_choice_code(&mut self, name: &str, set: &ObjectSetIr) -> Res<String> {
        let mut seen = HashMap::new();
        seen.insert("Unknown".to_owned(), "(the unknown IE variant)".to_owned());
        let mut decl = String::new();
        let mut enc = String::new();
        let mut dec = String::new();
        for row in &set.rows {
            let base = row
                .id_name
                .clone()
                .unwrap_or_else(|| format!("ie-{}", row.id));
            let base = base.strip_prefix("id-").unwrap_or(&base).to_owned();
            let variant = pascal(&base);
            if let Some(other) = seen.insert(variant.clone(), base.clone()) {
                return bail(format!(
                    "{name}: `{other}` and `{base}` both map to the variant `{variant}`"
                ));
            }
            let r = self.lower(&row.ty, name, &base)?;
            let crit = crit_variant(row.criticality);
            let _ = writeln!(
                decl,
                "    /// `{}` (id {}, {:?})",
                row.id_name.as_deref().unwrap_or("-"),
                row.id,
                row.criticality
            );
            let _ = writeln!(decl, "    {variant}({}),", r.ty());
            let make = if r.is_trait_backed() {
                format!(
                    "rt::ie::RawIe::new({}, rt::ie::Criticality::{crit}, x)?",
                    row.id
                )
            } else {
                format!(
                    "rt::ie::RawIe::with({}, rt::ie::Criticality::{crit}, |w| {})?",
                    row.id,
                    r.enc("x")
                )
            };
            let _ = writeln!(
                enc,
                "            Self::{variant}(x) => {make}.aper_encode(w),"
            );
            let value = if r.is_trait_backed() {
                "ie.decode()?".to_owned()
            } else {
                format!("ie.decode_with(|r| {})?", r.dec())
            };
            let _ = writeln!(dec, "            {} => Self::{variant}({value}),", row.id);
        }
        Ok(tpl(
            "/// The single IE field `@SET@` (@MOD@): one of the defined IEs, or an unknown one as received.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub enum @N@ {\n@DECL@    /// An IE this version of the specification does not define here.\n    Unknown(rt::ie::RawIe),\n}\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        match self {\n@ENC@            Self::Unknown(ie) => ie.aper_encode(w),\n        }\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        let ie = <rt::ie::RawIe>::aper_decode(r)?;\n        Ok(match ie.id {\n@DEC@            _ => Self::Unknown(ie),\n        })\n    }\n}\n",
            &[
                ("SET", &set.name),
                ("MOD", &self.group),
                ("N", name),
                ("DECL", &decl),
                ("ENC", &enc),
                ("DEC", &dec),
            ],
        ))
    }

    // ---- choices

    fn choice_code(&mut self, name: &str, doc: &str, c: &IrChoice) -> Res<String> {
        if !c.additions.is_empty() {
            return bail("CHOICE extension additions are not supported (NGAP-j40 has none)");
        }
        let n = c.root.len();
        let mut seen = HashMap::new();
        let (mut decl, mut enc, mut dec) = (String::new(), String::new(), String::new());
        for (i, alt) in c.root.iter().enumerate() {
            let variant = pascal(&alt.name);
            if let Some(other) = seen.insert(variant.clone(), alt.name.clone()) {
                return bail(format!(
                    "{name}: alternatives `{other}` and `{}` both map to `{variant}`",
                    alt.name
                ));
            }
            let r = self.lower(&alt.ty, name, &alt.name)?;
            let _ = writeln!(decl, "    /// `{}`", alt.name);
            if matches!(r, RTy::Null) {
                let _ = writeln!(decl, "    {variant},");
                let _ = writeln!(
                    enc,
                    "            Self::{variant} => w.write_index({i}, {n}, {}),",
                    c.extensible
                );
                let _ = writeln!(dec, "            {i} => Ok(Self::{variant}),");
            } else {
                let _ = writeln!(decl, "    {variant}({}),", r.ty());
                let _ = writeln!(
                    enc,
                    "            Self::{variant}(x) => {{\n                w.write_index({i}, {n}, {})?;\n                {}\n            }}",
                    c.extensible,
                    r.enc("x")
                );
                let _ = writeln!(dec, "            {i} => Ok(Self::{variant}({}?)),", r.dec());
            }
        }
        let attr = if c.extensible {
            "#[non_exhaustive]\n"
        } else {
            ""
        };
        // the PDU: every alternative is a procedure wrapper, so forward their accessors (a `#[non_exhaustive]` enum
        // cannot be matched exhaustively outside this crate)
        let is_pdu = !c.root.is_empty()
            && c.root.iter().all(|a| match &a.ty {
                IrType::Named(t) => matches!(
                    self.ir.types.get(t.as_str()).map(|t| &t.ty),
                    Some(IrType::Table(tab))
                        if self.ir.sets.get(&tab.set).is_some_and(|s| s.kind == SetKind::ElementaryProcedures)
                ),
                _ => false,
            });
        let mut forward = String::new();
        if is_pdu {
            let variants: Vec<String> = c.root.iter().map(|a| pascal(&a.name)).collect();
            for (sig, call, doc) in [
                (
                    "procedure_code(&self) -> u16",
                    "procedure_code",
                    "The procedure code of the message.",
                ),
                (
                    "criticality(&self) -> rt::ie::Criticality",
                    "criticality",
                    "The criticality of the procedure, as the specification defines it for this message.",
                ),
                (
                    "message_name(&self) -> &'static str",
                    "message_name",
                    "The ASN.1 name of the message type, e.g. `NGSetupRequest`.",
                ),
                (
                    "unknown_ies(&self) -> &[rt::ie::RawIe]",
                    "unknown_ies",
                    "The IEs of the message that this version of the specification does not define.",
                ),
                (
                    "ie_ids(&self) -> &'static [u32]",
                    "ie_ids",
                    "The ids of the IEs the specification defines for the message, in the required wire order.",
                ),
            ] {
                let _ = writeln!(
                    forward,
                    "    /// {doc}\n    pub fn {sig} {{\n        match self {{"
                );
                for v in &variants {
                    let _ = writeln!(forward, "            Self::{v}(m) => m.{call}(),");
                }
                forward.push_str("        }\n    }\n\n");
            }
            forward = format!(
                "\nimpl {name} {{\n{}}}\n",
                forward.trim_end_matches('\n').to_owned() + "\n"
            );
        }
        let code = tpl(
            "@DOC@#[derive(Debug, Clone, PartialEq, Eq)]\n@ATTR@pub enum @N@ {\n@DECL@}\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        match self {\n@ENC@        }\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        match r.read_index(@COUNT@, @EXT@)? {\n@DEC@            i => Err(r.error(rt::ErrorKind::InvalidIndex(i))),\n        }\n    }\n}\n",
            &[
                ("DOC", doc),
                ("ATTR", attr),
                ("N", name),
                ("DECL", &decl),
                ("ENC", &enc),
                ("DEC", &dec),
                ("COUNT", &n.to_string()),
                ("EXT", &c.extensible.to_string()),
            ],
        );
        Ok(code + &forward)
    }

    // ---- the procedure wrappers of the PDU

    fn procedure_enum_code(&mut self, name: &str, doc: &str, tab: &TableSeq) -> Res<String> {
        if self.set(&tab.set)?.kind != SetKind::ElementaryProcedures || tab.components.len() != 3 {
            return bail(
                "a named table is only supported for the elementary procedure wrappers of the PDU",
            );
        }
        let role = tab.components[2].field.as_str();
        self.check_procedure_code_range()?;
        let set = self.set(&tab.set)?;
        let (mut decl, mut enc, mut dec) = (String::new(), String::new(), String::new());
        let (mut codes, mut code_arms, mut crit_arms, mut name_arms) =
            (Vec::new(), String::new(), String::new(), String::new());
        let (mut unknown_arms, mut ids_arms, mut wire_arms) =
            (String::new(), String::new(), String::new());
        let mut seen = HashMap::new();
        for pname in &set.procedures {
            let p = self
                .ir
                .procedures
                .get(pname)
                .map_or_else(|| bail(format!("unknown procedure `{pname}`")), Ok)?;
            let msg = match role {
                "InitiatingMessage" => Some(&p.initiating),
                "SuccessfulOutcome" => p.successful.as_ref(),
                "UnsuccessfulOutcome" => p.unsuccessful.as_ref(),
                other => return bail(format!("unknown procedure wrapper field &{other}")),
            };
            let Some(msg) = msg else { continue };
            let message_shaped = matches!(
                self.ir.types.get(msg.as_str()).map(|t| &t.ty),
                Some(IrType::Sequence(seq)) if self.message_shape(seq).is_some()
            );
            let variant = self.rust_name(msg)?;
            if let Some(other) = seen.insert(variant.clone(), p.name.clone()) {
                return bail(format!(
                    "message `{msg}` is used by procedures `{other}` and `{}`",
                    p.name
                ));
            }
            let crit = crit_variant(p.criticality);
            let _ = writeln!(decl, "    /// Procedure `{}` (code {}).", p.name, p.code);
            let _ = writeln!(decl, "    {variant}({variant}),");
            let _ = writeln!(
                enc,
                "            Self::{variant}(m) => rt::ie::write_procedure(w, {}, rt::ie::Criticality::{crit}, m),",
                p.code
            );
            let _ = writeln!(
                dec,
                "            {} => Ok(Self::{variant}(rt::ie::decode_message(&content)?)),",
                p.code
            );
            codes.push(p.code.to_string());
            let _ = writeln!(code_arms, "            Self::{variant}(_) => {},", p.code);
            let _ = writeln!(
                crit_arms,
                "            Self::{variant}(_) => rt::ie::Criticality::{crit},"
            );
            let _ = writeln!(name_arms, "            Self::{variant}(_) => \"{msg}\",");
            if message_shaped {
                let _ = writeln!(
                    unknown_arms,
                    "            Self::{variant}(m) => &m.unknown_ies,"
                );
                let _ = writeln!(
                    ids_arms,
                    "            Self::{variant}(_) => {variant}::IE_IDS,"
                );
                let _ = writeln!(
                    wire_arms,
                    "            {} => {variant}::wire_ie_ids(content),",
                    p.code
                );
            } else {
                // e.g. the private message, whose container holds private IEs rather than protocol IEs
                let _ = writeln!(unknown_arms, "            Self::{variant}(_) => &[],");
                let _ = writeln!(ids_arms, "            Self::{variant}(_) => &[],");
            }
        }
        Ok(tpl(
            "@DOC@/// One variant per procedure; the procedure code and criticality on the wire are implied by the variant\n/// (the criticality received is not kept).\n#[derive(Debug, Clone, PartialEq, Eq)]\npub enum @N@ {\n@DECL@}\n\nimpl rt::AperEncode for @N@ {\n    fn aper_encode(&self, w: &mut rt::BitWriter) -> rt::Result<()> {\n        match self {\n@ENC@        }\n    }\n}\n\nimpl rt::AperDecode for @N@ {\n    fn aper_decode(r: &mut rt::BitReader<'_>) -> rt::Result<Self> {\n        let (code, criticality, content) = rt::ie::read_procedure(r)?;\n        match code {\n@DEC@            _ => Err(r.error(rt::ErrorKind::UnknownProcedure { code, criticality })),\n        }\n    }\n}\n\nimpl @N@ {\n    /// The procedure codes that have a variant here.\n    pub const PROCEDURE_CODES: &'static [u16] = &[@CODES@];\n\n    /// The procedure code of the message.\n    pub fn procedure_code(&self) -> u16 {\n        match self {\n@CODE_ARMS@        }\n    }\n\n    /// The criticality of the procedure, as the specification defines it for this message.\n    pub fn criticality(&self) -> rt::ie::Criticality {\n        match self {\n@CRIT_ARMS@        }\n    }\n\n    /// The ASN.1 name of the message type, e.g. `NGSetupRequest`.\n    pub fn message_name(&self) -> &'static str {\n        match self {\n@NAME_ARMS@        }\n    }\n\n    /// The IEs of the message that this version of the specification does not define (kept as received).\n    pub fn unknown_ies(&self) -> &[rt::ie::RawIe] {\n        match self {\n@UNKNOWN_ARMS@        }\n    }\n\n    /// The ids of the IEs the specification defines for the message, in the required wire order.\n    pub fn ie_ids(&self) -> &'static [u32] {\n        match self {\n@IDS_ARMS@        }\n    }\n\n    /// The ids of the IEs in the encoded message `content` of procedure `code`, in the order received;\n    /// `None` if `code` has no variant here.\n    pub fn wire_ie_ids(code: u16, content: &[u8]) -> Option<rt::Result<Vec<u32>>> {\n        Some(match code {\n@WIRE_ARMS@            _ => return None,\n        })\n    }\n}\n",
            &[
                ("DOC", doc),
                ("N", name),
                ("DECL", &decl),
                ("ENC", &enc),
                ("DEC", &dec),
                ("CODES", &codes.join(", ")),
                ("CODE_ARMS", &code_arms),
                ("CRIT_ARMS", &crit_arms),
                ("NAME_ARMS", &name_arms),
                ("UNKNOWN_ARMS", &unknown_arms),
                ("IDS_ARMS", &ids_arms),
                ("WIRE_ARMS", &wire_arms),
            ],
        ))
    }

    /// The runtime writes the procedure code as `INTEGER (0..255)`.
    fn check_procedure_code_range(&self) -> Res<()> {
        match self.ir.types.get("ProcedureCode").map(|t| &t.ty) {
            Some(IrType::Integer(r)) if r.lb == Some(0) && r.ub == Some(255) && !r.extensible => {
                Ok(())
            }
            _ => {
                bail("ProcedureCode is not INTEGER (0..255): update ngap_aper::ie::write_procedure")
            }
        }
    }

    // ---- constants

    pub fn constants_code(&mut self) -> Res<String> {
        let mut names = Names::default();
        let mut out = String::from(
            "//! The integer constants of the specification (`id-*` IE ids and procedure codes, `max*` bounds).\n\n",
        );
        for c in &self.ir.consts {
            let rust = screaming(&c.name);
            names.claim(&rust, &c.name).map_err(EmitError)?;
            let ty = match c.ty.as_str() {
                "ProtocolIE-ID" => "u16",
                "ProcedureCode" => "u8",
                _ if (0..=i128::from(u32::MAX)).contains(&c.value) => "u32",
                _ if (0..=i128::from(u64::MAX)).contains(&c.value) => "u64",
                _ => {
                    return bail(format!(
                        "constant {} = {} is negative or too large",
                        c.name, c.value
                    ));
                }
            };
            let _ = writeln!(
                out,
                "/// `{}` ({}).\npub const {rust}: {ty} = {};",
                c.name, c.module, c.value
            );
        }
        Ok(out)
    }
}

fn crit_variant(c: Criticality) -> &'static str {
    match c {
        Criticality::Reject => "Reject",
        Criticality::Ignore => "Ignore",
        Criticality::Notify => "Notify",
    }
}
