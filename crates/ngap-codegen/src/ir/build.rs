//! AST -> IR.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::*;
use crate::asn1::{
    ActualParam, Assignment, Bound, ClassAssignment, Constraint, Elem, ElementSet, FieldKind,
    FieldValue, Governor, Module, Object, ObjectSet, ObjectSetAssignment, ObjectSetElement, Type,
    TypeKind, Value,
};

type Res<T> = Result<T, IrError>;

/// Resolve the parsed modules into the [`Ir`] and validate it.
pub fn build_ir(modules: &[Module]) -> Res<Ir> {
    let ir = Builder::new(modules)?.build()?;
    super::validate::validate(&ir)?;
    Ok(ir)
}

/// What a formal parameter is bound to while a parameterized type is instantiated.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Actual {
    Int(i128),
    /// An object set, by name.
    Set(String),
}

type Env = HashMap<String, Actual>;

/// Where we are, for scope checks and error messages.
#[derive(Clone, Copy)]
struct Cx<'c> {
    module: &'c str,
    item: &'c str,
    line: u32,
    env: &'c Env,
}

impl Cx<'_> {
    fn err<T>(&self, message: impl Into<String>) -> Res<T> {
        Err(IrError {
            module: self.module.to_owned(),
            item: self.item.to_owned(),
            line: self.line,
            message: message.into(),
        })
    }
}

struct Scope<'a> {
    defined: HashSet<&'a str>,
    imported: HashSet<&'a str>,
}

struct Template<'a> {
    assignment: &'a crate::asn1::TypeAssignment,
    module: &'a str,
}

/// An object or object set assignment, for reference resolution.
#[derive(Clone, Copy)]
struct ObjInfo<'a> {
    class: &'a str,
    is_set: bool,
}

struct Builder<'a> {
    modules: &'a [Module],
    scopes: HashMap<&'a str, Scope<'a>>,
    classes: HashMap<&'a str, &'a ClassAssignment>,
    templates: HashMap<&'a str, Template<'a>>,
    objects: HashMap<&'a str, ObjInfo<'a>>,
    set_asts: HashMap<&'a str, &'a ObjectSetAssignment>,
    const_values: HashMap<String, i128>,
}

fn top_err<T>(module: &str, item: &str, line: u32, message: impl Into<String>) -> Res<T> {
    Err(IrError {
        module: module.to_owned(),
        item: item.to_owned(),
        line,
        message: message.into(),
    })
}

impl<'a> Builder<'a> {
    fn new(modules: &'a [Module]) -> Res<Self> {
        let mut b = Builder {
            modules,
            scopes: HashMap::new(),
            classes: HashMap::new(),
            templates: HashMap::new(),
            objects: HashMap::new(),
            set_asts: HashMap::new(),
            const_values: HashMap::new(),
        };
        let mut owner: HashMap<&str, &str> = HashMap::new();
        for m in modules {
            let mut defined = HashSet::new();
            for a in &m.assignments {
                if let Some(other) = owner.insert(a.name(), &m.name) {
                    return top_err(
                        &m.name,
                        a.name(),
                        a.line(),
                        format!(
                            "also defined in module {other}; names must be unique across modules"
                        ),
                    );
                }
                defined.insert(a.name());
                match a {
                    Assignment::Class(c) => {
                        b.classes.insert(&c.name, c);
                    }
                    Assignment::Type(t) if !t.params.is_empty() => {
                        b.templates.insert(
                            &t.name,
                            Template {
                                assignment: t,
                                module: &m.name,
                            },
                        );
                    }
                    Assignment::ObjectSet(s) => {
                        b.objects.insert(
                            &s.name,
                            ObjInfo {
                                class: &s.class,
                                is_set: true,
                            },
                        );
                        b.set_asts.insert(&s.name, s);
                    }
                    Assignment::Object(o) => {
                        b.objects.insert(
                            &o.name,
                            ObjInfo {
                                class: &o.class,
                                is_set: false,
                            },
                        );
                    }
                    _ => {}
                }
            }
            b.scopes.insert(
                &m.name,
                Scope {
                    defined,
                    imported: HashSet::new(),
                },
            );
        }
        for m in modules {
            for imp in &m.imports {
                let Some(target) = b.scopes.get(imp.module.as_str()) else {
                    return top_err(
                        &m.name,
                        "IMPORTS",
                        1,
                        format!("imports from unknown module {}", imp.module),
                    );
                };
                for s in &imp.symbols {
                    if !target.defined.contains(s.name.as_str()) {
                        return top_err(
                            &m.name,
                            "IMPORTS",
                            1,
                            format!("`{}` is not defined in {}", s.name, imp.module),
                        );
                    }
                }
                let names: Vec<&str> = imp.symbols.iter().map(|s| s.name.as_str()).collect();
                let scope = b.scopes.get_mut(m.name.as_str()).expect("scope exists");
                scope.imported.extend(names);
            }
        }
        b.resolve_consts()?;
        Ok(b)
    }

    // ---- constants

    fn resolve_consts(&mut self) -> Res<()> {
        let defs: HashMap<&str, (&crate::asn1::ValueAssignment, &str)> = self
            .modules
            .iter()
            .flat_map(|m| m.assignments.iter().map(move |a| (a, m.name.as_str())))
            .filter_map(|(a, m)| {
                if let Assignment::Value(v) = a {
                    Some((v.name.as_str(), (v, m)))
                } else {
                    None
                }
            })
            .collect();
        let mut done: HashMap<String, i128> = HashMap::new();
        for (name, (v, module)) in &defs {
            let mut chain = Vec::new();
            let mut cur = *name;
            let value = loop {
                let (va, _) = defs[cur];
                match &va.value {
                    Value::Integer(n) => break *n,
                    Value::Ident(next) => {
                        if let Some(x) = done.get(next.as_str()) {
                            break *x;
                        }
                        if chain.len() > 32 || !defs.contains_key(next.as_str()) {
                            return top_err(
                                module,
                                &v.name,
                                v.line,
                                format!("cannot evaluate `{next}`"),
                            );
                        }
                        chain.push(cur);
                        cur = next.as_str();
                    }
                }
            };
            done.insert((*name).to_owned(), value);
        }
        self.const_values = done;
        Ok(())
    }

    fn in_scope(&self, module: &str, name: &str) -> bool {
        self.scopes
            .get(module)
            .is_some_and(|s| s.defined.contains(name) || s.imported.contains(name))
    }

    // ---- top level

    fn build(&self) -> Res<Ir> {
        let mut ir = Ir::default();
        let no_env = Env::new();

        for m in self.modules {
            for a in &m.assignments {
                match a {
                    Assignment::Value(v) => {
                        let ty = match &v.ty.kind {
                            TypeKind::Integer => "INTEGER".to_owned(),
                            TypeKind::Reference(r) if r.args.is_empty() => r.name.clone(),
                            _ => {
                                return top_err(
                                    &m.name,
                                    &v.name,
                                    v.line,
                                    "unsupported type of a value assignment",
                                );
                            }
                        };
                        let value = self.const_values[&v.name];
                        ir.consts.insert(
                            &v.name,
                            Const {
                                name: v.name.clone(),
                                module: m.name.clone(),
                                ty,
                                value,
                            },
                        );
                    }
                    Assignment::Type(t) if t.params.is_empty() => {
                        let cx = Cx {
                            module: &m.name,
                            item: &t.name,
                            line: t.line,
                            env: &no_env,
                        };
                        let ty = self.lower_type(&t.ty, &cx, 0)?;
                        ir.types.insert(
                            &t.name,
                            NamedType {
                                name: t.name.clone(),
                                module: m.name.clone(),
                                line: t.line,
                                ty,
                            },
                        );
                    }
                    Assignment::ObjectSet(s) => {
                        let set = self.lower_set(s, &m.name)?;
                        ir.sets.insert(&s.name, set);
                    }
                    Assignment::Object(o) => {
                        let cx = Cx {
                            module: &m.name,
                            item: &o.name,
                            line: o.line,
                            env: &no_env,
                        };
                        if self.classify(&o.class, &cx)? != SetKind::ElementaryProcedures {
                            return cx
                                .err(format!("objects of class {} are not supported", o.class));
                        }
                        ir.procedures.insert(
                            &o.name,
                            self.lower_procedure(&o.name, &o.class, &o.object, &cx)?,
                        );
                    }
                    _ => {}
                }
            }
        }
        Ok(ir)
    }

    // ---- types

    fn lower_type(&self, ty: &Type, cx: &Cx, depth: usize) -> Res<IrType> {
        let cons = &ty.constraints;
        Ok(match &ty.kind {
            TypeKind::Null => {
                self.no_constraints(cons, cx)?;
                IrType::Null
            }
            TypeKind::Integer => IrType::Integer(self.int_range(cons, cx)?),
            TypeKind::Enumerated(e) => {
                self.no_constraints(cons, cx)?;
                IrType::Enumerated(self.lower_enum(e, cx)?)
            }
            TypeKind::BitString => IrType::BitString(self.size(cons, cx)?),
            TypeKind::OctetString => {
                let (size, contained) = self.octet_constraints(cons, cx, depth)?;
                IrType::OctetString { size, contained }
            }
            TypeKind::ObjectIdentifier => {
                self.no_constraints(cons, cx)?;
                IrType::ObjectIdentifier
            }
            TypeKind::CharString(kind) => IrType::CharString {
                kind: *kind,
                size: self.size(cons, cx)?,
            },
            TypeKind::Sequence(s) => {
                self.no_constraints(cons, cx)?;
                if s.root
                    .iter()
                    .any(|c| matches!(c.ty.kind, TypeKind::FieldRef { .. }))
                {
                    self.lower_table(s, cx)?
                } else {
                    self.lower_sequence(s, cx, depth)?
                }
            }
            TypeKind::SequenceOf(element) => IrType::SequenceOf {
                size: self.size(cons, cx)?,
                element: Box::new(self.lower_type(element, cx, depth)?),
            },
            TypeKind::Choice(c) => {
                self.no_constraints(cons, cx)?;
                self.lower_choice(c, cx, depth)?
            }
            TypeKind::Reference(r) => {
                if !cons.is_empty() {
                    return cx.err(format!(
                        "a constraint on the reference to `{}` is not supported",
                        r.name
                    ));
                }
                if !self.in_scope(cx.module, &r.name) {
                    return cx.err(format!(
                        "`{}` is not defined or imported in module {}",
                        r.name, cx.module
                    ));
                }
                if r.args.is_empty() {
                    if self.templates.contains_key(r.name.as_str()) {
                        return cx.err(format!(
                            "parameterized type `{}` used without arguments",
                            r.name
                        ));
                    }
                    if self.classes.contains_key(r.name.as_str()) {
                        return cx.err(format!("`{}` is a class, not a type", r.name));
                    }
                    IrType::Named(r.name.clone())
                } else {
                    self.instantiate(r, cx, depth)?
                }
            }
            TypeKind::FieldRef { class, field } => {
                return cx.err(format!("`{class}.&{field}` is only supported as a component of a table-constrained SEQUENCE"));
            }
        })
    }

    fn no_constraints(&self, cons: &[Constraint], cx: &Cx) -> Res<()> {
        if cons.is_empty() {
            Ok(())
        } else {
            cx.err("unexpected constraint on this type")
        }
    }

    fn lower_enum(&self, e: &crate::asn1::Enumerated, cx: &Cx) -> Res<IrEnum> {
        let adds: &[crate::asn1::EnumItem] = e.additions.as_deref().unwrap_or(&[]);
        let mut names = HashSet::new();
        for i in e.root.iter().chain(adds) {
            if !names.insert(i.name.as_str()) {
                return cx.err(format!("duplicate enumeration item `{}`", i.name));
            }
        }
        // automatic numbering: the lowest value not used explicitly or earlier
        let mut used: HashSet<i128> = e.root.iter().chain(adds).filter_map(|i| i.value).collect();
        let mut next = 0i128;
        let mut number = |explicit: Option<i128>| match explicit {
            Some(v) => v,
            None => {
                while used.contains(&next) {
                    next += 1;
                }
                used.insert(next);
                next
            }
        };
        let root_vals: Vec<i128> = e.root.iter().map(|i| number(i.value)).collect();
        let mut sorted = root_vals.clone();
        sorted.sort_unstable();
        let root = e
            .root
            .iter()
            .zip(&root_vals)
            .map(|(i, &v)| IrEnumItem {
                name: i.name.clone(),
                value: v,
                index: sorted.iter().position(|&s| s == v).unwrap() as u64,
            })
            .collect();
        let additions = adds
            .iter()
            .enumerate()
            .map(|(k, i)| IrEnumItem {
                name: i.name.clone(),
                value: number(i.value),
                index: k as u64,
            })
            .collect();
        Ok(IrEnum {
            root,
            extensible: e.additions.is_some(),
            additions,
        })
    }

    fn lower_sequence(&self, s: &crate::asn1::Sequence, cx: &Cx, depth: usize) -> Res<IrType> {
        let mut names = HashSet::new();
        let mut comps = |list: &[crate::asn1::Component]| -> Res<Vec<IrComponent>> {
            list.iter()
                .map(|c| {
                    if !names.insert(c.name.clone()) {
                        return cx.err(format!("duplicate component `{}`", c.name));
                    }
                    if c.default.is_some() {
                        return cx.err(format!("DEFAULT component `{}` is not supported", c.name));
                    }
                    Ok(IrComponent {
                        name: c.name.clone(),
                        ty: self.lower_type(&c.ty, cx, depth)?,
                        optional: c.optional,
                    })
                })
                .collect()
        };
        let root = comps(&s.root)?;
        let additions = comps(&s.additions)?;
        Ok(IrType::Sequence(IrSequence {
            root,
            extensible: s.additions_marker,
            additions,
        }))
    }

    fn lower_choice(&self, c: &crate::asn1::Choice, cx: &Cx, depth: usize) -> Res<IrType> {
        let mut names = HashSet::new();
        let mut alts = |list: &[crate::asn1::Alternative]| -> Res<Vec<IrAlternative>> {
            list.iter()
                .map(|a| {
                    if !names.insert(a.name.clone()) {
                        return cx.err(format!("duplicate alternative `{}`", a.name));
                    }
                    Ok(IrAlternative {
                        name: a.name.clone(),
                        ty: self.lower_type(&a.ty, cx, depth)?,
                    })
                })
                .collect()
        };
        let root = alts(&c.root)?;
        let additions = alts(&c.additions)?;
        Ok(IrType::Choice(IrChoice {
            root,
            extensible: c.additions_marker,
            additions,
        }))
    }

    /// `SEQUENCE { id CLASS.&id ({Set}), criticality CLASS.&criticality ({Set}{@id}), value CLASS.&Value ({Set}{@id}) }`
    fn lower_table(&self, s: &crate::asn1::Sequence, cx: &Cx) -> Res<IrType> {
        if s.additions_marker || !s.additions.is_empty() || s.root.len() < 2 {
            return cx.err("a table-constrained SEQUENCE needs at least two components and no extension marker");
        }
        let key_name = &s.root[0].name;
        let mut class_name: Option<&str> = None;
        let mut set_name: Option<String> = None;
        let mut components = Vec::new();
        for (i, c) in s.root.iter().enumerate() {
            let TypeKind::FieldRef { class, field } = &c.ty.kind else {
                return cx.err(format!("component `{}`: every component of a table-constrained SEQUENCE must be a class field reference", c.name));
            };
            let [Constraint::Table(tc)] = c.ty.constraints.as_slice() else {
                return cx.err(format!(
                    "component `{}`: expected exactly one table constraint",
                    c.name
                ));
            };
            let expected_at: &[String] = if i == 0 {
                &[]
            } else {
                std::slice::from_ref(key_name)
            };
            if tc.at != expected_at {
                return cx.err(format!(
                    "component `{}`: the component relation must be {:?}, found {:?}",
                    c.name, expected_at, tc.at
                ));
            }
            if *class_name.get_or_insert(class) != class {
                return cx.err("a table-constrained SEQUENCE mixes several classes");
            }
            let set = self.resolve_set(&tc.set, cx)?;
            if *set_name.get_or_insert_with(|| set.clone()) != set {
                return cx.err("a table-constrained SEQUENCE mixes several object sets");
            }
            let Some(class_def) = self.classes.get(class.as_str()) else {
                return cx.err(format!("unknown class `{class}`"));
            };
            let Some(cf) = class_def.field(field) else {
                return cx.err(format!("class {class} has no field &{field}"));
            };
            let role =
                if i == 0 {
                    TableRole::Key
                } else {
                    match &cf.kind {
                        FieldKind::Type => TableRole::Value,
                        FieldKind::FixedTypeValue(Type {
                            kind: TypeKind::Reference(r),
                            ..
                        }) if r.name == "Criticality" => TableRole::Criticality,
                        _ => return cx.err(format!(
                            "component `{}`: &{field} is neither a type field nor a Criticality",
                            c.name
                        )),
                    }
                };
            components.push(TableComponent {
                name: c.name.clone(),
                field: field.clone(),
                role,
            });
        }
        let class = class_name.expect("at least two components").to_owned();
        let set = set_name.expect("at least two components");
        if self.objects.get(set.as_str()).map(|o| o.class) != Some(class.as_str()) {
            return cx.err(format!("object set `{set}` is not of class {class}"));
        }
        Ok(IrType::Table(TableSeq {
            class,
            set,
            components,
        }))
    }

    fn resolve_set(&self, set: &ObjectSet, cx: &Cx) -> Res<String> {
        let [ObjectSetElement::Reference(n)] = set.elements.as_slice() else {
            return cx.err(
                "an object set expression other than a single reference is not supported here",
            );
        };
        match cx.env.get(n.as_str()) {
            Some(Actual::Set(s)) => Ok(s.clone()),
            Some(Actual::Int(_)) => {
                cx.err(format!("`{n}` is an integer parameter, not an object set"))
            }
            None => match self.objects.get(n.as_str()) {
                Some(o) if o.is_set && self.in_scope(cx.module, n) => Ok(n.clone()),
                _ => cx.err(format!("`{n}` is not a visible object set")),
            },
        }
    }

    // ---- parameterized types

    fn instantiate(&self, r: &crate::asn1::TypeRef, cx: &Cx, depth: usize) -> Res<IrType> {
        if depth > 8 {
            return cx.err("parameterized types nest too deeply");
        }
        let Some(tpl) = self.templates.get(r.name.as_str()) else {
            return cx.err(format!("`{}` is not a parameterized type", r.name));
        };
        let params = &tpl.assignment.params;
        if params.len() != r.args.len() {
            return cx.err(format!(
                "`{}` takes {} parameters, {} given",
                r.name,
                params.len(),
                r.args.len()
            ));
        }
        let mut env = Env::new();
        for (p, a) in params.iter().zip(&r.args) {
            let actual = match (a, &p.governor) {
                (
                    ActualParam::Value(v),
                    Some(Governor::Type(Type {
                        kind: TypeKind::Integer,
                        ..
                    })),
                ) => Actual::Int(self.eval_value(v, cx)?),
                (ActualParam::ObjectSet(s), Some(Governor::Class(class))) => {
                    let set = self.resolve_set(s, cx)?;
                    if self.objects.get(set.as_str()).map(|o| o.class) != Some(class.as_str()) {
                        return cx.err(format!(
                            "object set `{set}` is not of class {class} (parameter `{}` of `{}`)",
                            p.name, r.name
                        ));
                    }
                    Actual::Set(set)
                }
                _ => {
                    return cx.err(format!(
                        "argument for parameter `{}` of `{}` has the wrong kind",
                        p.name, r.name
                    ));
                }
            };
            env.insert(p.name.clone(), actual);
        }
        let inner = Cx {
            module: tpl.module,
            item: cx.item,
            line: cx.line,
            env: &env,
        };
        self.lower_type(&tpl.assignment.ty, &inner, depth + 1)
    }

    // ---- constraints

    fn eval_value(&self, v: &Value, cx: &Cx) -> Res<i128> {
        match v {
            Value::Integer(n) => Ok(*n),
            Value::Ident(n) => match cx.env.get(n.as_str()) {
                Some(Actual::Int(x)) => Ok(*x),
                Some(Actual::Set(_)) => {
                    cx.err(format!("`{n}` is an object set parameter, not an integer"))
                }
                None => match self.const_values.get(n.as_str()) {
                    Some(x) if self.in_scope(cx.module, n) => Ok(*x),
                    Some(_) => cx.err(format!("constant `{n}` is not imported into {}", cx.module)),
                    None => cx.err(format!("unknown constant `{n}`")),
                },
            },
        }
    }

    fn eval_bound(&self, b: &Bound, cx: &Cx) -> Res<Option<i128>> {
        match b {
            Bound::Value(v) => Ok(Some(self.eval_value(v, cx)?)),
            Bound::Min | Bound::Max => Ok(None),
        }
    }

    /// The union of `Value` / `Range` elements: `(lb, ub)` pairs with `None` for an open end.
    fn ranges(&self, elems: &[Elem], cx: &Cx) -> Res<Vec<(Option<i128>, Option<i128>)>> {
        elems
            .iter()
            .map(|e| match e {
                Elem::Value(v) => {
                    let x = self.eval_value(v, cx)?;
                    Ok((Some(x), Some(x)))
                }
                Elem::Range(lo, hi) => {
                    let (lo, hi) = (self.eval_bound(lo, cx)?, self.eval_bound(hi, cx)?);
                    if let (Some(a), Some(b)) = (lo, hi)
                        && a > b
                    {
                        return cx.err(format!("empty range {a}..{b}"));
                    }
                    Ok((lo, hi))
                }
                _ => cx.err("unexpected element in a value constraint"),
            })
            .collect()
    }

    fn subtype_sets<'c>(&self, cons: &'c [Constraint], cx: &Cx) -> Res<Vec<&'c ElementSet>> {
        cons.iter()
            .map(|c| match c {
                Constraint::Subtype(s) => Ok(s),
                Constraint::Table(_) => {
                    cx.err("a table constraint is only supported on class field references")
                }
            })
            .collect()
    }

    fn int_range(&self, cons: &[Constraint], cx: &Cx) -> Res<IntRange> {
        let sets = self.subtype_sets(cons, cx)?;
        let set = match sets.as_slice() {
            [] => return Ok(IntRange::default()),
            [one] => *one,
            _ => return cx.err("several constraints on one INTEGER are not supported"),
        };
        let ranges = self.ranges(&set.root, cx)?;
        let lb = if ranges.iter().any(|r| r.0.is_none()) {
            None
        } else {
            ranges.iter().filter_map(|r| r.0).min()
        };
        let ub = if ranges.iter().any(|r| r.1.is_none()) {
            None
        } else {
            ranges.iter().filter_map(|r| r.1).max()
        };
        let closed = ranges
            .iter()
            .map(|&(a, b)| a.zip(b))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        let additions = match &set.additions {
            Some(elems) => self
                .ranges(elems, cx)?
                .into_iter()
                .map(|(a, b)| match (a, b) {
                    (Some(a), Some(b)) => Ok((a, b)),
                    _ => cx.err("an unbounded range after the extension marker is not supported"),
                })
                .collect::<Res<Vec<_>>>()?,
            None => Vec::new(),
        };
        Ok(IntRange {
            lb,
            ub,
            extensible: set.additions.is_some(),
            ranges: closed,
            additions,
        })
    }

    fn size_of(&self, inner: &ElementSet, outer_ext: bool, cx: &Cx) -> Res<IrSize> {
        let ranges = self.ranges(&inner.root, cx)?;
        let lb = if ranges.iter().any(|r| r.0.is_none()) {
            Some(0)
        } else {
            ranges.iter().filter_map(|r| r.0).min()
        };
        let ub = if ranges.iter().any(|r| r.1.is_none()) {
            None
        } else {
            ranges.iter().filter_map(|r| r.1).max()
        };
        let to_u64 = |x: i128| u64::try_from(x).or_else(|_| cx.err(format!("negative size {x}")));
        Ok(IrSize {
            lb: to_u64(lb.unwrap_or(0))?,
            ub: ub.map(to_u64).transpose()?,
            extensible: inner.additions.is_some() || outer_ext,
        })
    }

    fn size(&self, cons: &[Constraint], cx: &Cx) -> Res<IrSize> {
        let sets = self.subtype_sets(cons, cx)?;
        match sets.as_slice() {
            [] => Ok(IrSize::UNBOUNDED),
            [set] => match set.root.as_slice() {
                [Elem::Size(inner)] => self.size_of(inner, set.additions.is_some(), cx),
                _ => cx.err("expected a SIZE constraint"),
            },
            _ => cx.err("several constraints on one type are not supported"),
        }
    }

    fn octet_constraints(
        &self,
        cons: &[Constraint],
        cx: &Cx,
        depth: usize,
    ) -> Res<(IrSize, Option<Box<IrType>>)> {
        let (mut size, mut contained) = (None, None);
        for set in self.subtype_sets(cons, cx)? {
            match set.root.as_slice() {
                [Elem::Size(inner)] if size.is_none() => {
                    size = Some(self.size_of(inner, set.additions.is_some(), cx)?)
                }
                [Elem::Containing(t)] if contained.is_none() => {
                    contained = Some(Box::new(self.lower_type(t, cx, depth)?))
                }
                _ => return cx.err("expected a SIZE or CONTAINING constraint on an OCTET STRING"),
            }
        }
        Ok((size.unwrap_or(IrSize::UNBOUNDED), contained))
    }

    // ---- information objects

    fn classify(&self, class: &str, cx: &Cx) -> Res<SetKind> {
        let Some(c) = self.classes.get(class) else {
            return cx.err(format!("unknown class `{class}`"));
        };
        let names: BTreeSet<&str> = c.fields.iter().map(|f| f.name.as_str()).collect();
        let is = |want: &[&str]| names == want.iter().copied().collect::<BTreeSet<_>>();
        let id_type = match c.field("id").map(|f| &f.kind) {
            Some(FieldKind::FixedTypeValue(Type {
                kind: TypeKind::Reference(r),
                ..
            })) => r.name.as_str(),
            _ => "",
        };
        if is(&[
            "InitiatingMessage",
            "SuccessfulOutcome",
            "UnsuccessfulOutcome",
            "procedureCode",
            "criticality",
        ]) {
            Ok(SetKind::ElementaryProcedures)
        } else if is(&["id", "criticality", "Value", "presence"]) {
            Ok(if id_type == "PrivateIE-ID" {
                SetKind::PrivateIes
            } else {
                SetKind::ProtocolIes
            })
        } else if is(&["id", "criticality", "Extension", "presence"]) {
            Ok(SetKind::ProtocolExtensions)
        } else if is(&[
            "id",
            "firstCriticality",
            "FirstValue",
            "secondCriticality",
            "SecondValue",
            "presence",
        ]) {
            Ok(SetKind::ProtocolIesPair)
        } else {
            cx.err(format!(
                "class `{class}` has an unsupported field layout {names:?}"
            ))
        }
    }

    fn lower_set(&self, s: &ObjectSetAssignment, module: &str) -> Res<ObjectSetIr> {
        let no_env = Env::new();
        let cx = Cx {
            module,
            item: &s.name,
            line: s.line,
            env: &no_env,
        };
        let kind = self.classify(&s.class, &cx)?;
        let mut out = ObjectSetIr {
            name: s.name.clone(),
            module: module.to_owned(),
            line: s.line,
            class: s.class.clone(),
            kind,
            extensible: s.set.is_extensible(),
            rows: Vec::new(),
            procedures: Vec::new(),
        };
        match kind {
            SetKind::ElementaryProcedures => {
                let mut visiting = vec![s.name.as_str()];
                self.flatten_procedures(&s.set, &cx, &mut visiting, &mut out.procedures)?;
            }
            SetKind::ProtocolIes | SetKind::ProtocolExtensions => {
                let ty_field = if kind == SetKind::ProtocolIes {
                    "Value"
                } else {
                    "Extension"
                };
                for e in &s.set.elements {
                    match e {
                        ObjectSetElement::Object(o) => {
                            out.rows.push(self.ie_row(o, ty_field, &cx)?)
                        }
                        ObjectSetElement::Extension => {}
                        ObjectSetElement::Reference(r) => {
                            return cx
                                .err(format!("reference `{r}` inside an IE set is not supported"));
                        }
                    }
                }
            }
            SetKind::PrivateIes | SetKind::ProtocolIesPair => {
                if s.set
                    .elements
                    .iter()
                    .any(|e| !matches!(e, ObjectSetElement::Extension))
                {
                    return cx.err(format!(
                        "rows in a {kind:?} set are not supported (NGAP defines none)"
                    ));
                }
            }
        }
        Ok(out)
    }

    fn flatten_procedures<'s>(
        &'s self,
        set: &'s ObjectSet,
        cx: &Cx,
        visiting: &mut Vec<&'s str>,
        out: &mut Vec<String>,
    ) -> Res<()> {
        for e in &set.elements {
            match e {
                ObjectSetElement::Extension => {}
                ObjectSetElement::Object(_) => {
                    return cx.err("inline procedure objects are not supported");
                }
                ObjectSetElement::Reference(r) => match self.objects.get(r.as_str()) {
                    Some(o) if o.is_set => {
                        if visiting.contains(&r.as_str()) {
                            return cx.err(format!("object set `{r}` includes itself"));
                        }
                        visiting.push(r);
                        self.flatten_procedures(&self.set_asts[r.as_str()].set, cx, visiting, out)?;
                        visiting.pop();
                    }
                    Some(_) => out.push(r.clone()),
                    None => return cx.err(format!("`{r}` is not an object or object set")),
                },
            }
        }
        Ok(())
    }

    fn field_value<'o>(&self, o: &'o Object, name: &str, cx: &Cx) -> Res<&'o FieldValue> {
        o.field(name)
            .map_or_else(|| cx.err(format!("object lacks field &{name}")), Ok)
    }

    fn ident_field<'o>(&self, o: &'o Object, name: &str, cx: &Cx) -> Res<&'o str> {
        match self.field_value(o, name, cx)? {
            FieldValue::Value(Value::Ident(s)) => Ok(s),
            _ => cx.err(format!("&{name} must be an identifier")),
        }
    }

    fn value_field(&self, o: &Object, name: &str, cx: &Cx) -> Res<i128> {
        match self.field_value(o, name, cx)? {
            FieldValue::Value(v) => self.eval_value(v, cx),
            FieldValue::Type(_) => cx.err(format!("&{name} must be a value")),
        }
    }

    fn type_field(&self, o: &Object, name: &str, cx: &Cx) -> Res<IrType> {
        match self.field_value(o, name, cx)? {
            FieldValue::Type(t) => self.lower_type(t, cx, 0),
            FieldValue::Value(_) => cx.err(format!("&{name} must be a type")),
        }
    }

    fn criticality(&self, s: &str, cx: &Cx) -> Res<Criticality> {
        match s {
            "reject" => Ok(Criticality::Reject),
            "ignore" => Ok(Criticality::Ignore),
            "notify" => Ok(Criticality::Notify),
            _ => cx.err(format!("`{s}` is not a criticality")),
        }
    }

    fn ie_row(&self, o: &Object, ty_field: &str, cx: &Cx) -> Res<IeRow> {
        let id = self.value_field(o, "id", cx)?;
        let id = u32::try_from(id).or_else(|_| cx.err(format!("IE id {id} out of range")))?;
        let presence = match self.ident_field(o, "presence", cx)? {
            "optional" => Presence::Optional,
            "conditional" => Presence::Conditional,
            "mandatory" => Presence::Mandatory,
            other => return cx.err(format!("`{other}` is not a presence")),
        };
        let id_name = match o.field("id") {
            Some(FieldValue::Value(Value::Ident(n))) => Some(n.clone()),
            _ => None,
        };
        Ok(IeRow {
            id,
            id_name,
            criticality: self.criticality(self.ident_field(o, "criticality", cx)?, cx)?,
            presence,
            ty: self.type_field(o, ty_field, cx)?,
        })
    }

    fn message_name(&self, o: &Object, field: &str, cx: &Cx) -> Res<Option<String>> {
        match o.field(field) {
            None => Ok(None),
            Some(FieldValue::Type(Type {
                kind: TypeKind::Reference(r),
                constraints,
            })) if r.args.is_empty() && constraints.is_empty() => {
                if !self.in_scope(cx.module, &r.name) {
                    return cx.err(format!("`{}` is not visible in {}", r.name, cx.module));
                }
                Ok(Some(r.name.clone()))
            }
            Some(_) => cx.err(format!("&{field} must name a type")),
        }
    }

    fn lower_procedure(&self, name: &str, class: &str, o: &Object, cx: &Cx) -> Res<Procedure> {
        let code = self.value_field(o, "procedureCode", cx)?;
        let code = u16::try_from(code)
            .or_else(|_| cx.err(format!("procedure code {code} out of range")))?;
        let criticality = match o.field("criticality") {
            Some(_) => self.criticality(self.ident_field(o, "criticality", cx)?, cx)?,
            None => {
                let default = self.classes[class]
                    .field("criticality")
                    .and_then(|f| f.default.as_ref());
                match default {
                    Some(Value::Ident(s)) => self.criticality(s, cx)?,
                    _ => {
                        return cx.err("procedure has no criticality and the class has no default");
                    }
                }
            }
        };
        let initiating = self
            .message_name(o, "InitiatingMessage", cx)?
            .map_or_else(|| cx.err("missing InitiatingMessage"), Ok)?;
        let successful = self.message_name(o, "SuccessfulOutcome", cx)?;
        let unsuccessful = self.message_name(o, "UnsuccessfulOutcome", cx)?;
        let class = if successful.is_some() || unsuccessful.is_some() {
            ProcedureClass::Class1
        } else {
            ProcedureClass::Class2
        };
        Ok(Procedure {
            name: name.to_owned(),
            module: cx.module.to_owned(),
            line: cx.line,
            code,
            criticality,
            class,
            initiating,
            successful,
            unsuccessful,
        })
    }
}
