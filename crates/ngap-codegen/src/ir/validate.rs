//! Whole-IR consistency checks.

use std::collections::{HashMap, HashSet};

use super::*;

type Res<T> = Result<T, IrError>;

fn err<T>(module: &str, item: &str, line: u32, message: impl Into<String>) -> Res<T> {
    Err(IrError {
        module: module.to_owned(),
        item: item.to_owned(),
        line,
        message: message.into(),
    })
}

/// Visit `ty` and every type nested in it, except the object-set rows behind a [`TableSeq`].
pub(super) fn walk(ty: &IrType, f: &mut impl FnMut(&IrType)) {
    f(ty);
    match ty {
        IrType::Sequence(s) => s
            .root
            .iter()
            .chain(&s.additions)
            .for_each(|c| walk(&c.ty, f)),
        IrType::Choice(c) => c
            .root
            .iter()
            .chain(&c.additions)
            .for_each(|a| walk(&a.ty, f)),
        IrType::SequenceOf { element, .. } => walk(element, f),
        IrType::OctetString {
            contained: Some(t), ..
        } => walk(t, f),
        _ => {}
    }
}

pub(super) fn validate(ir: &Ir) -> Res<()> {
    // references inside types and rows resolve; tables point at sets of their class
    for t in &ir.types {
        let mut result = Ok(());
        walk(&t.ty, &mut |n| {
            if result.is_err() {
                return;
            }
            result = check_node(ir, n, &t.module, &t.name, t.line);
        });
        result?;
    }
    for s in &ir.sets {
        let mut seen = HashSet::new();
        let id_range = ir.types.get("ProtocolIE-ID").and_then(|t| {
            if let IrType::Integer(r) = &t.ty {
                Some(r.clone())
            } else {
                None
            }
        });
        for row in &s.rows {
            if !seen.insert(row.id) {
                return err(
                    &s.module,
                    &s.name,
                    0,
                    format!("IE id {} appears twice", row.id),
                );
            }
            if let Some(r) = &id_range
                && (r.lb.is_some_and(|lb| i128::from(row.id) < lb)
                    || r.ub.is_some_and(|ub| i128::from(row.id) > ub))
            {
                return err(
                    &s.module,
                    &s.name,
                    0,
                    format!("IE id {} is outside the range of ProtocolIE-ID", row.id),
                );
            }
            let mut result = Ok(());
            walk(&row.ty, &mut |n| {
                if result.is_ok() {
                    result = check_node(ir, n, &s.module, &s.name, s.line);
                }
            });
            result?;
        }
        for p in &s.procedures {
            if !ir.procedures.contains(p) {
                return err(
                    &s.module,
                    &s.name,
                    0,
                    format!("lists unknown procedure `{p}`"),
                );
            }
        }
    }
    check_procedures(ir)?;
    check_pdu(ir)?;
    Ok(())
}

fn check_node(ir: &Ir, n: &IrType, module: &str, item: &str, line: u32) -> Res<()> {
    match n {
        IrType::Named(name) if !ir.types.contains(name) => err(
            module,
            item,
            line,
            format!("reference to undefined type `{name}`"),
        ),
        IrType::Table(t) => match ir.sets.get(&t.set) {
            Some(s) if s.class == t.class => Ok(()),
            Some(s) => err(
                module,
                item,
                line,
                format!(
                    "table over set `{}` of class {}, expected {}",
                    s.name, s.class, t.class
                ),
            ),
            None => err(
                module,
                item,
                line,
                format!("table over unknown object set `{}`", t.set),
            ),
        },
        _ => Ok(()),
    }
}

fn check_procedures(ir: &Ir) -> Res<()> {
    let code_range = ir.types.get("ProcedureCode").and_then(|t| {
        if let IrType::Integer(r) = &t.ty {
            Some(r.clone())
        } else {
            None
        }
    });
    let mut codes: HashMap<u16, &str> = HashMap::new();
    for p in &ir.procedures {
        if let Some(other) = codes.insert(p.code, &p.name) {
            return err(
                "",
                &p.name,
                0,
                format!("procedure code {} is also used by `{other}`", p.code),
            );
        }
        if let Some(r) = &code_range
            && (r.lb.is_some_and(|lb| i128::from(p.code) < lb)
                || r.ub.is_some_and(|ub| i128::from(p.code) > ub))
        {
            return err(
                "",
                &p.name,
                0,
                format!(
                    "procedure code {} is outside the range of ProcedureCode",
                    p.code
                ),
            );
        }
        let messages = [
            Some(&p.initiating),
            p.successful.as_ref(),
            p.unsuccessful.as_ref(),
        ];
        for m in messages.into_iter().flatten() {
            let Some(t) = ir.types.get(m) else {
                return err(
                    &p.module,
                    &p.name,
                    p.line,
                    format!("message type `{m}` is not defined"),
                );
            };
            if !matches!(&t.ty, IrType::Sequence(s) if s.root.iter().any(|c| is_ie_container(&c.ty)))
            {
                return err(
                    &t.module,
                    m,
                    t.line,
                    "a message must be a SEQUENCE with an IE container component",
                );
            }
        }
    }
    // class membership agrees with the CLASS-1 / CLASS-2 sets, and the union set lists every procedure
    let members = |set: &str| {
        ir.sets.get(set).map(|s| {
            s.procedures
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>()
        })
    };
    if let Some(c1) = members("NGAP-ELEMENTARY-PROCEDURES-CLASS-1") {
        for p in &ir.procedures {
            if (p.class == ProcedureClass::Class1) != c1.contains(p.name.as_str()) {
                return err(
                    "",
                    &p.name,
                    0,
                    "its class (response messages present or not) disagrees with NGAP-ELEMENTARY-PROCEDURES-CLASS-1",
                );
            }
        }
    }
    if let Some(all) = members("NGAP-ELEMENTARY-PROCEDURES") {
        for p in &ir.procedures {
            if !all.contains(p.name.as_str()) {
                return err(
                    &p.module,
                    &p.name,
                    p.line,
                    "is not in NGAP-ELEMENTARY-PROCEDURES",
                );
            }
        }
        if all.len() != ir.procedures.len() {
            return err(
                "",
                "NGAP-ELEMENTARY-PROCEDURES",
                0,
                "does not match the procedure objects",
            );
        }
    }
    Ok(())
}

/// A component holding IEs: a (list of) table over a `NGAP-PROTOCOL-IES`-like set.
fn is_ie_container(ty: &IrType) -> bool {
    match ty {
        IrType::SequenceOf { element, .. } => matches!(element.as_ref(), IrType::Table(_)),
        IrType::Table(_) => true,
        _ => false,
    }
}

fn check_pdu(ir: &Ir) -> Res<()> {
    let Some(pdu) = ir.types.get("NGAP-PDU") else {
        return Ok(());
    };
    let IrType::Choice(c) = &pdu.ty else {
        return err(
            &pdu.module,
            &pdu.name,
            pdu.line,
            "NGAP-PDU must be a CHOICE",
        );
    };
    let expect = [
        ("initiatingMessage", "InitiatingMessage"),
        ("successfulOutcome", "SuccessfulOutcome"),
        ("unsuccessfulOutcome", "UnsuccessfulOutcome"),
    ];
    if c.root.len() != 3 || !c.extensible {
        return err(
            &pdu.module,
            &pdu.name,
            pdu.line,
            "NGAP-PDU must have three alternatives and an extension marker",
        );
    }
    for (alt, (name, field)) in c.root.iter().zip(expect) {
        let IrType::Named(tn) = &alt.ty else {
            return err(
                &pdu.module,
                &pdu.name,
                pdu.line,
                format!("alternative `{}` must be a type name", alt.name),
            );
        };
        let t = ir.types.get(tn);
        let ok = alt.name == name
            && matches!(t.map(|t| &t.ty), Some(IrType::Table(tab)) if tab.class == "NGAP-ELEMENTARY-PROCEDURE"
                && tab.components.len() == 3
                && tab.components[2].field == field
                && tab.components[2].role == TableRole::Value);
        if !ok {
            return err(
                &pdu.module,
                &pdu.name,
                pdu.line,
                format!("alternative `{name}` is not a procedure table over &{field}"),
            );
        }
    }
    Ok(())
}

/// Groups of named types that (transitively) contain themselves by value. A generated Rust type in such a group
/// needs indirection (`Box`). Octet strings that merely *contain* a type are not edges (they hold raw bytes).
pub fn recursive_groups(ir: &Ir) -> Vec<Vec<String>> {
    let names: Vec<&str> = ir.types.iter().map(|t| t.name.as_str()).collect();
    let pos: HashMap<&str, usize> = names.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let edges: Vec<Vec<usize>> = ir
        .types
        .iter()
        .map(|t| {
            let mut out = Vec::new();
            let add_named = |n: &IrType, out: &mut Vec<usize>| {
                if let IrType::Named(x) = n
                    && let Some(&i) = pos.get(x.as_str())
                {
                    out.push(i);
                }
            };
            // `walk` descends into CONTAINING; skip those by collecting only direct structure
            direct_refs(&t.ty, &mut |n| add_named(n, &mut out));
            let mut sets = Vec::new();
            direct_refs(&t.ty, &mut |n| {
                if let IrType::Table(tab) = n {
                    sets.push(tab.set.clone());
                }
            });
            for s in sets {
                if let Some(set) = ir.sets.get(&s) {
                    for row in &set.rows {
                        direct_refs(&row.ty, &mut |n| add_named(n, &mut out));
                    }
                }
            }
            out
        })
        .collect();

    // Tarjan's strongly connected components
    struct St<'e> {
        edges: &'e [Vec<usize>],
        index: Vec<Option<usize>>,
        low: Vec<usize>,
        on: Vec<bool>,
        stack: Vec<usize>,
        next: usize,
        groups: Vec<Vec<usize>>,
    }
    fn visit(s: &mut St, v: usize) {
        s.index[v] = Some(s.next);
        s.low[v] = s.next;
        s.next += 1;
        s.stack.push(v);
        s.on[v] = true;
        for &w in &s.edges[v] {
            match s.index[w] {
                None => {
                    visit(s, w);
                    s.low[v] = s.low[v].min(s.low[w]);
                }
                Some(iw) if s.on[w] => s.low[v] = s.low[v].min(iw),
                _ => {}
            }
        }
        if Some(s.low[v]) == s.index[v] {
            let mut comp = Vec::new();
            while let Some(w) = s.stack.pop() {
                s.on[w] = false;
                comp.push(w);
                if w == v {
                    break;
                }
            }
            if comp.len() > 1 || s.edges[v].contains(&v) {
                s.groups.push(comp);
            }
        }
    }
    let n = names.len();
    let mut st = St {
        edges: &edges,
        index: vec![None; n],
        low: vec![0; n],
        on: vec![false; n],
        stack: Vec::new(),
        next: 0,
        groups: Vec::new(),
    };
    for v in 0..n {
        if st.index[v].is_none() {
            visit(&mut st, v);
        }
    }
    st.groups
        .into_iter()
        .map(|g| g.into_iter().map(|i| names[i].to_owned()).collect())
        .collect()
}

/// Like [`walk`] but does not descend into `CONTAINING` types.
fn direct_refs(ty: &IrType, f: &mut impl FnMut(&IrType)) {
    f(ty);
    match ty {
        IrType::Sequence(s) => s
            .root
            .iter()
            .chain(&s.additions)
            .for_each(|c| direct_refs(&c.ty, f)),
        IrType::Choice(c) => c
            .root
            .iter()
            .chain(&c.additions)
            .for_each(|a| direct_refs(&a.ty, f)),
        IrType::SequenceOf { element, .. } => direct_refs(element, f),
        _ => {}
    }
}
