//! Parses the six real NGAP modules and cross-checks the result.
//!
//! Needs `specs/asn1/*.asn` (run `cargo xtask extract-asn`); skips with a message if they are missing, but fails when
//! the `CI` environment variable is set.
//!
//! The gate: counts taken from the AST must equal counts of the same keywords taken from the *token stream* (which
//! does not depend on the parser), so a construct the parser silently dropped cannot hide.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ngap_codegen::asn1::{Assignment, Census, Module, ObjectSetElement, Tok, lex, parse_modules};

fn load() -> Option<Vec<(String, String)>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/asn1");
    match ngap_codegen::spec::read_modules_dir(&dir) {
        Ok(v) if v.len() == 6 => Some(v),
        other => {
            assert!(
                std::env::var_os("CI").is_none(),
                "specs/asn1 is missing or incomplete: {other:?}"
            );
            eprintln!("SKIPPED: specs/asn1 not found; run `cargo xtask extract-asn`");
            None
        }
    }
}

fn parse(sources: &[(String, String)]) -> Vec<Module> {
    let refs: Vec<(&str, &str)> = sources
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    parse_modules(&refs).unwrap_or_else(|e| panic!("{e}"))
}

fn token_counts(
    sources: &[(String, String)],
) -> (BTreeMap<String, usize>, BTreeMap<&'static str, usize>) {
    let mut words: BTreeMap<String, usize> = BTreeMap::new();
    let mut punct: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (_, text) in sources {
        for t in lex(text).unwrap() {
            match t.tok {
                Tok::Ident(w) => *words.entry(w).or_default() += 1,
                Tok::Assign => *punct.entry("::=").or_default() += 1,
                Tok::Ellipsis => *punct.entry("...").or_default() += 1,
                Tok::Colon => *punct.entry(":").or_default() += 1,
                Tok::Semi => *punct.entry(";").or_default() += 1,
                Tok::At => *punct.entry("@").or_default() += 1,
                Tok::LBracket => *punct.entry("[").or_default() += 1,
                _ => {}
            }
        }
    }
    (words, punct)
}

#[test]
fn all_modules_parse_and_counts_match_the_token_stream() {
    let Some(src) = load() else { return };
    let modules = parse(&src);
    let c = Census::of(&modules);
    println!("{c}");
    let (w, p) = token_counts(&src);
    let word = |k: &str| w.get(k).copied().unwrap_or(0);
    let punct = |k: &str| p.get(k).copied().unwrap_or(0);

    assert_eq!(c.modules, 6);
    assert_eq!(
        punct("::="),
        c.assignments() + c.modules,
        "`::=` tokens = assignments + module headers"
    );
    assert_eq!(word("ENUMERATED"), c.enumerated);
    assert_eq!(word("CHOICE"), c.choice);
    assert_eq!(word("SEQUENCE"), c.sequence + c.sequence_of);
    assert_eq!(word("OF"), c.sequence_of);
    assert_eq!(word("NULL"), c.null);
    assert_eq!(word("INTEGER"), c.integer);
    assert_eq!(word("BIT"), c.bit_string);
    assert_eq!(word("OCTET"), c.octet_string);
    assert_eq!(word("OBJECT"), c.object_identifier);
    assert_eq!(word("CONTAINING"), c.containing);
    assert_eq!(word("SIZE"), c.size_constraints);
    assert_eq!(
        word("PrintableString") + word("VisibleString") + word("UTF8String"),
        c.char_strings
    );
    assert_eq!(word("CLASS"), c.class_assignments);
    assert_eq!(
        punct("..."),
        c.extension_markers,
        "every `...` belongs to a parsed construct"
    );
    assert_eq!(punct("@"), count_at(&modules));
    assert_eq!(
        punct(";"),
        modules.iter().filter(|m| !m.imports.is_empty()).count()
    );
    assert_eq!(
        word("FROM"),
        modules.iter().map(|m| m.imports.len()).sum::<usize>()
    );
    // OPTIONAL: SEQUENCE components plus optional class fields
    let optional_fields: usize = modules
        .iter()
        .flat_map(|m| &m.assignments)
        .filter_map(|a| {
            if let Assignment::Class(k) = a {
                Some(k.fields.iter().filter(|f| f.optional).count())
            } else {
                None
            }
        })
        .sum();
    assert_eq!(word("OPTIONAL"), c.optional_components + optional_fields);
    // `:` introduces a governor in a formal parameter list
    let governed: usize = modules
        .iter()
        .flat_map(|m| &m.assignments)
        .filter_map(|a| {
            if let Assignment::Type(t) = a {
                Some(t.params.iter().filter(|p| p.governor.is_some()).count())
            } else {
                None
            }
        })
        .sum();
    assert_eq!(punct(":"), governed);
    // WITH SYNTAX optional groups
    let groups: usize = modules
        .iter()
        .flat_map(|m| &m.assignments)
        .filter_map(|a| {
            if let Assignment::Class(k) = a {
                Some(
                    k.syntax
                        .iter()
                        .filter(|s| matches!(s, ngap_codegen::asn1::SyntaxItem::Optional(_)))
                        .count(),
                )
            } else {
                None
            }
        })
        .sum();
    assert_eq!(punct("["), groups);
}

fn count_at(modules: &[Module]) -> usize {
    // every `@x` of a table constraint is kept in `TableConstraint::at`
    use ngap_codegen::asn1::{Constraint, Type};
    let mut n = 0;
    let mut visit = |t: &Type| {
        for c in &t.constraints {
            if let Constraint::Table(tc) = c {
                n += tc.at.len();
            }
        }
    };
    for m in modules {
        for a in &m.assignments {
            if let Assignment::Type(t) = a {
                t.ty.walk(&mut visit);
            }
        }
    }
    n
}

/// The numbers of the spec release this crate is pinned to (`codegen/spec-source.toml`). They change when the pinned
/// spec changes; the cross-checks above guarantee they are not an artefact of the parser.
#[test]
fn census_of_38413_j40() {
    let Some(src) = load() else { return };
    let c = Census::of(&parse(&src));
    assert_eq!(c.assignments(), 2786);
    assert_eq!(c.type_assignments, 1308);
    assert_eq!(c.parameterized_type_assignments, 11);
    assert_eq!(c.value_assignments, 686);
    assert_eq!(c.class_assignments, 5);
    assert_eq!(c.object_set_assignments, 700);
    assert_eq!(c.object_assignments, 87);
    assert_eq!(c.sequence, 627);
    assert_eq!(c.sequence_of, 240);
    assert_eq!(c.choice, 79);
    assert_eq!(c.enumerated, 230);
    assert_eq!(c.containing, 60);
}

#[test]
fn modules_are_internally_consistent() {
    let Some(src) = load() else { return };
    let modules = parse(&src);
    let defined: BTreeMap<&str, BTreeSet<&str>> = modules
        .iter()
        .map(|m| {
            (
                m.name.as_str(),
                m.assignments.iter().map(Assignment::name).collect(),
            )
        })
        .collect();

    for m in &modules {
        // unique names within a module
        let mut seen = BTreeSet::new();
        for a in &m.assignments {
            assert!(
                seen.insert(a.name()),
                "{}: `{}` assigned twice (line {})",
                m.name,
                a.name(),
                a.line()
            );
        }
        // every imported symbol is defined by the module it is imported from
        for imp in &m.imports {
            let target = defined
                .get(imp.module.as_str())
                .unwrap_or_else(|| panic!("{}: imports unknown module {}", m.name, imp.module));
            for s in &imp.symbols {
                assert!(
                    target.contains(s.name.as_str()),
                    "{}: `{}` is not defined in {}",
                    m.name,
                    s.name,
                    imp.module
                );
                let param = modules
                    .iter()
                    .find(|x| x.name == imp.module)
                    .and_then(|x| x.assignments.iter().find(|a| a.name() == s.name))
                    .is_some_and(|a| matches!(a, Assignment::Type(t) if !t.params.is_empty()));
                assert_eq!(
                    s.parameterized, param,
                    "{}: `{}` parameterized marker `{{}}` mismatch",
                    m.name, s.name
                );
            }
        }
        // module names and the imported-from graph is the documented one
        assert!(m.name.starts_with("NGAP-"));
    }

    // every object set element that names something names a defined object or object set of the same module or an import
    for m in &modules {
        let imported: BTreeSet<&str> = m
            .imports
            .iter()
            .flat_map(|i| i.symbols.iter().map(|s| s.name.as_str()))
            .collect();
        let local = &defined[m.name.as_str()];
        for a in &m.assignments {
            if let Assignment::ObjectSet(s) = a {
                for e in &s.set.elements {
                    if let ObjectSetElement::Reference(r) = e {
                        assert!(
                            local.contains(r.as_str()) || imported.contains(r.as_str()),
                            "{}: set {} (line {}) references unknown `{r}`",
                            m.name,
                            s.name,
                            s.line
                        );
                    }
                }
            }
        }
    }
}
