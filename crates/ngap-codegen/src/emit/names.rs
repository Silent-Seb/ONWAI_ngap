//! ASN.1 name -> Rust identifier rules (documented in `docs/mapping-rules.md`).

use std::collections::HashMap;

/// Mixed-case technical terms that must stay one word (longest first).
const TOKENS: &[(&str, &str)] = &[
    ("AIoT", "Aiot"),
    ("IoT", "Iot"),
    ("QoS", "Qos"),
    ("QoE", "Qoe"),
    ("ProSe", "Prose"),
    ("A2X", "A2x"),
    ("V2X", "V2x"),
    ("a2X", "a2x"),
    ("v2X", "v2x"),
];

/// Split an ASN.1 name into lowercase words: at `-` / `_`, at lower-to-upper changes, and at the end of an acronym
/// (`PDUSession` -> `pdu`, `session`). A plural acronym (`TAIs`, `IEs`) stays one word. A single lowercase letter
/// before an uppercase one belongs to the acronym (`aMFName` -> `amf`, `name`).
pub fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in s.split(['-', '_']).filter(|c| !c.is_empty()) {
        let mut chunk = chunk.to_owned();
        for (from, to) in TOKENS {
            chunk = chunk.replace(from, to);
        }
        let mut cs: Vec<char> = chunk.chars().collect();
        if cs.len() >= 2 && cs[0].is_ascii_lowercase() && cs[1].is_ascii_uppercase() {
            cs[0] = cs[0].to_ascii_uppercase();
        }
        let mut cur = String::new();
        for i in 0..cs.len() {
            let c = cs[i];
            if i > 0 && c.is_ascii_uppercase() {
                let p = cs[i - 1];
                let next_lower = cs.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
                let plural = cs.get(i + 1) == Some(&'s')
                    && cs.get(i + 2).is_none_or(|n| !n.is_ascii_lowercase());
                let boundary = p.is_ascii_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_ascii_uppercase() && next_lower && !plural);
                if boundary {
                    out.push(std::mem::take(&mut cur).to_ascii_lowercase());
                }
            }
            cur.push(c);
        }
        out.push(cur.to_ascii_lowercase());
    }
    out
}

/// `NGSetupRequest` -> `NgSetupRequest`.
pub fn pascal(s: &str) -> String {
    words(s)
        .iter()
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or_else(String::new, |f| {
                f.to_ascii_uppercase().to_string() + c.as_str()
            })
        })
        .collect()
}

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen",
];

/// `pDUSessionID` -> `pdu_session_id`; Rust keywords get a trailing `_`.
pub fn snake(s: &str) -> String {
    escape(words(s).join("_"))
}

/// Constants: `id-NGSetup` -> `ID_NGSETUP`, `maxnoofTAIs` -> `MAXNOOF_TAIS` (only `-` and lower-to-upper split).
pub fn screaming(s: &str) -> String {
    let mut out = String::new();
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if c == '-' || c == '_' {
            out.push('_');
        } else {
            if c.is_ascii_uppercase()
                && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
            {
                out.push('_');
            }
            out.push(c.to_ascii_uppercase());
        }
        prev = Some(c);
    }
    out
}

fn escape(mut s: String) -> String {
    if s.is_empty() {
        s.push('_');
    }
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    if KEYWORDS.contains(&s.as_str()) {
        s.push('_');
    }
    s
}

/// Names that must not be generated because the generated code (or the prelude) uses them.
const RESERVED_TYPES: &[&str] = &[
    "Option", "Result", "Vec", "String", "Box", "Some", "None", "Ok", "Err", "Self",
];

/// Detects two ASN.1 names that map to the same Rust name.
#[derive(Debug, Default)]
pub struct Names {
    claimed: HashMap<String, String>,
}

impl Names {
    /// Claim `rust` for `origin`; error text if it is taken or reserved.
    pub fn claim(&mut self, rust: &str, origin: &str) -> Result<(), String> {
        if RESERVED_TYPES.contains(&rust) {
            return Err(format!("`{origin}` maps to the reserved name `{rust}`"));
        }
        match self.claimed.insert(rust.to_owned(), origin.to_owned()) {
            Some(other) if other != origin => Err(format!(
                "`{origin}` and `{other}` both map to the Rust name `{rust}`"
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pascal_case_handles_acronyms() {
        for (a, b) in [
            ("NGSetupRequest", "NgSetupRequest"),
            (
                "PDUSessionResourceSetupRequest",
                "PduSessionResourceSetupRequest",
            ),
            ("AMF-UE-NGAP-ID", "AmfUeNgapId"),
            ("S-NSSAI", "SNssai"),
            ("E-RAB-ID", "ERabId"),
            ("RANNodeName", "RanNodeName"),
            ("SupportedTAIs", "SupportedTais"),
            ("UEIdentityIndexValue", "UeIdentityIndexValue"),
            ("initiatingMessage", "InitiatingMessage"),
            ("choice-Extensions", "ChoiceExtensions"),
            ("NR-CGI", "NrCgi"),
            ("n2", "N2"),
            ("m50", "M50"),
            ("AIoT-Support", "AiotSupport"),
            ("A2XPc5QoSFlowItem", "A2xPc5QosFlowItem"),
            ("NB-IoT-DefaultPagingDRX", "NbIotDefaultPagingDrx"),
            ("not-restricted", "NotRestricted"),
        ] {
            assert_eq!(pascal(a), b, "{a}");
        }
    }

    #[test]
    fn snake_case_and_keywords() {
        for (a, b) in [
            ("aMFName", "amf_name"),
            ("rANNodeName", "ran_node_name"),
            ("pDUSessionID", "pdu_session_id"),
            ("iE-Extensions", "ie_extensions"),
            ("iE-Extension", "ie_extension"),
            ("privateIEs", "private_ies"),
            ("gNB-ID", "gnb_id"),
            ("type", "type_"),
            ("AMF-UE-NGAP-ID", "amf_ue_ngap_id"),
            ("sST", "sst"),
            ("aIOTFName", "aiotf_name"),
            ("a2X-Range", "a2x_range"),
            ("alternativeQoSParaSetList", "alternative_qos_para_set_list"),
            (
                "fiveG-ProSeDirectDiscovery",
                "five_g_prose_direct_discovery",
            ),
            ("v2XServicesAuthorized", "v2x_services_authorized"),
        ] {
            assert_eq!(snake(a), b, "{a}");
        }
    }

    #[test]
    fn constants_keep_their_lexical_words() {
        assert_eq!(screaming("id-NGSetup"), "ID_NGSETUP");
        assert_eq!(screaming("maxnoofTAIs"), "MAXNOOF_TAIS");
        assert_eq!(screaming("id-AMF-UE-NGAP-ID"), "ID_AMF_UE_NGAP_ID");
        assert_eq!(screaming("maxProtocolIEs"), "MAX_PROTOCOL_IES");
    }

    #[test]
    fn collisions_are_detected() {
        let mut n = Names::default();
        n.claim("Foo", "foo-A").unwrap();
        n.claim("Foo", "foo-A").unwrap();
        assert!(n.claim("Foo", "FooA").unwrap_err().contains("both map"));
        assert!(n.claim("Option", "Option").is_err());
    }
}
