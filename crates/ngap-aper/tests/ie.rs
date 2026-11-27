//! The IE container machinery (`ngap_aper::ie`) against vectors from `asn1tools`, using hand-written types that
//! follow exactly the pattern the generator emits for messages, extension containers, `choice-Extensions`
//! and the procedure wrapper. See `tools/gen_aper_vectors.py` (`SPEC2`) for the ASN.1.

use std::collections::BTreeMap;

use ngap_aper::ie::{self, Criticality, RawIe, UnknownIes};
use ngap_aper::{
    AperDecode, AperEncode, AperError, BitReader, BitWriter, ErrorKind, IntSpec, Result, Size,
    from_slice, to_vec,
};

fn vectors() -> BTreeMap<String, Vec<u8>> {
    include_str!("vectors.txt")
        .lines()
        .filter_map(|l| l.split_once(" | "))
        .filter(|(k, _)| k.starts_with("ie_"))
        .map(|(k, v)| {
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (k.to_owned(), bytes)
        })
        .collect()
}

/// `TE ::= ENUMERATED { a, b, c }`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Te {
    A,
    B,
    C,
}

impl AperEncode for Te {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_index(*self as u64, 3, false)
    }
}
impl AperDecode for Te {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        Ok(match r.read_index(3, false)? {
            0 => Te::A,
            1 => Te::B,
            _ => Te::C,
        })
    }
}

/// `Msg ::= SEQUENCE { protocolIEs Container {{MsgIEs}}, ... }` flattened, as the generator does it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Msg {
    ti: Option<u8>, // mandatory in the ASN.1: id 1, reject
    to: Option<Vec<u8>>,
    te: Option<Te>,
    unknown_ies: Vec<RawIe>,
}

const MSG_SIZE: Size = Size::range(0, 65535);

impl AperEncode for Msg {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_bit(false); // extension marker
        let mut ies = Vec::new();
        let ti = self
            .ti
            .as_ref()
            .ok_or_else(|| w.error(ErrorKind::ValueOutOfRange))?;
        ies.push(RawIe::with(1, Criticality::Reject, |w| {
            w.write_int(i128::from(*ti), &IntSpec::range(0, 255))
        })?);
        if let Some(v) = &self.to {
            ies.push(RawIe::with(2, Criticality::Ignore, |w| {
                w.write_octet_string(v, Size::fixed(2))
            })?);
        }
        if let Some(v) = &self.te {
            ies.push(RawIe::new(300, Criticality::Notify, v)?);
        }
        ies.extend(self.unknown_ies.iter().cloned());
        ie::write_container(w, MSG_SIZE, &ies)
    }
}

impl AperDecode for Msg {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let ext = r.read_bit()?;
        let (mut ti, mut to, mut te): (Option<u8>, Option<Vec<u8>>, Option<Te>) =
            (None, None, None);
        let mut unknown_ies = Vec::new();
        for ie in ie::read_container(r, MSG_SIZE)? {
            match ie.id {
                1 => ie::set_once(
                    &mut ti,
                    1,
                    ie.decode_with(|r| r.read_int_as::<u8>(&IntSpec::range(0, 255)))?,
                )?,
                2 => ie::set_once(
                    &mut to,
                    2,
                    ie.decode_with(|r| r.read_octet_string(Size::fixed(2)))?,
                )?,
                300 => ie::set_once(&mut te, 300, ie.decode()?)?,
                _ => unknown_ies.push(ie),
            }
        }
        if ext {
            r.read_extension_additions()?;
        }
        ie::required(ti, 1, Criticality::Reject)?; // mandatory
        Ok(Msg {
            ti,
            to,
            te,
            unknown_ies,
        })
    }
}

fn msg(ti: u8) -> Msg {
    Msg {
        ti: Some(ti),
        ..Msg::default()
    }
}

#[test]
fn ie_container_matches_the_oracle() {
    let v = vectors();
    let m = msg(200);
    assert_eq!(to_vec(&m).unwrap(), v["ie_msg_1"]);
    assert_eq!(from_slice::<Msg>(&v["ie_msg_1"]).unwrap(), m);

    let m = Msg {
        to: Some(b"ab".to_vec()),
        ..msg(7)
    };
    assert_eq!(to_vec(&m).unwrap(), v["ie_msg_12"]);
    assert_eq!(from_slice::<Msg>(&v["ie_msg_12"]).unwrap(), m);

    let m = Msg {
        to: Some(b"zz".to_vec()),
        te: Some(Te::C),
        ..msg(255)
    };
    assert_eq!(to_vec(&m).unwrap(), v["ie_msg_123"]);
    assert_eq!(from_slice::<Msg>(&v["ie_msg_123"]).unwrap(), m);
}

#[test]
fn an_empty_container_has_no_mandatory_ie() {
    // `ie_msg_empty` is a valid *encoding* of the container, but the message is missing its mandatory IE 1
    let v = vectors();
    let e = from_slice::<Msg>(&v["ie_msg_empty"]).unwrap_err();
    assert_eq!(
        e.kind,
        ErrorKind::MissingIe {
            id: 1,
            criticality: Criticality::Reject
        }
    );
}

#[test]
fn unknown_ies_are_kept_and_re_encoded() {
    // IE 99 (not in the set) between the known ones, as a newer peer might send
    let mut w = BitWriter::new();
    w.write_bit(false);
    let ies = vec![
        RawIe::with(1, Criticality::Reject, |w| {
            w.write_int(5, &IntSpec::range(0, 255))
        })
        .unwrap(),
        RawIe {
            id: 99,
            criticality: Criticality::Notify,
            content: vec![0xDE, 0xAD],
        },
    ];
    ie::write_container(&mut w, MSG_SIZE, &ies).unwrap();
    let bytes = w.into_bytes();
    let m = from_slice::<Msg>(&bytes).unwrap();
    assert_eq!(m.ti, Some(5));
    assert_eq!(
        m.unknown_ies,
        [RawIe {
            id: 99,
            criticality: Criticality::Notify,
            content: vec![0xDE, 0xAD]
        }]
    );
    assert_eq!(
        to_vec(&m).unwrap(),
        bytes,
        "re-encoding keeps the unknown IE"
    );
}

#[test]
fn duplicate_ies_and_bad_contents_are_errors() {
    let dup = |ies: Vec<RawIe>| {
        let mut w = BitWriter::new();
        w.write_bit(false);
        ie::write_container(&mut w, MSG_SIZE, &ies).unwrap();
        from_slice::<Msg>(&w.into_bytes()).unwrap_err()
    };
    let one = || {
        RawIe::with(1, Criticality::Reject, |w| {
            w.write_int(5, &IntSpec::range(0, 255))
        })
        .unwrap()
    };
    assert_eq!(
        dup(vec![one(), one()]).kind,
        ErrorKind::DuplicateIe { id: 1 }
    );
    // a value that does not decode (IE 300 holds an ENUMERATED with 3 values: index 3 is invalid)
    let bad = RawIe {
        id: 300,
        criticality: Criticality::Notify,
        content: vec![0xC0],
    };
    assert_eq!(dup(vec![one(), bad]).kind, ErrorKind::ValueOutOfRange);
    // a value followed by a whole spare octet
    let extra = RawIe {
        id: 1,
        criticality: Criticality::Reject,
        content: vec![5, 0],
    };
    assert_eq!(dup(vec![extra]).kind, ErrorKind::TrailingData);
}

/// `Item ::= SEQUENCE { a INTEGER (0..7), iE-Extensions ExtContainer {{ItemExt}} OPTIONAL, ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    a: u8,
    ie_extensions: Option<ItemExt>,
}

/// The extension set with one row (id 7, ignore, INTEGER (0..255)), plus whatever else arrives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ItemExt {
    ti: Option<u8>,
    unknown_ies: Vec<RawIe>,
}

const EXT_SIZE: Size = Size::range(1, 65535);

impl AperEncode for ItemExt {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        let mut ies = Vec::new();
        if let Some(v) = &self.ti {
            ies.push(RawIe::with(7, Criticality::Ignore, |w| {
                w.write_int(i128::from(*v), &IntSpec::range(0, 255))
            })?);
        }
        ies.extend(self.unknown_ies.iter().cloned());
        ie::write_container(w, EXT_SIZE, &ies)
    }
}
impl AperDecode for ItemExt {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let mut out = ItemExt::default();
        for ie in ie::read_container(r, EXT_SIZE)? {
            match ie.id {
                7 => ie::set_once(
                    &mut out.ti,
                    7,
                    ie.decode_with(|r| r.read_int_as::<u8>(&IntSpec::range(0, 255)))?,
                )?,
                _ => out.unknown_ies.push(ie),
            }
        }
        Ok(out)
    }
}

impl AperEncode for Item {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_bit(false);
        w.write_bit(self.ie_extensions.is_some());
        w.write_int(i128::from(self.a), &IntSpec::range(0, 7))?;
        if let Some(v) = &self.ie_extensions {
            v.aper_encode(w)?;
        }
        Ok(())
    }
}
impl AperDecode for Item {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let ext = r.read_bit()?;
        let has_ext_ies = r.read_bit()?;
        let a = r.read_int_as::<u8>(&IntSpec::range(0, 7))?;
        let ie_extensions = if has_ext_ies {
            Some(ItemExt::aper_decode(r)?)
        } else {
            None
        };
        if ext {
            r.read_extension_additions()?;
        }
        Ok(Item { a, ie_extensions })
    }
}

#[test]
fn extension_containers_match_the_oracle() {
    let v = vectors();
    let plain = Item {
        a: 3,
        ie_extensions: None,
    };
    assert_eq!(to_vec(&plain).unwrap(), v["ie_item_noext"]);
    assert_eq!(from_slice::<Item>(&v["ie_item_noext"]).unwrap(), plain);
    let with = Item {
        a: 3,
        ie_extensions: Some(ItemExt {
            ti: Some(9),
            unknown_ies: vec![],
        }),
    };
    assert_eq!(to_vec(&with).unwrap(), v["ie_item_ext"]);
    assert_eq!(from_slice::<Item>(&v["ie_item_ext"]).unwrap(), with);
    // an extension container must hold at least one member
    let empty = Item {
        a: 3,
        ie_extensions: Some(ItemExt::default()),
    };
    assert_eq!(to_vec(&empty).unwrap_err().kind, ErrorKind::SizeOutOfRange);
}

#[test]
fn unknown_extension_members_survive() {
    let mut w = BitWriter::new();
    Item {
        a: 1,
        ie_extensions: Some(ItemExt {
            ti: None,
            unknown_ies: vec![RawIe {
                id: 4000,
                criticality: Criticality::Reject,
                content: vec![1, 2, 3],
            }],
        }),
    }
    .aper_encode(&mut w)
    .unwrap();
    let back = from_slice::<Item>(&w.into_bytes()).unwrap();
    assert_eq!(back.ie_extensions.unwrap().unknown_ies[0].id, 4000);
    let _ = UnknownIes::default();
}

/// `Ch ::= CHOICE { x INTEGER (0..7), choice-Extensions ProtocolIE-Field {{ChIEs}} }` (no CHOICE extension marker)
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ch {
    X(u8),
    ChoiceExtensions(RawIe),
}
impl AperEncode for Ch {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        match self {
            Ch::X(v) => {
                w.write_index(0, 2, false)?;
                w.write_int(i128::from(*v), &IntSpec::range(0, 7))
            }
            Ch::ChoiceExtensions(ie) => {
                w.write_index(1, 2, false)?;
                ie.aper_encode(w)
            }
        }
    }
}
impl AperDecode for Ch {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        match r.read_index(2, false)? {
            0 => Ok(Ch::X(r.read_int_as::<u8>(&IntSpec::range(0, 7))?)),
            _ => Ok(Ch::ChoiceExtensions(RawIe::aper_decode(r)?)),
        }
    }
}

#[test]
fn a_single_ie_field_matches_the_oracle() {
    let v = vectors();
    assert_eq!(to_vec(&Ch::X(5)).unwrap(), v["ie_choice_x"]);
    assert_eq!(from_slice::<Ch>(&v["ie_choice_x"]).unwrap(), Ch::X(5));
    let c = Ch::ChoiceExtensions(
        RawIe::with(5, Criticality::Reject, |w| {
            w.write_int(77, &IntSpec::range(0, 255))
        })
        .unwrap(),
    );
    assert_eq!(to_vec(&c).unwrap(), v["ie_choice_ext"]);
    assert_eq!(from_slice::<Ch>(&v["ie_choice_ext"]).unwrap(), c);
}

/// `Pdu ::= CHOICE { initiatingMessage InitiatingMessage, successfulOutcome SuccessfulOutcome, ... }`
#[derive(Debug, Clone, PartialEq, Eq)]
enum Initiating {
    Msg(Msg),
    Item(Item),
}
/// `Rsp ::= SEQUENCE { protocolIEs Container {{RspIEs}}, ... }` with `RspIEs`: id 1, ignore, mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rsp {
    ti: u8,
}
impl AperEncode for Rsp {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_bit(false);
        let ies = [RawIe::with(1, Criticality::Ignore, |w| {
            w.write_int(i128::from(self.ti), &IntSpec::range(0, 255))
        })?];
        ie::write_container(w, MSG_SIZE, &ies)
    }
}
impl AperDecode for Rsp {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let ext = r.read_bit()?;
        let mut ti = None;
        for ie in ie::read_container(r, MSG_SIZE)? {
            if ie.id == 1 {
                ie::set_once(
                    &mut ti,
                    1,
                    ie.decode_with(|r| r.read_int_as::<u8>(&IntSpec::range(0, 255)))?,
                )?;
            }
        }
        if ext {
            r.read_extension_additions()?;
        }
        Ok(Rsp {
            ti: ie::required(ti, 1, Criticality::Ignore)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Successful {
    Rsp(Rsp),
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pdu {
    Initiating(Initiating),
    Successful(Successful),
}

impl AperEncode for Initiating {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        match self {
            Initiating::Msg(m) => ie::write_procedure(w, 21, Criticality::Reject, m),
            Initiating::Item(m) => ie::write_procedure(w, 200, Criticality::Ignore, m),
        }
    }
}
impl AperDecode for Initiating {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let (code, criticality, content) = ie::read_procedure(r)?;
        match code {
            21 => Ok(Initiating::Msg(ie::decode_message(&content)?)),
            200 => Ok(Initiating::Item(ie::decode_message(&content)?)),
            _ => Err(r.error(ErrorKind::UnknownProcedure { code, criticality })),
        }
    }
}
impl AperEncode for Successful {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        match self {
            Successful::Rsp(m) => ie::write_procedure(w, 21, Criticality::Reject, m),
        }
    }
}
impl AperDecode for Successful {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        let (code, criticality, content) = ie::read_procedure(r)?;
        match code {
            21 => Ok(Successful::Rsp(ie::decode_message(&content)?)),
            _ => Err(r.error(ErrorKind::UnknownProcedure { code, criticality })),
        }
    }
}
impl AperEncode for Pdu {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        match self {
            Pdu::Initiating(m) => {
                w.write_index(0, 2, true)?;
                m.aper_encode(w)
            }
            Pdu::Successful(m) => {
                w.write_index(1, 2, true)?;
                m.aper_encode(w)
            }
        }
    }
}
impl AperDecode for Pdu {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        match r.read_index(2, true)? {
            0 => Ok(Pdu::Initiating(Initiating::aper_decode(r)?)),
            1 => Ok(Pdu::Successful(Successful::aper_decode(r)?)),
            i => Err(r.error(ErrorKind::InvalidIndex(i))),
        }
    }
}

#[test]
fn the_procedure_wrapper_matches_the_oracle() {
    let v = vectors();
    let a = Pdu::Initiating(Initiating::Msg(msg(7)));
    assert_eq!(to_vec(&a).unwrap(), v["ie_pdu_init_a"]);
    assert_eq!(from_slice::<Pdu>(&v["ie_pdu_init_a"]).unwrap(), a);
    let b = Pdu::Initiating(Initiating::Item(Item {
        a: 6,
        ie_extensions: None,
    }));
    assert_eq!(to_vec(&b).unwrap(), v["ie_pdu_init_b"]);
    assert_eq!(from_slice::<Pdu>(&v["ie_pdu_init_b"]).unwrap(), b);
    let c = Pdu::Successful(Successful::Rsp(Rsp { ti: 1 }));
    assert_eq!(to_vec(&c).unwrap(), v["ie_pdu_succ_a"]);
    assert_eq!(from_slice::<Pdu>(&v["ie_pdu_succ_a"]).unwrap(), c);
}

#[test]
fn an_unknown_procedure_reports_its_code_and_criticality() {
    let mut w = BitWriter::new();
    w.write_index(0, 2, true).unwrap();
    ie::write_procedure(&mut w, 77, Criticality::Notify, &msg(1)).unwrap();
    let bytes = w.into_bytes();
    let e: AperError = from_slice::<Pdu>(&bytes).unwrap_err();
    assert_eq!(
        e.kind,
        ErrorKind::UnknownProcedure {
            code: 77,
            criticality: Criticality::Notify
        }
    );
}

#[test]
fn the_unknown_ie_recorder_collects_only_while_active_and_nests() {
    use ngap_aper::ie::{Criticality, RawIe, note_unknown, record_unknown_ies};
    let ie = |id| RawIe {
        id,
        criticality: Criticality::Ignore,
        content: vec![0],
    };
    note_unknown(&ie(1)); // nobody is recording: dropped
    let (((), inner), outer) = record_unknown_ies(|| {
        note_unknown(&ie(2));
        let r = record_unknown_ies(|| {
            note_unknown(&ie(3));
        });
        note_unknown(&ie(4));
        r
    });
    let ids = |v: &[RawIe]| v.iter().map(|i| i.id).collect::<Vec<_>>();
    assert_eq!(
        ids(&inner),
        vec![3],
        "the inner scope gets only its own IEs"
    );
    assert_eq!(ids(&outer), vec![2, 4]);
    let (_, after) = record_unknown_ies(|| {});
    assert!(after.is_empty(), "nothing leaks into the next recording");
}
