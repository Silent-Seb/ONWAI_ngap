//! Checks the APER runtime against vectors produced by an independent implementation (Python `asn1tools`,
//! ALIGNED PER). Regenerate with `tools/gen_aper_vectors.py`; see `vectors.txt` for the format.
//!
//! Every vector is checked in four ways: encode == vector, decode(vector) == value, the same wrapped between
//! two 3-bit fields (`name@w`, exposes alignment), and decoding every truncated prefix must not panic.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use ngap_aper::{
    AperDecode, AperEncode, AperError, BitReader, BitString, BitWriter, CharSet, Contained,
    IntSpec, ObjectIdentifier, Result, Size,
};

type Enc<V> = fn(&mut BitWriter, &V) -> Result<()>;
type Dec<V> = fn(&mut BitReader<'_>) -> Result<V>;

struct Harness {
    vectors: BTreeMap<String, String>,
    used: BTreeSet<String>,
}

fn pat(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + 3) % 251) as u8).collect()
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xCBF2_9CE4_8422_2325u64, |h, &x| {
        (h ^ u64::from(x)).wrapping_mul(0x0100_0000_01B3)
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Harness {
    fn new() -> Self {
        let text = include_str!("vectors.txt");
        let vectors = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let (k, v) = l
                    .split_once(" | ")
                    .unwrap_or_else(|| panic!("bad vector line {l:?}"));
                (k.to_owned(), v.trim().to_owned())
            })
            .collect();
        Self {
            vectors,
            used: BTreeSet::new(),
        }
    }

    /// Names (without `@w`) that start with `prefix`, with the part after the prefix.
    fn names(&self, prefix: &str) -> Vec<(String, String)> {
        self.vectors
            .keys()
            .filter(|k| !k.ends_with("@w") && k.starts_with(prefix))
            .map(|k| (k.clone(), k[prefix.len()..].to_owned()))
            .collect()
    }

    fn check<V: PartialEq + Debug>(&mut self, name: &str, value: V, enc: Enc<V>, dec: Dec<V>) {
        self.check_one(name, false, &value, enc, dec);
        if self.vectors.contains_key(&format!("{name}@w")) {
            self.check_one(&format!("{name}@w"), true, &value, enc, dec);
        }
        self.used.insert(name.to_owned());
    }

    fn check_one<V: PartialEq + Debug>(
        &mut self,
        key: &str,
        wrapped: bool,
        value: &V,
        enc: Enc<V>,
        dec: Dec<V>,
    ) {
        let expected = self
            .vectors
            .get(key)
            .unwrap_or_else(|| panic!("no vector {key}"))
            .clone();
        let mut w = BitWriter::new();
        if wrapped {
            w.write_bits(0b101, 3);
        }
        enc(&mut w, value).unwrap_or_else(|e| panic!("{key}: encode failed: {e}"));
        if wrapped {
            w.write_bits(0b110, 3);
        }
        let got = w.into_bytes();

        if let Some(big) = expected.strip_prefix("big:") {
            let mut it = big.split(':');
            let (len, hash, head) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
            assert_eq!(got.len().to_string(), len, "{key}: length");
            assert_eq!(format!("{:016x}", fnv(&got)), hash, "{key}: content hash");
            assert_eq!(hex(&got[..16]), head, "{key}: first octets");
        } else {
            assert_eq!(hex(&got), expected, "{key}: encoding");
        }

        // decode what the oracle (or, for big vectors, we) produced
        let mut r = BitReader::new(&got);
        if wrapped {
            assert_eq!(r.read_bits(3).unwrap(), 0b101, "{key}: prefix");
        }
        let back = dec(&mut r).unwrap_or_else(|e| panic!("{key}: decode failed: {e}"));
        assert_eq!(&back, value, "{key}: decoded value");
        if wrapped {
            assert_eq!(r.read_bits(3).unwrap(), 0b110, "{key}: suffix");
        }
        assert!(
            r.remaining_bits() < 8,
            "{key}: {} bits left over",
            r.remaining_bits()
        );

        // robustness: no truncated input may panic (small encodings fully, big ones at sampled cut points)
        let step = (got.len() / 64).max(1);
        for cut in (0..got.len()).step_by(step) {
            let mut r = BitReader::new(&got[..cut]);
            let _ = dec(&mut r);
        }
    }

    /// For vectors the oracle cannot produce: check against a hand-derived encoding.
    fn check_hand<V: PartialEq + Debug>(
        &mut self,
        name: &str,
        hexstr: &str,
        value: V,
        enc: Enc<V>,
        dec: Dec<V>,
    ) {
        let mut w = BitWriter::new();
        enc(&mut w, &value).unwrap();
        assert_eq!(hex(&w.into_bytes()), hexstr, "{name}: encoding");
        let bytes = unhex(hexstr);
        let mut r = BitReader::new(&bytes);
        assert_eq!(dec(&mut r).unwrap(), value, "{name}: decoded");
    }
}

fn num(s: &str) -> i128 {
    s.parse().unwrap_or_else(|_| panic!("not a number: {s}"))
}

#[derive(Debug, PartialEq)]
struct I8(i128);
impl AperEncode for I8 {
    fn aper_encode(&self, w: &mut BitWriter) -> Result<()> {
        w.write_constrained_int(self.0, 0, 255)
    }
}
impl AperDecode for I8 {
    fn aper_decode(r: &mut BitReader<'_>) -> Result<Self> {
        Ok(I8(r.read_constrained_int(0, 255)?))
    }
}

#[derive(Debug, PartialEq)]
enum Cx {
    A(i128),
    B,
    C(i128),
    D(Vec<u8>),
}

#[derive(Debug, PartialEq)]
struct Sx {
    a: i128,
    b: Option<i128>,
    c: Option<i128>,
}

fn open<F: FnOnce(&mut BitWriter) -> Result<()>>(f: F) -> Vec<u8> {
    let mut w = BitWriter::new();
    f(&mut w).unwrap();
    w.into_complete_bytes()
}

fn bit_pat(n: usize) -> BitString {
    BitString::new(pat(n.div_ceil(8)), n).unwrap()
}

fn bits_of(s: &str) -> BitString {
    BitString::from_bits(&s.bytes().map(|b| b == b'1').collect::<Vec<_>>())
}

fn items(n: usize, modulo: usize) -> Vec<i128> {
    (0..n).map(|i| (i % modulo) as i128).collect()
}

#[test]
fn oracle_vectors() {
    let mut h = Harness::new();

    // ---- integers (the value is the name's suffix)
    h.check(
        "i1",
        5i128,
        |w, v| w.write_constrained_int(*v, 5, 5),
        |r| r.read_constrained_int(5, 5),
    );
    for (n, s) in h.names("i3_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 7),
            |r| r.read_constrained_int(0, 7),
        );
    }
    for (n, s) in h.names("i8_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 255),
            |r| r.read_constrained_int(0, 255),
        );
    }
    for (n, s) in h.names("i9_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 256),
            |r| r.read_constrained_int(0, 256),
        );
    }
    for (n, s) in h.names("i16_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 65535),
            |r| r.read_constrained_int(0, 65535),
        );
    }
    for (n, s) in h.names("i17_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 65536),
            |r| r.read_constrained_int(0, 65536),
        );
    }
    for (n, s) in h.names("i32_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, 4294967295),
            |r| r.read_constrained_int(0, 4294967295),
        );
    }
    for (n, s) in h.names("i64_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, 0, i128::from(u64::MAX)),
            |r| r.read_constrained_int(0, i128::from(u64::MAX)),
        );
    }
    for (n, s) in h.names("is_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_constrained_int(*v, -127, 127),
            |r| r.read_constrained_int(-127, 127),
        );
    }
    for (n, s) in h.names("ix1_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_ext_constrained_int(*v, -420, 10000),
            |r| r.read_ext_constrained_int(-420, 10000),
        );
    }
    for (n, s) in h.names("ix2_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_ext_constrained_int(*v, 1, 65535),
            |r| r.read_ext_constrained_int(1, 65535),
        );
    }
    for (n, s) in h.names("iu_") {
        h.check(
            &n,
            num(&s),
            |w, v| w.write_unconstrained_int(*v),
            |r| r.read_unconstrained_int(),
        );
    }
    // the same integers through the spec-driven API the generated code uses
    for (n, x) in h.names("i3_") {
        h.check(
            &n,
            num(&x),
            |w, v| w.write_int(*v, &IntSpec::range(0, 7)),
            |r| r.read_int(&IntSpec::range(0, 7)),
        );
    }
    for (n, x) in h.names("i17_") {
        h.check(
            &n,
            num(&x),
            |w, v| w.write_int(*v, &IntSpec::range(0, 65536)),
            |r| r.read_int(&IntSpec::range(0, 65536)),
        );
    }
    for (n, x) in h.names("i64_") {
        const S: IntSpec = IntSpec::range(0, u64::MAX as i128);
        h.check(&n, num(&x), |w, v| w.write_int(*v, &S), |r| r.read_int(&S));
    }
    for (n, x) in h.names("ix1_") {
        const S: IntSpec = IntSpec::range(-420, 10000)
            .extensible()
            .with_additions(&[(i128::MIN, i128::MAX)]);
        h.check(&n, num(&x), |w, v| w.write_int(*v, &S), |r| r.read_int(&S));
    }
    for (n, x) in h.names("ix2_") {
        const S: IntSpec = IntSpec::range(1, 65535)
            .extensible()
            .with_additions(&[(i128::MIN, i128::MAX)]);
        h.check(&n, num(&x), |w, v| w.write_int(*v, &S), |r| r.read_int(&S));
    }
    for (n, x) in h.names("iu_") {
        h.check(
            &n,
            num(&x),
            |w, v| w.write_int(*v, &IntSpec::UNCONSTRAINED),
            |r| r.read_int(&IntSpec::UNCONSTRAINED),
        );
    }

    // semi-constrained INTEGER (lb..MAX): the oracle gets this wrong (see gen_aper_vectors.py), so hand-derived
    // from X.691 10.7: length determinant + minimal *unsigned* octets of (v - lb)
    for (hexstr, v, lb) in [
        ("0100", 0i128, 0i128),
        ("01ff", 255, 0),
        ("020100", 256, 0),
        ("06010000000000", 1 << 40, 0),
        ("0100", 10, 10),
        ("017f", 137, 10),
        ("0180", 138, 10),
        ("0203de", 1000, 10),
    ] {
        let mut w = BitWriter::new();
        w.write_semi_constrained_int(v, lb).unwrap();
        assert_eq!(hex(&w.into_bytes()), hexstr, "semi-constrained {v} lb {lb}");
        assert_eq!(
            BitReader::new(&unhex(hexstr))
                .read_semi_constrained_int(lb)
                .unwrap(),
            v
        );
    }

    // ---- bit strings
    h.check(
        "b8",
        BitString::new(vec![0xa5], 8).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8)),
        |r| r.read_bit_string(Size::fixed(8)),
    );
    h.check(
        "b16",
        BitString::new(vec![0xa5, 0x5a], 16).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(16)),
        |r| r.read_bit_string(Size::fixed(16)),
    );
    h.check(
        "b17",
        BitString::new(vec![0xa5, 0x5a, 0x80], 17).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(17)),
        |r| r.read_bit_string(Size::fixed(17)),
    );
    h.check(
        "b28",
        BitString::new(vec![0x12, 0x34, 0x56, 0x70], 28).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(28)),
        |r| r.read_bit_string(Size::fixed(28)),
    );
    for (n, s) in h.names("b0_") {
        h.check(
            &n,
            bits_of(&"1011"[..num(&s) as usize]),
            |w, v| w.write_bit_string(v, Size::range(0, 4)),
            |r| r.read_bit_string(Size::range(0, 4)),
        );
    }
    for (n, s) in h.names("bv_") {
        let bits = num(&s) as usize;
        h.check(
            &n,
            bit_pat(bits),
            |w, v| w.write_bit_string(v, Size::range(1, 1024).extensible()),
            |r| r.read_bit_string(Size::range(1, 1024).extensible()),
        );
    }
    for (n, s) in h.names("bu_") {
        h.check(
            &n,
            bit_pat(num(&s) as usize),
            |w, v| w.write_bit_string(v, Size::UNBOUNDED),
            |r| r.read_bit_string(Size::UNBOUNDED),
        );
    }
    h.check(
        "bf_8",
        BitString::new(vec![0x5a], 8).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8).extensible()),
        |r| r.read_bit_string(Size::fixed(8).extensible()),
    );
    h.check(
        "bg_8",
        BitString::new(vec![0x5a], 8).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8).extensible()),
        |r| r.read_bit_string(Size::fixed(8).extensible()),
    );
    for (n, s) in h.names("bs_") {
        h.check(
            &n,
            bits_of(&"1011001110001011"[..num(&s) as usize]),
            |w, v| w.write_bit_string(v, Size::range(1, 16)),
            |r| r.read_bit_string(Size::range(1, 16)),
        );
    }
    // oracle lacks BIT STRING size extension: hand-derived (ext bit 1, unconstrained length, aligned bits)
    h.check_hand(
        "bf_9",
        "80095a80",
        BitString::new(vec![0x5a, 0x80], 9).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8).extensible()),
        |r| r.read_bit_string(Size::fixed(8).extensible()),
    );
    h.check_hand(
        "bg_16",
        "80105aa5",
        BitString::new(vec![0x5a, 0xa5], 16).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8).extensible()),
        |r| r.read_bit_string(Size::fixed(8).extensible()),
    );
    h.check_hand(
        "bg_12",
        "800c5aa0",
        BitString::new(vec![0x5a, 0xa0], 12).unwrap(),
        |w, v| w.write_bit_string(v, Size::fixed(8).extensible()),
        |r| r.read_bit_string(Size::fixed(8).extensible()),
    );
    {
        let bs = bit_pat(1025);
        let mut expect = String::from("808401");
        expect.push_str(&hex(bs.as_bytes()));
        h.check_hand(
            "bv_1025",
            &expect,
            bs,
            |w, v| w.write_bit_string(v, Size::range(1, 1024).extensible()),
            |r| r.read_bit_string(Size::range(1, 1024).extensible()),
        );
    }

    // ---- octet strings
    h.check(
        "o1",
        vec![0x42u8],
        |w, v| w.write_octet_string(v, Size::fixed(1)),
        |r| r.read_octet_string(Size::fixed(1)),
    );
    h.check(
        "o2",
        vec![0x42u8, 0x43],
        |w, v| w.write_octet_string(v, Size::fixed(2)),
        |r| r.read_octet_string(Size::fixed(2)),
    );
    h.check(
        "o3",
        vec![0x42u8, 0x43, 0x44],
        |w, v| w.write_octet_string(v, Size::fixed(3)),
        |r| r.read_octet_string(Size::fixed(3)),
    );
    h.check(
        "o32",
        pat(32),
        |w, v| w.write_octet_string(v, Size::fixed(32)),
        |r| r.read_octet_string(Size::fixed(32)),
    );
    for (n, s) in h.names("ov_") {
        h.check(
            &n,
            pat(num(&s) as usize),
            |w, v| w.write_octet_string(v, Size::range(1, 255)),
            |r| r.read_octet_string(Size::range(1, 255)),
        );
    }
    for (n, s) in h.names("ow_") {
        h.check(
            &n,
            pat(num(&s) as usize),
            |w, v| w.write_octet_string(v, Size::range(0, 2)),
            |r| r.read_octet_string(Size::range(0, 2)),
        );
    }
    for (n, s) in h.names("ox_") {
        h.check(
            &n,
            pat(num(&s) as usize),
            |w, v| w.write_octet_string(v, Size::range(1, 150).extensible()),
            |r| r.read_octet_string(Size::range(1, 150).extensible()),
        );
    }
    for (n, s) in h.names("om_") {
        h.check(
            &n,
            pat(num(&s) as usize),
            |w, v| w.write_octet_string(v, Size::range(1, 65535)),
            |r| r.read_octet_string(Size::range(1, 65535)),
        );
    }
    for (n, s) in h.names("ou_") {
        h.check(
            &n,
            pat(num(&s) as usize),
            |w, v| w.write_octet_string(v, Size::UNBOUNDED),
            |r| r.read_octet_string(Size::UNBOUNDED),
        );
    }
    h.check(
        "oc",
        Contained::<I8>::from_raw(vec![7]),
        |w, v| v.aper_encode(w),
        Contained::<I8>::aper_decode,
    );

    // ---- character strings
    let ps = |w: &mut BitWriter, v: &String| {
        w.write_char_string(v, Size::range(1, 150).extensible(), CharSet::Printable)
    };
    let psd = |r: &mut BitReader<'_>| {
        r.read_char_string(Size::range(1, 150).extensible(), CharSet::Printable)
    };
    h.check("ps_a", "a".to_owned(), ps, psd);
    h.check("ps_hello", "hello".to_owned(), ps, psd);
    h.check("ps_150", "A".repeat(150), ps, psd);
    let vs = |w: &mut BitWriter, v: &String| {
        w.write_char_string(v, Size::range(1, 150).extensible(), CharSet::Visible)
    };
    let vsd = |r: &mut BitReader<'_>| {
        r.read_char_string(Size::range(1, 150).extensible(), CharSet::Visible)
    };
    h.check("vs_a", "a".to_owned(), vs, vsd);
    h.check("vs_http://x.y/z", "http://x.y/z".to_owned(), vs, vsd);
    let vu =
        |w: &mut BitWriter, v: &String| w.write_char_string(v, Size::UNBOUNDED, CharSet::Visible);
    let vud = |r: &mut BitReader<'_>| r.read_char_string(Size::UNBOUNDED, CharSet::Visible);
    h.check("vu_0", String::new(), vu, vud);
    h.check("vu_5", "abcde".to_owned(), vu, vud);
    let u8w = |w: &mut BitWriter, v: &String| w.write_utf8_string(v);
    let u8r = |r: &mut BitReader<'_>| r.read_utf8_string();
    h.check("us_a", "a".to_owned(), u8w, u8r);
    h.check("us_utf8", "h\u{e9}llo \u{20ac}".to_owned(), u8w, u8r);
    h.check("uu_utf8", "h\u{e9}llo \u{20ac}".to_owned(), u8w, u8r);
    h.check("uu_empty", String::new(), u8w, u8r);
    h.check_hand(
        "ps_151",
        &format!("808097{}", "42".repeat(151)),
        "B".repeat(151),
        ps,
        psd,
    );

    // ---- enumerations and choices (index = position among root values; extension additions follow the root)
    for (n, s) in h.names("en_") {
        let idx = (s.as_bytes()[0] - b'a') as u64;
        h.check(
            &n,
            idx,
            |w, v| w.write_index(*v, 3, false),
            |r| r.read_index(3, false),
        );
    }
    h.check(
        "e1",
        0u64,
        |w, v| w.write_index(*v, 1, false),
        |r| r.read_index(1, false),
    );
    for (n, s) in h.names("ex_") {
        let idx = (s.as_bytes()[0] - b'a') as u64;
        h.check(
            &n,
            idx,
            |w, v| w.write_index(*v, 3, true),
            |r| r.read_index(3, true),
        );
    }
    for (n, s) in h.names("eb_") {
        let idx = num(&s[1..]) as u64;
        h.check(
            &n,
            idx,
            |w, v| w.write_index(*v, 10, false),
            |r| r.read_index(10, false),
        );
    }
    h.check("nl", (), |_, _| Ok(()), |_| Ok(()));
    let oid = |a: &[u64]| ObjectIdentifier::new(a.to_vec()).unwrap();
    h.check(
        "oid_1",
        oid(&[1, 2, 840, 113549]),
        |w, v| w.write_object_identifier(v),
        |r| r.read_object_identifier(),
    );
    h.check(
        "oid_2",
        oid(&[0, 4, 0, 0, 22, 3, 1, 1, 0]),
        |w, v| w.write_object_identifier(v),
        |r| r.read_object_identifier(),
    );
    h.check(
        "oid_3",
        oid(&[2, 999, 3]),
        |w, v| w.write_object_identifier(v),
        |r| r.read_object_identifier(),
    );

    // CHOICE { a INTEGER(0..7), b NULL, c OCTET STRING(SIZE(2)) }
    #[derive(Debug, PartialEq)]
    enum Ch {
        A(i128),
        B,
        C(Vec<u8>),
    }
    let ch_w = |w: &mut BitWriter, v: &Ch| match v {
        Ch::A(x) => {
            w.write_index(0, 3, false)?;
            w.write_constrained_int(*x, 0, 7)
        }
        Ch::B => w.write_index(1, 3, false),
        Ch::C(x) => {
            w.write_index(2, 3, false)?;
            w.write_octet_string(x, Size::fixed(2))
        }
    };
    let ch_r = |r: &mut BitReader<'_>| -> Result<Ch> {
        Ok(match r.read_index(3, false)? {
            0 => Ch::A(r.read_constrained_int(0, 7)?),
            1 => Ch::B,
            _ => Ch::C(r.read_octet_string(Size::fixed(2))?),
        })
    };
    h.check("ch_a", Ch::A(5), ch_w, ch_r);
    h.check("ch_b", Ch::B, ch_w, ch_r);
    h.check("ch_c", Ch::C(vec![1, 2]), ch_w, ch_r);

    // CHOICE { a INTEGER(0..7), b NULL, ..., c INTEGER(0..255), d OCTET STRING(SIZE(2)) }
    let cx_w = |w: &mut BitWriter, v: &Cx| match v {
        Cx::A(x) => {
            w.write_index(0, 2, true)?;
            w.write_constrained_int(*x, 0, 7)
        }
        Cx::B => w.write_index(1, 2, true),
        Cx::C(x) => {
            w.write_index(2, 2, true)?;
            w.write_open_type(&open(|iw| iw.write_constrained_int(*x, 0, 255)))
        }
        Cx::D(x) => {
            w.write_index(3, 2, true)?;
            w.write_open_type(&open(|iw| iw.write_octet_string(x, Size::fixed(2))))
        }
    };
    let cx_r = |r: &mut BitReader<'_>| -> Result<Cx> {
        Ok(match r.read_index(2, true)? {
            0 => Cx::A(r.read_constrained_int(0, 7)?),
            1 => Cx::B,
            2 => Cx::C(BitReader::new(&r.read_open_type()?).read_constrained_int(0, 255)?),
            3 => Cx::D(BitReader::new(&r.read_open_type()?).read_octet_string(Size::fixed(2))?),
            i => return Err(r.error(ngap_aper::ErrorKind::InvalidIndex(i))),
        })
    };
    h.check("cx_a", Cx::A(5), cx_w, cx_r);
    h.check("cx_b", Cx::B, cx_w, cx_r);
    h.check("cx_c", Cx::C(200), cx_w, cx_r);
    h.check("cx_d", Cx::D(vec![1, 2]), cx_w, cx_r);
    h.check(
        "c1",
        3i128,
        |w, v| {
            w.write_index(0, 1, false)?;
            w.write_constrained_int(*v, 0, 7)
        },
        |r| {
            r.read_index(1, false)?;
            r.read_constrained_int(0, 7)
        },
    );

    // SEQUENCE { a INTEGER(0..7), ..., b INTEGER(0..255) OPTIONAL, c INTEGER(0..1) OPTIONAL }
    let sx_w = |w: &mut BitWriter, v: &Sx| {
        let ext = v.b.is_some() || v.c.is_some();
        w.write_bit(ext);
        w.write_constrained_int(v.a, 0, 7)?;
        if ext {
            let b = v.b.map(|x| open(|iw| iw.write_constrained_int(x, 0, 255)));
            let c = v.c.map(|x| open(|iw| iw.write_constrained_int(x, 0, 1)));
            w.write_extension_additions(&[b, c])?;
        }
        Ok(())
    };
    let sx_r = |r: &mut BitReader<'_>| -> Result<Sx> {
        let ext = r.read_bit()?;
        let a = r.read_constrained_int(0, 7)?;
        let (mut b, mut c) = (None, None);
        if ext {
            let adds = r.read_extension_additions()?;
            if let Some(Some(x)) = adds.first() {
                b = Some(BitReader::new(x).read_constrained_int(0, 255)?);
            }
            if let Some(Some(x)) = adds.get(1) {
                c = Some(BitReader::new(x).read_constrained_int(0, 1)?);
            }
        }
        Ok(Sx { a, b, c })
    };
    h.check(
        "sx_a",
        Sx {
            a: 3,
            b: None,
            c: None,
        },
        sx_w,
        sx_r,
    );
    h.check(
        "sx_ab",
        Sx {
            a: 3,
            b: Some(200),
            c: None,
        },
        sx_w,
        sx_r,
    );
    h.check(
        "sx_ac",
        Sx {
            a: 3,
            b: None,
            c: Some(1),
        },
        sx_w,
        sx_r,
    );
    h.check(
        "sx_abc",
        Sx {
            a: 3,
            b: Some(200),
            c: Some(1),
        },
        sx_w,
        sx_r,
    );
    h.check(
        "sy_a",
        3i128,
        |w, v| {
            w.write_bit(false);
            w.write_constrained_int(*v, 0, 7)
        },
        |r| {
            r.read_bit()?;
            r.read_constrained_int(0, 7)
        },
    );

    // ---- SEQUENCE OF
    macro_rules! seq_of {
        ($prefix:literal, $size:expr, $hi:expr, $modulo:expr) => {
            for (n, s) in h.names($prefix) {
                h.check(
                    &n,
                    items(num(&s) as usize, $modulo),
                    |w, v| w.write_seq_of(v, $size, |w, x| w.write_constrained_int(*x, 0, $hi)),
                    |r| r.read_seq_of($size, |r| r.read_constrained_int(0, $hi)),
                );
            }
        };
    }
    seq_of!("so1_", Size::range(1, 4), 7, 8);
    seq_of!("so2_", Size::range(0, 65535), 255, 256);
    seq_of!("so3_", Size::UNBOUNDED, 255, 256);
    seq_of!("so5_", Size::range(1, 4).extensible(), 7, 8);
    seq_of!("so6_", Size::range(1, 256), 7, 8);
    h.check(
        "so4",
        vec![1i128, 2, 3],
        |w, v| w.write_seq_of(v, Size::fixed(3), |w, x| w.write_constrained_int(*x, 0, 7)),
        |r| r.read_seq_of(Size::fixed(3), |r| r.read_constrained_int(0, 7)),
    );

    // every vector must have been exercised (except the wrapped twins, handled with their bare vector)
    // the `ie_*` vectors are checked in tests/ie.rs
    let missing: Vec<_> = h
        .vectors
        .keys()
        .filter(|k| !k.ends_with("@w") && !k.starts_with("ie_") && !h.used.contains(*k))
        .collect();
    assert!(missing.is_empty(), "vectors without a test: {missing:?}");
}

#[allow(dead_code)]
fn _error_type_is_exported(_: AperError) {}
