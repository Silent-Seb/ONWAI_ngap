//! Error paths, boundary cases and robustness of the APER runtime (not covered by the oracle vectors).

use ngap_aper::{
    AperDecode, AperEncode, BitReader, BitString, BitWriter, CharSet, Contained, ErrorKind,
    ObjectIdentifier, Size, from_slice, to_vec,
};

fn kind<T: std::fmt::Debug>(r: ngap_aper::Result<T>) -> ErrorKind {
    r.expect_err("expected an error").kind
}

#[test]
fn integer_range_violations() {
    let mut w = BitWriter::new();
    assert_eq!(
        kind(w.write_constrained_int(8, 0, 7)),
        ErrorKind::ValueOutOfRange
    );
    assert_eq!(
        kind(w.write_constrained_int(-1, 0, 7)),
        ErrorKind::ValueOutOfRange
    );
    assert_eq!(
        kind(w.write_constrained_int(0, 7, 0)),
        ErrorKind::ValueOutOfRange
    );
    assert_eq!(
        kind(w.write_semi_constrained_int(9, 10)),
        ErrorKind::ValueOutOfRange
    );
    // 3 bits can hold 5..7 but the range 0..4 forbids them
    for v in 5..8u64 {
        let mut w = BitWriter::new();
        w.write_bits(v, 3);
        let bytes = w.into_bytes();
        assert_eq!(
            kind(BitReader::new(&bytes).read_constrained_int(0, 4)),
            ErrorKind::ValueOutOfRange
        );
    }
    // 8-bit field, range 0..=200 (201 values): 201..=255 are invalid
    assert_eq!(
        kind(BitReader::new(&[201]).read_constrained_int(0, 200)),
        ErrorKind::ValueOutOfRange
    );
    assert_eq!(
        BitReader::new(&[200]).read_constrained_int(0, 200).unwrap(),
        200
    );
}

#[test]
fn unconstrained_integer_extremes_and_errors() {
    for v in [
        i128::MIN,
        i128::MAX,
        -1,
        0,
        1,
        i128::from(i64::MIN),
        i128::from(u64::MAX),
    ] {
        let mut w = BitWriter::new();
        w.write_unconstrained_int(v).unwrap();
        let b = w.into_bytes();
        assert_eq!(
            BitReader::new(&b).read_unconstrained_int().unwrap(),
            v,
            "{v}"
        );
    }
    // 17 octets do not fit i128; zero octets are invalid
    let mut big = vec![17u8];
    big.extend([1u8; 17]);
    assert_eq!(
        kind(BitReader::new(&big).read_unconstrained_int()),
        ErrorKind::IntegerOverflow
    );
    assert_eq!(
        kind(BitReader::new(&[0]).read_unconstrained_int()),
        ErrorKind::InvalidLength
    );
}

#[test]
fn normally_small_numbers() {
    for n in [0u64, 1, 63, 64, 65, 255, 256, 1000, 70000, u64::MAX] {
        let mut w = BitWriter::new();
        w.write_normally_small(n).unwrap();
        let b = w.into_bytes();
        assert_eq!(BitReader::new(&b).read_normally_small().unwrap(), n);
    }
    // 63 is the last value in the 7-bit form, 64 switches to the long form
    let mut w = BitWriter::new();
    w.write_normally_small(63).unwrap();
    assert_eq!(w.bit_len(), 7);
    let mut w = BitWriter::new();
    w.write_normally_small(64).unwrap();
    assert!(w.bit_len() > 7);
}

#[test]
fn size_constraint_violations() {
    let mut w = BitWriter::new();
    assert_eq!(
        kind(w.write_octet_string(&[1, 2, 3], Size::range(1, 2))),
        ErrorKind::SizeOutOfRange
    );
    assert_eq!(
        kind(w.write_octet_string(&[], Size::range(1, 2))),
        ErrorKind::SizeOutOfRange
    );
    assert_eq!(
        kind(w.write_octet_string(&[1], Size::fixed(2))),
        ErrorKind::SizeOutOfRange
    );
    assert_eq!(
        kind(w.write_seq_of(&[1u8; 5], Size::range(1, 4), |w, x| {
            w.write_constrained_int(i128::from(*x), 0, 7)
        })),
        ErrorKind::SizeOutOfRange
    );
    // decoding: a length of 3 in a SIZE(0..2) field is not a valid constrained length (2-bit field, value 3)
    assert_eq!(
        kind(BitReader::new(&[0b1100_0000]).read_octet_string(Size::range(0, 2))),
        ErrorKind::ValueOutOfRange
    );
    // extensible size: lengths outside the root round-trip through the unconstrained form
    let data = vec![9u8; 200];
    let mut w = BitWriter::new();
    w.write_octet_string(&data, Size::range(1, 10).extensible())
        .unwrap();
    let b = w.into_bytes();
    assert_eq!(
        BitReader::new(&b)
            .read_octet_string(Size::range(1, 10).extensible())
            .unwrap(),
        data
    );
}

#[test]
fn unbounded_size_with_a_minimum_is_checked_on_decode() {
    // SIZE(5..MAX): encoded with an unconstrained length; a length of 2 violates the root
    let mut w = BitWriter::new();
    w.write_octet_string(&[1, 2], Size::UNBOUNDED).unwrap();
    let b = w.into_bytes();
    let size = Size {
        lb: 5,
        ub: None,
        ext: false,
    };
    assert_eq!(
        kind(BitReader::new(&b).read_octet_string(size)),
        ErrorKind::SizeOutOfRange
    );
    let mut w = BitWriter::new();
    assert_eq!(
        kind(w.write_octet_string(&[1, 2], size)),
        ErrorKind::SizeOutOfRange
    );
}

#[test]
fn fragmentation_boundaries_roundtrip() {
    for n in [
        0usize, 127, 128, 16383, 16384, 16385, 32767, 32768, 49152, 65535, 65536, 65537, 81920,
        131072,
    ] {
        let data: Vec<u8> = (0..n).map(|i| (i % 253) as u8).collect();
        let mut w = BitWriter::new();
        w.write_octet_string(&data, Size::UNBOUNDED).unwrap();
        let b = w.into_bytes();
        assert_eq!(
            BitReader::new(&b)
                .read_octet_string(Size::UNBOUNDED)
                .unwrap(),
            data,
            "{n}"
        );
        // bit strings too, including a non-octet tail
        let bits =
            BitString::new((0..n.div_ceil(8)).map(|i| (i % 251) as u8).collect(), n).unwrap();
        let mut w = BitWriter::new();
        w.write_bit_string(&bits, Size::UNBOUNDED).unwrap();
        let b = w.into_bytes();
        assert_eq!(
            BitReader::new(&b).read_bit_string(Size::UNBOUNDED).unwrap(),
            bits,
            "{n} bits"
        );
    }
    // a fragment length determinant with multiplier 0 or > 4 is invalid
    assert_eq!(
        kind(BitReader::new(&[0xC0]).read_octet_string(Size::UNBOUNDED)),
        ErrorKind::InvalidLength
    );
    assert_eq!(
        kind(BitReader::new(&[0xC5]).read_octet_string(Size::UNBOUNDED)),
        ErrorKind::InvalidLength
    );
}

#[test]
fn truncated_fragments_do_not_allocate_or_panic() {
    // claims 64K octets but supplies none
    assert_eq!(
        kind(BitReader::new(&[0xC4]).read_octet_string(Size::UNBOUNDED)),
        ErrorKind::UnexpectedEof
    );
    // claims 16383 octets, supplies 3
    assert_eq!(
        kind(BitReader::new(&[0xBF, 0xFF, 1, 2, 3]).read_octet_string(Size::UNBOUNDED)),
        ErrorKind::UnexpectedEof
    );
}

#[test]
fn character_strings_check_the_alphabet() {
    let mut w = BitWriter::new();
    assert_eq!(
        kind(w.write_char_string("a_b", Size::UNBOUNDED, CharSet::Printable)),
        ErrorKind::InvalidCharacter
    );
    assert_eq!(
        kind(w.write_char_string("\u{e9}", Size::UNBOUNDED, CharSet::Visible)),
        ErrorKind::InvalidCharacter
    );
    assert_eq!(
        kind(w.write_char_string("a\tb", Size::UNBOUNDED, CharSet::Visible)),
        ErrorKind::InvalidCharacter
    );
    w.write_char_string("Az09 '()+,-./:=?", Size::UNBOUNDED, CharSet::Printable)
        .unwrap();
    // decoding a '*' as PrintableString is an error, as VisibleString it is fine
    let mut w = BitWriter::new();
    w.write_octet_string(b"a*b", Size::UNBOUNDED).unwrap();
    let b = w.into_bytes();
    assert_eq!(
        kind(BitReader::new(&b).read_char_string(Size::UNBOUNDED, CharSet::Printable)),
        ErrorKind::InvalidCharacter
    );
    assert_eq!(
        BitReader::new(&b)
            .read_char_string(Size::UNBOUNDED, CharSet::Visible)
            .unwrap(),
        "a*b"
    );
    // invalid UTF-8
    let mut w = BitWriter::new();
    w.write_octet_string(&[0xff, 0xfe], Size::UNBOUNDED)
        .unwrap();
    let b = w.into_bytes();
    assert_eq!(
        kind(BitReader::new(&b).read_utf8_string()),
        ErrorKind::InvalidUtf8
    );
}

#[test]
fn bit_string_values() {
    assert_eq!(
        kind(BitString::new(vec![0], 9)),
        ErrorKind::InvalidBitString
    );
    assert_eq!(
        kind(BitString::new(vec![0, 0], 8)),
        ErrorKind::InvalidBitString
    );
    // unused trailing bits are cleared so equal bit strings compare equal
    assert_eq!(
        BitString::new(vec![0xFF], 3).unwrap(),
        BitString::new(vec![0xE0], 3).unwrap()
    );
    let b = BitString::from_bits(&[true, false, true]);
    assert_eq!(
        (
            b.bit_len(),
            b.as_bytes(),
            b.get(0),
            b.get(1),
            b.get(2),
            b.get(3)
        ),
        (3, &[0xA0][..], Some(true), Some(false), Some(true), None)
    );
    assert_eq!(format!("{b:?}"), "BitString<101>");
    assert!(BitString::default().is_empty());
}

#[test]
fn object_identifiers() {
    assert!(ObjectIdentifier::new(vec![1]).is_err());
    assert!(ObjectIdentifier::new(vec![3, 1]).is_err());
    assert!(ObjectIdentifier::new(vec![1, 40]).is_err());
    assert!(ObjectIdentifier::new(vec![2, 40]).is_ok());
    for arcs in [
        vec![0, 0],
        vec![1, 39, 5],
        vec![2, 47, 18446744073709551615],
        vec![2, 100, 3, 128, 16384, 2097152],
    ] {
        let oid = ObjectIdentifier::new(arcs).unwrap();
        let mut w = BitWriter::new();
        w.write_object_identifier(&oid).unwrap();
        let b = w.into_bytes();
        assert_eq!(BitReader::new(&b).read_object_identifier().unwrap(), oid);
    }
    // malformed contents: empty, dangling continuation bit, non-minimal subidentifier (0x80 lead)
    for bad in [&[0u8][..], &[1, 0x81], &[2, 0x80, 0x01]] {
        assert_eq!(
            kind(BitReader::new(bad).read_object_identifier()),
            ErrorKind::InvalidObjectIdentifier,
            "{bad:?}"
        );
    }
}

#[test]
fn indices() {
    let mut w = BitWriter::new();
    assert_eq!(kind(w.write_index(3, 3, false)), ErrorKind::InvalidIndex(3));
    assert_eq!(kind(w.write_index(0, 0, false)), ErrorKind::ValueOutOfRange);
    // extension additions are reported as root_count + k, including k >= 64 (long form)
    for idx in [0u64, 2, 3, 4, 66, 67, 500] {
        let mut w = BitWriter::new();
        w.write_index(idx, 3, true).unwrap();
        let b = w.into_bytes();
        assert_eq!(BitReader::new(&b).read_index(3, true).unwrap(), idx);
    }
    // a non-extensible 3-value field read as value 3 is invalid
    assert_eq!(
        kind(BitReader::new(&[0b1100_0000]).read_index(3, false)),
        ErrorKind::ValueOutOfRange
    );
}

#[test]
fn extension_additions() {
    let mut w = BitWriter::new();
    assert_eq!(
        kind(w.write_extension_additions(&[])),
        ErrorKind::SizeOutOfRange
    );
    // 70 additions (> 64: long form of the normally small length), only two present
    let mut adds: Vec<Option<Vec<u8>>> = vec![None; 70];
    adds[3] = Some(vec![0xAB]);
    adds[69] = Some(vec![1, 2, 3]);
    let mut w = BitWriter::new();
    w.write_bit(true);
    w.write_extension_additions(&adds).unwrap();
    let b = w.into_bytes();
    let mut r = BitReader::new(&b);
    assert!(r.read_bit().unwrap());
    assert_eq!(r.read_extension_additions().unwrap(), adds);
    // an empty complete encoding is written as one zero octet
    let mut w = BitWriter::new();
    w.write_extension_additions(&[Some(vec![])]).unwrap();
    let b = w.into_bytes();
    assert_eq!(
        BitReader::new(&b).read_extension_additions().unwrap(),
        vec![Some(vec![0u8])]
    );
}

#[derive(Debug, PartialEq)]
struct Pair(i128, Vec<u8>);
impl AperEncode for Pair {
    fn aper_encode(&self, w: &mut BitWriter) -> ngap_aper::Result<()> {
        w.write_constrained_int(self.0, 0, 7)?;
        w.write_octet_string(&self.1, Size::range(1, 10))
    }
}
impl AperDecode for Pair {
    fn aper_decode(r: &mut BitReader<'_>) -> ngap_aper::Result<Self> {
        Ok(Pair(
            r.read_constrained_int(0, 7)?,
            r.read_octet_string(Size::range(1, 10))?,
        ))
    }
}

#[test]
fn whole_value_helpers_and_contained() {
    let p = Pair(5, vec![9, 8, 7]);
    let bytes = to_vec(&p).unwrap();
    assert_eq!(from_slice::<Pair>(&bytes).unwrap(), p);
    // trailing whole octets are rejected, padding bits are not
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(kind(from_slice::<Pair>(&extra)), ErrorKind::TrailingData);
    // an encoding of zero bits still becomes one octet
    struct Nothing;
    impl AperEncode for Nothing {
        fn aper_encode(&self, _: &mut BitWriter) -> ngap_aper::Result<()> {
            Ok(())
        }
    }
    assert_eq!(to_vec(&Nothing).unwrap(), vec![0]);

    let c = Contained::<Pair>::encode_from(&p).unwrap();
    assert_eq!(c.raw(), &bytes[..]);
    assert_eq!(c.decode().unwrap(), p);
    assert_eq!(c.clone(), c);
    assert!(format!("{c:?}").contains("Pair"));
    // as a field it is an unconstrained OCTET STRING: forwarded untouched, even if the content is not valid
    let junk = Contained::<Pair>::from_raw(vec![0xFF, 0xFF, 0xFF]);
    let mut w = BitWriter::new();
    junk.aper_encode(&mut w).unwrap();
    let b = w.into_bytes();
    let back = Contained::<Pair>::aper_decode(&mut BitReader::new(&b)).unwrap();
    assert_eq!(back, junk);
    assert!(back.decode().is_err());
    assert_eq!(back.into_raw(), vec![0xFF, 0xFF, 0xFF]);
}

#[test]
fn zero_size_items_are_bounded() {
    // SEQUENCE OF a single-valued INTEGER: items take no bits; 4 fragments of 16K * many would be amplification
    // three headers of 64K items each, no data, then a zero-length final chunk
    let mut input = vec![0xC4; 3];
    input.push(0x00);
    let res = BitReader::new(&input).read_seq_of(Size::UNBOUNDED, |r| r.read_constrained_int(0, 0));
    assert_eq!(kind(res), ErrorKind::SizeOutOfRange);
}

/// Deterministic pseudo-random garbage into every decoder: errors are fine, panics and hangs are not.
#[test]
fn random_input_never_panics() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for round in 0..30_000 {
        let len = (next() % 40) as usize;
        let mut data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 3 == 0 && !data.is_empty() {
            data[0] = [0x00, 0x7F, 0x80, 0xBF, 0xC1, 0xC4, 0xFF][(next() % 7) as usize]; // length-determinant shapes
        }
        let d = &data[..];
        let _ = BitReader::new(d).read_constrained_int(0, 7);
        let _ = BitReader::new(d).read_constrained_int(-5, 100_000);
        let _ = BitReader::new(d).read_constrained_int(0, i128::from(u64::MAX));
        let _ = BitReader::new(d).read_ext_constrained_int(1, 65535);
        let _ = BitReader::new(d).read_unconstrained_int();
        let _ = BitReader::new(d).read_semi_constrained_int(3);
        let _ = BitReader::new(d).read_normally_small();
        let _ = BitReader::new(d).read_index(5, true);
        let _ = BitReader::new(d).read_octet_string(Size::UNBOUNDED);
        let _ = BitReader::new(d).read_octet_string(Size::range(1, 150).extensible());
        let _ = BitReader::new(d).read_octet_string(Size::fixed(3));
        let _ = BitReader::new(d).read_bit_string(Size::UNBOUNDED);
        let _ = BitReader::new(d).read_bit_string(Size::range(1, 1024).extensible());
        let _ = BitReader::new(d).read_bit_string(Size::fixed(28));
        let _ = BitReader::new(d)
            .read_char_string(Size::range(1, 150).extensible(), CharSet::Printable);
        let _ = BitReader::new(d).read_utf8_string();
        let _ = BitReader::new(d).read_object_identifier();
        let _ = BitReader::new(d).read_extension_additions();
        let _ = BitReader::new(d).read_open_type();
        let _ = BitReader::new(d).read_seq_of(Size::range(1, 4), |r| r.read_constrained_int(0, 7));
        let _ = BitReader::new(d)
            .read_seq_of(Size::UNBOUNDED, |r| r.read_octet_string(Size::range(1, 4)));
        let _ = BitReader::new(d).read_seq_of(Size::range(0, 65535), |r| r.read_bit());
    }
}

#[test]
fn int_spec_validates_gaps_and_extension_additions() {
    // `INTEGER (1..30|40|181, ..., 500..600)`: PER encodes the span 1..=181, but 35 is not a defined value
    const S: ngap_aper::IntSpec = ngap_aper::IntSpec::range(1, 181)
        .extensible()
        .with_ranges(&[(1, 30), (40, 40), (181, 181)])
        .with_additions(&[(500, 600)]);
    for ok in [1, 30, 40, 181, 500, 550, 600] {
        let mut w = BitWriter::new();
        w.write_int(ok, &S).unwrap();
        let b = w.into_bytes();
        assert_eq!(BitReader::new(&b).read_int(&S).unwrap(), ok, "{ok}");
    }
    for bad in [0, 31, 35, 39, 41, 180, 182, 499, 601, -5] {
        assert_eq!(
            kind(BitWriter::new().write_int(bad, &S)),
            ErrorKind::ValueOutOfRange,
            "{bad}"
        );
    }
    // a decoder meeting a value in a gap (the PER range accepts it) rejects it as well
    let mut w = BitWriter::new();
    w.write_bit(false);
    w.write_constrained_int(35, 1, 181).unwrap();
    let b = w.into_bytes();
    assert_eq!(
        kind(BitReader::new(&b).read_int(&S)),
        ErrorKind::ValueOutOfRange
    );
    // an extension value that no addition defines
    let mut w = BitWriter::new();
    w.write_bit(true);
    w.write_unconstrained_int(700).unwrap();
    let b = w.into_bytes();
    assert_eq!(
        kind(BitReader::new(&b).read_int(&S)),
        ErrorKind::ValueOutOfRange
    );
    // conversion to a narrower Rust type
    let mut w = BitWriter::new();
    w.write_int(300, &ngap_aper::IntSpec::range(0, 1000))
        .unwrap();
    let b = w.into_bytes();
    assert_eq!(
        kind(BitReader::new(&b).read_int_as::<u8>(&ngap_aper::IntSpec::range(0, 1000))),
        ErrorKind::ValueOutOfRange
    );
    // semi-constrained and unconstrained
    for v in [0i128, 5, 1 << 40] {
        let mut w = BitWriter::new();
        w.write_int(v, &ngap_aper::IntSpec::semi(0)).unwrap();
        let b = w.into_bytes();
        assert_eq!(
            BitReader::new(&b)
                .read_int(&ngap_aper::IntSpec::semi(0))
                .unwrap(),
            v
        );
    }
    assert_eq!(
        kind(BitWriter::new().write_int(-1, &ngap_aper::IntSpec::semi(0))),
        ErrorKind::ValueOutOfRange
    );
}

#[test]
fn an_open_type_of_length_zero_is_invalid() {
    // X.691 11.2: the complete encoding of a value is at least one octet (an empty one is sent as one zero octet)
    let mut w = ngap_aper::BitWriter::new();
    w.write_open_type(&[]).unwrap();
    let bytes = w.into_complete_bytes();
    assert_eq!(bytes, [0x01, 0x00]);
    assert_eq!(
        ngap_aper::BitReader::new(&bytes).read_open_type().unwrap(),
        [0]
    );
    let e = ngap_aper::BitReader::new(&[0x00])
        .read_open_type()
        .unwrap_err();
    assert_eq!(e.kind, ngap_aper::ErrorKind::InvalidLength);
}
