//! Every standalone type vector of `testdata/types.txt` (sampled from the resolved ASN.1 without using the generated
//! types, and also checked against the Python oracle by `tools/check_vectors.py`): the generated type must decode the
//! octets and encode them back unchanged.

use std::collections::BTreeSet;

fn vectors() -> Vec<(String, String, Vec<u8>)> {
    include_str!("../../../testdata/types.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(" | "))
        .map(|(k, v)| {
            let (name, tag) = k.rsplit_once('.').expect("name.tag");
            let bytes = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (name.to_owned(), tag.to_owned(), bytes)
        })
        .collect()
}

#[test]
fn every_sampled_type_round_trips_octet_for_octet() {
    let all = vectors();
    assert!(all.len() >= 3800, "only {} vectors", all.len());
    for (name, tag, bytes) in &all {
        let result = ngap_types::round_trip_by_name(name, bytes)
            .unwrap_or_else(|| panic!("{name}: no generated type of that name"));
        let again = result.unwrap_or_else(|e| panic!("{name}.{tag}: {e}"));
        assert_eq!(&again, bytes, "{name}.{tag}: re-encoding differs");
    }
}

#[test]
fn many_distinct_types_are_covered_and_unknown_names_are_not() {
    let names: BTreeSet<_> = vectors().into_iter().map(|(n, ..)| n).collect();
    assert!(names.len() >= 1200, "only {} types", names.len());
    assert!(ngap_types::round_trip_by_name("NoSuchType", &[0]).is_none());
}
