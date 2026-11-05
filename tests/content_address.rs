use std::collections::{BTreeMap, HashMap};

use proptest::prelude::*;
use serde::Serialize;
use serde::ser::{Error as _, SerializeMap, Serializer};
use serde_json::{Value, json};
use tameshi::content_address::{CanonicalJson, ContentAddress, ContentAddressError};

const EMPTY_BYTES_B3: &str = "b3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

const GOLDEN: &[(&str, &str)] = &[
    (
        r#"{"a":1,"b":2,"c":{"y":null,"z":true}}"#,
        "b3:77ee186fd5b0e9b2ecbd7a75af54a52039ae91802636442b3b2cccf755bd9a12",
    ),
    (
        r#"{"outer":{"inner":{"k":"v","list":[3,1,2]}}}"#,
        "b3:f5fbbfc62e3874e60c4a90410d5a3e001320047194a7e008855101b9a2fa9888",
    ),
    (
        "{\"ctl\":\"\\n\\t\\\"\\\\\\u0001\",\"emoji\":\"🦀\",\"é\":\"é\",\"名前\":\"試し\"}",
        "b3:5a1ac527e4e0d9f8aa50a830877740d1637ab38ffa59a47f93f164e8e3116516",
    ),
    (
        r#"{"exp":1e+300,"float":1.5,"i64min":-9223372036854775808,"neg":-1,"negzero":-0.0,"u64max":18446744073709551615,"zero":0}"#,
        "b3:17d0e3829aea95d78a51410f5ad678d4c4094165838938b1ffee85b35fa7053e",
    ),
    (
        "{}",
        "b3:6e46dd10defc9b56c29a6ec56b508c21f54c08192194e4df25bf36f0c9c3c279",
    ),
    (
        "[]",
        "b3:d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab",
    ),
    (
        "null",
        "b3:03f88b99c3d8073bba8948d6e762aac443b265f606cc05abd4d172f03a4def6a",
    ),
    (
        "\"\"",
        "b3:1286f4d583fcffb2849e654c9ec78d95c03e83bf73d6b4c18b21df1dda49c7fa",
    ),
    (
        r#"{"10":1,"2":0}"#,
        "b3:49e0b61f3be269d649e5adcceb77b5bfc9075d946c2dda5925bc1dc9e2ab0992",
    ),
];

fn golden_inputs() -> Vec<Box<dyn erased::Addressable>> {
    vec![
        Box::new(json!({"b": 2, "a": 1, "c": {"z": true, "y": null}})),
        Box::new(json!({"outer": {"inner": {"list": [3, 1, 2], "k": "v"}}})),
        Box::new(json!({"名前": "試し", "é": "é", "emoji": "🦀", "ctl": "\n\t\"\\\u{1}"})),
        Box::new(json!({
            "zero": 0, "u64max": u64::MAX, "neg": -1, "negzero": -0.0,
            "i64min": i64::MIN, "float": 1.5, "exp": 1e300,
        })),
        Box::new(json!({})),
        Box::new(json!([])),
        Box::new(json!(null)),
        Box::new(json!("")),
        Box::new(BTreeMap::from([(2u32, 0u8), (10, 1)])),
    ]
}

mod erased {
    use super::{CanonicalJson, ContentAddress, ContentAddressError};

    pub trait Addressable {
        fn canonical(&self) -> Result<CanonicalJson, ContentAddressError>;
        fn address(&self) -> Result<ContentAddress, ContentAddressError>;
    }

    impl<T: serde::Serialize> Addressable for T {
        fn canonical(&self) -> Result<CanonicalJson, ContentAddressError> {
            CanonicalJson::of(self)
        }
        fn address(&self) -> Result<ContentAddress, ContentAddressError> {
            ContentAddress::of_json(self)
        }
    }
}

#[test]
fn golden_vectors_pin_bytes_and_address() {
    let inputs = golden_inputs();
    assert_eq!(inputs.len(), GOLDEN.len());
    for (input, (bytes, b3)) in inputs.iter().zip(GOLDEN) {
        let canonical = input.canonical().unwrap();
        assert_eq!(std::str::from_utf8(canonical.as_bytes()).unwrap(), *bytes);
        assert_eq!(canonical.address().to_b3(), *b3);
        assert_eq!(input.address().unwrap().to_b3(), *b3);
        assert_eq!(
            ContentAddress::of_json(&serde_json::from_str::<Value>(bytes).unwrap())
                .unwrap()
                .to_b3(),
            *b3
        );
    }
}

#[derive(Serialize)]
struct Forward {
    alpha: u32,
    beta: &'static str,
    gamma: Vec<bool>,
}

#[derive(Serialize)]
struct Reordered {
    gamma: Vec<bool>,
    beta: &'static str,
    alpha: u32,
}

struct Ordered(Vec<(&'static str, Value)>);

impl Serialize for Ordered {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

#[test]
fn field_reordering_keeps_the_address() {
    let forward = Forward {
        alpha: 7,
        beta: "b",
        gamma: vec![true, false],
    };
    let reordered = Reordered {
        gamma: vec![true, false],
        beta: "b",
        alpha: 7,
    };
    let a = ContentAddress::of_json(&forward).unwrap();
    assert_eq!(a, ContentAddress::of_json(&reordered).unwrap());
    assert_eq!(
        CanonicalJson::of(&forward).unwrap().as_bytes(),
        br#"{"alpha":7,"beta":"b","gamma":[true,false]}"#
    );
    let insertion = Ordered(vec![
        ("gamma", json!([true, false])),
        ("beta", json!("b")),
        ("alpha", json!(7)),
    ]);
    assert_eq!(a, ContentAddress::of_json(&insertion).unwrap());
}

#[test]
fn array_order_is_content() {
    assert_ne!(
        ContentAddress::of_json(&[1, 2]).unwrap(),
        ContentAddress::of_json(&[2, 1]).unwrap()
    );
}

struct Fails;

impl Serialize for Fails {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(S::Error::custom("capture failed"))
    }
}

#[derive(Serialize)]
struct Capture {
    ok: u8,
    bad: Fails,
}

#[test]
fn failed_serialization_is_refused_not_hashed_as_empty() {
    assert_eq!(
        ContentAddress::of_json(&Fails),
        Err(ContentAddressError::Refused("capture failed".to_owned()))
    );
    assert_eq!(
        ContentAddress::of_json(&Capture { ok: 1, bad: Fails }),
        Err(ContentAddressError::Refused("capture failed".to_owned()))
    );
    assert!(CanonicalJson::of(&vec![Fails]).is_err());
    assert_eq!(
        ContentAddress::from_b3(EMPTY_BYTES_B3).unwrap().as_bytes(),
        blake3::hash(b"").as_bytes()
    );
    for (_, b3) in GOLDEN {
        assert_ne!(*b3, EMPTY_BYTES_B3);
    }
}

#[test]
fn values_without_a_canonical_form_are_refused() {
    assert!(matches!(
        ContentAddress::of_json(&f64::NAN),
        Err(ContentAddressError::NonFinite(_))
    ));
    assert!(matches!(
        ContentAddress::of_json(&vec![1.0f32, f32::INFINITY]),
        Err(ContentAddressError::NonFinite(_))
    ));
    assert!(matches!(
        ContentAddress::of_json(&(u128::from(u64::MAX) + 1)),
        Err(ContentAddressError::IntegerOutOfRange(_))
    ));
    assert!(matches!(
        ContentAddress::of_json(&i128::MIN),
        Err(ContentAddressError::IntegerOutOfRange(_))
    ));
    assert_eq!(
        ContentAddress::of_json(&u128::from(u64::MAX)).unwrap(),
        ContentAddress::of_json(&u64::MAX).unwrap()
    );
    assert!(matches!(
        ContentAddress::of_json(&BTreeMap::from([(vec![1u8], 0u8)])),
        Err(ContentAddressError::KeyNotString(_))
    ));
    assert_eq!(
        ContentAddress::of_json(&Ordered(vec![("k", json!(1)), ("k", json!(2))])),
        Err(ContentAddressError::DuplicateKey("k".to_owned()))
    );
}

#[test]
fn enums_take_the_serde_json_external_tag() {
    #[derive(Serialize)]
    enum E {
        Unit,
        New(u8),
        Tuple(u8, u8),
        Struct { b: u8, a: u8 },
    }
    let text = |e: &E| String::from_utf8(CanonicalJson::of(e).unwrap().into_bytes()).unwrap();
    assert_eq!(text(&E::Unit), r#""Unit""#);
    assert_eq!(text(&E::New(1)), r#"{"New":1}"#);
    assert_eq!(text(&E::Tuple(1, 2)), r#"{"Tuple":[1,2]}"#);
    assert_eq!(
        text(&E::Struct { b: 2, a: 1 }),
        r#"{"Struct":{"a":1,"b":2}}"#
    );
}

#[test]
fn b3_text_round_trips_and_refuses_other_forms() {
    let a = ContentAddress::of_json(&json!({"a": 1})).unwrap();
    assert_eq!(a.to_string(), a.to_b3());
    assert_eq!(a.to_b3().parse::<ContentAddress>().unwrap(), a);
    let wire = serde_json::to_string(&a).unwrap();
    assert_eq!(wire, format!("\"{}\"", a.to_b3()));
    assert_eq!(serde_json::from_str::<ContentAddress>(&wire).unwrap(), a);
    let hex = a.to_hex();
    for bad in [
        hex.clone(),
        format!("blake3:{hex}"),
        format!("b3:{}", hex.to_uppercase()),
        format!("b3:{}", &hex[..63]),
        format!("b3:{hex}0"),
        format!("b3:{}g", &hex[..63]),
    ] {
        assert_eq!(
            ContentAddress::from_b3(&bad),
            Err(ContentAddressError::NotAnAddress(bad.clone()))
        );
        assert!(serde_json::from_value::<ContentAddress>(Value::String(bad)).is_err());
    }
}

proptest! {
    #[test]
    fn map_kind_and_insertion_order_never_move_the_address(
        entries in proptest::collection::vec(("[a-zA-Z0-9_é名]{0,8}", any::<i64>()), 0..24)
    ) {
        let hash: HashMap<String, i64> = entries.iter().cloned().collect();
        let tree: BTreeMap<String, i64> = hash.clone().into_iter().collect();
        let a = ContentAddress::of_json(&hash).unwrap();
        prop_assert_eq!(a, ContentAddress::of_json(&tree).unwrap());
        let canonical = CanonicalJson::of(&tree).unwrap();
        prop_assert_eq!(serde_json::from_slice::<Value>(canonical.as_bytes()).unwrap(), serde_json::to_value(&tree).unwrap());
        prop_assert_eq!(canonical.address(), a);
    }
}

#[cfg(feature = "full")]
#[test]
fn widens_to_the_blake3_hash_it_is() {
    let a = ContentAddress::of_json(&json!({"a": 1})).unwrap();
    let h = tameshi::hash::Blake3Hash::from(a);
    assert_eq!(h.to_b3(), a.to_b3());
    assert_eq!(&h.0, a.as_bytes());
}
