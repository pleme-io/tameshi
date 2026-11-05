//! One content address for a serializable value: BLAKE3 over one canonical JSON.
//!
//! The canonical form sorts every object's keys by byte order, writes no
//! whitespace, and uses `serde_json` string escaping and number text. The
//! address prints as `b3:<64 lowercase hex>`.
//!
//! A value that has no canonical form is refused, never hashed: a failed
//! `Serialize`, a non-finite float, a map key that is not a string, an integer
//! outside the 64-bit range, and a map that names one key twice.
//!
//! ```rust
//! use tameshi::content_address::ContentAddress;
//!
//! let a = ContentAddress::of_json(&serde_json::json!({"b": 2, "a": 1})).unwrap();
//! assert_eq!(
//!     a.to_b3(),
//!     ContentAddress::of_json(&serde_json::json!({"a": 1, "b": 2})).unwrap().to_b3()
//! );
//! assert_eq!(a, a.to_b3().parse().unwrap());
//! assert!(ContentAddress::of_json(&f64::NAN).is_err());
//! ```

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::str::FromStr;

use serde::ser::{self, Serialize};
use serde_json::Number;

/// Why a value has no content address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentAddressError {
    /// The value's own `Serialize` implementation failed.
    #[error("serialization failed: {0}")]
    Refused(String),
    /// A float that JSON cannot carry: NaN or an infinity.
    #[error("non-finite float has no JSON form: {0}")]
    NonFinite(String),
    /// A 128-bit integer outside the 64-bit range JSON numbers carry here.
    #[error("integer outside the 64-bit range: {0}")]
    IntegerOutOfRange(String),
    /// A map key that does not serialize to a string, an integer, a bool or a char.
    #[error("map key is not a string: {0}")]
    KeyNotString(&'static str),
    /// One map named the same key twice.
    #[error("map names key {0:?} twice")]
    DuplicateKey(String),
    /// Text that is not `b3:<64 lowercase hex>`.
    #[error("not a content address (want b3:<64 lowercase hex>): {0:?}")]
    NotAnAddress(String),
}

impl ser::Error for ContentAddressError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::Refused(msg.to_string())
    }
}

/// The canonical JSON bytes of one value: the exact input its address hashes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalJson(Vec<u8>);

impl CanonicalJson {
    /// The canonical JSON of `value`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentAddressError`] naming why `value` has no canonical form.
    pub fn of<T: Serialize + ?Sized>(value: &T) -> Result<Self, ContentAddressError> {
        let tree = value.serialize(Canon)?;
        let mut out = Vec::new();
        write_canonical(&tree, &mut out)?;
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn address(&self) -> ContentAddress {
        ContentAddress(*blake3::hash(&self.0).as_bytes())
    }
}

impl fmt::Debug for CanonicalJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalJson({})", String::from_utf8_lossy(&self.0))
    }
}

/// BLAKE3 over a value's [`CanonicalJson`]. Built only from canonical bytes or parsed `b3:` text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentAddress([u8; 32]);

impl ContentAddress {
    /// The address of `value`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentAddressError`] naming why `value` has no canonical form.
    pub fn of_json<T: Serialize + ?Sized>(value: &T) -> Result<Self, ContentAddressError> {
        CanonicalJson::of(value).map(|c| c.address())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        const_hex::encode(self.0)
    }

    #[must_use]
    pub fn to_b3(&self) -> String {
        format!("b3:{}", self.to_hex())
    }

    /// Parse the strict `b3:<64 lowercase hex>` form.
    ///
    /// # Errors
    ///
    /// Returns [`ContentAddressError::NotAnAddress`] when the prefix, the length or a digit is wrong.
    pub fn from_b3(s: &str) -> Result<Self, ContentAddressError> {
        let refuse = || ContentAddressError::NotAnAddress(s.to_owned());
        let hex = s.strip_prefix("b3:").ok_or_else(refuse)?;
        if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(refuse());
        }
        let mut bytes = [0u8; 32];
        const_hex::decode_to_slice(hex, &mut bytes).map_err(|_| refuse())?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for ContentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_b3())
    }
}

impl fmt::Debug for ContentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentAddress({})", self.to_b3())
    }
}

impl FromStr for ContentAddress {
    type Err = ContentAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_b3(s)
    }
}

impl Serialize for ContentAddress {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_b3())
    }
}

impl<'de> serde::Deserialize<'de> for ContentAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_b3(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "full")]
impl From<ContentAddress> for crate::hash::Blake3Hash {
    fn from(address: ContentAddress) -> Self {
        Self(address.0)
    }
}

enum Node {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Node>),
    Object(BTreeMap<String, Node>),
}

fn int<T: Into<Number>>(v: T) -> Node {
    Node::Number(v.into())
}

fn write_canonical(node: &Node, out: &mut Vec<u8>) -> Result<(), ContentAddressError> {
    match node {
        Node::Null => out.extend_from_slice(b"null"),
        Node::Bool(true) => out.extend_from_slice(b"true"),
        Node::Bool(false) => out.extend_from_slice(b"false"),
        Node::Number(n) => write_json(n, out)?,
        Node::String(s) => write_json(s, out)?,
        Node::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Node::Object(map) => {
            out.push(b'{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json(key, out)?;
                out.push(b':');
                write_canonical(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_json<T: Serialize + ?Sized>(
    value: &T,
    out: &mut Vec<u8>,
) -> Result<(), ContentAddressError> {
    serde_json::to_writer(out, value).map_err(|e| ContentAddressError::Refused(e.to_string()))
}

fn float(v: f64) -> Result<Node, ContentAddressError> {
    Number::from_f64(v)
        .map(Node::Number)
        .ok_or_else(|| ContentAddressError::NonFinite(v.to_string()))
}

fn insert(
    map: &mut BTreeMap<String, Node>,
    key: String,
    value: Node,
) -> Result<(), ContentAddressError> {
    match map.entry(key) {
        Entry::Occupied(taken) => Err(ContentAddressError::DuplicateKey(taken.key().clone())),
        Entry::Vacant(slot) => {
            slot.insert(value);
            Ok(())
        }
    }
}

fn tagged(variant: &str, value: Node) -> Node {
    Node::Object(BTreeMap::from([(variant.to_owned(), value)]))
}

struct Canon;

impl ser::Serializer for Canon {
    type Ok = Node;
    type Error = ContentAddressError;
    type SerializeSeq = Seq;
    type SerializeTuple = Seq;
    type SerializeTupleStruct = Seq;
    type SerializeTupleVariant = TaggedSeq;
    type SerializeMap = Obj;
    type SerializeStruct = Obj;
    type SerializeStructVariant = TaggedObj;

    fn serialize_bool(self, v: bool) -> Result<Node, Self::Error> {
        Ok(Node::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_i16(self, v: i16) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_i32(self, v: i32) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_i64(self, v: i64) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_i128(self, v: i128) -> Result<Node, Self::Error> {
        i64::try_from(v)
            .map(int)
            .or_else(|_| u64::try_from(v).map(int))
            .map_err(|_| ContentAddressError::IntegerOutOfRange(v.to_string()))
    }
    fn serialize_u8(self, v: u8) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_u16(self, v: u16) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_u32(self, v: u32) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_u64(self, v: u64) -> Result<Node, Self::Error> {
        Ok(int(v))
    }
    fn serialize_u128(self, v: u128) -> Result<Node, Self::Error> {
        u64::try_from(v)
            .map(int)
            .map_err(|_| ContentAddressError::IntegerOutOfRange(v.to_string()))
    }
    fn serialize_f32(self, v: f32) -> Result<Node, Self::Error> {
        float(f64::from(v))
    }
    fn serialize_f64(self, v: f64) -> Result<Node, Self::Error> {
        float(v)
    }
    fn serialize_char(self, v: char) -> Result<Node, Self::Error> {
        Ok(Node::String(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Node, Self::Error> {
        Ok(Node::String(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Node, Self::Error> {
        Ok(Node::Array(v.iter().copied().map(int).collect()))
    }
    fn serialize_none(self) -> Result<Node, Self::Error> {
        Ok(Node::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Node, Self::Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Node, Self::Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Node, Self::Error> {
        Ok(Node::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Node, Self::Error> {
        Ok(Node::String(variant.to_owned()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Node, Self::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Node, Self::Error> {
        Ok(tagged(variant, value.serialize(Canon)?))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Seq, Self::Error> {
        Ok(Seq(Vec::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<Seq, Self::Error> {
        Ok(Seq(Vec::with_capacity(len)))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<Seq, Self::Error> {
        Ok(Seq(Vec::with_capacity(len)))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<TaggedSeq, Self::Error> {
        Ok(TaggedSeq(variant, Seq(Vec::with_capacity(len))))
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Obj, Self::Error> {
        Ok(Obj::default())
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Obj, Self::Error> {
        Ok(Obj::default())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<TaggedObj, Self::Error> {
        Ok(TaggedObj(variant, Obj::default()))
    }
}

struct Seq(Vec<Node>);

impl Seq {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), ContentAddressError> {
        self.0.push(value.serialize(Canon)?);
        Ok(())
    }
}

impl ser::SerializeSeq for Seq {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTuple for Seq {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Array(self.0))
    }
}

impl ser::SerializeTupleStruct for Seq {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.push(value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Array(self.0))
    }
}

struct TaggedSeq(&'static str, Seq);

impl ser::SerializeTupleVariant for TaggedSeq {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.1.push(value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(tagged(self.0, Node::Array(self.1.0)))
    }
}

#[derive(Default)]
struct Obj {
    map: BTreeMap<String, Node>,
    key: Option<String>,
}

impl Obj {
    fn field<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), ContentAddressError> {
        let value = value.serialize(Canon)?;
        insert(&mut self.map, key.to_owned(), value)
    }
}

impl ser::SerializeMap for Obj {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.key = Some(key.serialize(Key)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| ContentAddressError::Refused("map value without a key".to_owned()))?;
        let value = value.serialize(Canon)?;
        insert(&mut self.map, key, value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Object(self.map))
    }
}

impl ser::SerializeStruct for Obj {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Object(self.map))
    }
}

struct TaggedObj(&'static str, Obj);

impl ser::SerializeStructVariant for TaggedObj {
    type Ok = Node;
    type Error = ContentAddressError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.1.field(key, value)
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(tagged(self.0, Node::Object(self.1.map)))
    }
}

struct Key;

impl Key {
    fn refuse<T>(kind: &'static str) -> Result<T, ContentAddressError> {
        Err(ContentAddressError::KeyNotString(kind))
    }
}

impl ser::Serializer for Key {
    type Ok = String;
    type Error = ContentAddressError;
    type SerializeSeq = ser::Impossible<String, ContentAddressError>;
    type SerializeTuple = ser::Impossible<String, ContentAddressError>;
    type SerializeTupleStruct = ser::Impossible<String, ContentAddressError>;
    type SerializeTupleVariant = ser::Impossible<String, ContentAddressError>;
    type SerializeMap = ser::Impossible<String, ContentAddressError>;
    type SerializeStruct = ser::Impossible<String, ContentAddressError>;
    type SerializeStructVariant = ser::Impossible<String, ContentAddressError>;

    fn serialize_bool(self, v: bool) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_i8(self, v: i8) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_i16(self, v: i16) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_i32(self, v: i32) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_i64(self, v: i64) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_i128(self, v: i128) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_u8(self, v: u8) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_u16(self, v: u16) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_u32(self, v: u32) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_u64(self, v: u64) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_u128(self, v: u128) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_f32(self, _v: f32) -> Result<String, Self::Error> {
        Self::refuse("f32")
    }
    fn serialize_f64(self, _v: f64) -> Result<String, Self::Error> {
        Self::refuse("f64")
    }
    fn serialize_char(self, v: char) -> Result<String, Self::Error> {
        Ok(v.to_string())
    }
    fn serialize_str(self, v: &str) -> Result<String, Self::Error> {
        Ok(v.to_owned())
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<String, Self::Error> {
        Self::refuse("bytes")
    }
    fn serialize_none(self) -> Result<String, Self::Error> {
        Self::refuse("none")
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, Self::Error> {
        Self::refuse("option")
    }
    fn serialize_unit(self) -> Result<String, Self::Error> {
        Self::refuse("unit")
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, Self::Error> {
        Self::refuse("unit struct")
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<String, Self::Error> {
        Ok(variant.to_owned())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, Self::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, Self::Error> {
        Self::refuse("newtype variant")
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Self::refuse("sequence")
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Self::refuse("tuple")
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Self::refuse("tuple struct")
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Self::refuse("tuple variant")
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Self::refuse("map")
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Self::refuse("struct")
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Self::refuse("struct variant")
    }
}
