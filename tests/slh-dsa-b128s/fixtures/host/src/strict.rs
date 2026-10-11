//! Bounded JSON decoding and canonical hashing for public fixture transport.

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_BYTES: usize = 16 * 1024 * 1024;

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded unsigned ASCII JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                if !v.is_ascii() {
                    return Err(E::custom("non_ascii"));
                }
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if !k.is_ascii() || values.contains_key(&k) {
                        return Err(de::Error::custom("duplicate_or_non_ascii_key"));
                    }
                    let Strict(v) = a.next_value()?;
                    values.insert(k, v);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

pub fn parse(bytes: &[u8]) -> Result<Value, &'static str> {
    if bytes.len() > MAX_BYTES {
        return Err("encoded_size");
    }
    let (mut quoted, mut escaped, mut depth) = (false, false, 0usize);
    for &b in bytes {
        if !b.is_ascii() {
            return Err("non_ascii");
        }
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 16 {
                        return Err("nesting");
                    }
                }
                b'}' | b']' => {
                    depth = depth.checked_sub(1).ok_or("json")?;
                }
                // No accepted literal contains these bytes except `false`/`true`.
                b'-' | b'+' | b'.' => return Err("numeric_token"),
                _ => {}
            }
        }
    }
    // StrictVisitor rejects floats (including exponent notation), signed values,
    // overflow, non-ASCII escape expansions, and duplicates before typed decoding.
    let Strict(value) = serde_json::from_slice(bytes).map_err(|_| "json")?;
    Ok(value)
}

pub fn canonical(value: &Value) -> Vec<u8> {
    fn ascii_json(v: impl serde::Serialize, out: &mut Vec<u8>) {
        for byte in serde_json::to_vec(&v).expect("bounded JSON serializes") {
            if byte == 127 {
                out.extend_from_slice(b"\\u007f");
            } else {
                out.push(byte);
            }
        }
    }
    fn write(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Object(map) => {
                let sorted: BTreeMap<_, _> = map.iter().collect();
                out.push(b'{');
                for (i, (key, value)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    ascii_json(key, out);
                    out.push(b':');
                    write(value, out);
                }
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write(value, out);
                }
                out.push(b']');
            }
            _ => ascii_json(v, out),
        }
    }
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn artifact_hash(value: &Value) -> Result<String, &'static str> {
    let mut object = value.as_object().ok_or("artifact_object")?.clone();
    object.remove("artifact_sha256");
    Ok(hash(&canonical(&Value::Object(object))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_json_before_deserialization() {
        for (bytes, reason) in [
            (b"{\"a\":1,\"a\":2}".as_slice(), "json"),
            (b"{\"a\":-0}", "numeric_token"),
            (b"[1.0]", "numeric_token"),
            (b"[1e0]", "json"),
            (b"[18446744073709551616]", "json"),
            (b"[\"\\u00e9\"]", "json"),
            (b"[\"\xc3\xa9\"]", "non_ascii"),
            (b"[NaN]", "json"),
        ] {
            assert_eq!(parse(bytes), Err(reason), "{:?}", bytes);
        }
        let nested = |depth| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse(nested(16).as_bytes()).is_ok());
        assert_eq!(parse(nested(17).as_bytes()), Err("nesting"));
        // Pad a valid document so only the size bound can reject it.
        let mut bounded = b"[0]".to_vec();
        bounded.resize(MAX_BYTES + 1, b' ');
        assert_eq!(parse(&bounded), Err("encoded_size"));
        bounded.pop();
        assert_eq!(parse(&bounded), Ok(serde_json::json!([0])));
        assert_eq!(
            canonical(&parse(br#"{"z":{"b":2,"a":1},"a":[true,null,"x"]}"#).unwrap()),
            br#"{"a":[true,null,"x"],"z":{"a":1,"b":2}}"#
        );
    }
}
