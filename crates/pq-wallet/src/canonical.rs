use crate::Error;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// Typed structs declare fields in ASCII order. Deserialization rejects duplicate
// and unknown fields; exact reserialization rejects alternate number/key forms.
// Borrowing the recovery root avoids a second heap allocation containing it.
pub(crate) fn decode<'a, T: Deserialize<'a> + Serialize>(
    bytes: &'a [u8],
    limit: usize,
) -> Result<T, Error> {
    if bytes.len() > limit {
        return Err(Error::Limits);
    }
    let mut depth = 0usize;
    let mut string = false;
    for byte in bytes {
        if !(0x20..=0x7e).contains(byte) || *byte == b'\\' {
            return Err(Error::Encoding);
        }
        match byte {
            b'"' => string = !string,
            b'[' | b'{' if !string => {
                depth += 1;
                if depth > 16 {
                    return Err(Error::Limits);
                }
            }
            b']' | b'}' if !string => {
                depth = depth.checked_sub(1).ok_or(Error::Encoding)?;
            }
            _ => {}
        }
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| Error::Encoding)?;
    if encode(&value, limit)?.as_slice() != bytes {
        return Err(Error::Encoding);
    }
    Ok(value)
}

pub(crate) fn encode(value: &impl Serialize, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Length {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Length {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| std::io::Error::other("encoding size limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Count before allocation, then serialize directly into a clearing buffer
    // with enough capacity. Reallocation could leave a plaintext root copy in
    // an old allocation that Zeroizing would no longer own.
    let mut length = Length { bytes: 0, limit };
    serde_json::to_writer(&mut length, value).map_err(|_| Error::Limits)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length.bytes)
        .map_err(|_| Error::Limits)?;
    serde_json::to_writer(&mut *bytes, value).map_err(|_| Error::Encoding)?;
    Ok(bytes)
}
