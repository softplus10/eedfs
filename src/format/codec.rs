//! Shared framing and bounded Serde/Postcard helpers. Not a cryptographic layer.

use super::header::FormatError;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, DeserializeOwned, SeqAccess, Visitor},
};
use std::{fmt, marker::PhantomData};
type Result<T> = std::result::Result<T, FormatError>;
const PREFIX_SIZE: usize = 16;

pub(super) fn frame<T: Serialize>(
    magic: &[u8; 8],
    version: u16,
    limit: usize,
    value: &T,
) -> Result<Vec<u8>> {
    let body = encode_value(value, limit.saturating_sub(PREFIX_SIZE))?;
    let len = u32::try_from(body.len()).map_err(|_| FormatError::TooLarge)?;
    let mut out = Vec::with_capacity(PREFIX_SIZE + body.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}
pub(super) fn unframe<T: DeserializeOwned + Serialize>(
    magic: &[u8; 8],
    version: u16,
    limit: usize,
    bytes: &[u8],
) -> Result<T> {
    if bytes.len() > limit {
        return Err(FormatError::TooLarge);
    }
    if bytes.len() < PREFIX_SIZE {
        return Err(FormatError::Truncated);
    }
    if &bytes[..8] != magic {
        return Err(FormatError::Invalid("magic"));
    }
    let actual = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if actual != version {
        return Err(FormatError::UnsupportedVersion(actual));
    }
    if bytes[10..12] != [0, 0] {
        return Err(FormatError::Invalid("reserved flags"));
    }
    let len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if len != bytes.len() - PREFIX_SIZE {
        return Err(FormatError::Invalid("body length"));
    }
    decode_value(&bytes[PREFIX_SIZE..])
}
pub(super) fn encode_value<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let size = postcard::serialize_with_flavor(value, postcard::ser_flavors::Size::default())?;
    if size > limit {
        return Err(FormatError::TooLarge);
    }
    Ok(postcard::to_allocvec(value)?)
}
pub(super) fn decode_value<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let (value, rest): (T, _) = postcard::take_from_bytes(bytes)?;
    if !rest.is_empty() {
        return Err(FormatError::Invalid("trailing Postcard bytes"));
    }
    if encode_value(&value, bytes.len())? != bytes {
        return Err(FormatError::Invalid("noncanonical Postcard encoding"));
    }
    Ok(value)
}

pub(super) fn bounded<'de, D, T, const N: usize>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|count| count > N) {
                return Err(de::Error::custom("sequence length limit exceeded"));
            }
            let mut out = Vec::new();
            while let Some(value) = seq.next_element()? {
                if out.len() >= N {
                    return Err(de::Error::custom("sequence length limit exceeded"));
                }
                out.push(value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(PhantomData))
}

// Byte blobs use the serializer's bulk-byte API rather than per-byte sequence
// operations. Postcard's byte encoding is identical to Vec<u8>'s wire encoding.
pub(super) fn serialize_bytes<S: Serializer>(
    bytes: &[u8],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}
pub(super) fn bounded_bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    struct Bytes<const N: usize>;
    impl<const N: usize> Visitor<'_> for Bytes<N> {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} bytes")
        }
        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> std::result::Result<Vec<u8>, E> {
            if bytes.len() > N {
                return Err(E::custom("byte length limit exceeded"));
            }
            Ok(bytes.to_vec())
        }
    }
    deserializer.deserialize_bytes(Bytes::<N>)
}

pub(super) fn validate_object_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 1024 {
        return Err(FormatError::Invalid("S3 object key length"));
    }
    Ok(())
}
