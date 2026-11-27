//! Inode v7 file indexes: immutable offset-ordered extents and last-writer ranges.
use super::{
    codec,
    header::{FormatError, NamingConfig},
    inode::MAX_INLINE_SIZE,
};
use serde::{Deserialize, Serialize};
pub const FANOUT: usize = 128;
pub const MAX_ENTRIES: u64 = 1_000_000;
pub const MAX_HEIGHT: u8 = 6;
type Result<T> = std::result::Result<T, FormatError>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Child {
    pub first: u64,
    pub end: u64,
    pub count: u64,
    pub id: [u8; 16],
    pub len: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    pub child: Child,
    pub height: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Extent { allocation: [u8; 16], index: u64 },
    Version(u64),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub start: u64,
    pub end: u64,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Page {
    Leaf(#[serde(deserialize_with = "codec::bounded::<_, _, FANOUT>")] Vec<Record>),
    Branch(#[serde(deserialize_with = "codec::bounded::<_, _, FANOUT>")] Vec<Child>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRoot {
    pub size: u64,
    pub allocated: u64,
    pub naming: NamingConfig,
    pub extents: Option<Root>,
    pub versions: Option<Root>,
    /// EOF and five explicitly changed attribute-field versions.
    pub flags: [u64; 6],
    #[serde(
        deserialize_with = "codec::bounded_bytes::<_, MAX_INLINE_SIZE>",
        serialize_with = "codec::serialize_bytes"
    )]
    pub inline: Vec<u8>,
}
impl Child {
    pub fn validate(&self) -> Result<()> {
        if self.first >= self.end
            || self.end > i64::MAX as u64
            || self.count == 0
            || self.count > MAX_ENTRIES
            || self.id == [0; 16]
            || !(16..=MAX_INLINE_SIZE as u32).contains(&self.len)
        {
            return Err(FormatError::Invalid("file index child"));
        }
        Ok(())
    }
}
impl Root {
    pub fn validate(&self) -> Result<()> {
        self.child.validate()?;
        if self.height > MAX_HEIGHT {
            return Err(FormatError::Invalid("file index height"));
        }
        Ok(())
    }
}
impl FileRoot {
    pub fn validate(&self, generation: u64) -> Result<()> {
        self.naming.algorithm.validate()?;
        if self.size > i64::MAX as u64
            || self.allocated > self.size
            || self.flags.iter().any(|v| *v > generation)
        {
            return Err(FormatError::Invalid("file index summary"));
        }
        if let Some(root) = &self.extents {
            root.validate()?;
            if root.child.end > self.size
                || self.size <= MAX_INLINE_SIZE as u64
                || !self.inline.is_empty()
            {
                return Err(FormatError::Invalid("file extent summary"));
            }
        }
        if self.size > MAX_INLINE_SIZE as u64 && self.extents.is_none() && self.allocated != 0 {
            return Err(FormatError::Invalid("missing allocated extents"));
        }
        if self.size <= MAX_INLINE_SIZE as u64 {
            if self.inline.len() as u64 != self.size || self.allocated != self.size {
                return Err(FormatError::Invalid("indexed inline bytes"));
            }
        } else if !self.inline.is_empty() {
            return Err(FormatError::Invalid("large indexed inline bytes"));
        }
        if let Some(root) = &self.versions {
            root.validate()?;
        }
        Ok(())
    }
}
impl Page {
    pub fn bounds(&self) -> (u64, u64, u64) {
        match self {
            Self::Leaf(v) => (v[0].start, v.last().unwrap().end, v.len() as u64),
            Self::Branch(v) => (
                v[0].first,
                v.last().unwrap().end,
                v.iter().map(|c| c.count).sum(),
            ),
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Leaf(records) => {
                if records.is_empty() || records.len() > FANOUT {
                    return Err(FormatError::Invalid("file index leaf size"));
                }
                let mut previous = 0;
                for (i, r) in records.iter().enumerate() {
                    if r.start >= r.end || r.end > i64::MAX as u64 || (i > 0 && r.start < previous)
                    {
                        return Err(FormatError::Invalid("file index range order"));
                    }
                    match r.value {
                        Value::Extent { .. }
                            if r.end - r.start > super::data_chunk::MAX_CHUNK_PLAINTEXT as u64 =>
                        {
                            return Err(FormatError::Invalid("file extent length"));
                        }
                        Value::Version(0) => {
                            return Err(FormatError::Invalid("file range generation"));
                        }
                        _ => {}
                    }
                    previous = r.end;
                }
            }
            Self::Branch(children) => {
                if children.is_empty() || children.len() > FANOUT {
                    return Err(FormatError::Invalid("file index branch size"));
                }
                let mut previous = 0;
                let mut count = 0u64;
                for (i, c) in children.iter().enumerate() {
                    c.validate()?;
                    if i > 0 && c.first < previous {
                        return Err(FormatError::Invalid("file index branch order"));
                    }
                    previous = c.end;
                    count = count.checked_add(c.count).ok_or(FormatError::TooLarge)?;
                }
                if count > MAX_ENTRIES {
                    return Err(FormatError::TooLarge);
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(b"EEDFSFPG", 1, MAX_INLINE_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: Self = codec::unframe(b"EEDFSFPG", 1, MAX_INLINE_SIZE, bytes)?;
        p.validate()?;
        Ok(p)
    }
}
