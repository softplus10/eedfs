//! Directory v2 root and immutable B+tree pages, all stored under encryption.
use super::{
    codec,
    directory::{Entry, validate_entries},
    header::FormatError,
    inode::MAX_INLINE_SIZE,
};
use serde::{Deserialize, Serialize};

pub const FANOUT: usize = 64;
pub const MAX_HEIGHT: u8 = 6;
pub const MAX_ENTRIES: u64 = 1_000_000;
type Result<T> = std::result::Result<T, FormatError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRef {
    pub id: [u8; 16],
    pub len: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Child {
    pub first: String,
    pub page: PageRef,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    pub child: Child,
    pub height: u8,
    pub entries: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Page {
    Leaf(#[serde(deserialize_with = "codec::bounded::<_, _, FANOUT>")] Vec<Entry>),
    Branch(#[serde(deserialize_with = "codec::bounded::<_, _, FANOUT>")] Vec<Child>),
}
impl Child {
    fn validate(&self) -> Result<()> {
        validate_entries(
            &[Entry {
                name: self.first.clone(),
                id: [0; 16],
                kind: super::inode::FILE,
            }],
            1,
        )?;
        if self.page.id == [0; 16] || !(16..=MAX_INLINE_SIZE as u32).contains(&self.page.len) {
            return Err(FormatError::Invalid("directory page reference"));
        }
        Ok(())
    }
}
impl Root {
    pub fn is_tree(bytes: &[u8]) -> bool {
        bytes.get(..10) == Some(b"COCFSDIR\x02\x00")
    }
    fn validate(&self) -> Result<()> {
        self.child.validate()?;
        if self.height > MAX_HEIGHT || self.entries == 0 || self.entries > MAX_ENTRIES {
            return Err(FormatError::Invalid("directory tree bounds"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(b"COCFSDIR", 2, MAX_INLINE_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root: Self = codec::unframe(b"COCFSDIR", 2, MAX_INLINE_SIZE, bytes)?;
        root.validate()?;
        Ok(root)
    }
}
impl Page {
    pub fn first(&self) -> &str {
        match self {
            Self::Leaf(entries) => &entries[0].name,
            Self::Branch(children) => &children[0].first,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Leaf(entries) => {
                if entries.is_empty() {
                    return Err(FormatError::Invalid("empty directory leaf"));
                }
                validate_entries(entries, FANOUT)?;
            }
            Self::Branch(children) => {
                if children.is_empty() || children.len() > FANOUT {
                    return Err(FormatError::Invalid("directory branch size"));
                }
                let mut previous = "";
                for child in children {
                    child.validate()?;
                    if child.first.as_str() <= previous {
                        return Err(FormatError::Invalid("directory branch order"));
                    }
                    previous = &child.first;
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        codec::frame(b"COCFSDPG", 1, MAX_INLINE_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let page: Self = codec::unframe(b"COCFSDPG", 1, MAX_INLINE_SIZE, bytes)?;
        page.validate()?;
        Ok(page)
    }
}
