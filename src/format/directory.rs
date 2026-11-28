//! Sorted inline directory payload; large directories use directory_tree pages.
use super::{
    codec,
    header::FormatError,
    inode::{DIRECTORY, FILE, MAX_INLINE_SIZE, SYMLINK},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub id: [u8; 16],
    pub kind: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Directory {
    #[serde(deserialize_with = "codec::bounded::<_,_,1024>")]
    pub entries: Vec<Entry>,
}
impl Directory {
    fn validate(&self) -> Result<(), FormatError> {
        validate_entries(&self.entries, 1024)
    }
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        codec::frame(b"COCFSDIR", 1, MAX_INLINE_SIZE, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let d: Self = codec::unframe(b"COCFSDIR", 1, MAX_INLINE_SIZE, bytes)?;
        d.validate()?;
        Ok(d)
    }
}

pub(crate) fn validate_entries(entries: &[Entry], limit: usize) -> Result<(), FormatError> {
    if entries.len() > limit {
        return Err(FormatError::TooLarge);
    }
    let mut previous = "";
    for e in entries {
        if e.name.is_empty()
            || e.name.len() > 255
            || e.name.contains(['/', '\0'])
            || matches!(e.name.as_str(), "." | "..")
            || e.name.as_str() <= previous
            || !matches!(e.kind, FILE | DIRECTORY | SYMLINK)
        {
            return Err(FormatError::Invalid("directory entry"));
        }
        previous = &e.name;
    }
    Ok(())
}
