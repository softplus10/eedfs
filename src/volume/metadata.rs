//! Numeric ownership checks and independent attribute updates.
use super::{Error, Result};
use crate::format::metadata::{Metadata, Timestamp};
#[derive(Clone, Debug, Default)]
pub struct MetadataUpdate {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
}
impl MetadataUpdate {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
    }
    pub fn apply(&self, current: &Metadata, actor: (u32, u32)) -> Result<Metadata> {
        if actor.0 != 0 {
            if actor.0 != current.uid {
                return Err(Error::Permission);
            }
            if self.uid.is_some_and(|u| u != current.uid)
                || self.gid.is_some_and(|g| g != current.gid && g != actor.1)
            {
                return Err(Error::Permission);
            }
        }
        let mut m = current.clone();
        if let Some(v) = self.mode {
            m.mode = v;
        }
        if let Some(v) = self.uid {
            m.uid = v;
            m.mode &= !0o6000;
        }
        if let Some(v) = self.gid {
            m.gid = v;
            m.mode &= !0o6000;
        }
        if let Some(v) = self.atime {
            m.atime = v;
        }
        if let Some(v) = self.mtime {
            m.mtime = v;
        }
        m.ctime = Timestamp::now();
        m.validate()?;
        Ok(m)
    }
    pub(super) fn accumulate(&mut self, other: &Self) {
        if other.mode.is_some() {
            self.mode = other.mode;
        }
        if other.uid.is_some() {
            self.uid = other.uid;
        }
        if other.gid.is_some() {
            self.gid = other.gid;
        }
        if other.atime.is_some() {
            self.atime = other.atime;
        }
        if other.mtime.is_some() {
            self.mtime = other.mtime;
        }
    }
    pub(super) fn rebase(
        &self,
        base: &Metadata,
        latest: &Metadata,
        desired: &Metadata,
    ) -> Result<Metadata> {
        let mut next = latest.clone();
        macro_rules! field {
            ($f:ident) => {
                if self.$f.is_some() {
                    if base.$f != latest.$f && desired.$f != latest.$f {
                        return Err(Error::Conflict);
                    }
                    next.$f = desired.$f;
                }
            };
        }
        field!(mode);
        field!(uid);
        field!(gid);
        field!(atime);
        field!(mtime);
        next.ctime = Timestamp::now();
        Ok(next)
    }
}
