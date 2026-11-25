//! Numeric POSIX ownership and basic inode timestamps; no identity mapping.
use super::header::FormatError;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}
impl Timestamp {
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now()).expect("current time fits i64 seconds")
    }
    pub fn from_system_time(t: SystemTime) -> Result<Self, FormatError> {
        let (seconds, nanos) = match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (
                i64::try_from(d.as_secs()).map_err(|_| FormatError::Invalid("timestamp"))?,
                d.subsec_nanos(),
            ),
            Err(e) => {
                let d = e.duration();
                let secs =
                    i64::try_from(d.as_secs()).map_err(|_| FormatError::Invalid("timestamp"))?;
                if d.subsec_nanos() == 0 {
                    (-secs, 0)
                } else {
                    (
                        secs.checked_add(1)
                            .and_then(i64::checked_neg)
                            .ok_or(FormatError::Invalid("timestamp"))?,
                        1_000_000_000 - d.subsec_nanos(),
                    )
                }
            }
        };
        Ok(Self { seconds, nanos })
    }
    pub fn to_system_time(self) -> Result<SystemTime, FormatError> {
        if self.nanos >= 1_000_000_000 {
            return Err(FormatError::Invalid("timestamp nanos"));
        }
        let t = if self.seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(self.seconds as u64, self.nanos))
        } else if self.nanos == 0 {
            UNIX_EPOCH.checked_sub(Duration::new(self.seconds.unsigned_abs(), 0))
        } else {
            UNIX_EPOCH.checked_sub(Duration::new(
                (self.seconds + 1).unsigned_abs(),
                1_000_000_000 - self.nanos,
            ))
        };
        t.ok_or(FormatError::Invalid("timestamp range"))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub created: Timestamp,
}
impl Default for Metadata {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            mode: 0o644,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
            created: Timestamp::default(),
        }
    }
}
impl Metadata {
    pub fn new(uid: u32, gid: u32, mode: u16) -> Self {
        let now = Timestamp::now();
        Self {
            uid,
            gid,
            mode,
            atime: now,
            mtime: now,
            ctime: now,
            created: now,
        }
    }
    pub fn validate(&self) -> Result<(), FormatError> {
        if self.uid == u32::MAX || self.gid == u32::MAX {
            return Err(FormatError::Invalid("uid/gid"));
        }
        if self.mode > 0o7777 {
            return Err(FormatError::Invalid("permission mode"));
        }
        for t in [self.atime, self.mtime, self.ctime, self.created] {
            t.to_system_time()?;
        }
        Ok(())
    }
}
