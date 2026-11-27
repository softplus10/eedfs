//! Inode-local expiring directory leases. No transaction log or recovery worker.
use super::{Error, Loaded, Result, Volume};
use crate::{
    crypto,
    format::{
        directory::{Directory, Entry},
        inode::{self, DirectoryLease, InodeBody},
        metadata::Timestamp,
    },
};
use std::time::{Duration, SystemTime};

/// Bound on relative clock error assumed by the protocol. This is not a clock
/// synchronization service; mounts must run on clocks within this bound.
pub const CLOCK_MARGIN: Duration = Duration::from_secs(2);
pub const DEFAULT_DURATION: Duration = Duration::from_secs(30);
type DirectoryEdit<'a> = (&'a str, Option<Entry>, Option<Entry>);

/// An acquired lease's current ETag is private and never rebased automatically.
/// A new acquisition gets a fresh owner token, even in the same process.
pub struct Lease {
    loaded: Loaded,
}
impl Lease {
    pub fn inode(&self) -> &Loaded {
        &self.loaded
    }
    pub fn expires_at(&self) -> Timestamp {
        self.loaded
            .body
            .lease
            .as_ref()
            .expect("acquired lease")
            .expires_at
    }
    pub(super) fn check_owner_time(&self) -> Result<()> {
        let stop = self
            .expires_at()
            .to_system_time()?
            .checked_sub(CLOCK_MARGIN)
            .ok_or(Error::Invalid)?;
        if SystemTime::now() >= stop {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
pub(super) fn can_take_over(lease: &DirectoryLease, now: SystemTime) -> Result<bool> {
    let after = lease
        .expires_at
        .to_system_time()?
        .checked_add(CLOCK_MARGIN)
        .ok_or(Error::Invalid)?;
    Ok(now >= after)
}
fn expiration(duration: Duration) -> Result<Timestamp> {
    if duration <= CLOCK_MARGIN * 2 || duration > Duration::from_secs(300) {
        return Err(Error::Invalid);
    }
    Ok(Timestamp::from_system_time(
        SystemTime::now()
            .checked_add(duration)
            .ok_or(Error::Invalid)?,
    )?)
}
impl Volume {
    /// An ordinary directory/metadata edit may clear an expired lease. If a
    /// previous owner is still running, this CAS makes its ETag unusable.
    pub(super) async fn load_writable(&self, id: [u8; 16]) -> Result<Loaded> {
        let mut loaded = self.load(id).await?;
        if loaded.body.deleted {
            return Err(Error::Missing);
        }
        if let Some(lease) = &loaded.body.lease {
            if !can_take_over(lease, SystemTime::now())? {
                return Err(Error::Conflict);
            }
            let mut body = loaded.body.clone();
            body.lease = None;
            body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
            loaded.etag = self.publish_raw(&loaded, &body, Some(&loaded.etag)).await?;
            loaded.body = body;
        }
        Ok(loaded)
    }
    /// One CAS attempt: an active lease or racing acquisition returns Conflict.
    pub async fn acquire_directory_lease(&self, id: [u8; 16]) -> Result<Lease> {
        self.acquire_directory_lease_for(id, DEFAULT_DURATION).await
    }
    pub async fn acquire_directory_lease_for(
        &self,
        id: [u8; 16],
        duration: Duration,
    ) -> Result<Lease> {
        let expires_at = expiration(duration)?;
        let mut loaded = self.load(id).await?;
        if loaded.body.deleted {
            return Err(Error::Missing);
        }
        if loaded.body.kind != inode::DIRECTORY {
            return Err(Error::NotDirectory);
        }
        if let Some(lease) = &loaded.body.lease
            && !can_take_over(lease, SystemTime::now())?
        {
            return Err(Error::Conflict);
        }
        let mut owner = crypto::random_array()?;
        while owner == [0; 16] {
            owner = crypto::random_array()?;
        }
        let mut body = loaded.body.clone();
        body.lease = Some(DirectoryLease { owner, expires_at });
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        loaded.etag = self.publish_raw(&loaded, &body, Some(&loaded.etag)).await?;
        loaded.body = body;
        let acquired = Lease { loaded };
        acquired.check_owner_time()?;
        Ok(acquired)
    }
    pub async fn renew_directory_lease(&self, lease: &mut Lease, duration: Duration) -> Result<()> {
        lease.check_owner_time()?;
        let mut body = lease.loaded.body.clone();
        body.lease.as_mut().ok_or(Error::Invalid)?.expires_at = expiration(duration)?;
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        let etag = self
            .publish_raw(&lease.loaded, &body, Some(&lease.loaded.etag))
            .await?;
        lease.loaded.body = body;
        lease.loaded.etag = etag;
        lease.check_owner_time()
    }
    /// Publish using exactly the acquired/renewed inode ETag. Do not reload or
    /// rebase a failed holder's write onto a successor's version.
    pub async fn write_leased_directory(
        &self,
        lease: &mut Lease,
        directory: &Directory,
    ) -> Result<()> {
        lease.check_owner_time()?;
        if lease.loaded.body.deleted {
            return Err(Error::Missing);
        }
        let mut body = lease.loaded.body.clone();
        let (content, retired) = self.prepare_directory(&lease.loaded, directory).await?;
        lease.check_owner_time()?;
        body.nlink = 2 + directory
            .entries
            .iter()
            .filter(|e| e.kind == inode::DIRECTORY)
            .count() as u32;
        body.content = content;
        self.publish_leased_directory(lease, body, retired).await
    }
    /// Stage a batch of path copies and publish them with one exact lease CAS.
    /// This preserves same-directory rename atomicity without a full tree read.
    pub(super) async fn edit_leased_directory(
        &self,
        lease: &mut Lease,
        edits: &[DirectoryEdit<'_>],
    ) -> Result<()> {
        lease.check_owner_time()?;
        let mut staged = lease.loaded.clone();
        let mut retired = Vec::new();
        for (name, expected, next) in edits {
            let (content, excluded) = self
                .prepare_directory_edit(&staged, name, expected, next.clone())
                .await?;
            staged.body.content = content;
            staged.body.nlink = staged
                .body
                .nlink
                .checked_sub(u32::from(
                    expected
                        .as_ref()
                        .is_some_and(|e| e.kind == inode::DIRECTORY),
                ))
                .and_then(|n| {
                    n.checked_add(u32::from(
                        next.as_ref().is_some_and(|e| e.kind == inode::DIRECTORY),
                    ))
                })
                .ok_or(Error::TooLarge)?;
            retired.extend(excluded);
        }
        self.publish_leased_directory(lease, staged.body, retired)
            .await
    }
    async fn publish_leased_directory(
        &self,
        lease: &mut Lease,
        mut body: InodeBody,
        retired: Vec<String>,
    ) -> Result<()> {
        lease.check_owner_time()?;
        if lease.loaded.body.deleted {
            return Err(Error::Missing);
        }
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        body.metadata.mtime = Timestamp::now();
        body.metadata.ctime = body.metadata.mtime;
        let etag = self
            .publish_raw(&lease.loaded, &body, Some(&lease.loaded.etag))
            .await?;
        lease.loaded.body = body;
        lease.loaded.etag = etag;
        self.delete_objects(retired).await;
        // A slow response does not imply rollback: the caller must stop using
        // an expired handle, including when the conditional PUT was applied.
        lease.check_owner_time()
    }
    pub(super) async fn touch_directory(&self, lease: &mut Lease) -> Result<()> {
        lease.check_owner_time()?;
        let mut body = lease.loaded.body.clone();
        body.metadata.ctime = Timestamp::now();
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        lease.loaded.etag = self
            .publish_raw(&lease.loaded, &body, Some(&lease.loaded.etag))
            .await?;
        lease.loaded.body = body;
        Ok(())
    }
    pub(super) async fn retire_directory(&self, lease: &mut Lease) -> Result<()> {
        lease.check_owner_time()?;
        if !self.directory_is_empty(&lease.loaded)? {
            return Err(Error::NotEmpty);
        }
        let mut body = lease.loaded.body.clone();
        body.deleted = true;
        body.metadata.ctime = Timestamp::now();
        body.nlink = 0;
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        lease.loaded.etag = self
            .publish_raw(&lease.loaded, &body, Some(&lease.loaded.etag))
            .await?;
        lease.loaded.body = body;
        Ok(())
    }
    pub async fn release_directory_lease(&self, lease: Lease) -> Result<()> {
        lease.check_owner_time()?;
        let mut body = lease.loaded.body.clone();
        body.lease = None;
        body.generation = body.generation.checked_add(1).ok_or(Error::TooLarge)?;
        self.publish_raw(&lease.loaded, &body, Some(&lease.loaded.etag))
            .await?;
        Ok(())
    }
}
