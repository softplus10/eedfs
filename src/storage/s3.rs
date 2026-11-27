//! Pooled S3 client, bounded object reads and conditional object publication.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region, timeout::TimeoutConfig},
};

/// Provider-neutral S3 connection settings. Credentials come from S3_* variables.
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub bucket: String,
    /// Signing region, including provider-specific values such as R2's "auto".
    pub region: String,
    /// Optional base URL for an S3-compatible service.
    pub endpoint_url: Option<String>,
    pub force_path_style: bool,
    pub timeout: Duration,
}

/// A reusable SDK client. Cloning shares the SDK's underlying connection pool.
#[derive(Clone)]
pub struct Connection {
    client: Client,
    bucket: String,
    data_requests: Arc<Semaphore>,
    control_requests: Arc<Semaphore>,
    usage_cache: Arc<std::sync::Mutex<Option<(String, std::time::Instant, Usage)>>>,
}

pub type ConnectionError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Usage {
    pub objects: usize,
    pub bytes: u64,
    pub scanned_at: u64,
}
impl Connection {
    pub fn with_request_limit(mut self, limit: usize) -> Result<Self, ConnectionError> {
        if !(2..=4096).contains(&limit) {
            return Err("S3 request limit must be 2..4096".into());
        }
        let control = (limit / 8).clamp(1, 4);
        self.data_requests = Arc::new(Semaphore::new(limit - control));
        self.control_requests = Arc::new(Semaphore::new(control));
        Ok(self)
    }
    async fn request(&self, data: bool) -> Result<OwnedSemaphorePermit, ConnectionError> {
        Ok(if data {
            self.data_requests.clone()
        } else {
            self.control_requests.clone()
        }
        .acquire_owned()
        .await?)
    }
    /// Read-only current-object estimate, cached per client/prefix for 60 seconds.
    pub async fn usage(&self, prefix: &str, max_objects: usize) -> Result<Usage, ConnectionError> {
        if prefix.is_empty() || !prefix.ends_with('/') || max_objects == 0 {
            return Err(
                "usage requires a volume prefix ending in / and a positive object limit".into(),
            );
        }
        if let Some((cached, at, usage)) = &*self.usage_cache.lock().unwrap()
            && cached == prefix
            && at.elapsed() < Duration::from_secs(60)
            && usage.objects <= max_objects
        {
            return Ok(usage.clone());
        }
        let mut token = None;
        let mut tokens = std::collections::BTreeSet::new();
        let mut objects = 0usize;
        let mut bytes = 0u64;
        loop {
            let page = self.list_page(prefix, token.as_deref()).await?;
            for object in page.objects {
                objects = objects
                    .checked_add(1)
                    .ok_or("usage object count overflow")?;
                if objects > max_objects {
                    return Err("usage inventory exceeds object limit".into());
                }
                bytes = bytes
                    .checked_add(object.size)
                    .ok_or("usage byte count overflow")?;
            }
            match page.next {
                Some(next) => {
                    if !tokens.insert(next.clone()) {
                        return Err("usage pagination repeated a token".into());
                    }
                    token = Some(next)
                }
                None => break,
            }
        }
        let usage = Usage {
            objects,
            bytes,
            scanned_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        *self.usage_cache.lock().unwrap() =
            Some((prefix.to_owned(), std::time::Instant::now(), usage.clone()));
        Ok(usage)
    }
    /// Read S3 credentials and construct a pooled S3 client.
    /// This does not create a bucket or access any objects.
    pub fn new(config: ConnectionConfig) -> Result<Self, ConnectionError> {
        if config.bucket.trim().is_empty() {
            return Err("bucket must not be empty".into());
        }
        if config.timeout.is_zero() {
            return Err("timeout must be greater than zero".into());
        }
        if config.region.trim().is_empty() {
            return Err("region must not be empty".into());
        }
        let credentials = s3_credentials()?;
        let timeouts = TimeoutConfig::builder()
            .connect_timeout(config.timeout.min(Duration::from_secs(5)))
            .operation_timeout(config.timeout)
            .build();
        let mut builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region))
            .credentials_provider(credentials)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(3))
            .force_path_style(config.force_path_style)
            .timeout_config(timeouts);
        if let Some(endpoint) = config.endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket,
            data_requests: Arc::new(Semaphore::new(60)),
            control_requests: Arc::new(Semaphore::new(4)),
            usage_cache: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Check bucket access without listing, downloading, or writing objects.
    /// A success does not imply permission to read or write individual objects.
    pub async fn check_bucket(&self) -> Result<(), ConnectionError> {
        let _permit = self.request(false).await?;
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await?;
        Ok(())
    }
}

/// Use only the provider-issued credentials explicitly configured for EEDFS.
/// No AWS profiles, role discovery, or instance metadata lookups are performed.
fn s3_credentials() -> Result<Credentials, ConnectionError> {
    fn read(name: &str) -> Result<Option<String>, ConnectionError> {
        match std::env::var(name) {
            Ok(value) if value.trim().is_empty() => Err(format!("{name} must not be empty").into()),
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} must contain valid Unicode").into()),
        }
    }
    let access = read("S3_ACCESS_KEY_ID")?;
    let secret = read("S3_SECRET_ACCESS_KEY")?;
    let token = read("S3_SESSION_TOKEN")?;
    match (access, secret, token) {
        (Some(access), Some(secret), token) => Ok(Credentials::new(
            access,
            secret,
            token,
            None,
            "EEDFS environment",
        )),
        _ => Err(
            "set both S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY; S3_SESSION_TOKEN is optional"
                .into(),
        ),
    }
}

/// Conditional publication result. A conflict is distinct from a transport error.
#[derive(Debug)]
pub enum PutResult {
    Applied(String),
    Conflict,
}
pub struct StoredObject {
    pub bytes: Vec<u8>,
    pub etag: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedObject {
    pub key: String,
    pub etag: String,
    pub size: u64,
}
pub struct ObjectPage {
    pub objects: Vec<ListedObject>,
    pub next: Option<String>,
}
impl Connection {
    /// One bounded inventory page. This is not a point-in-time bucket snapshot.
    pub async fn list_page(
        &self,
        prefix: &str,
        continuation: Option<&str>,
    ) -> Result<ObjectPage, ConnectionError> {
        let _permit = self.request(false).await?;
        let response = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .max_keys(1000)
            .set_continuation_token(continuation.map(str::to_owned))
            .send()
            .await?;
        let mut objects = Vec::new();
        for object in response.contents() {
            let key = object.key().ok_or("S3 LIST response lacks object key")?;
            if !key.starts_with(prefix) {
                return Err("S3 LIST returned a key outside the requested prefix".into());
            }
            objects.push(ListedObject {
                key: key.to_owned(),
                etag: object
                    .e_tag()
                    .ok_or("S3 LIST response lacks ETag")?
                    .to_owned(),
                size: object
                    .size()
                    .filter(|n| *n >= 0)
                    .ok_or("S3 LIST response lacks a valid size")? as u64,
            });
        }
        let next = if response
            .is_truncated()
            .ok_or("S3 LIST lacks truncation status")?
        {
            let token = response
                .next_continuation_token()
                .filter(|t| !t.is_empty() && Some(*t) != continuation)
                .ok_or("S3 LIST pagination did not advance")?;
            if objects.is_empty() {
                return Err("S3 LIST returned an empty truncated page".into());
            }
            Some(token.to_owned())
        } else {
            None
        };
        Ok(ObjectPage { objects, next })
    }
    /// Offline sweep guard only. HEAD + DELETE is NOT atomic: callers must
    /// stop every client. Does not require provider support for conditional DELETE.
    pub async fn delete_checked(&self, key: &str, etag: &str) -> Result<(), ConnectionError> {
        if self.head_etag(key).await? != etag {
            return Err("offline GC candidate ETag changed; no delete issued for this key".into());
        }
        self.delete(key).await
    }
    /// Idempotent cleanup of an immutable object after its reference is retired.
    pub async fn delete(&self, key: &str) -> Result<(), ConnectionError> {
        let _permit = self.request(false).await?;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }
    pub async fn head_etag(&self, key: &str) -> Result<String, ConnectionError> {
        let _permit = self.request(false).await?;
        let response = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(response
            .e_tag()
            .ok_or("S3 HEAD response lacks ETag")?
            .to_owned())
    }
    /// Explicit setup helper; normal format/mount operations never create buckets.
    pub async fn create_bucket(&self) -> Result<(), ConnectionError> {
        let _permit = self.request(false).await?;
        self.client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await?;
        Ok(())
    }
    pub async fn get(
        &self,
        key: &str,
        limit: usize,
    ) -> Result<Option<StoredObject>, ConnectionError> {
        self.get_class(key, limit, false).await
    }
    pub async fn get_data(
        &self,
        key: &str,
        limit: usize,
    ) -> Result<Option<StoredObject>, ConnectionError> {
        self.get_class(key, limit, true).await
    }
    async fn get_class(
        &self,
        key: &str,
        limit: usize,
        data: bool,
    ) -> Result<Option<StoredObject>, ConnectionError> {
        let _permit = self.request(data).await?;
        let mut response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) if e.as_service_error().is_some_and(|s| s.is_no_such_key()) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if response
            .content_length()
            .is_some_and(|n| n < 0 || n as u64 > limit as u64)
        {
            return Err("S3 object exceeds read limit".into());
        }
        let etag = response.e_tag().ok_or("S3 response lacks ETag")?.to_owned();
        let mut bytes = Vec::new();
        while let Some(part) = response.body.try_next().await? {
            if part.len() > limit.saturating_sub(bytes.len()) {
                return Err("S3 object exceeds read limit".into());
            }
            bytes.extend_from_slice(&part);
        }
        Ok(Some(StoredObject { bytes, etag }))
    }
    /// None means create-only; Some(etag) means replace that exact version.
    /// Exact-byte readback resolves a retry that reached S3 before losing its reply.
    pub async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: Option<&str>,
    ) -> Result<PutResult, ConnectionError> {
        self.put_class(key, bytes, expected, false).await
    }
    pub async fn put_data(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: Option<&str>,
    ) -> Result<PutResult, ConnectionError> {
        self.put_class(key, bytes, expected, true).await
    }
    async fn put_class(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: Option<&str>,
        data: bool,
    ) -> Result<PutResult, ConnectionError> {
        let permit = self.request(data).await?;
        let bytes = bytes::Bytes::from(bytes);
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/octet-stream")
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.clone()));
        request = match expected {
            Some(etag) => request.if_match(etag),
            None => request.if_none_match("*"),
        };
        let started = std::time::Instant::now();
        let result = request.send().await;
        drop(permit);
        match result {
            Ok(r) => Ok(PutResult::Applied(
                r.e_tag().ok_or("S3 PUT response lacks ETag")?.to_owned(),
            )),
            Err(e) => {
                let conflict = e
                    .raw_response()
                    .is_some_and(|r| matches!(r.status().as_u16(), 409 | 412));
                if !conflict {
                    log::warn!(
                        "S3 PUT failed: class={}, bytes={}, elapsed={:?}, status={:?}, error={e:?}",
                        if data { "data" } else { "metadata" },
                        bytes.len(),
                        started.elapsed(),
                        e.raw_response().map(|r| r.status().as_u16()),
                    );
                }
                // A matching readback is safe even when the original result was ambiguous.
                if let Ok(Some(current)) = self.get_class(key, bytes.len(), data).await
                    && current.bytes.as_slice() == bytes.as_ref()
                {
                    log::info!("S3 PUT confirmed by exact-byte readback after failed response");
                    return Ok(PutResult::Applied(current.etag));
                }
                if conflict {
                    Ok(PutResult::Conflict)
                } else {
                    Err(e.into())
                }
            }
        }
    }
}

#[cfg(test)]
impl Connection {
    pub(crate) fn test_client(endpoint: &str) -> Self {
        Self::test_client_attempts(endpoint, 1)
    }
    pub(crate) fn test_client_attempts(endpoint: &str, attempts: u32) -> Self {
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "unit test"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(attempts),
            )
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(10))
                    .build(),
            )
            .build();
        Self {
            client: Client::from_conf(config),
            bucket: "test".into(),
            data_requests: Arc::new(Semaphore::new(60)),
            control_requests: Arc::new(Semaphore::new(4)),
            usage_cache: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}
