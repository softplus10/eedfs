//! Pooled S3 client, bounded object reads and conditional object publication.

use std::error::Error;
use std::time::Duration;

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
}

pub type ConnectionError = Box<dyn Error + Send + Sync>;

impl Connection {
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
            .force_path_style(config.force_path_style)
            .timeout_config(timeouts);
        if let Some(endpoint) = config.endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: config.bucket,
        })
    }

    /// Check bucket access without listing, downloading, or writing objects.
    /// A success does not imply permission to read or write individual objects.
    pub async fn check_bucket(&self) -> Result<(), ConnectionError> {
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
impl Connection {
    pub async fn head_etag(&self, key: &str) -> Result<String, ConnectionError> {
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
        match request.send().await {
            Ok(r) => Ok(PutResult::Applied(
                r.e_tag().ok_or("S3 PUT response lacks ETag")?.to_owned(),
            )),
            Err(e) => {
                let conflict = e
                    .raw_response()
                    .is_some_and(|r| matches!(r.status().as_u16(), 409 | 412));
                // A matching readback is safe even when the original result was ambiguous.
                if let Ok(Some(current)) = self.get(key, bytes.len()).await
                    && current.bytes.as_slice() == bytes.as_ref()
                {
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
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "unit test"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(10))
                    .build(),
            )
            .build();
        Self {
            client: Client::from_conf(config),
            bucket: "test".into(),
        }
    }
}
