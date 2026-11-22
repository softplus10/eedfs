//! S3 client configuration and a read-only bucket connectivity check.

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
