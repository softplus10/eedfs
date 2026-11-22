mod fs;

use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use eedfs::s3::{Connection, ConnectionConfig, ConnectionError};
use fuser::{Config, MountOption};

#[derive(Parser)]
#[command(version, about = "EEDFS development filesystem")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mount the read-only development filesystem in the foreground.
    Mount { mountpoint: PathBuf },
    /// Inspect S3 connectivity without modifying the bucket.
    S3 {
        #[command(subcommand)]
        command: S3Command,
    },
}

#[derive(Subcommand)]
enum S3Command {
    /// Verify bucket access using a signed HeadBucket request.
    Check(S3Args),
}

#[derive(Args)]
struct S3Args {
    #[arg(long, env = "S3_BUCKET")]
    bucket: String,
    /// Signing region; use auto for Cloudflare R2.
    #[arg(long, env = "S3_REGION", default_value = "us-east-1")]
    region: String,
    /// S3-compatible base URL; omitted for the standard AWS S3 regional endpoint.
    #[arg(long, env = "S3_ENDPOINT_URL")]
    endpoint_url: Option<String>,
    /// Address buckets as endpoint/bucket instead of bucket.endpoint.
    #[arg(long, env = "S3_FORCE_PATH_STYLE", default_value_t = false)]
    force_path_style: bool,
    /// Overall deadline, including SDK retries.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_seconds: u64,
}

fn main() -> Result<(), ConnectionError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Mount { mountpoint } => mount(mountpoint),
        Command::S3 {
            command: S3Command::Check(args),
        } => {
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(check_s3(args))
        }
    }
}

async fn check_s3(args: S3Args) -> Result<(), ConnectionError> {
    let timeout = Duration::from_secs(args.timeout_seconds);
    let bucket = args.bucket.clone();
    tokio::time::timeout(timeout, async {
        let connection = Connection::new(ConnectionConfig {
            bucket: args.bucket,
            region: args.region,
            endpoint_url: args.endpoint_url,
            force_path_style: args.force_path_style,
            timeout,
        })?;
        connection.check_bucket().await
    })
    .await
    .map_err(|_| {
        format!(
            "S3 connection check timed out after {} seconds",
            args.timeout_seconds
        )
    })??;
    println!("S3 bucket access verified: {bucket}");
    Ok(())
}

fn mount(mountpoint: PathBuf) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mountpoint = mountpoint.canonicalize()?;
    let metadata = mountpoint.metadata()?;
    if !metadata.is_dir() {
        return Err("mountpoint must be an existing directory".into());
    }
    if std::fs::read_dir(&mountpoint)?.next().is_some() {
        return Err("mountpoint must be empty".into());
    }

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("eedfs".into()),
        MountOption::Subtype("eedfs".into()),
        MountOption::RO,
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    log::info!(
        "mounting development filesystem at {}",
        mountpoint.display()
    );
    fuser::mount(
        fs::DevFilesystem::new(metadata.uid(), metadata.gid()),
        mountpoint,
        &config,
    )?;
    Ok(())
}
