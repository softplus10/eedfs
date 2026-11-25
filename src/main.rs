mod handlers;

use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use eedfs::storage::s3::{Connection, ConnectionConfig, ConnectionError};
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
    /// Initialize a new encrypted volume in an unused S3 prefix.
    Format(VolumeArgs),
    /// Mount an encrypted S3 volume with experimental writable FUSE support.
    MountS3 {
        mountpoint: PathBuf,
        #[command(flatten)]
        volume: VolumeArgs,
        /// Private local directory for anonymous plaintext staging files.
        #[arg(long)]
        cache_dir: PathBuf,
        #[arg(long, default_value_t = 8)]
        threads: usize,
    },
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

#[derive(Args)]
struct VolumeArgs {
    #[command(flatten)]
    s3: S3Args,
    #[arg(long, default_value = "eedfs/")]
    prefix: String,
    /// Password bytes; a single trailing LF (and optional CR) is removed.
    #[arg(long, env = "EEDFS_PASSWORD_FILE")]
    password_file: PathBuf,
    /// Writer policy, not a persisted per-file maximum.
    #[arg(long, default_value_t=8*1024*1024)]
    chunk_size: usize,
    #[arg(long, default_value_t = 8)]
    parallelism: usize,
    /// Test/development setup only: explicitly create a missing bucket at format.
    #[arg(long)]
    create_bucket: bool,
}
fn connection(args: S3Args) -> Result<Connection, ConnectionError> {
    Connection::new(ConnectionConfig {
        bucket: args.bucket,
        region: args.region,
        endpoint_url: args.endpoint_url,
        force_path_style: args.force_path_style,
        timeout: Duration::from_secs(args.timeout_seconds),
    })
}
fn password(path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>, ConnectionError> {
    let mut p = zeroize::Zeroizing::new(std::fs::read(path)?);
    if p.last() == Some(&b'\n') {
        p.pop();
        if p.last() == Some(&b'\r') {
            p.pop();
        }
    }
    if p.is_empty() {
        return Err("password file is empty".into());
    }
    Ok(p)
}
fn main() -> Result<(), ConnectionError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Mount { mountpoint } => mount(mountpoint),
        Command::Format(args) => {
            let runtime = tokio::runtime::Runtime::new()?;
            let password = password(&args.password_file)?;
            let c = connection(args.s3)?;
            runtime.block_on(async {
                if args.create_bucket {
                    c.create_bucket().await?;
                }
                eedfs::volume::Volume::format(
                    c,
                    args.prefix,
                    &password,
                    args.chunk_size,
                    args.parallelism,
                )
                .await?;
                Ok::<_, ConnectionError>(())
            })?;
            println!("Encrypted S3 volume initialized");
            Ok(())
        }
        Command::MountS3 {
            mountpoint,
            volume: args,
            cache_dir,
            threads,
        } => {
            if threads == 0 || threads > 64 {
                return Err("threads must be 1..64".into());
            }
            if args.create_bucket {
                return Err("--create-bucket is only valid with format".into());
            }
            let mountpoint = mountpoint.canonicalize()?;
            if !mountpoint.is_dir() || std::fs::read_dir(&mountpoint)?.next().is_some() {
                return Err("mountpoint must be an existing empty directory".into());
            }
            std::fs::create_dir_all(&cache_dir)?;
            let cache = cache_dir.canonicalize()?;
            if cache.starts_with(&mountpoint) {
                return Err("cache directory must be outside mountpoint".into());
            }
            let metadata = mountpoint.metadata()?;
            let runtime = tokio::runtime::Runtime::new()?;
            let volume = runtime.block_on(eedfs::volume::Volume::open(
                connection(args.s3)?,
                args.prefix,
                &password(&args.password_file)?,
                args.chunk_size,
                args.parallelism,
            ))?;
            let mut config = Config::default();
            config.n_threads = Some(threads);
            config.mount_options = vec![
                MountOption::FSName("eedfs-s3".into()),
                MountOption::Subtype("eedfs".into()),
                MountOption::RW,
                MountOption::DefaultPermissions,
                MountOption::NoDev,
                MountOption::NoSuid,
            ];
            fuser::mount(
                handlers::S3Filesystem::new(volume, runtime, cache, metadata.uid(), metadata.gid()),
                mountpoint,
                &config,
            )?;
            Ok(())
        }
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
        handlers::development::DevFilesystem::new(metadata.uid(), metadata.gid()),
        mountpoint,
        &config,
    )?;
    Ok(())
}
