mod handlers;
mod password_input;

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
    /// Replace the volume's first password slot using an ETag-conditional write.
    ChangePassword {
        #[command(flatten)]
        s3: S3Args,
        #[arg(long, default_value = "eedfs/")]
        prefix: String,
        #[arg(long, env = "EEDFS_PASSWORD_FILE")]
        password_file: Option<PathBuf>,
        #[arg(long)]
        new_password_file: Option<PathBuf>,
    },
    /// Inspect unreachable objects; deletion requires all clients to be stopped.
    Gc {
        #[command(flatten)]
        s3: S3Args,
        #[arg(long, default_value = "eedfs/")]
        prefix: String,
        #[arg(long, env = "EEDFS_PASSWORD_FILE")]
        password_file: Option<PathBuf>,
        /// Delete unreachable objects instead of reporting only.
        #[arg(long, requires = "offline")]
        delete: bool,
        /// Assert all clients, mappings and upload workers are stopped until completion.
        #[arg(long)]
        offline: bool,
        /// Bound the inventory; fail before deletion if exceeded.
        #[arg(long, default_value_t = 100_000, value_parser = clap::value_parser!(u64).range(1..))]
        max_objects: u64,
    },
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
        /// Poll metadata for open snapshots without changing their content.
        #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..))]
        inode_poll_seconds: u64,
        /// Permit other local users; kernel uid/gid/mode checks remain enabled.
        #[arg(long)]
        allow_other: bool,
        #[arg(long, default_value_t = 512)]
        memory_mib: u64,
        #[arg(long, default_value_t = 4096)]
        spool_mib: u64,
        #[arg(long, default_value_t = 64)]
        s3_requests: usize,
        #[arg(long, default_value_t = 65_536)]
        max_cached_inodes: usize,
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
    /// Scan current object sizes without downloading inode or data bodies.
    Usage {
        #[command(flatten)]
        s3: S3Args,
        #[arg(long, default_value = "eedfs/")]
        prefix: String,
        #[arg(long, default_value_t = 1_000_000)]
        max_objects: usize,
    },
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
    /// Per-S3-operation deadline, including SDK retries (not the whole transfer).
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_seconds: u64,
}

#[derive(Args)]
struct VolumeArgs {
    #[command(flatten)]
    s3: S3Args,
    #[arg(long, default_value = "eedfs/")]
    prefix: String,
    /// Password file; omit for hidden terminal input. A trailing LF/CRLF is removed.
    #[arg(long, env = "EEDFS_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
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
fn main() -> Result<(), ConnectionError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Mount { mountpoint } => mount(mountpoint),
        Command::ChangePassword {
            s3,
            prefix,
            password_file,
            new_password_file,
        } => {
            let old_password =
                password_input::read(password_file.as_deref(), "Current volume password: ", false)?;
            let new_password =
                password_input::read(new_password_file.as_deref(), "New volume password: ", true)?;
            tokio::runtime::Runtime::new()?.block_on(eedfs::volume::Volume::change_password(
                connection(s3)?,
                &prefix,
                &old_password,
                &new_password,
            ))?;
            println!("Volume password changed");
            Ok(())
        }
        Command::Gc {
            s3,
            prefix,
            password_file,
            delete,
            offline: _,
            max_objects,
        } => {
            let password =
                password_input::read(password_file.as_deref(), "Volume password: ", false)?;
            let max_objects = usize::try_from(max_objects)?;
            let report = tokio::runtime::Runtime::new()?.block_on(async {
                let volume = eedfs::volume::Volume::open(
                    connection(s3)?,
                    prefix,
                    &password,
                    8 * 1024 * 1024,
                    8,
                )
                .await?;
                volume
                    .collect_garbage(eedfs::volume::GcOptions {
                        delete,
                        max_objects,
                    })
                    .await
                    .map_err(ConnectionError::from)
            })?;
            println!(
                "Mode: {}",
                if delete {
                    "offline sweep"
                } else {
                    "report only (no deletes)"
                }
            );
            println!(
                "Listed: {} objects, {} bytes",
                report.listed_objects, report.listed_bytes
            );
            println!(
                "Reachable: {} inodes, {} objects, {} stored bytes",
                report.live_inodes, report.live_objects, report.live_bytes
            );
            println!(
                "Logical regular-file bytes (hard links counted once): {}",
                report.logical_file_bytes
            );
            println!(
                "Unreferenced: {} objects, {} bytes",
                report.unreferenced_objects, report.unreferenced_bytes
            );
            println!(
                "Ignored keys outside the reserved object-name pattern: {}",
                report.ignored_objects
            );
            println!(
                "Deleted: {} objects, {} listed bytes",
                report.deleted_objects, report.deleted_bytes
            );
            Ok(())
        }
        Command::Format(args) => {
            let runtime = tokio::runtime::Runtime::new()?;
            let password =
                password_input::read(args.password_file.as_deref(), "New volume password: ", true)?;
            let c = connection(args.s3)?;
            runtime.block_on(async {
                if args.create_bucket {
                    c.create_bucket().await?;
                }
                eedfs::volume::Volume::format_with_metadata(
                    c,
                    args.prefix,
                    &password,
                    args.chunk_size,
                    args.parallelism,
                    // POSIX effective IDs; no remote identity mapping.
                    eedfs::format::metadata::Metadata::new(
                        unsafe { libc::geteuid() },
                        unsafe { libc::getegid() },
                        0o755,
                    ),
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
            inode_poll_seconds,
            allow_other,
            memory_mib,
            spool_mib,
            s3_requests,
            max_cached_inodes,
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
            let runtime = tokio::runtime::Runtime::new()?;
            let volume = runtime.block_on(eedfs::volume::Volume::open(
                connection(args.s3)?.with_request_limit(s3_requests)?,
                args.prefix,
                &password_input::read(args.password_file.as_deref(), "Volume password: ", false)?,
                args.chunk_size,
                args.parallelism,
            ))?;
            volume
                .resources
                .configure(eedfs::volume::resources::Limits {
                    memory_bytes: memory_mib
                        .checked_mul(1024 * 1024)
                        .ok_or("memory limit overflow")?,
                    spool_bytes: spool_mib
                        .checked_mul(1024 * 1024)
                        .ok_or("spool limit overflow")?,
                })?;
            let filesystem = handlers::S3Filesystem::new(
                volume,
                runtime,
                cache,
                Duration::from_secs(inode_poll_seconds),
            );
            filesystem.set_node_limit(max_cached_inodes)?;
            let mut config = Config::default();
            config.n_threads = Some(threads);
            if allow_other {
                config.acl = fuser::SessionACL::All;
            }
            config.mount_options = vec![
                MountOption::FSName("eedfs-s3".into()),
                MountOption::Subtype("eedfs".into()),
                MountOption::RW,
                MountOption::NoAtime,
                MountOption::DefaultPermissions,
                MountOption::NoDev,
                MountOption::NoSuid,
            ];
            fuser::mount(filesystem, mountpoint, &config)?;
            Ok(())
        }
        Command::S3 {
            command:
                S3Command::Usage {
                    s3,
                    prefix,
                    max_objects,
                },
        } => {
            let usage = tokio::runtime::Runtime::new()?
                .block_on(connection(s3)?.usage(&prefix, max_objects))?;
            println!(
                "Current listed objects: {}\nCurrent listed bytes: {}\nScanned at Unix seconds: {}\nNo fixed capacity or quota is inferred; this is a cached scan estimate.",
                usage.objects, usage.bytes, usage.scanned_at
            );
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
