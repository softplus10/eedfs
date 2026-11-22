mod fs;

use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let Cli {
        command: Command::Mount { mountpoint },
    } = Cli::parse();
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
