//! S3 object baseline without FUSE, encryption or a local staging file.
use clap::Parser;
use eedfs::{
    crypto,
    s3::{Connection, ConnectionConfig, PutResult},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 1024)]
    mib: usize,
    #[arg(long, default_value_t = 8)]
    chunk_mib: usize,
    #[arg(long, default_value_t = 8)]
    jobs: usize,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let a = Args::parse();
    if a.mib == 0 || a.chunk_mib == 0 || a.jobs == 0 || a.mib % a.chunk_mib != 0 {
        return Err("positive sizes, whole chunks and positive jobs required".into());
    }
    let c = Connection::new(ConnectionConfig {
        bucket: std::env::var("S3_BUCKET")?,
        region: std::env::var("S3_REGION").unwrap_or("us-east-1".into()),
        endpoint_url: std::env::var("S3_ENDPOINT_URL").ok(),
        force_path_style: std::env::var("S3_FORCE_PATH_STYLE").as_deref() == Ok("true"),
        timeout: Duration::from_secs(60),
    })?;
    let prefix = format!(
        "baseline-{:x}/",
        u128::from_le_bytes(crypto::random_array()?)
    );
    let mut payload = vec![0; a.chunk_mib * 1048576];
    getrandom::getrandom(&mut payload).map_err(|_| crypto::Error::Random)?;
    let payload = Arc::new(payload);
    let count = a.mib / a.chunk_mib;
    for writing in [true, false] {
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..count {
            let c = c.clone();
            let key = format!("{prefix}{i}");
            let payload = payload.clone();
            tasks.spawn(async move {
                if writing {
                    if !matches!(
                        c.put(&key, (*payload).clone(), None).await?,
                        PutResult::Applied(_)
                    ) {
                        return Err("baseline create conflict".into());
                    }
                } else {
                    let got = c
                        .get(&key, payload.len())
                        .await?
                        .ok_or("baseline object missing")?;
                    if got.bytes != *payload {
                        return Err("baseline verification failed".into());
                    }
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            if tasks.len() >= a.jobs {
                tasks.join_next().await.ok_or("task missing")???;
            }
        }
        while let Some(result) = tasks.join_next().await {
            result??;
        }
        let seconds = start.elapsed().as_secs_f64();
        println!(
            "{{\"case\":\"s3_{}\",\"mib\":{},\"chunk_mib\":{},\"jobs\":{},\"seconds\":{:.6},\"mib_s\":{:.3},\"prefix\":\"{}\"}}",
            if writing { "put" } else { "get_verified" },
            a.mib,
            a.chunk_mib,
            a.jobs,
            seconds,
            a.mib as f64 / seconds,
            prefix
        );
    }
    Ok(())
}
