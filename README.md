# EEDFS

End-to-end encrypted distributed filesystem. **Early development.**

EEDFS is a Rust/FUSE filesystem targeting shared, S3-compatible object storage.
The current implementation is a read-only FUSE scaffold exposing `README.txt`.
An S3 connection check, binary object formats, and in-memory authenticated
encryption helpers are also available. S3 object reads/writes, persistence, and
distributed concurrency control are not implemented yet.

## Development environment

Use Linux, Rust stable, a C linker, and the FUSE 3 runtime. EEDFS uses `fuser`'s
pure Rust mount implementation; libfuse development headers are not required.

```sh
# Debian / Ubuntu
sudo apt-get install build-essential fuse3

# Fedora
sudo dnf install gcc fuse3
```

With rustup installed, `rust-toolchain.toml` selects stable Rust, rustfmt, and
clippy. Mounting requires access to `/dev/fuse`.

```sh
cargo build --locked
mkdir -p mnt
cargo run --locked -- mount ./mnt
```

The process runs in the foreground. Use another terminal to inspect and unmount
it. The mountpoint must be an existing, empty directory.

```sh
ls -la mnt
cat mnt/README.txt
fusermount3 -u ./mnt
```

Set `RUST_LOG=debug` for debug logging. Run `cargo run -- --help` for CLI help.

## S3 connection check

For S3-compatible providers supporting Signature Version 4, set `S3_ACCESS_KEY_ID` and
`S3_SECRET_ACCESS_KEY` to the credentials issued by that provider. Set
`S3_SESSION_TOKEN` as well when using temporary credentials. Both keys must be
provided together; incomplete or empty values are rejected. Credentials are not
accepted as CLI arguments or stored by EEDFS. Do not commit credentials.

Only these explicit S3 credentials are used. EEDFS does not load AWS profiles,
SSO, workload roles, or instance metadata, and it ignores `AWS_*` credentials.
The AWS SDK is used as an S3 protocol client; no AWS account is needed for
non-AWS providers.

For an S3-compatible service, supply its endpoint and signing region. Use
path-style addressing if required by the provider:

```sh
cargo run --locked -- s3 check \
  --bucket my-bucket \
  --endpoint-url https://s3.example.com \
  --region us-east-1 \
  --force-path-style
```

For Cloudflare R2, use the S3 API endpoint shown in the bucket's dashboard
(normally `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`) and `--region auto`.
Use the **Access Key ID and Secret Access Key** generated for R2's S3 API,
not a Cloudflare management API bearer token. Jurisdiction-specific buckets
may use a different endpoint; copy the endpoint from the dashboard.

```sh
# With S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY already exported:
cargo run --locked -- s3 check \
  --endpoint-url https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --bucket my-bucket --region auto --force-path-style
```

`S3_BUCKET`, `S3_ENDPOINT_URL`, `S3_REGION`, and `S3_FORCE_PATH_STYLE`
can replace the corresponding flags. The signing region defaults to
`us-east-1`; set it to the value required by your provider. Without an endpoint
override, the SDK uses the standard AWS S3 endpoint for the specified region.

The command sends a signed **HeadBucket** request only. It does not create a
bucket, list objects, upload data, or connect the FUSE scaffold to S3. Success
confirms bucket access for this operation, not object read/write permissions.
AWS S3 requires `s3:ListBucket` permission for this check; errors such as 403
can indicate a missing bucket or insufficient access and are not always
specific enough to distinguish the two.

`--timeout-seconds` sets an overall deadline (default: 30 seconds), including
SDK retries. The reusable `s3::Connection` shares an SDK HTTP connection pool
across clones. Its operation timeout bounds individual bucket checks.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
./scripts/smoke-fuse.sh
```

The smoke test mounts a temporary filesystem and checks directory listing, file
contents, write rejection, and clean unmount. It requires `/dev/fuse`.
GitHub Actions runs these checks. The S3 integration tests use a local HTTP
server and dummy credentials to verify signed HEAD requests and access-denied
handling; they do not contact a cloud provider. They also verify rejection of
incomplete credentials and the absence of an AWS credential fallback. This checks
connectivity only, not full S3 API or conditional-write support. Real-provider
compatibility requires running `s3 check` with that provider's endpoint and credentials.

## Object formats and encryption

- [Header v4](docs/header-format.md): password keyslots, protected root inode ID
  and filesystem-wide inode naming configuration.
- [Inode/chunk v2](docs/object-format.md): wrapped per-inode key, common inode/chunk
  encryption profile, inline data or variable-size chunk runs. Chunk bytes contain
  only nonce and ciphertext/tag; names derive from allocation ID and chunk index.
- [Crypto profiles and key hierarchy](docs/crypto.md): XChaCha20-Poly1305,
  AES-256-GCM-SIV, Argon2id, HKDF-SHA256, HMAC-SHA256; explicit stable algorithm IDs.

`crypto::objects` creates/unlocks headers, seals/opens inode objects, and seals/opens
chunks in memory, including shared access using a separately granted inode key.
All of this remains independent of the read-only FUSE scaffold and S3 connectivity
check. Old experimental formats are incompatible and rejected. Directory entries,
POSIX attributes, encryption key lifecycle workflows and filesystem writes remain
future work. The cryptographic integration has not received a security audit.

## Local crypto benchmark

```sh
cargo run --release --locked --example crypto_bench -- --ten-gib
```

CSV on stdout, metadata sizes on stderr. Three samples per case by default;
`--mib-per-sample` controls the logical input size (default 64 MiB). Cases cover
4 KiB, 64 KiB, 1 MiB and 8 MiB chunks, raw in-place AEAD, complete chunk seal/open,
three-worker aggregate encryption, inode serialization, and password KDF latency.
The [recorded benchmark](docs/benchmarks/crypto-2026-11-24.md) includes raw CSV
and environment details. The optional 10 GiB stream retains one chunk at a time; it performs no network or
disk I/O. Results measure CPU/allocation costs, not NAS throughput.

## Design direction

- Per-file inodes and independent encrypted data chunks.
- Inline data in inode objects for small files.
- Immutable chunk uploads followed by an ETag-conditional inode PUT.
- Metadata conflict detection, merge, and retry.
- Client-side encryption of object names and contents.

Atomic directory changes, key lifecycle workflows, ambiguous commit recovery, and safe
reclamation still need to be designed. The scaffold does not implement or
guarantee these features.

## License

[The Unlicense](LICENSE). Dependencies retain their respective licenses.
