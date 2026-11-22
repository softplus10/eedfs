# EEDFS

End-to-end encrypted distributed filesystem. **Early development.**

EEDFS is a Rust/FUSE filesystem targeting shared, S3-compatible object storage.
The current implementation is a read-only FUSE scaffold exposing `README.txt`.
S3 storage, encryption, persistence, and distributed concurrency control are not
implemented yet.

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
GitHub Actions runs these checks.

## Design direction

- Per-file inodes and independent encrypted data chunks.
- Inline data in inode objects for small files.
- Immutable chunk uploads followed by an ETag-conditional inode PUT.
- Metadata conflict detection, merge, and retry.
- Client-side encryption of object names and contents.

Atomic directory changes, key management, ambiguous commit recovery, and safe
reclamation still need to be designed. The scaffold does not implement or
guarantee these features.

## License

[The Unlicense](LICENSE). Dependencies retain their respective licenses.
