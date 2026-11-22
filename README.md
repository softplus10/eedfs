# EEDFS

End-to-end encrypted distributed filesystem. **초기 개발 단계입니다.**

S3 호환 오브젝트 스토리지를 사용하는 다중 클라이언트 파일시스템을 Rust와
FUSE로 개발합니다. 현재 구현은 `README.txt`를 제공하는 읽기 전용 FUSE
스캐폴드입니다. S3 연결, 암호화, 영구 저장과 분산 동시성 제어는 아직 없습니다.

## 개발 환경

Linux, Rust stable, C linker와 FUSE 3 런타임이 필요합니다.
`fuser`의 순수 Rust 마운트 구현을 사용하므로 libfuse 개발 헤더는 필요 없습니다.

```sh
# Debian / Ubuntu
sudo apt-get install build-essential fuse3

# Fedora
sudo dnf install gcc fuse3
```

`rustup`으로 설치한 환경에서는 `rust-toolchain.toml`에 따라 stable,
rustfmt와 clippy를 사용합니다. 실행 환경에 `/dev/fuse`가 있어야 합니다.

```sh
cargo build --locked
mkdir -p mnt
cargo run --locked -- mount ./mnt
```

프로세스는 foreground에서 동작합니다. 다른 터미널에서 확인하고 해제합니다.
마운트 지점은 기존의 빈 디렉터리여야 합니다.

```sh
ls -la mnt
cat mnt/README.txt
fusermount3 -u ./mnt
```

로그 수준은 `RUST_LOG=debug`로 설정합니다. CLI 도움말은 `cargo run -- --help`입니다.

## 검증

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
./scripts/smoke-fuse.sh
```

smoke test는 임시 디렉터리에 실제 마운트해 디렉터리 조회, 파일 내용,
쓰기 거부와 정상 unmount를 확인합니다. `/dev/fuse`가 없는 환경에서는
마운트 테스트를 실행할 수 없습니다. GitHub Actions에서 위 검증을 실행합니다.

## 설계 방향

- 파일별 inode와 독립적인 암호화 데이터 청크.
- 작은 파일의 데이터는 inode 오브젝트에 inline 저장하는 방향.
- immutable 청크 업로드 후 inode를 ETag 조건부 PUT으로 커밋.
- 메타데이터 충돌 시 최신 상태에 병합하고 재시도.
- 오브젝트 이름과 내용 암호화는 클라이언트에서 수행.

디렉터리 변경의 원자성, 키 관리, 불명확한 커밋 결과의 복구, 안전한 GC는
후속 설계 항목입니다. 현재 실행 파일은 이 기능들을 구현하거나 보장하지 않습니다.

## License

[The Unlicense](LICENSE). 의존성에는 각 프로젝트의 라이선스가 적용됩니다.
