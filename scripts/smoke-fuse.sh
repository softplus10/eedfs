#!/bin/sh
# Run after `cargo build`; requires /dev/fuse and fusermount3.
set -eu
binary=${EEDFS_BINARY:-./target/debug/eedfs}
[ -c /dev/fuse ] || { echo '/dev/fuse is required' >&2; exit 1; }
command -v fusermount3 >/dev/null
command -v mountpoint >/dev/null
work=$(mktemp -d)
mkdir "$work/mnt"
pid=
cleanup() {
    if mountpoint -q "$work/mnt"; then
        fusermount3 -u "$work/mnt" || return 1
    fi
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"$binary" mount "$work/mnt" >"$work/mount.log" 2>&1 &
pid=$!
attempt=0
until mountpoint -q "$work/mnt"; do
    attempt=$((attempt + 1))
    if ! kill -0 "$pid" 2>/dev/null || [ "$attempt" -ge 50 ]; then
        cat "$work/mount.log" >&2
        echo 'FUSE mount failed or timed out' >&2
        exit 1
    fi
    sleep 0.1
done
ls -la "$work/mnt"
printf 'EEDFS development filesystem\nS3 storage and end-to-end encryption are not implemented yet.\n' > "$work/expected"
cmp "$work/expected" "$work/mnt/README.txt"
if touch "$work/mnt/should-fail" 2>/dev/null; then
    echo 'read-only filesystem accepted a write' >&2
    exit 1
fi
fusermount3 -u "$work/mnt"
wait "$pid"
pid=
echo 'FUSE smoke test passed'
