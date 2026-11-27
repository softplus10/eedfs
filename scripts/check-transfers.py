#!/usr/bin/env python3
"""Close-only large copy, small-file copy, stat listing and remount verification.

Requires a disposable S3 bucket configured through S3_* and a password file.
Creates a unique volume prefix; never uses an existing volume.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--password-file', required=True)
p.add_argument('--work-dir', required=True)
p.add_argument('--large-mib', type=int, default=1024)
p.add_argument('--small-files', type=int, default=171)
a = p.parse_args()
if a.large_mib < 1 or a.small_files < 1:
    p.error('sizes and counts must be positive')
binary = str(Path(a.binary).resolve())
work = Path(a.work_dir).resolve()
work.mkdir(parents=True, exist_ok=True)
mount = work/'mount'
cache = work/'cache'
mount.mkdir(exist_ok=True)
cache.mkdir(exist_ok=True)
common = ['--password-file', str(Path(a.password_file).resolve()),
          '--prefix', 'transfer-check-'+uuid.uuid4().hex+'/']
print('Test volume prefix:', common[-1], flush=True)
subprocess.run([binary, 'format', *common], check=True)
proc = None
report = {'prefix': common[-1]}
log = open(work/'client.log', 'ab')

def start():
    global proc
    proc = subprocess.Popen([binary, 'mount-s3', str(mount), *common,
                             '--cache-dir', str(cache), '--spool-mib',
                             str(max(4096, a.large_mib*2))], stdout=log, stderr=log)
    for _ in range(600):
        if os.path.ismount(mount):
            return
        if proc.poll() is not None:
            raise RuntimeError('mount failed; inspect '+str(work/'client.log'))
        time.sleep(.05)
    raise RuntimeError('mount timed out')

def stop():
    global proc
    subprocess.run(['fusermount3', '-u', str(mount)], check=True)
    assert proc.wait(timeout=300) == 0
    proc = None

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while block := f.read(1024*1024):
            h.update(block)
    return h.hexdigest()

try:
    start()
    block = os.urandom(1024*1024)
    expected = hashlib.sha256()
    begin = time.monotonic()
    copy_begin = begin
    # Deliberately omit fsync: close queues work, normal unmount drains it.
    with open(mount/'large.bin', 'wb', buffering=0) as f:
        for i in range(a.large_mib):
            view = memoryview(block)
            while view:
                n = f.write(view)
                assert n > 0
                view = view[n:]
            expected.update(block)
            if (i+1) % 256 == 0:
                print('large MiB written:', i+1, flush=True)
    report['large_close_seconds'] = time.monotonic()-begin
    print('Large write and close accepted:', report['large_close_seconds'], 'seconds', flush=True)
    assert (mount/'large.bin').stat().st_size == a.large_mib*1048576
    (mount/'small').mkdir()
    begin = time.monotonic()
    small = {}
    for i in range(a.small_files):
        data = bytes([i % 251]) * (4096 if i % 2 else 262144)
        name = f'{i:04d}.bin'
        with open(mount/'small'/name, 'wb') as f:
            f.write(data)
        small[name] = (len(data), hashlib.sha256(data).hexdigest())
        if (i+1) % 50 == 0:
            print('Small files queued:', i+1, flush=True)
    report['small_copy_seconds'] = time.monotonic()-begin
    print('All small file closes accepted:', a.small_files, flush=True)
    drain_begin = time.monotonic()
    stop()
    report['shutdown_drain_seconds'] = time.monotonic()-drain_begin
    report['copy_and_drain_seconds'] = time.monotonic()-copy_begin
    start()
    begin = time.monotonic()
    with os.scandir(mount/'small') as entries:
        sizes = {e.name: e.stat().st_size for e in entries}
    report['cold_stat_listing_seconds'] = time.monotonic()-begin
    print('Cold listing seconds:', report['cold_stat_listing_seconds'], flush=True)
    assert sizes == {name: size for name, (size, _) in small.items()}
    assert digest(mount/'large.bin') == expected.hexdigest()
    for name, (_, sha) in small.items():
        assert digest(mount/'small'/name) == sha
    report.update(large_mib=a.large_mib, large_sha256=expected.hexdigest(),
                  small_files=a.small_files, verified=True)
    print(json.dumps(report, indent=2), flush=True)
    (work/'result.json').write_text(json.dumps(report, indent=2)+'\n')
finally:
    if proc is not None:
        if os.path.ismount(mount):
            stop()
        else:
            proc.terminate()
            proc.wait(timeout=300)
    log.close()
