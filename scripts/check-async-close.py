#!/usr/bin/env python3
"""Real FUSE close/fsync/unmount checks through a gated disposable HTTP S3 proxy.

Requires a local HTTP MinIO endpoint and a disposable bucket configured by S3_*.
Uses a unique volume prefix. No existing mounted volume is accessed.
"""
import argparse
import concurrent.futures
import errno
import http.client
import http.server
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.parse
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', required=True)
p.add_argument('--password-file', required=True)
p.add_argument('--work-dir', required=True)
a = p.parse_args()
binary = str(Path(a.binary).resolve())
work = Path(a.work_dir).resolve()
work.mkdir(parents=True, exist_ok=True)
mount = work/'mount'
cache = work/'cache'
mount.mkdir(exist_ok=True)
cache.mkdir(exist_ok=True)
upstream = urllib.parse.urlsplit(os.environ['S3_ENDPOINT_URL'])
assert upstream.scheme == 'http' and not upstream.path.strip('/'), 'local HTTP S3 endpoint required'
known = set()
gates = {}
denied = set()
lock = threading.Lock()

class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *args):
        pass

    def forward(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with lock:
            if self.command == 'PUT':
                known.add(self.path)
            gate = gates.get(self.path) if self.command == 'PUT' else None
            deny = self.command == 'PUT' and self.path in denied
        if gate:
            gate[0].set()
            assert gate[1].wait(timeout=30), 'test gate was never released'
        if deny:
            data = b'<Error><Code>AccessDenied</Code></Error>'
            self.send_response(403)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        connection = http.client.HTTPConnection(upstream.hostname, upstream.port or 80, timeout=30)
        try:
            connection.request(self.command, self.path, body=body, headers=dict(self.headers))
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                    self.send_header(key, value)
            self.send_header('Content-Length', response.getheader('Content-Length', '0')
                             if self.command == 'HEAD' else str(len(data)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(data)
        finally:
            connection.close()

    do_GET = do_PUT = do_HEAD = do_DELETE = forward

proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
threading.Thread(target=proxy.serve_forever, daemon=True).start()
common = ['--password-file', str(Path(a.password_file).resolve()),
          '--prefix', 'async-close-'+uuid.uuid4().hex+'/',
          '--endpoint-url', f'http://127.0.0.1:{proxy.server_port}', '--force-path-style']
subprocess.run([binary, 'format', *common], check=True)
process = None
log_path = work/'client.log'
log = open(log_path, 'ab')

def start():
    global process
    process = subprocess.Popen([binary, 'mount-s3', str(mount), *common,
                                '--cache-dir', str(cache)], stdout=log, stderr=log)
    wait(lambda: os.path.ismount(mount), 'mount did not start')

def wait(predicate, message):
    deadline = time.monotonic()+15
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(.01)

def create(name, flags=0):
    with lock:
        before = set(known)
    fd = os.open(mount/name, os.O_CREAT | os.O_EXCL | os.O_RDWR | flags, 0o600)
    with lock:
        new = known-before
    assert len(new) == 1, new  # one new child inode, plus the existing parent CAS
    return fd, new.pop()

def gate(path):
    pair = threading.Event(), threading.Event()
    with lock:
        gates[path] = pair
    return pair

def blocked(future):
    try:
        future.result(timeout=.1)
    except concurrent.futures.TimeoutError:
        return
    raise AssertionError('operation acknowledged while its S3 commit was blocked')

def stop(expect_error=False):
    global process
    subprocess.run(['fusermount3', '-u', str(mount)], check=True)
    result = process.wait(timeout=60)
    assert (result != 0) == expect_error, result
    process = None

try:
    start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fd, key = create('closed')
        os.write(fd, b'closed data')
        entered, release = gate(key)
        timestamps = pool.submit(os.utime, mount/'closed', ns=(1_000_000_000, 2_000_000_000))
        assert entered.wait(timeout=10)
        timestamps.result(timeout=.5)  # metadata after buffered data is not fsync
        closed = pool.submit(os.close, fd)
        assert entered.wait(timeout=10)
        closed.result(timeout=.5)  # final close returns before S3 acknowledges
        other, _ = create('independent')
        os.write(other, b'other data')
        pool.submit(os.fsync, other).result(timeout=5)  # another inode progresses
        os.close(other)
        release.set()
        assert (mount/'closed').read_bytes() == b'closed data'

        fd, key = create('barrier')
        os.write(fd, b'barrier data')
        entered, release = gate(key)
        synced = pool.submit(os.fsync, fd)
        assert entered.wait(timeout=10)
        blocked(synced)
        release.set()
        synced.result(timeout=10)
        os.close(fd)

        for name, flags in [('sync', os.O_SYNC), ('dsync', os.O_DSYNC)]:
            fd, key = create(name, flags)
            entered, release = gate(key)
            written = pool.submit(os.write, fd, b'synchronous')
            assert entered.wait(timeout=10)
            blocked(written)
            release.set()
            assert written.result(timeout=10) == len(b'synchronous')
            os.close(fd)

        fd, key = create('unmount')
        os.write(fd, b'drained data')
        entered, release = gate(key)
        os.close(fd)
        assert entered.wait(timeout=10)
        subprocess.run(['fusermount3', '-u', str(mount)], check=True)
        exited = pool.submit(process.wait, timeout=30)
        blocked(exited)
        release.set()
        assert exited.result(timeout=10) == 0
        process = None
    start()
    assert (mount/'closed').read_bytes() == b'closed data'
    assert (mount/'closed').stat().st_mtime_ns == 2_000_000_000
    assert (mount/'independent').read_bytes() == b'other data'
    assert (mount/'barrier').read_bytes() == b'barrier data'
    assert (mount/'unmount').read_bytes() == b'drained data'
    assert (mount/'sync').read_bytes() == b'synchronous'
    assert (mount/'dsync').read_bytes() == b'synchronous'

    fd, key = create('failed')
    os.write(fd, b'retained after error')
    with lock:
        denied.add(key)
    os.close(fd)
    wait(lambda: 'background inode commit failed' in log_path.read_text(), 'failure not latched')
    fd = os.open(mount/'failed', os.O_RDWR)
    assert os.pread(fd, 20, 0) == b'retained after error'
    with lock:
        denied.remove(key)
    try:
        os.fsync(fd)
    except OSError as error:
        assert error.errno == errno.EIO, error
    else:
        raise AssertionError('prior background failure was hidden')
    os.fsync(fd)  # explicit retry after observing the previous error
    os.close(fd)

    fd, key = create('failed-unmount')
    os.write(fd, b'cannot be acknowledged')
    with lock:
        denied.add(key)
    before = log_path.read_text().count('background inode commit failed')
    os.close(fd)
    wait(lambda: log_path.read_text().count('background inode commit failed') > before,
         'final failure not latched')
    stop(expect_error=True)
    assert 'mount shutdown has uncommitted data' in log_path.read_text()
    print('Async close checks passed: last-close ownership, cross-file progress, fsync barrier, '
          'unmount drain, remount persistence, deferred errors, explicit retry, failed shutdown', flush=True)
finally:
    with lock:
        for _, release in gates.values():
            release.set()
    if process is not None:
        if os.path.ismount(mount):
            subprocess.run(['fusermount3', '-u', str(mount)], check=True)
        process.wait(timeout=60)
    proxy.shutdown()
    proxy.server_close()
    log.close()
