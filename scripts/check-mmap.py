#!/usr/bin/env python3
"""Exercise mmap/msync on three mounted clients of one disposable CoCryptFS volume."""
import ctypes
import errno
import mmap
import os
import pathlib
import select
import signal
import subprocess
import sys
import time

mounts = [pathlib.Path(p) for p in sys.argv[1:]]
if len(mounts) != 3:
    raise SystemExit("usage: check-mmap.py MOUNT_0 MOUNT_1 MOUNT_2")
page = mmap.PAGESIZE
libc = ctypes.CDLL(None, use_errno=True)
libc.msync.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.msync.restype = ctypes.c_int
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
libc.mmap.restype = ctypes.c_void_p
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.munmap.restype = ctypes.c_int
MS_ASYNC, MS_SYNC = 1, 4
roots = [p / "mmap-tests" for p in mounts]
roots[0].mkdir()


def fresh(name, size):
    data = (bytes(range(251)) * (size // 251 + 1))[:size]
    path = roots[0] / name
    with open(path, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path, bytearray(data)


def sync(mapping, offset=0, length=None, flags=MS_SYNC):
    length = len(mapping) - offset if length is None else length
    address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
    if libc.msync(address + offset, length, flags) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def passed(name):
    print("mmap check passed:", name, flush=True)


for name, size in [("inline", 3 * page), ("chunked", 40 * page)]:
    path, expected = fresh(name, size)
    fd = os.open(path, os.O_RDONLY)
    try:
        with mmap.mmap(fd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ) as view:
            assert view[:] == expected
        try:
            invalid = mmap.mmap(fd, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except OSError as error:
            assert error.errno == errno.EACCES, error
        else:
            invalid.close()
            raise AssertionError("read-only FD allowed a writable shared mapping")
        # Writable private mappings are copy-on-write and never alter the file.
        with mmap.mmap(fd, size, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as private:
            private[0:7] = b"private"
            sync(private)
            assert os.pread(fd, 7, 0) == expected[:7]
        assert (roots[1] / name).read_bytes() == expected
    finally:
        os.close(fd)
    passed(name + "-read-and-private-copy")

    fd1, fd2 = os.open(path, os.O_RDWR), os.open(path, os.O_RDWR)
    try:
        with mmap.mmap(fd1, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as first:
            with mmap.mmap(fd2, size, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as second:
                first[113:119] = b"mapped"
                expected[113:119] = b"mapped"
                assert second[113:119] == b"mapped"
                # Ordinary direct reads flush pending pages into the shared
                # spool, without publishing the inode to another client.
                assert os.pread(fd2, 6, 113) == b"mapped"
                assert (roots[1] / name).read_bytes()[113:119] != b"mapped"
                os.pwrite(fd2, b"pwrite", 137)
                expected[137:143] = b"pwrite"
                assert first[137:143] == second[137:143] == b"pwrite"
                first[page - 2:page + 3] = b"cross"
                expected[page - 2:page + 3] = b"cross"
                # The final page has not passed through ordinary write().
                first[size - 6:size] = b"mapped"
                expected[size - 6:size] = b"mapped"
                sync(first, 0, page)
                assert (roots[1] / name).read_bytes()[113:119] == b"mapped"
                sync(first)
                assert (roots[1] / name).read_bytes() == expected
                # Later msync generations on the same old FD stay usable.
                second[17:23] = b"second"
                expected[17:23] = b"second"
                sync(second)
                assert (roots[2] / name).read_bytes() == expected
                # MS_ASYNC queues/initiates writeback; a later barrier confirms it.
                first[32:37] = b"async"
                expected[32:37] = b"async"
                sync(first, flags=MS_ASYNC)
                os.fsync(fd2)
                assert (roots[2] / name).read_bytes() == expected
    finally:
        os.close(fd2)
        os.close(fd1)
    passed(name + "-shared-direct-io-msync-and-fsync")

# Page writeback from an O_APPEND|O_SYNC handle is still positioned page I/O.
path, expected = fresh("append-flags", 3 * page)
fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_SYNC)
try:
    with mmap.mmap(fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as view:
        view[page + 9:page + 15] = b"mapped"
        expected[page + 9:page + 15] = b"mapped"
        sync(view)
    assert path.stat().st_size == len(expected)
    assert (roots[1] / path.name).read_bytes() == expected
finally:
    os.close(fd)
passed("page-writeback-is-not-append")

# A mapping holds the FUSE handle even after the application's FD is closed.
path, expected = fresh("closed-fd", 3 * page)
fd = os.open(path, os.O_RDWR)
# Use libc here: Python mmap normally retains a duplicated FD of its own.
address = libc.mmap(None, len(expected), mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED, fd, 0)
assert address not in (None, ctypes.c_void_p(-1).value), ctypes.get_errno()
os.close(fd)
try:
    ctypes.memmove(address, b"closed", 6)
    expected[:6] = b"closed"
    if libc.msync(address, len(expected), MS_SYNC) != 0:
        raise OSError(ctypes.get_errno(), "msync after FD close failed")
    assert (roots[1] / path.name).read_bytes() == expected
finally:
    assert libc.munmap(address, len(expected)) == 0
passed("msync-after-fd-close")

# munmap has no durability acknowledgement, but a final release must not simply
# discard new pages delivered after the application's earlier close/flush.
path, expected = fresh("unmap-without-fd", 3 * page)
fd = os.open(path, os.O_RDWR)
address = libc.mmap(None, len(expected), mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED, fd, 0)
assert address not in (None, ctypes.c_void_p(-1).value), ctypes.get_errno()
os.close(fd)
ctypes.memmove(address, b"unmap!", 6)
expected[:6] = b"unmap!"
assert libc.munmap(address, len(expected)) == 0
deadline = time.monotonic() + 30
while (roots[1] / path.name).read_bytes() != expected:
    assert time.monotonic() < deadline, "final unmap discarded pending mapped data"
    time.sleep(.05)
passed("final-unmap-commits-new-unattempted-pages")

# Rename/unlink alter namespace references, not the identity of a live mapping.
path, expected = fresh("namespace", 3 * page)
fd = os.open(path, os.O_RDWR)
try:
    with mmap.mmap(fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as view:
        moved = path.with_name("namespace-renamed")
        os.rename(path, moved)
        view[0:6] = b"rename"
        expected[:6] = b"rename"
        sync(view)
        assert (roots[1] / moved.name).read_bytes() == expected
        moved.unlink()
        assert os.fstat(fd).st_nlink == 0
        view[0:6] = b"unlink"
        sync(view)
        assert view[:6] == b"unlink"
        assert not moved.exists() and not (roots[1] / moved.name).exists()
finally:
    os.close(fd)
passed("mapped-rename-and-open-unlink")

# Last-page bytes beyond EOF may be writable in memory but must not extend S3 data.
path, expected = fresh("partial-page", page + 123)
fd = os.open(path, os.O_RDWR)
try:
    with mmap.mmap(fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as view:
        view[-3:] = b"end"
        expected[-3:] = b"end"
        sync(view)
    assert path.stat().st_size == len(expected)
    assert (roots[1] / path.name).read_bytes() == expected
finally:
    os.close(fd)
passed("partial-final-page-keeps-eof")

# Truncating another FD of the same inode invalidates pages beyond the new EOF.
path, expected = fresh("truncate", 3 * page)
code = """
import mmap, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
fd = os.open(sys.argv[1], os.O_RDONLY)
view = mmap.mmap(fd, 3*mmap.PAGESIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
view[-1]
print('ready', flush=True)
sys.stdin.readline()
view[-1]
"""
child = subprocess.Popen([sys.executable, "-c", code, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    assert select.select([child.stdout], [], [], 30)[0], "mapped child did not become ready"
    assert child.stdout.readline().strip() == "ready"
    fd = os.open(path, os.O_RDWR)
    try:
        os.ftruncate(fd, page)
        os.fsync(fd)
    finally:
        os.close(fd)
    _, error = child.communicate("go\n", timeout=30)
    assert child.returncode == -signal.SIGBUS, (child.returncode, error)
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
passed("truncate-invalidates-mapping-with-sigbus")

# A later open/mapping may adopt a remote commit while older dirty pages still
# exist in the kernel. Writeback must not silently overwrite that remote change.
path, expected = fresh("stale-page", 40 * page)
fd1, fd2 = os.open(path, os.O_RDWR), None
first, second = None, None
try:
    first = mmap.mmap(fd1, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    assert first[:6] == expected[:6]
    first[:6] = b"local!"
    remote = os.open(roots[1] / path.name, os.O_RDWR)
    try:
        os.pwrite(remote, b"remote", 0)
        os.fsync(remote)
    finally:
        os.close(remote)
    fd2 = os.open(path, os.O_RDWR)
    second = mmap.mmap(fd2, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    try:
        sync(first)
    except OSError as error:
        assert error.errno in (errno.EAGAIN, errno.EIO), error
    else:
        raise AssertionError("stale mapped page overwrote a remote commit")
    assert (roots[2] / path.name).read_bytes()[:6] == b"remote"
finally:
    for view in (second, first):
        if view is not None:
            view.close()
    for fd in (fd2, fd1):
        if fd is not None:
            try:
                os.close(fd)
            except OSError as error:
                assert error.errno in (errno.EAGAIN, errno.EIO), error
passed("stale-page-after-reopen-reports-conflict")
assert (roots[2] / path.name).read_bytes()[:6] == b"remote"

# An old read-only view cannot dirty file-backed pages and must not prevent a
# fresh O_RDWR mapping from updating the version it actually opened.
path, expected = fresh("old-readonly-view", 3 * page)
old_fd = os.open(path, os.O_RDONLY)
try:
    with mmap.mmap(old_fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ) as old_view:
        assert old_view[:6] == expected[:6]
        remote = os.open(roots[1] / path.name, os.O_RDWR)
        try:
            os.pwrite(remote, b"remote", 0)
            os.fsync(remote)
        finally:
            os.close(remote)
        expected[:6] = b"remote"
        fd = os.open(path, os.O_RDWR)
        try:
            with mmap.mmap(fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE) as view:
                assert view[:6] == b"remote"
                view[64:70] = b"latest"
                expected[64:70] = b"latest"
                sync(view)
                assert old_view[64:70] == b"latest"
        finally:
            os.close(fd)
    assert (roots[2] / path.name).read_bytes() == expected
finally:
    os.close(old_fd)
passed("old-readonly-view-does-not-fence-fresh-writable-map")

# A successful partial msync may merge a remote change to another page. The
# still-cached old image of that other page must remain fenced afterwards.
path, expected = fresh("disjoint-then-stale", 40 * page)
fd = os.open(path, os.O_RDWR)
view = None
try:
    view = mmap.mmap(fd, len(expected), flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    assert view[:6] == expected[:6]
    assert view[page + 31:page + 37] == expected[page + 31:page + 37]
    remote = os.open(roots[1] / path.name, os.O_RDWR)
    try:
        os.pwrite(remote, b"remote", page + 31)
        os.fsync(remote)
    finally:
        os.close(remote)
    expected[page + 31:page + 37] = b"remote"
    view[:6] = b"local0"
    expected[:6] = b"local0"
    sync(view, 0, page)
    assert (roots[2] / path.name).read_bytes() == expected
    view[page + 31:page + 37] = b"local!"
    try:
        sync(view)
    except OSError as error:
        assert error.errno in (errno.EAGAIN, errno.EIO), error
    else:
        raise AssertionError("a prior disjoint merge hid stale-page conflict history")
    assert (roots[2] / path.name).read_bytes() == expected
finally:
    if view is not None:
        view.close()
    try:
        os.close(fd)
    except OSError as error:
        assert error.errno in (errno.EAGAIN, errno.EIO), error
passed("partial-msync-merge-keeps-other-stale-pages-fenced")
assert (roots[2] / path.name).read_bytes() == expected
