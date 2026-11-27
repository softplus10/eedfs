#!/usr/bin/env python3
"""Mounted extent/history promotion, bounded directory cache and local spool limits."""
import ctypes
import errno
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

binary,password,prefix,primary,workspace=sys.argv[1:]
primary=pathlib.Path(primary)
workspace=pathlib.Path(workspace)
# Cross the inline metadata thresholds with actual fsyncs and immutable objects.
path=primary/'indexed-file'
expected=hashlib.sha256()
fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
try:
    initial=b'base'*(32768)
    assert os.write(fd,initial)==len(initial)
    expected.update(initial)
    os.fsync(fd)
    for i in range(1050):
        data=bytes([i%251])*4096
        assert os.write(fd,data)==len(data)
        expected.update(data)
        os.fsync(fd)
        if (i+1)%250==0:print('indexed file fsyncs:',i+1,flush=True)
finally:
    os.close(fd)
size=131072+1050*4096
assert path.stat().st_size==size

mount=workspace/'bounded-mount'
cache=workspace/'bounded-cache'
mount.mkdir(exist_ok=True)
cache.mkdir(exist_ok=True)
log=open(workspace/'bounded-client.log','ab')
proc=subprocess.Popen([binary,'mount-s3',str(mount),'--password-file',password,'--prefix',prefix,'--cache-dir',str(cache),'--chunk-size','65536','--parallelism','2','--memory-mib','16','--spool-mib','1','--s3-requests','4','--max-cached-inodes','64'],stdout=log,stderr=log)
try:
    for _ in range(400):
        if os.path.ismount(mount):break
        assert proc.poll() is None,'bounded mount failed; inspect bounded-client.log'
        time.sleep(.05)
    else:raise AssertionError('bounded mount timeout')
    # readdir entries do not create lookup references. A 64-node registry can
    # enumerate 1,199 entries; inode numbers survive eviction/re-lookup.
    entries={entry.name:entry.inode() for entry in os.scandir(mount/'indexed')}
    assert len(entries)==1199
    for name in ['entry-0063','entry-0064','entry-1023','entry-1024','renamed']:
        assert (mount/'indexed'/name).stat().st_ino==entries[name]
    # Exercise a backwards directory cookie through libc seekdir.
    class Dirent(ctypes.Structure):
        _fields_=[('ino',ctypes.c_ulong),('offset',ctypes.c_long),('length',ctypes.c_ushort),('kind',ctypes.c_ubyte),('name',ctypes.c_char*256)]
    libc=ctypes.CDLL(None,use_errno=True)
    libc.opendir.argtypes=[ctypes.c_char_p];libc.opendir.restype=ctypes.c_void_p
    libc.readdir.argtypes=[ctypes.c_void_p];libc.readdir.restype=ctypes.POINTER(Dirent)
    libc.telldir.argtypes=[ctypes.c_void_p];libc.telldir.restype=ctypes.c_long
    libc.seekdir.argtypes=[ctypes.c_void_p,ctypes.c_long]
    libc.closedir.argtypes=[ctypes.c_void_p]
    directory=libc.opendir(os.fsencode(mount/'indexed'))
    assert directory
    try:
        for _ in range(150):assert libc.readdir(directory)
        cookie=libc.telldir(directory)
        names=[bytes(libc.readdir(directory).contents.name) for _ in range(8)]
        libc.seekdir(directory,cookie)
        assert [bytes(libc.readdir(directory).contents.name) for _ in range(8)]==names
    finally:libc.closedir(directory)
    # Cached read data must be evictable when an append needs its spool budget.
    fd=os.open(mount/'resource-budget',os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
    accepted=0
    try:
        for _ in range(32):
            try:accepted+=os.write(fd,b'q'*65536)
            except OSError as error:
                assert error.errno==errno.ENOSPC,error
                break
        else:raise AssertionError('1 MiB spool limit was not enforced')
        assert accepted==1048576,accepted
        assert os.pread(fd,64,0)==b'q'*64
        assert (primary/'resource-budget').stat().st_size==0
        os.fsync(fd)
        assert os.pread(fd,1048576,0)==b'q'*1048576
        assert os.write(fd,b'after-commit')==12
        os.fsync(fd)
    finally:os.close(fd)
    assert (mount/'resource-budget').stat().st_size==accepted+12
    usage=subprocess.run([binary,'s3','usage','--prefix',prefix],check=True,text=True,capture_output=True)
    assert 'Current listed bytes:' in usage.stdout
    # Use the default-budget client to checksum the complete indexed file.
    with path.open('rb') as stream:
        actual=hashlib.file_digest(stream,'sha256').hexdigest()
    assert actual==expected.hexdigest()
    manifest={'passed':True,'file_bytes':size,'file_sha256':actual,'fsync_appends':1050,'directory_entries_with_64_node_budget':1199,'spool_limit_bytes':accepted,'directory_seek_verified':True}
    (workspace/'scaling-check.json').write_text(json.dumps(manifest))
    print('mounted scaling checks passed',flush=True)
finally:
    if os.path.ismount(mount):subprocess.run(['fusermount3','-u',str(mount)],check=True)
    proc.wait(timeout=30)
    log.close()
