#!/usr/bin/env python3
"""Run real FUSE/S3 correctness checks and optional bounded filesystem benchmarks.
Requires a disposable S3 bucket, Linux FUSE, provider S3_* env and a password file.
Creates a unique prefix; never deletes remote objects (there is no GC yet).
"""
import argparse, concurrent.futures, errno, hashlib, json, os, pathlib, random, subprocess, time, uuid

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',default='target/release/eedfs')
p.add_argument('--password-file',required=True)
p.add_argument('--work-dir',required=True)
p.add_argument('--benchmark',action='store_true')
p.add_argument('--large-mib',type=int,default=10240)
p.add_argument('--parallel-mib',type=int,default=512)
p.add_argument('--chunk-size',type=int,default=8*1024*1024)
p.add_argument('--parallelism',type=int,default=8)
p.add_argument('--output',required=True)
a=p.parse_args()
if min(a.large_mib,a.parallel_mib,a.chunk_size,a.parallelism)<=0:p.error('sizes and parallelism must be positive')
root=pathlib.Path(a.work_dir).resolve();root.mkdir(parents=True,exist_ok=True)
binary=str(pathlib.Path(a.binary).resolve());password=str(pathlib.Path(a.password_file).resolve())
prefix='fuse-bench-'+uuid.uuid4().hex+'/'
common=['--password-file',password,'--prefix',prefix,'--chunk-size',str(a.chunk_size),'--parallelism',str(a.parallelism)]
subprocess.run([binary,'format',*common],check=True)
processes={};logs=[];results=[]
def start(i):
    mount=root/f'mount-{i}';cache=root/f'cache-{i}';mount.mkdir(exist_ok=True);cache.mkdir(exist_ok=True)
    log=open(root/f'client-{i}.log','ab');logs.append(log)
    proc=subprocess.Popen([binary,'mount-s3',str(mount),*common,'--cache-dir',str(cache)],stdout=log,stderr=log)
    processes[i]=proc
    for _ in range(400):
        if os.path.ismount(mount):return mount
        if proc.poll() is not None:raise RuntimeError(f'client {i} failed; inspect {log.name}')
        time.sleep(.05)
    raise RuntimeError(f'client {i} mount timeout')
def stop(i):
    proc=processes.pop(i);mount=root/f'mount-{i}'
    subprocess.run(['fusermount3','-u',str(mount)],check=True)
    proc.wait(timeout=30)
    if proc.returncode:raise RuntimeError(f'client {i} exited with {proc.returncode}')
def write_file(path,total,block=1024*1024):
    payload=os.urandom(block);h=hashlib.sha256();start_time=time.perf_counter()
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    try:
        for offset in range(0,total,block):
            data=payload[:min(block,total-offset)];view=memoryview(data)
            while view:
                n=os.write(fd,view);assert n>0;view=view[n:]
            h.update(data)
        write_done=time.perf_counter();os.fsync(fd);sync_done=time.perf_counter()
    finally:os.close(fd)
    elapsed=time.perf_counter()-start_time
    return {'bytes':total,'seconds':elapsed,'mib_s':total/1048576/elapsed,'write_seconds':write_done-start_time,'fsync_seconds':sync_done-write_done,'sha256':h.hexdigest()}
def read_fd(fd,total):
    h=hashlib.sha256();count=0;start_time=time.perf_counter()
    while True:
        data=os.read(fd,1024*1024)
        if not data:break
        h.update(data);count+=len(data)
    elapsed=time.perf_counter()-start_time;assert count==total,(count,total)
    return {'bytes':count,'seconds':elapsed,'mib_s':count/1048576/elapsed,'sha256':h.hexdigest()}
def read_file(path,total,expected,warm=False):
    fd=os.open(path,os.O_RDONLY)
    try:
        cold=read_fd(fd,total);assert cold['sha256']==expected
        if warm:
            os.lseek(fd,0,os.SEEK_SET);cached=read_fd(fd,total);assert cached['sha256']==expected;return cold,cached
        return cold
    finally:os.close(fd)
def record(name,result):
    result={'case':name,**result};results.append(result);print(json.dumps(result),flush=True)
    pathlib.Path(a.output).write_text(json.dumps({'prefix':prefix,'chunk_size':a.chunk_size,'parallelism':a.parallelism,'results':results},indent=2)+'\n')
try:
    mounts=[start(i) for i in range(3)]
    # Cross-client visibility, nested directories, overwrite, truncate and sparse gaps.
    (mounts[0]/'nested').mkdir()
    with open(mounts[0]/'nested'/'small','wb') as f:f.write(b'hello');f.flush();os.fsync(f.fileno())
    assert (mounts[1]/'nested'/'small').read_bytes()==b'hello'
    data=os.urandom(300_000)
    with open(mounts[0]/'check','wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    fd=os.open(mounts[1]/'check',os.O_RDWR)
    os.pwrite(fd,b'updated',150_000);os.fsync(fd);os.ftruncate(fd,10);os.fsync(fd);os.ftruncate(fd,300_000);os.fsync(fd)
    assert os.pread(fd,300_000,0)==data[:10]+bytes(299_990)
    os.pwrite(fd,b'tail',400_000);os.fsync(fd);assert os.pread(fd,14,399_990)==bytes(10)+b'tail';os.close(fd)
    # A partial fsync seals a chunk; subsequent append and close add new chunks.
    append_path=mounts[0]/'mid-sync'
    fd=os.open(append_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    expected=b''
    for size,value in [(3*1048576,11),(2*1048576,12)]:
        data=bytes([value])*size;view=memoryview(data)
        while view:
            n=os.write(fd,view);assert n>0;view=view[n:]
        assert (mounts[1]/'mid-sync').read_bytes()==expected
        os.fsync(fd);expected+=data
        assert (mounts[1]/'mid-sync').read_bytes()==expected
    assert os.write(fd,b'close-commits')==13
    os.close(fd)  # deliberately no final fsync; check successful close publication
    assert (mounts[2]/'mid-sync').read_bytes()==expected+b'close-commits'
    # Open snapshots: stale writer must report EAGAIN and leave the winner intact.
    f0=os.open(mounts[0]/'check',os.O_RDWR);f1=os.open(mounts[1]/'check',os.O_RDWR)
    os.pwrite(f0,b'winner',0);os.pwrite(f1,b'loser!',0);os.fsync(f0)
    try:os.fsync(f1)
    except OSError as e:assert e.errno==errno.EAGAIN,e
    else:raise AssertionError('stale writer unexpectedly committed')
    os.close(f0)
    try:os.close(f1)
    except OSError as e:assert e.errno==errno.EAGAIN,e
    assert (mounts[2]/'check').read_bytes()[:6]==b'winner'
    (mounts[0]/'check').unlink();assert not (mounts[1]/'check').exists()
    stop(0);mounts[0]=start(0)
    assert (mounts[0]/'nested'/'small').read_bytes()==b'hello'
    record('correctness',{'passed':True,'checks':['cross-client','nested-directory','overwrite','truncate','sparse-gap','stale-writer-conflict','unlink','remount','partial-fsync-append','close-commit']})
    if a.benchmark:
        # Same-directory metadata contention, with each writer on a different mount.
        def small_files(i):
            for n in range(20):
                with open(mounts[i]/f'small-{i}-{n}','xb') as f:f.write(bytes([i])*4096);f.flush();os.fsync(f.fileno())
        t=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(small_files,range(3)))
        elapsed=time.perf_counter()-t
        for i in range(3):
            for n in range(20):assert (mounts[2]/f'small-{i}-{n}').read_bytes()==bytes([i])*4096
        record('shared-directory-3-clients-4KiB-files',{'files':60,'seconds':elapsed,'files_s':60/elapsed,'verified':True})
        small=write_file(mounts[0]/'small-writes',64*1048576,4096)
        read_file(mounts[1]/'small-writes',small['bytes'],small['sha256'])
        record('64MiB-write-4KiB-syscalls-fsync',small)
        expected=bytearray((mounts[1]/'small-writes').read_bytes())
        fd=os.open(mounts[0]/'small-writes',os.O_RDWR);rng=random.Random(42)
        changes=[(rng.randrange(len(expected)//4096)*4096,os.urandom(4096)) for _ in range(32)]
        t=time.perf_counter()
        try:
            for offset,data in changes:
                assert os.pwrite(fd,data,offset)==len(data);os.fsync(fd)
        finally:os.close(fd)
        elapsed=time.perf_counter()-t
        for offset,data in changes:expected[offset:offset+len(data)]=data
        assert hashlib.sha256((mounts[2]/'small-writes').read_bytes()).digest()==hashlib.sha256(expected).digest()
        record('4KiB-random-overwrite-fsync',{'operations':32,'bytes':32*4096,'seconds':elapsed,'ops_s':32/elapsed,'verified':True})
        del expected
        single=write_file(mounts[0]/'large',a.large_mib*1048576)
        record('sequential-write-fsync',single)
        stop(0);mounts[0]=start(0)
        cold,warm=read_file(mounts[0]/'large',single['bytes'],single['sha256'],warm=True)
        record('sequential-read-remounted-client',cold);record('sequential-read-warm-open-handle',warm)
        t=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures=[pool.submit(write_file,mounts[i]/f'parallel-{i}',a.parallel_mib*1048576) for i in range(3)]
            outputs=[f.result() for f in futures]
        elapsed=time.perf_counter()-t
        for i,r in enumerate(outputs):read_file(mounts[(i+1)%3]/f'parallel-{i}',r['bytes'],r['sha256'])
        record('parallel-write-fsync-3-clients',{'bytes':sum(r['bytes'] for r in outputs),'seconds':elapsed,'mib_s':sum(r['bytes'] for r in outputs)/1048576/elapsed,'clients':outputs,'verified':True})
finally:
    for i in list(processes):stop(i)
    for log in logs:log.close()
