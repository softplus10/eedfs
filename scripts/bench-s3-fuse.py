#!/usr/bin/env python3
"""Run real FUSE/S3 correctness checks and optional bounded filesystem benchmarks.
Requires a disposable S3 bucket, Linux FUSE, provider S3_* env and a password file.
Creates a unique prefix and leaves it behind; file commits retire excluded chunks.
"""
import argparse, concurrent.futures, errno, hashlib, json, os, pathlib, random, stat, subprocess, sys, threading, time, uuid

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',default='target/release/cocryptfs')
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
if os.geteuid()==0:root.chmod(0o755)  # permit numeric-UID test traversal
binary=str(pathlib.Path(a.binary).resolve());password=str(pathlib.Path(a.password_file).resolve())
prefix='fuse-bench-'+uuid.uuid4().hex+'/'
common=['--password-file',password,'--prefix',prefix,'--chunk-size',str(a.chunk_size),'--parallelism',str(a.parallelism)]
subprocess.run([binary,'format',*common],check=True)
processes={};logs=[];results=[];expected_shutdown_errors=set()
def start(i):
    mount=root/f'mount-{i}';cache=root/f'cache-{i}';mount.mkdir(exist_ok=True);cache.mkdir(exist_ok=True)
    log=open(root/f'client-{i}.log','ab');logs.append(log)
    options=['--inode-poll-seconds','1','--spool-mib',str(max(4096,2*a.large_mib,2*a.parallel_mib) if a.benchmark else 4096)]+(['--allow-other'] if os.geteuid()==0 else [])
    proc=subprocess.Popen([binary,'mount-s3',str(mount),*common,'--cache-dir',str(cache),*options],stdout=log,stderr=log)
    processes[i]=proc
    for _ in range(400):
        if os.path.ismount(mount):return mount
        if proc.poll() is not None:raise RuntimeError(f'client {i} failed; inspect {log.name}')
        time.sleep(.05)
    raise RuntimeError(f'client {i} mount timeout')
def stop(i):
    proc=processes.pop(i);mount=root/f'mount-{i}'
    subprocess.run(['fusermount3','-u',str(mount)],check=True)
    proc.wait(timeout=300)
    if i in expected_shutdown_errors:
        expected_shutdown_errors.remove(i)
        assert proc.returncode!=0, 'failed writeback was hidden at shutdown'
        assert 'mount shutdown has uncommitted data' in (root/f'client-{i}.log').read_text()
    elif proc.returncode:raise RuntimeError(f'client {i} exited with {proc.returncode}')
def fsync_path(path):
    fd=os.open(path,os.O_RDWR)
    try:os.fsync(fd)
    finally:os.close(fd)
def write_committed(path,data):
    with open(path,'wb') as f:
        n=f.write(data);f.flush();os.fsync(f.fileno())
    return n
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
    subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('check-mmap.py')),*map(str,mounts)],check=True)
    expected_shutdown_errors.add(0)  # intentionally rejected stale mapped pages
    # Cross-client visibility, nested directories, overwrite, truncate and sparse gaps.
    (mounts[0]/'nested').mkdir()
    with open(mounts[0]/'nested'/'small','wb') as f:f.write(b'hello');f.flush();os.fsync(f.fileno())
    assert (mounts[1]/'nested'/'small').read_bytes()==b'hello'
    # One inode working state per mount: separate opens and hard-link aliases
    # see local writes/resize before fsync, with independent kernel FD flags.
    write_committed(mounts[1]/'shared-local',b'abcdef')
    shared=mounts[0]/'shared-local';local_fds=[]
    try:
        writer=os.open(shared,os.O_RDWR);local_fds.append(writer)
        reader=os.open(shared,os.O_RDONLY);local_fds.append(reader)
        os.pwrite(writer,b'local',0)
        assert os.pread(reader,6,0)==b'localf'
        joined=os.open(shared,os.O_RDWR);local_fds.append(joined)
        assert os.pread(joined,6,0)==b'localf'
        assert (mounts[2]/'shared-local').read_bytes()==b'abcdef'
        os.ftruncate(joined,3)
        assert shared.stat().st_size==os.fstat(writer).st_size==os.fstat(reader).st_size==3
        assert os.pread(reader,6,0)==b'loc'
        os.ftruncate(joined,8)
        assert os.pread(reader,10,0)==b'loc'+bytes(5)
        assert shared.stat().st_size==8 and (mounts[2]/'shared-local').stat().st_size==6
        os.fsync(joined)
        assert (mounts[2]/'shared-local').read_bytes()==b'loc'+bytes(5)
        appender=os.open(shared,os.O_RDWR|os.O_APPEND);local_fds.append(appender)
        assert os.write(appender,b'A')==1
        os.pwrite(writer,b'P',0)
        assert os.pread(reader,10,0)==b'Poc'+bytes(5)+b'A'
        assert os.read(reader,2)==b'Po' and os.read(joined,1)==b'P'
        duplicate=os.dup(reader);local_fds.append(duplicate)
        assert os.read(duplicate,1)==b'c' and os.lseek(reader,0,os.SEEK_CUR)==3
        os.link(shared,mounts[0]/'shared-alias')
        alias=os.open(mounts[0]/'shared-alias',os.O_RDWR);local_fds.append(alias)
        os.pwrite(alias,b'Q',1)
        assert os.pread(reader,3,0)==b'PQc'
        assert shared.stat().st_ino==(mounts[0]/'shared-alias').stat().st_ino
        os.fsync(alias)
        (mounts[0]/'shared-alias').unlink()
    finally:
        for fd in local_fds:os.close(fd)
    # O_TRUNC updates existing readers of this mount too.
    reader=os.open(shared,os.O_RDONLY);writer=None
    try:
        assert os.pread(reader,3,0)==b'PQc'
        writer=os.open(shared,os.O_RDWR|os.O_TRUNC)
        assert shared.stat().st_size==0 and os.pread(reader,10,0)==b''
        os.write(writer,b'new')
        assert os.pread(reader,10,0)==b'new'
    finally:
        if writer is not None:os.close(writer)
        os.close(reader)
    # A clean reopen adopts a remote commit for all handles of this mount.
    reader=os.open(shared,os.O_RDONLY)
    try:
        assert os.pread(reader,3,0)==b'new'
        write_committed(mounts[1]/'shared-local',b'remote')
        joined=os.open(shared,os.O_RDONLY)
        try:
            assert os.pread(joined,6,0)==os.pread(reader,6,0)==b'remote'
        finally:os.close(joined)
    finally:os.close(reader)
    # Cold concurrent opens must join one state, even before it has a handle.
    # No worker closes/flushes until all local reads and the remote check finish.
    for append in [False,True]:
        name='local-append' if append else 'local-concurrent'
        write_committed(mounts[1]/name,b'')
        barrier=threading.Barrier(9,timeout=60)
        records=[bytes([i+1])*32 for i in range(8)]
        def local_worker(i):
            fd=os.open(mounts[0]/name,os.O_RDWR|(os.O_APPEND if append else 0))
            try:
                barrier.wait()
                if append:assert os.write(fd,records[i])==32
                else:assert os.pwrite(fd,records[i],i*32)==32
                barrier.wait()
                observed=os.pread(fd,256,0)
                if append:assert len(observed)==256 and sorted(observed[n:n+32] for n in range(0,256,32))==records
                else:assert observed==b''.join(records)
                barrier.wait()
            finally:os.close(fd)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            jobs=[pool.submit(local_worker,i) for i in range(8)]
            barrier.wait();barrier.wait()
            assert (mounts[2]/name).read_bytes()==b''
            barrier.wait()
            for job in jobs:job.result()
        fsync_path(mounts[0]/name)
        observed=(mounts[2]/name).read_bytes()
        if append:assert len(observed)==256 and sorted(observed[n:n+32] for n in range(0,256,32))==records
        else:assert observed==b''.join(records)
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
    os.close(fd)  # no final fsync: publication is now eventual
    deadline=time.monotonic()+30
    while (mounts[2]/'mid-sync').read_bytes()!=expected+b'close-commits':
        assert time.monotonic()<deadline, 'background close did not publish'
        time.sleep(.05)
    # Numeric metadata survives reopening from a different mount.
    os.chmod(mounts[0]/'check',0o640)
    os.utime(mounts[0]/'check',ns=(1_234_000_000_000,5_678_000_000_000))
    info=(mounts[1]/'check').stat()
    assert stat.S_IMODE(info.st_mode)==0o640 and info.st_mtime_ns==5_678_000_000_000
    assert (info.st_uid,info.st_gid)==(os.geteuid(),os.getegid())
    # Concurrent disjoint writes in one chunk both survive CAS retry.
    d0=os.open(mounts[0]/'check',os.O_RDWR);d1=os.open(mounts[1]/'check',os.O_RDWR)
    os.pwrite(d0,b'left',100);os.pwrite(d1,b'right',200);os.fsync(d0);os.fsync(d1);os.close(d0);os.close(d1)
    with open(mounts[2]/'check','rb') as f:
        f.seek(100);assert f.read(4)==b'left';f.seek(200);assert f.read(5)==b'right'
    # Cached bytes stay old through polling; a chunk 404 refreshes the session.
    snapshot=os.open(mounts[0]/'check',os.O_RDONLY)
    old=os.pread(snapshot,6,0);writer=os.open(mounts[1]/'check',os.O_RDWR)
    os.pwrite(writer,b'newver',0);os.fsync(writer);os.close(writer)
    time.sleep(1.2)
    assert os.pread(snapshot,6,0)==old
    # Force a cache miss in a superseded fifth chunk, then verify the first
    # cached chunk is invalidated along with the rest of the old snapshot.
    refresh_path=mounts[0]/'refresh-reader';refresh_len=5*a.chunk_size
    refresh_writer=os.open(refresh_path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o644)
    for _ in range(5):assert os.write(refresh_writer,bytes(a.chunk_size))==a.chunk_size
    os.fsync(refresh_writer)
    refresh_reader=os.open(mounts[1]/'refresh-reader',os.O_RDONLY)
    assert os.pread(refresh_reader,5,0)==bytes(5)
    os.pwrite(refresh_writer,b'first',0);os.pwrite(refresh_writer,b'last',refresh_len-4)
    os.fsync(refresh_writer)
    assert os.pread(refresh_reader,4,refresh_len-4)==b'last'
    assert os.pread(refresh_reader,5,0)==b'first'
    os.close(refresh_reader);os.close(refresh_writer)
    with open(mounts[0]/'check','rb') as f:assert f.read(6)==b'newver'
    os.close(snapshot)
    # Two appenders: the first successful CAS wins even if it wrote later.
    write_committed(mounts[2]/'append-conflict',b'baseline')
    expected_shutdown_errors.add(0)
    a0=os.open(mounts[0]/'append-conflict',os.O_WRONLY|os.O_APPEND);a1=os.open(mounts[1]/'append-conflict',os.O_WRONLY|os.O_APPEND)
    before=(mounts[2]/'append-conflict').stat().st_size
    os.write(a0,b'loser');os.write(a1,b'winner');os.fsync(a1)
    try:os.fsync(a0)
    except OSError as e:assert e.errno==errno.EAGAIN,e
    else:raise AssertionError('stale append unexpectedly merged')
    os.close(a1)
    try:os.close(a0)
    except OSError as e:assert e.errno==errno.EAGAIN,e
    with open(mounts[2]/'append-conflict','rb') as f:f.seek(before);assert f.read()==b'winner'
    if os.geteuid()==0:
        permissions=mounts[0]/'permissions';permissions.mkdir();os.chmod(permissions,0o777)
        def as_user(uid,gid,code,path):
            command='import os,sys;os.setgroups([]);os.setgid(int(sys.argv[1]));os.setuid(int(sys.argv[2]));'+code
            subprocess.run([sys.executable,'-c',command,str(gid),str(uid),str(path)],check=True)
        owned=permissions/'owned'
        as_user(1234,2000,'fd=os.open(sys.argv[3],os.O_CREAT|os.O_WRONLY,0o640);os.write(fd,b"secret");os.fsync(fd);os.close(fd)',owned)
        st=(mounts[1]/'permissions'/'owned').stat();assert (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(1234,2000,0o640)
        as_user(1235,2000,'assert open(sys.argv[3],"rb").read()==b"secret"',mounts[1]/'permissions'/'owned')
        as_user(1235,2001,'\ntry:open(sys.argv[3],"rb");raise AssertionError("DAC allowed other user")\nexcept PermissionError:pass',mounts[2]/'permissions'/'owned')
        groups='import os,sys;os.setgroups([3000]);os.setgid(2000);os.setuid(1234);os.chown(sys.argv[1],-1,3000)'
        subprocess.run([sys.executable,'-c',groups,str(owned)],check=True)
        assert (mounts[1]/'permissions'/'owned').stat().st_gid==3000
        os.chown(owned,2345,3000);st=(mounts[2]/'permissions'/'owned').stat();assert (st.st_uid,st.st_gid)==(2345,3000)
    # Open snapshots: stale writer must report EAGAIN and leave the winner intact.
    expected_shutdown_errors.add(1)
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
    # Namespace callbacks: replacement keeps old open snapshots alive.
    (mounts[0]/'ns-left').mkdir();(mounts[0]/'ns-right').mkdir()
    source=mounts[0]/'ns-left'/'source';write_committed(source,b'new-content')
    destination=mounts[1]/'ns-right'/'destination';write_committed(destination,b'old-content')
    old_fd=os.open(destination,os.O_RDONLY)
    os.replace(source,mounts[0]/'ns-right'/'destination')
    assert os.pread(old_fd,11,0)==b'old-content';os.close(old_fd)
    assert (mounts[2]/'ns-right'/'destination').read_bytes()==b'new-content'
    os.rename(mounts[0]/'ns-right'/'destination',mounts[0]/'ns-right'/'renamed')
    os.link(mounts[1]/'ns-right'/'renamed',mounts[1]/'ns-left'/'alias')
    assert (mounts[2]/'ns-left'/'alias').stat().st_nlink==2
    survivor=os.open(mounts[2]/'ns-left'/'alias',os.O_RDWR)
    (mounts[0]/'ns-right'/'renamed').unlink();(mounts[1]/'ns-left'/'alias').unlink()
    assert os.fstat(survivor).st_nlink==0
    os.pwrite(survivor,b'updated',0);os.fsync(survivor)
    assert os.pread(survivor,7,0)==b'updated';os.close(survivor)
    assert not (mounts[2]/'ns-left'/'alias').exists()
    write_committed(mounts[0]/'ns-right'/'target',b'target')
    os.symlink('../ns-right/target',mounts[0]/'ns-left'/'relative')
    assert os.readlink(mounts[1]/'ns-left'/'relative')=='../ns-right/target'
    assert (mounts[2]/'ns-left'/'relative').read_bytes()==b'target'
    os.symlink(str(mounts[2]/'ns-right'/'target'),mounts[2]/'absolute')
    assert (mounts[2]/'absolute').read_bytes()==b'target'
    os.symlink('does-not-exist',mounts[0]/'dangling')
    assert (mounts[1]/'dangling').is_symlink() and not (mounts[1]/'dangling').exists()
    try:(mounts[0]/'ns-left').rmdir()
    except OSError as e:assert e.errno==errno.ENOTEMPTY,e
    else:raise AssertionError('rmdir accepted nonempty directory')
    (mounts[1]/'ns-left'/'relative').unlink();(mounts[0]/'ns-left').rmdir()
    (mounts[0]/'ns-right'/'child').mkdir();(mounts[0]/'empty-dir').mkdir()
    os.rename(mounts[1]/'ns-right'/'child',mounts[1]/'empty-dir')
    assert (mounts[2]/'empty-dir').is_dir() and not (mounts[2]/'ns-right'/'child').exists()
    try:os.rename(mounts[0]/'ns-right',mounts[0]/'ns-right'/'cycle')
    except OSError as e:assert e.errno==errno.EINVAL,e
    else:raise AssertionError('directory cycle accepted')
    (mounts[1]/'empty-dir').rmdir()
    # Sparse 16 GiB logical file stores only the explicitly written bytes.
    sparse=os.open(mounts[0]/'large-hole',os.O_CREAT|os.O_RDWR,0o600)
    os.ftruncate(sparse,1<<34);os.fsync(sparse)
    st=(mounts[1]/'large-hole').stat();assert st.st_size==1<<34 and st.st_blocks==0,st
    os.pwrite(sparse,b'middle',1<<33);os.fsync(sparse);os.close(sparse)
    with open(mounts[2]/'large-hole','rb') as f:f.seek((1<<33)-2);assert f.read(10)==bytes(2)+b'middle'+bytes(2)
    assert (mounts[1]/'large-hole').stat().st_blocks<=8
    # Repeat independent same-file writes from all three clients.
    merge=mounts[0]/'merge-three';write_committed(merge,bytes(4096))
    for iteration in range(12):
        fds=[os.open(m/'merge-three',os.O_RDWR) for m in mounts]
        for i,fd in enumerate(fds):os.pwrite(fd,bytes([iteration+1+i])*16,i*64)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(os.fsync,fds))
        for fd in fds:os.close(fd)
        data=merge.read_bytes()
        for i in range(3):assert data[i*64:i*64+16]==bytes([iteration+1+i])*16
    # Repeated directory create, cross-directory move, link and unlink contention.
    (mounts[0]/'race-a').mkdir();(mounts[0]/'race-b').mkdir()
    def namespace_worker(i):
        for n in range(12):
            name=f'entry-{i}-{n}';left=mounts[i]/'race-a'/name;right=mounts[i]/'race-b'/name
            write_committed(left,bytes([i])*32);os.rename(left,right)
            os.link(right,left);right.unlink();left.unlink()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(namespace_worker,range(3)))
    assert list((mounts[2]/'race-a').iterdir())==[] and list((mounts[2]/'race-b').iterdir())==[]
    (mounts[0]/'race-a').rmdir();(mounts[1]/'race-b').rmdir()
    # Promote beyond the inline limit with real entries from three mounts.
    (mounts[0]/'indexed').mkdir()
    def indexed_create(i):
        path=mounts[i%3]/'indexed'/f'entry-{i:04}'
        write_committed(path,str(i).encode())
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(indexed_create,range(1200)))
    assert len(list((mounts[2]/'indexed').iterdir()))==1200
    for i in [0,63,64,1023,1024,1199]:assert (mounts[1]/'indexed'/f'entry-{i:04}').read_bytes()==str(i).encode()
    os.rename(mounts[0]/'indexed'/'entry-0000',mounts[0]/'indexed'/'renamed')
    (mounts[1]/'indexed'/'entry-1199').unlink()
    assert (mounts[2]/'indexed'/'renamed').read_bytes()==b'0'
    assert len(list((mounts[2]/'indexed').iterdir()))==1199
    subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('check-scaling.py')),binary,password,prefix,str(mounts[0]),str(root)],check=True)
    scaling=json.loads((root/'scaling-check.json').read_text())
    record('scaling',scaling)
    # Password changes update only the header; current mounts keep their keys.
    changed_password=root/f'changed-password-{uuid.uuid4().hex}'
    password_fd=os.open(changed_password,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:os.write(password_fd,b'disposable changed integration password\n')
    finally:os.close(password_fd)
    subprocess.run([binary,'change-password','--prefix',prefix,'--password-file',password,'--new-password-file',str(changed_password)],check=True)
    assert (mounts[0]/'nested'/'small').read_bytes()==b'hello'
    stop(2)
    rejected=subprocess.run([binary,'mount-s3',str(mounts[2]),*common,'--cache-dir',str(root/'cache-2')],capture_output=True,timeout=30)
    assert rejected.returncode!=0 and not os.path.ismount(mounts[2]),rejected.stderr
    common[common.index('--password-file')+1]=str(changed_password)
    mounts[2]=start(2)
    assert (mounts[2]/'indexed'/'renamed').read_bytes()==b'0'
    record('correctness',{'passed':True,'checks':['cross-client','nested-directory','overwrite','truncate','sparse-gap','stale-writer-conflict','unlink','remount','partial-fsync-append','background-close-commit','disjoint-merge','append-first-CAS','snapshot-polling','retired-chunk-refresh','numeric-metadata-permissions','rename-replace','hard-link','open-unlink-write','symlink','rmdir','directory-move-cycle','objectless-16GiB-hole','three-client-merge-12-rounds','namespace-contention-36-rounds','indexed-directory-1200','password-change-and-remount','shared-local-inode','shared-local-truncate','shared-local-fd-flags-and-offsets','clean-open-refresh','concurrent-local-opens','local-atomic-append','mmap-shared-msync-13-checks']})
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
    # All clients stop before the offline reachability scan/sweep. Check that
    # forgotten inodes/uploads are reclaimed and reachable indexed/mapped data
    # still reads correctly after mounting again.
    for i in list(processes):stop(i)
    gc_command=[binary,'gc','--prefix',prefix,'--password-file',str(changed_password)]
    missing_offline=subprocess.run([*gc_command,'--delete'],capture_output=True,text=True)
    assert missing_offline.returncode!=0 and '--offline' in missing_offline.stderr
    inspected=subprocess.run(gc_command,capture_output=True,text=True,check=True)
    assert 'Deleted: 0 objects' in inspected.stdout,inspected.stdout
    swept=subprocess.run([*gc_command,'--offline','--delete'],capture_output=True,text=True,check=True)
    checked=subprocess.run(gc_command,capture_output=True,text=True,check=True)
    assert 'Unreferenced: 0 objects' in checked.stdout,checked.stdout
    mounts[2]=start(2)
    assert (mounts[2]/'nested'/'small').read_bytes()==b'hello'
    assert len(list((mounts[2]/'indexed').iterdir()))==1199
    for i in [63,64,1023,1024]:assert (mounts[2]/'indexed'/f'entry-{i:04}').read_bytes()==str(i).encode()
    assert (mounts[2]/'mmap-tests'/'stale-page').read_bytes()[:6]==b'remote'
    disjoint=(mounts[2]/'mmap-tests'/'disjoint-then-stale').read_bytes()
    page_size=os.sysconf('SC_PAGE_SIZE')
    assert disjoint[:6]==b'local0' and disjoint[page_size+31:page_size+37]==b'remote'
    with open(mounts[2]/'large-hole','rb') as f:f.seek((1<<33)-2);assert f.read(10)==bytes(2)+b'middle'+bytes(2)
    assert read_file(mounts[2]/'indexed-file',scaling['file_bytes'],scaling['file_sha256'])['sha256']==scaling['file_sha256']
    assert (mounts[2]/'resource-budget').stat().st_size==1048588
    record('offline-gc',{'passed':True,'sweep':swept.stdout.splitlines(),'remount_verified':True})
finally:
    for i in list(processes):stop(i)
    for log in logs:log.close()
