#!/usr/bin/env python3
"""Exercise the real CLI on a PTY without cloud credentials or network writes."""
import errno
import os
import pathlib
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
env = os.environ.copy()
for key in ('S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY', 'S3_SESSION_TOKEN', 'EEDFS_PASSWORD_FILE'):
    env.pop(key, None)
env['RUST_LOG'] = 'off'
base = ['--bucket', 'prompt-test']
secret = b'prompt-fixture-secret-one'

def interactive(args, answers, expected):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(binary, [binary, *args, *base], env)
    output = bytearray()
    deadline = time.monotonic()+15
    status = None
    try:
        for prompt, answer in answers:
            begin = len(output)
            while prompt not in output[begin:]:
                assert time.monotonic() < deadline, bytes(output)
                if select.select([fd], [], [], .1)[0]:
                    output.extend(os.read(fd, 4096))
            while termios.tcgetattr(fd)[3] & termios.ECHO:
                assert time.monotonic() < deadline, 'terminal echo was not disabled'
                time.sleep(.005)
            os.write(fd, answer+b'\n')
        while status is None:
            assert time.monotonic() < deadline, bytes(output)
            if select.select([fd], [], [], .1)[0]:
                try:
                    data = os.read(fd, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b''
                output.extend(data)
            done, value = os.waitpid(pid, os.WNOHANG)
            if done:
                status = value
        assert expected in output, bytes(output)
        assert secret not in output, 'password was echoed'
        assert termios.tcgetattr(fd)[3] & termios.ECHO, 'terminal echo was not restored'
        assert os.waitstatus_to_exitcode(status) != 0  # expected validation/credential failure
    finally:
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)

interactive(['format'], [(b'New volume password:', secret), (b'Confirm password:', secret)],
            b'set both S3_ACCESS_KEY_ID')
interactive(['format'], [(b'New volume password:', secret), (b'Confirm password:', b'different')],
            b'passwords do not match')
interactive(['format'], [(b'New volume password:', b'')], b'password must not be empty')
interactive(['gc'], [(b'Volume password:', secret)], b'set both S3_ACCESS_KEY_ID')
interactive(['change-password'], [(b'Current volume password:', secret),
            (b'New volume password:', secret), (b'Confirm password:', secret)],
            b'set both S3_ACCESS_KEY_ID')

result = subprocess.run([binary, 'format', *base], env=env, stdin=subprocess.DEVNULL,
                        capture_output=True, start_new_session=True, timeout=15)
assert result.returncode != 0 and b'no controlling terminal' in result.stderr, result
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory)/'password'
    path.write_bytes(secret+b'\r\n')
    result = subprocess.run([binary, 'format', *base, '--password-file', str(path)],
                            env=env, capture_output=True, start_new_session=True, timeout=15)
    assert b'set both S3_ACCESS_KEY_ID' in result.stderr, result
    assert b'Confirm password:' not in result.stderr and secret not in result.stderr, result
    path.write_bytes(b'\n')
    result = subprocess.run([binary, 'format', *base, '--password-file', str(path)],
                            env=env, capture_output=True, start_new_session=True, timeout=15)
    assert b'password file is empty' in result.stderr, result
print('Password prompt checks passed: hidden input, echo restoration, confirmation, mismatch, empty input, current/new passwords, no TTY, file compatibility')
