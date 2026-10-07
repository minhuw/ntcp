#!/usr/bin/env python3
"""Live Redis/LD_PRELOAD test; --self-check needs neither Redis nor namespaces."""
import concurrent.futures
import contextlib
import io
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[4]
LIBRARY = ROOT / 'target/debug/libntcp_socket.so'
KERNEL, ENGINE, PORT = '10.73.0.1', '10.73.0.2', 16379
TUN = 'ntcp0'


def clean_env():
    env = os.environ.copy()
    for key in list(env):
        if key == 'LD_PRELOAD' or key.startswith('NTCP_SOCKET_'):
            del env[key]
    return env


def tool(name):
    path = shutil.which(name, path=clean_env()['PATH'])
    if not path:
        raise RuntimeError(f'required tool not found: {name}')
    return path


def run(args, *, timeout=10, env=None, input=None):
    return subprocess.run([str(arg) for arg in args], env=env or clean_env(),
                          input=input, capture_output=True, check=True, timeout=timeout)


def bounded_group(args, *, timeout, output):
    # The namespace watchdog kills Redis too, even if Python cannot unwind.
    process = subprocess.Popen([str(arg) for arg in args], cwd=ROOT, env=clean_env(),
                               stdout=output, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
        if code:
            raise subprocess.CalledProcessError(code, args)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def frame(*args):
    parts = [arg if isinstance(arg, bytes) else str(arg).encode() for arg in args]
    return b'*%d\r\n' % len(parts) + b''.join(
        b'$%d\r\n' % len(part) + part + b'\r\n' for part in parts)


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise EOFError('truncated RESP payload')
        result.extend(chunk)
    return bytes(result)


def response(stream):
    line = stream.readline(65537)
    if not line.endswith(b'\r\n'):
        raise ValueError(f'invalid/truncated RESP line: {line[:100]!r}')
    kind, value = line[:1], line[1:-2]
    if kind == b'+':
        return value
    if kind == b'-':
        raise RuntimeError(f'Redis error: {value!r}')
    if kind == b':':
        return int(value)
    if kind in (b'$', b'*'):
        size = int(value)
        if size == -1:
            return None
        if not 0 <= size <= 2 * 1024 * 1024:
            raise ValueError(f'invalid RESP length: {size}')
        if kind == b'*':
            return [response(stream) for _ in range(size)]
        data = exact(stream, size)
        if exact(stream, 2) != b'\r\n':
            raise ValueError('invalid RESP bulk terminator')
        return data
    raise ValueError(f'unknown RESP type: {kind!r}')


@contextlib.contextmanager
def client(address, timeout=15):
    with socket.create_connection((address, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with sock.makefile('rb') as stream:
            yield sock, stream


def command(sock, stream, *args):
    sock.sendall(frame(*args))
    return response(stream)


def self_check():
    assert frame('SET', b'a', b'\x00\r\n') == b'*3\r\n$3\r\nSET\r\n$1\r\na\r\n$3\r\n\x00\r\n\r\n'
    wire = io.BytesIO(b'+PONG\r\n:1\r\n$-1\r\n*2\r\n$3\r\na\x00b\r\n+OK\r\n')
    assert [response(wire) for _ in range(4)] == [b'PONG', 1, None, [b'a\x00b', b'OK']]
    class ShortReads(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 2))
    assert response(ShortReads(b'$5\r\na\r\n\x00b\r\n')) == b'a\r\n\x00b'
    for bad in (b'', b'+bad\n', b'$4\r\nabc', b'$1\r\naXX', b'$-2\r\n', b'?x\r\n'):
        try:
            response(io.BytesIO(bad))
        except (ValueError, EOFError):
            pass
        else:
            raise AssertionError(f'accepted malformed RESP: {bad!r}')
    try:
        response(io.BytesIO(b'-ERR test\r\n'))
    except RuntimeError:
        pass
    else:
        raise AssertionError('accepted Redis error')
    print('RESP framing, binary data, short reads and malformed replies: PASS', flush=True)


@contextlib.contextmanager
def redis(address, env, directory, log_path):
    args = [tool('redis-server'), '--bind', address, '--port', str(PORT),
            '--protected-mode', 'no', '--save', '', '--appendonly', 'no',
            '--daemonize', 'no', '--dir', directory]
    with open(log_path, 'wb') as log:
        process = subprocess.Popen(args, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f'Redis exited at startup ({process.returncode}); see {log_path}')
                try:
                    with client(address, timeout=0.3) as (sock, stream):
                        assert command(sock, stream, 'PING') == b'PONG'
                    break
                except (OSError, EOFError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f'Redis readiness timed out; see {log_path}')
                    time.sleep(0.05)
            yield process
            assert process.poll() is None, 'Redis exited during tests'
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def counters():
    # Netlink follows the current netns; an inherited sysfs mount may not.
    link = json.loads(run([tool('ip'), '-j', '-s', 'link', 'show', 'dev', TUN]).stdout)[0]
    stats = link['stats64'] if 'stats64' in link else link['stats']
    return stats['rx']['packets'], stats['tx']['packets']


def assert_engine_unassigned():
    addresses = json.loads(run([tool('ip'), '-j', 'addr', 'show']).stdout)
    assert all(info['local'] != ENGINE for dev in addresses for info in dev.get('addr_info', []))
    route = run([tool('ip'), 'route', 'get', ENGINE]).stdout
    assert b'dev ntcp0' in route and not route.startswith(b'local '), route


def assert_no_kernel_listener():
    for table in ('tcp', 'tcp6'):
        for line in pathlib.Path('/proc/net', table).read_text().splitlines()[1:]:
            fields = line.split()
            assert not (fields[3] == '0A' and int(fields[1].split(':')[1], 16) == PORT), line


def exercise():
    payload = bytes(range(256)) * 4096
    with client(ENGINE, timeout=30) as (sock, stream):
        assert command(sock, stream, 'PING') == b'PONG'
        assert command(sock, stream, 'SET', 'test', b'value\x00\r\n') == b'OK'
        assert command(sock, stream, 'GET', 'test') == b'value\x00\r\n'
        assert command(sock, stream, 'DEL', 'test') == 1
        assert command(sock, stream, 'GET', 'test') is None
        requests = [('SET', 'pipe', 'first'), ('GET', 'pipe'), ('DEL', 'pipe'), ('PING',)]
        sock.sendall(b''.join(frame(*args) for args in requests))
        assert [response(stream) for _ in requests] == [b'OK', b'first', 1, b'PONG']
        assert command(sock, stream, 'SET', 'large', payload) == b'OK'
        assert command(sock, stream, 'GET', 'large') == payload
        assert command(sock, stream, 'DEL', 'large') == 1

    def worker(index):
        # Separate connections also check disconnect/reconnect and persisted data.
        key, value = f'client-{index}', bytes([index]) * 16384
        with client(ENGINE) as (sock, stream):
            assert command(sock, stream, 'SET', key, value) == b'OK'
        with client(ENGINE) as (sock, stream):
            assert command(sock, stream, 'GET', key) == value
            assert command(sock, stream, 'DEL', key) == 1
            assert command(sock, stream, 'PING') == b'PONG'
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    cli = run([tool('redis-cli'), '-h', ENGINE, '-p', PORT, 'PING'])
    assert cli.stdout.strip() == b'PONG', cli.stdout


def isolated(parent_namespace, artifact_dir):
    if str(os.stat('/proc/self/ns/net').st_ino) == parent_namespace:
        raise RuntimeError('refusing to change the parent network namespace')
    ip = tool('ip')
    run([ip, 'link', 'set', 'lo', 'up'])
    run([ip, 'tuntap', 'add', 'dev', TUN, 'mode', 'tun'])
    run([ip, 'addr', 'add', f'{KERNEL}/24', 'dev', TUN])
    run([ip, 'link', 'set', TUN, 'mtu', '1500', 'up'])
    assert_engine_unassigned()
    preload = clean_env() | {'LD_PRELOAD': str(LIBRARY), 'NTCP_SOCKET_TUN': TUN,
                            'NTCP_SOCKET_ADDR': ENGINE, 'NTCP_SOCKET_PREFIX': '24'}
    with tempfile.TemporaryDirectory(prefix='redis-data-', dir=artifact_dir) as data:
        before = counters()
        with redis(ENGINE, preload, data, artifact_dir / 'preloaded-server.log') as server:
            assert str(LIBRARY) in pathlib.Path(f'/proc/{server.pid}/maps').read_text(), 'preload not mapped'
            assert_no_kernel_listener()
            exercise()
            assert_no_kernel_listener()
            assert_engine_unassigned()
            after = counters()
            assert all(end > start for start, end in zip(before, after)), (before, after)
            print(f'PASS passive: PING, SET/GET/DEL, pipeline, 1MiB binary, 8 concurrent '
                  f'clients, reconnect, redis-cli; unassigned engine, no kernel listener, '
                  f'TUN rx/tx {before} -> {after}', flush=True)
        # The first runtime has exited and released exclusive TUN ownership.
        with redis(KERNEL, clean_env(), data, artifact_dir / 'kernel-server.log'):
            before = counters()
            args = [tool('redis-cli'), '-h', KERNEL, '-p', PORT]
            # A reachable kernel server makes accidental native fallback detectable.
            missing = preload.copy()
            del missing['NTCP_SOCKET_ADDR']
            invalid = preload | {'NTCP_SOCKET_ADDR': 'not-an-ip-address'}
            with open(artifact_dir / 'invalid-config.log', 'wb') as log:
                for label, env in [('missing address', missing), ('invalid address', invalid)]:
                    rejected = subprocess.run([str(arg) for arg in args + ['PING']], env=env,
                                              capture_output=True, timeout=10)
                    log.write(label.encode() + b'\n' + rejected.stdout + rejected.stderr)
                    log.flush()
                    assert rejected.returncode != 0 and b'PONG' not in rejected.stdout, (
                        label, rejected.returncode, rejected.stdout, rejected.stderr)
            blocking = run(args + ['PING'], env=preload, timeout=20)
            assert blocking.stdout.strip() == b'PONG', blocking.stdout
            info = run(args + ['CLIENT', 'INFO'], env=preload, timeout=20).stdout
            assert f'addr={ENGINE}:'.encode() in info, info
            # redis-cli --pipe uses the nonblocking hiredis write/read loop.
            pipe = run(args + ['--pipe', '--pipe-timeout', '10'], env=preload,
                       input=frame('SET', 'active', b'active\x00value') + frame('PING'), timeout=20)
            assert b'errors: 0, replies: 2' in pipe.stdout, (pipe.stdout, pipe.stderr)
            with client(KERNEL) as (sock, stream):
                assert command(sock, stream, 'GET', 'active') == b'active\x00value'
                assert command(sock, stream, 'DEL', 'active') == 1
            after = counters()
            assert all(end > start for start, end in zip(before, after)), (before, after)
            assert_engine_unassigned()
            print(f'PASS active: missing/invalid address rejected, preloaded redis-cli '
                  f'PING + nonblocking --pipe, engine source IP and kernel-verified '
                  f'payload; TUN rx/tx {before} -> {after}', flush=True)


def main():
    if sys.argv[1:] == ['--self-check']:
        self_check()
        return
    if len(sys.argv) == 4 and sys.argv[1] == '--isolated':
        isolated(sys.argv[2], pathlib.Path(sys.argv[3]))
        return
    if len(sys.argv) != 1:
        raise SystemExit('usage: redis.py [--self-check]')
    self_check()
    artifact_dir = pathlib.Path(tempfile.mkdtemp(prefix='redis-socket-', dir=ROOT / 'workbench'))
    try:
        version = run([tool('redis-server'), '--version']).stdout
        print(version.decode().strip(), flush=True)
        # Build on the host, with no inherited preload/configuration.
        with open(artifact_dir / 'build.log', 'wb') as output:
            bounded_group([tool('cargo'), 'build', '-p', 'ntcp-socket'], timeout=180, output=output)
        if not LIBRARY.is_file():
            raise RuntimeError(f'build did not produce {LIBRARY}')
        namespace = str(os.stat('/proc/self/ns/net').st_ino)
        with open(artifact_dir / 'integration.log', 'wb') as output:
            bounded_group([tool('unshare'), '--user', '--map-root-user', '--net',
                           sys.executable, pathlib.Path(__file__).resolve(), '--isolated',
                           namespace, artifact_dir], timeout=180, output=output)
        print((artifact_dir / 'integration.log').read_text(), end='')
        print(f'Logs: {artifact_dir}')
    except BaseException:
        print(f'FAIL; retained logs: {artifact_dir}', file=sys.stderr)
        for path in sorted(artifact_dir.glob('*.log')):
            print(f'--- {path.name} ---', file=sys.stderr)
            print(path.read_bytes()[-16384:].decode(errors='replace'), file=sys.stderr)
        raise


if __name__ == '__main__':
    (ROOT / 'workbench').mkdir(exist_ok=True)
    main()
