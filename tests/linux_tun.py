#!/usr/bin/env python3
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def isolated_test(parent_namespace):
    if str(os.stat('/proc/self/ns/net').st_ino) == parent_namespace:
        raise RuntimeError('refusing to change the parent network namespace')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'tuntap', 'add', 'dev', 'ntcp-test', 'mode', 'tun'], check=True)
    subprocess.run(['ip', 'addr', 'add', '10.73.0.1/24', 'dev', 'ntcp-test'], check=True)
    subprocess.run(['ip', 'link', 'set', 'ntcp-test', 'up'], check=True)
    executable = ROOT / 'target/debug/examples/tun_echo'
    with tempfile.TemporaryFile(mode='w+b') as log:
        process = subprocess.Popen([str(executable), 'ntcp-test', '10.73.0.2', '8080'], stderr=log)
        try:
            for attempt in range(100):
                if process.poll() is not None:
                    raise RuntimeError('TUN adapter exited during startup')
                log.seek(0)
                if b'echo listening' in log.read():
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError('TUN adapter did not start')
            for size in [1, 31, 1460, 65536, 1048576]:
                payload = bytes(i % 251 for i in range(size))
                with socket.create_connection(('10.73.0.2', 8080), timeout=10) as client:
                    client.settimeout(30)
                    errors = []
                    def send():
                        try:
                            client.sendall(payload)
                            client.shutdown(socket.SHUT_WR)
                        except BaseException as error:
                            errors.append(error)
                    sender = threading.Thread(target=send)
                    sender.start()
                    received = bytearray()
                    try:
                        while chunk := client.recv(16384):
                            received.extend(chunk)
                            if len(received) > len(payload):
                                raise AssertionError('duplicate stream bytes')
                    finally:
                        sender.join(timeout=35)
                    if sender.is_alive() or errors:
                        raise AssertionError(f'sender failed: {errors}')
                    assert received == payload, (size, len(received))
            # Linux sends one urgent byte; ntcp must retain it inline.
            with socket.create_connection(('10.73.0.2', 8080), timeout=10) as client:
                client.settimeout(10)
                client.sendall(b'before')
                assert client.send(b'!', socket.MSG_OOB) == 1
                client.sendall(b'after')
                client.shutdown(socket.SHUT_WR)
                received = bytearray()
                while chunk := client.recv(1024):
                    received.extend(chunk)
                assert received == b'before!after', received
            assert process.poll() is None
            process.terminate()
            process.wait(timeout=5)
            with socket.socket() as listener:
                listener.settimeout(10)
                listener.bind(('10.73.0.1', 9090))
                listener.listen(1)
                process = subprocess.Popen([str(executable), 'ntcp-test', '10.73.0.2',
                                            '8080', '10.73.0.1:9090'], stderr=log)
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(10)
                    payload = bytes(i % 247 for i in range(32768))
                    peer.sendall(payload)
                    peer.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while chunk := peer.recv(4096):
                        received.extend(chunk)
                    assert received == payload
            assert process.poll() is None
            print('Linux TUN: active/passive open, 5 transfer sizes, half-close and urgent data passed')
        except BaseException:
            log.seek(0)
            sys.stderr.write(log.read().decode(errors='replace'))
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        isolated_test(sys.argv[2])
    elif len(sys.argv) == 1:
        subprocess.run(['cargo', 'build', '--example', 'tun_echo'], cwd=ROOT, check=True)
        namespace = str(os.stat('/proc/self/ns/net').st_ino)
        subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable,
                        str(pathlib.Path(__file__).resolve()), '--isolated', namespace], check=True)
    else:
        raise SystemExit('unexpected test arguments')
