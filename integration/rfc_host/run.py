#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Required T5 gate. All mutations occur after inherited namespace-fd proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True

from bridge import Bridge
import icmp
from linux_peer import fnv, pattern

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BINARY = ROOT / "workbench/network-target/debug/ntcp-rfc-host"
TUN_ECHO = ROOT / "workbench/network-target/debug/examples/tun_echo"


def emit(tag, data):
    print(tag + " " + json.dumps(data, sort_keys=True), flush=True)


def command(args, timeout=30):
    p = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(json.dumps(dict(command=list(map(str, args)), exit=p.returncode,
                                          stdout=p.stdout[-12000:], stderr=p.stderr[-12000:])))
    return p.stdout


def matrix():
    cases = []
    for family in (4, 6):
        for role in ("client", "server"):
            policies = ("hmac",) if role == "client" else ("hmac", "linux")
            for policy in policies:
                for scenario in ("ordinary", "warm", "deferred", "disabled", "client-disabled", "strip", "drop", "stale"):
                    cases.append(dict(family=family, role=role, policy=policy, scenario=scenario))
                if role == "client":
                    cases.append(dict(family=family, role=role, policy=policy, scenario="refused"))
                if role == "server":
                    for scenario in ("expiry", "partial"):
                        cases.append(dict(family=family, role=role, policy=policy, scenario=scenario))
                    if policy == "linux":
                        cases.append(dict(family=family, role=role, policy=policy, scenario="expiry-no-issuer"))
    return cases


def namespace_guard():
    proof = {}
    for kind in ("net", "user"):
        fd = int(os.environ["T5_PARENT_" + kind.upper() + "_FD"])
        parent = os.fstat(fd).st_ino
        current = os.stat("/proc/self/ns/" + kind).st_ino
        assert parent != current, f"refuse mutation in parent {kind} namespace"
        assert os.readlink(f"/proc/self/fd/{fd}").startswith(kind + ":["), "invalid namespace fd"
        proof[kind] = dict(parent=parent, current=current)
        os.close(fd)
    return proof


def setup(family, kernel, native):
    def ip(*args):
        return command(["ip", *args])
    ip("link", "set", "lo", "up")
    for port, bridge, mac in (("t5k", "t5bk", "02:00:00:00:00:01"),
                              ("t5n", "t5bn", "02:00:00:00:00:02")):
        ip("link", "add", port, "type", "veth", "peer", "name", bridge)
        ip("link", "set", port, "address", mac)
        for interface in (port, bridge):
            # Complete wire checksums, no GSO superpackets at this Ethernet tap.
            command(["ethtool", "-K", interface, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"])
            with open(f"/proc/sys/net/ipv6/conf/{interface}/addr_gen_mode", "w") as f:
                f.write("1")  # no kernel address on native or forwarding ports
            ip("link", "set", interface, "up")
    prefix = "24" if family == 4 else "64"
    ip("addr", "add", kernel + "/" + prefix, "dev", "t5k", *([] if family == 4 else ["nodad"]))
    ip("-" + str(family), "route", "replace", native + ("/32" if family == 4 else "/128"), "dev", "t5k", "src", kernel)
    ip("-" + str(family), "neigh", "replace", native, "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "t5k")
    addresses = json.loads(ip("-j", "addr", "show"))
    assert all(a["local"] != native for link in addresses for a in link.get("addr_info", [])), "native address assigned to kernel"
    native_link = next(link for link in addresses if link["ifname"] == "t5n")
    assert not native_link.get("addr_info"), "kernel address on native-owned port"
    route = json.loads(ip("-j", "-" + str(family), "route", "get", native))[0]
    assert route["dev"] == "t5k" and route.get("type") != "local", route
    with open("/proc/sys/net/ipv4/tcp_fastopen", "w") as f:
        f.write("3")
    return dict(route=route, native_kernel_address=False, tcp_fastopen=3,
                mtu=1500, static_neighbor="02:00:00:00:00:02", offload="disabled on owned veths")


class Peer:
    def __init__(self, args):
        env = dict(os.environ)
        env.pop("LD_PRELOAD", None)
        env.pop("NTCP_SOCKET_CONFIG", None)
        self.p = subprocess.Popen(list(map(str, args)), cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.p.stdout, selectors.EVENT_READ)
        self.ready = self.read()
        assert self.ready["event"] == "ready", self.ready
        assert not self.ready.get("preload"), self.ready

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def read(self):
        if not self.selector.select(30):
            raise TimeoutError(f"peer deadline: {self.p.args}")
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"peer exited {self.p.poll()}: {self.p.stderr.read(12000)}")
        result = json.loads(line)
        assert result["event"] != "error", result
        return result

    def close(self):
        if self.p.poll() is None:
            try:
                self.send("quit")
                self.p.wait(2)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.p.kill()
                self.p.wait()
        self.selector.close()
        err = self.p.stderr.read(12000)
        remaining = self.p.stdout.read(12000)
        assert self.p.returncode == 0, dict(exit=self.p.returncode, stdout=remaining, stderr=err)


def validate_stream(server, client):
    for item, tx, rx, first, second in ((server, 7168, 11264, (8192, 7), (3072, 19)),
                                        (client, 11264, 7168, (6144, 11), (1024, 23))):
        assert item["event"] == "stream" and item["eof"]
        assert (item["tx"], item["rx"]) == (tx, rx), item
        assert item["first_hash"] == fnv(pattern(*first)) and item["second_hash"] == fnv(pattern(*second)), item


def wire_proof(events, direction, expectation):
    initial = next(e for e in events if e["direction"] == direction and e["flags"] & 0x12 == 2)
    # Closing ACKs from the preceding exchange may still be in flight. Only
    # this connection's actual port pair may supply admission/window evidence.
    ports = (initial["sport"], initial["dport"])
    events = [e for e in events if (e["sport"], e["dport"]) ==
              (ports if e["direction"] == direction else ports[::-1])]
    syns = [e for e in events if e["direction"] == direction and e["flags"] & 0x12 == 2]
    replies = [e for e in events if e["direction"] != direction and e["flags"] & 0x12 == 0x12]
    assert syns and replies, "empty handshake capture"
    initial, reply = syns[0], replies[0]
    admitted = (reply["ack"] - initial["seq"] - 1) & 0xffffffff
    if expectation == "ordinary":
        assert initial["payload"] == 0, initial
    elif expectation == "cold":
        assert initial["payload"] == 0 and initial["cookie"] == [""], initial
        assert reply["cookie"] and reply["cookie"][0], reply
    elif expectation in ("warm", "partial", "rejected", "drop", "strip"):
        assert initial["payload"] > 0 and initial["cookie"] and initial["cookie"][0], initial
        if expectation == "warm":
            assert admitted == initial["payload"], (initial, reply)
        elif expectation == "partial":
            assert 0 < admitted < initial["payload"] and admitted == 128, (initial, reply)
        elif expectation in ("rejected", "strip"):
            assert admitted == 0, (initial, reply)
        elif expectation == "drop":
            assert initial["action"] == "drop" and len(syns) >= 2, syns
            assert any(e["payload"] == 0 and not e["cookie"] for e in syns[1:]), "missing ordinary SYN retry"
    if direction == "native-to-kernel":
        scale = reply["window_scale"] if initial["window_scale"] is not None else None
        right_edge = admitted + reply["window"]  # SYN window is unscaled.
        for event in events[events.index(reply) + 1:]:
            if event["direction"] != direction and event["flags"] & 16:
                relative_ack = (event["ack"] - initial["seq"] - 1) & 0xffffffff
                right_edge = relative_ack + (event["window"] << (scale or 0))
            elif event["direction"] == direction and event["payload"] and not event["flags"] & 2:
                relative_end = ((event["seq"] - initial["seq"] - 1) & 0xffffffff) + event["payload"]
                assert relative_end <= right_edge, "native ordinary repair exceeded actual peer window"
    # Preserve actual ordinary retries/repair and window history, including
    # Linux's first repair on a partial SYNACK with a zero window.
    history = [{k: e[k] for k in ("direction", "flags", "seq", "ack", "window", "payload", "action", "time_ns")}
               for e in events if not e["flags"] & 2]
    return dict(initial_syn=initial, synack=reply, retry_syns=syns[1:], syn_count=len(syns), admitted_prefix=admitted,
                repair_and_window_history=history[:256], history_truncated=len(history) > 256,
                native_sender_credit_checked=direction == "native-to-kernel",
                payload_packets=sum(e["payload"] > 0 for e in events), frame_count=len(events),
                all_checksums_valid=all(e["checksum_valid"] for e in events))


def icmp_child(case, proof):
    evidence = icmp.child(case, proof, TUN_ECHO, Peer, command, emit)
    emit("T9_ICMP_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                              kernel_version=os.uname().version, evidence=evidence,
                              build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                         commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def child(case):
    proof = namespace_guard()  # Must precede every link/sysctl/neighbor/route mutation.
    if case.get("kind") == "icmp":
        return icmp_child(case, proof)
    family, role, policy, scenario = (case[k] for k in ("family", "role", "policy", "scenario"))
    kernel, native = ("198.18.0.1", "198.18.0.2") if family == 4 else ("fd54:3500::1", "fd54:3500::2")
    settings = setup(family, kernel, native)
    if scenario == "client-disabled":
        with open("/proc/sys/net/ipv4/tcp_fastopen", "w") as f:
            f.write("2" if role == "server" else "3")
    capacity = 128 if scenario == "partial" else 65536
    lifetime = 2_000_000 if scenario in ("expiry", "expiry-no-issuer") else 3_600_000_000
    managed = scenario != "expiry-no-issuer"
    native_disabled = (scenario == "disabled" and role == "server") or (scenario == "client-disabled" and role == "client")
    linux_disabled = scenario == "disabled" and role == "client"
    settings["tcp_fastopen"] = int(Path("/proc/sys/net/ipv4/tcp_fastopen").read_text())
    settings.update(receive_capacity=capacity, stream_receive_capacity=65536,
                    partial_admission_buffer_growth="public SO_RCVBUF after initial prefix read" if scenario == "partial" else None,
                    lifetime_us=lifetime, managed_keys=managed,
                    native_tfo_disabled=native_disabled, linux_listener_tfo_disabled=linux_disabled,
                    server_cookie_policy="Linux kernel opaque cookie" if role == "client" else policy)
    bridge = Bridge()
    peers = []
    results = []
    try:
        n = Peer([BINARY, role, native, kernel, policy, capacity, lifetime, int(managed), int(native_disabled)])
        peers.append(n)
        k = None if scenario == "refused" else Peer([sys.executable, HERE / "linux_peer.py", "server" if role == "client" else "client", kernel, native, int(linux_disabled)])
        if k is not None:
            peers.append(k)
        server, client = (k, n) if role == "client" else (n, k)
        direction = "native-to-kernel" if role == "client" else "kernel-to-native"

        learned_cookie = None

        def exchange(name, mode, nonblock, expected, fault="none", cookie=None):
            nonlocal learned_cookie
            start = bridge.configure(fault, direction)
            server.send("accept")
            client.send(mode + (" nonblock" if nonblock else " blocking") + (" " + cookie if cookie else ""))
            try:
                c, s = client.read(), server.read()
                validate_stream(s, c)
            except BaseException:
                events, count = bridge.snapshot(start)
                emit("T5_NETWORK_TRACE_FAILURE", dict(case=case, name=name, fault_count=count,
                     wire=[{k: v for k, v in e.items() if k not in ("raw", "egress_raw")} for e in events[:200]],
                     syn_frames=[e for e in events if e["flags"] & 6][:12], frames=len(events)))
                raise
            events, count = bridge.snapshot(start)
            assert count == (0 if fault == "none" else 1), (fault, count)
            wire = wire_proof(events, direction, expected)
            if expected in ("warm", "partial", "rejected", "drop", "strip"):
                assert wire["initial_syn"]["cookie"] == learned_cookie, "opaque cookie was not returned byte-for-byte"
            if wire["synack"]["cookie"]:
                learned_cookie = wire["synack"]["cookie"]
            if expected == "partial":
                assert wire["synack"]["window"] == 0, wire
                assert s["initial_read_count"] <= 128 and s["receive_capacity_after_read"] == 65536, s
                assert s["initial_read_hash"] == fnv(pattern(s["initial_read_count"], 7)), s
            item = dict(name=name, mode=mode, nonblock=nonblock, expected=expected, fault=fault,
                        fault_count=count, server=s, client=c, wire=wire)
            results.append(item)
            emit("T5_NETWORK_STREAM", dict(case=case, **item))
            return wire

        if scenario == "refused":
            for mode in ("connect", "msg", "deferred"):
                for nonblock in (False, True):
                    start = bridge.configure("none", direction)
                    client.send("refuse-" + mode + (" nonblock" if nonblock else " blocking"))
                    result = client.read()
                    assert result["event"] == "refused" and result["tcp_state"] == 7, result
                    events, count = bridge.snapshot(start)
                    syn = next(e for e in events if e["direction"] == direction and e["flags"] & 2)
                    rst = next(e for e in events if e["direction"] != direction and e["flags"] & 4
                               and (e["sport"], e["dport"]) == (syn["dport"], syn["sport"]))
                    assert rst["ack"] == (syn["seq"] + 1) & 0xffffffff and count == 0, (syn, rst)
                    item = dict(name="refused-" + mode, nonblock=nonblock, result=result,
                                wire=dict(initial_syn=syn, reset=rst, frame_count=len(events)))
                    results.append(item)
                    emit("T5_NETWORK_REFUSAL", dict(case=case, **item))
        elif scenario in ("ordinary", "disabled", "client-disabled"):
            exchange(scenario + "-connect", "connect", False, "ordinary")
            if scenario == "ordinary":
                exchange("ordinary-nonblocking-connect", "connect", True, "ordinary")
            if scenario != "ordinary":
                exchange(scenario + "-msg", "msg", True, "ordinary")
                exchange(scenario + "-deferred", "deferred", False, "ordinary")
        else:
            cold = exchange("cold-request", "deferred" if scenario == "deferred" else "msg", True, "cold")
            if scenario in ("expiry", "expiry-no-issuer"):
                # At most two HMAC epochs can authorize the old credential.
                # A 5s real monotonic wait exceeds both 2s epochs with margin.
                before = time.monotonic_ns()
                time.sleep(5)
                emit("T5_NETWORK_DEADLINE", dict(case=case, wait_ns=time.monotonic_ns() - before,
                                                lifetime_us=lifetime, owner_clock="real monotonic", managed=managed))
                old = exchange("expired-old-cookie", "msg", False, "rejected")
                if scenario == "expiry-no-issuer":
                    assert not old["synack"]["cookie"], old
                else:
                    assert old["synack"]["cookie"] and old["synack"]["cookie"] != cold["synack"]["cookie"], old
                    exchange("replacement", "deferred", True, "warm")
            elif scenario == "stale":
                if role == "client":
                    server.send("rotate")
                    rotation = server.read()
                    assert rotation["event"] == "rotated"
                    emit("T5_NETWORK_ROTATION", dict(case=case, server="Linux kernel", **rotation))
                    old = exchange("kernel-old-key-revoked", "msg", False, "rejected")
                    assert old["synack"]["cookie"] != cold["synack"]["cookie"], old
                    # Real native per-service negative caching lasts 60s after
                    # rejected committed SYN data; preserve that production policy.
                    cooldown_start = time.monotonic_ns()
                    time.sleep(61)
                    emit("T5_NETWORK_DEADLINE", dict(case=case, wait_ns=time.monotonic_ns() - cooldown_start,
                                                    reason="native service negative-cache expiry", policy_us=60_000_000))
                    exchange("replacement-after-cooldown", "deferred", True, "warm")
                else:
                    # Real kernel client cache is opaque. Revoke the listener's
                    # actual key through its supported socket API in the driver.
                    server.send("rotate")
                    rotation = server.read()
                    assert rotation["event"] == "rotated"
                    emit("T5_NETWORK_ROTATION", dict(case=case, server="native", **rotation))
                    exchange("native-old-key-revoked", "msg", False, "rejected")
                    exchange("replacement", "deferred", True, "warm")
            elif scenario in ("drop", "strip"):
                exchange("first-warm-" + scenario, "msg", False, scenario, fault=scenario)
            else:
                expected = "partial" if scenario == "partial" else "warm"
                exchange("warm-msg", "msg", False, expected)
                exchange("warm-deferred", "deferred", True, expected)
                if scenario in ("warm", "deferred"):
                    exchange("warm-msg-nonblocking", "msg", True, expected)
                    exchange("warm-deferred-blocking", "deferred", False, expected)
        assert results and all(r["wire"]["frame_count"] for r in results)
    finally:
        primary_error = sys.exc_info()[0] is not None
        errors = []
        for p in peers:
            try:
                p.close()
            except Exception as e:
                errors.append(str(e))
        bridge.close()
        if errors:
            emit("T5_NETWORK_CLEANUP", dict(errors=errors))
            if not primary_error:
                raise RuntimeError(errors)
    emit("T5_NETWORK_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                                 settings=settings,
                                 kernel_version=os.uname().version,
                                 build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                            commit=os.environ.get("T5_BUILD_COMMIT")),
                                 streams=sum("client" in r for r in results), completions=len(results), exit=0))


def fingerprint():
    paths = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]).split("\0")
    h = hashlib.sha256()
    for path in sorted(filter(None, paths)):
        h.update(path.encode() + b"\0" + (ROOT / path).read_bytes())
    return h.hexdigest()


def main():
    if not __debug__:
        raise RuntimeError("the required network gate cannot run with Python assertions disabled")
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-netns", action="store_true", required=True)
    parser.add_argument("--in-namespace", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.in_namespace:
        child(json.loads(args.in_namespace))
        return
    started = time.monotonic()
    command([sys.executable, "-B", "-m", "unittest", "discover", "-s", "integration/rfc_host", "-p", "test_*.py"])
    env = dict(os.environ)
    env["CARGO_HOME"] = str(ROOT / "workbench/cargo-home")
    build = ["cargo", "build", "--locked", "-p", "ntcp-rfc-host", "--target-dir", str(BINARY.parents[1])]
    p = subprocess.run(build, cwd=ROOT, env=env, timeout=600)
    assert p.returncode == 0, dict(command=build, exit=p.returncode)
    features = subprocess.run(["cargo", "tree", "--locked", "-p", "ntcp-rfc-host", "-e", "features"],
                              cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert features.returncode == 0 and "packet-test" not in features.stdout, features.stderr
    # The ICMP cases run the unmodified tun_echo example: real TUN, one Host.
    echo_build = ["cargo", "build", "--locked", "-p", "ntcp", "--example", "tun_echo",
                  "--target-dir", str(BINARY.parents[1])]
    p = subprocess.run(echo_build, cwd=ROOT, env=env, timeout=600)
    assert p.returncode == 0, dict(command=echo_build, exit=p.returncode)
    source = fingerprint()
    commit = command(["git", "rev-parse", "HEAD"]).strip()
    cases = matrix()
    icmp_cases = icmp.cases()
    emit("T5_NETWORK_BUILD", dict(schema_version=1, command=build, commit=commit,
                                  source_sha256=source, binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                                  icmp_command=echo_build, icmp_cases=icmp_cases,
                                  tun_echo_sha256=hashlib.sha256(TUN_ECHO.read_bytes()).hexdigest(),
                                  kernel=os.uname().release, kernel_version=os.uname().version,
                                  rustc=command(["rustc", "--version"]).strip(), packet_test=False,
                                  applicability=dict(partial_syn="Native server 128-byte receive admission, then public SO_RCVBUF growth after prefix read",
                                                     linux_partial="No manufactured Linux partial ACK; Linux listener buffer minimum does not produce the selected small-SYN partial case",
                                                     linux_stale="Actual TCP_FASTOPEN_KEY revocation, not clock-lease expiration",
                                                     later_host_capabilities="No host path service or Neighbor Discovery proxy in T5"), declared_cases=cases))
    completed = 0
    stream_count = 0
    refusal_count = 0
    namespace_ids = []
    icmp_completed = 0
    for case in icmp_cases + cases:
        assert time.monotonic() - started < 1740, "30 minute total gate budget"
        fds = [os.open("/proc/self/ns/" + kind, os.O_RDONLY) for kind in ("net", "user")]
        try:
            child_env = dict(env, T5_PARENT_NET_FD=str(fds[0]), T5_PARENT_USER_FD=str(fds[1]),
                             T5_SOURCE_SHA256=source, T5_BUILD_COMMIT=commit)
            cmd = ["unshare", "--user", "--map-root-user", "--net", sys.executable, str(HERE / "run.py"),
                   "--require-netns", "--in-namespace", json.dumps(case)]
            # One process group owns the namespace, peers and bridge. The outer
            # deadline kills every remaining member, including on SIGINT/TERM.
            p = subprocess.Popen(cmd, cwd=ROOT, env=child_env, pass_fds=fds, start_new_session=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                out, err = p.communicate(timeout=min(100, max(1, 1770 - (time.monotonic() - started))))
                code = p.returncode
            except BaseException:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                raise
            finally:
                # Peer cleanup failure must not leave the namespace alive.
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            assert len(out) <= 4 * 1024 * 1024 and len(err) <= 65536, "child output limit"
            print(out, end="", flush=True)
            if err:
                print(err, end="", file=sys.stderr, flush=True)
            assert code == 0, dict(case=case, command=cmd, exit=code)
            tag = "T9_ICMP_CASE " if case in icmp_cases else "T5_NETWORK_CASE "
            summaries = [json.loads(line.split(" ", 1)[1]) for line in out.splitlines() if line.startswith(tag)]
            assert len(summaries) == 1 and summaries[0]["case"] == case, "missing case summary"
            summary = summaries[0]
            if case in icmp_cases:
                namespace_ids.append(summary["namespace"])
                icmp_completed += 1
                continue
            stream_count += summary["streams"]
            refusal_count += summary["completions"] - summary["streams"]
            namespace_ids.append(summary["namespace"])
            completed += 1
        finally:
            for fd in fds:
                os.close(fd)
    assert completed == len(cases) and stream_count > 0 and refusal_count == 12
    assert icmp_completed == len(icmp_cases) == 8
    emit("T5_NETWORK_SUMMARY", dict(exit=0, cases=completed, streams=stream_count, refusals=refusal_count,
                                    icmp_cases=icmp_completed,
                                    namespaces=namespace_ids, kernel=os.uname().release,
                                    stream_sha256={name: hashlib.sha256(pattern(n, salt)).hexdigest()
                                                   for name, n, salt in (("request", 8192, 7), ("response", 6144, 11),
                                                                         ("second_request", 3072, 19), ("second_response", 1024, 23))},
                                    source_sha256=source, duration_seconds=round(time.monotonic() - started, 3)))


if __name__ == "__main__":
    # Raising on TERM runs the parent's group cleanup path.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError("SIGTERM")))
    try:
        main()
    except Exception as e:
        emit("T5_NETWORK_FAILURE", dict(exit=1, error=str(e), type=type(e).__name__))
        raise
