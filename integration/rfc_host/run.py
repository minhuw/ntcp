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
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

from bridge import Bridge
import admin
import icmp
import mss
import options
from linux_peer import fnv, pattern

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BINARY = ROOT / "workbench/network-target/debug/ntcp-rfc-host"
TUN_ECHO = ROOT / "workbench/network-target/debug/examples/tun_echo"
# Harness-only staged sender for the PTB attribution cases (same build).
STAGED = ROOT / "workbench/network-target/debug/ptb_stage"
# Harness-only datagram driver for the driven Host UDP cases (same build).
DRIVER = ROOT / "workbench/network-target/debug/datagram_drive"
# The real path administration utility (separate process per request).
PATHCTL = ROOT / "workbench/network-target/debug/ntcp-pathctl"
# Harness-only two-TUN driver for the receive-MSS and send-space cases.
TWO_LINK = ROOT / "workbench/network-target/debug/two_link"


# The native runtime's physical receive bound on an AF_PACKET port (no fixed
# adapter limit: the IPv4 datagram maximum) and the reassembly capacity it
# configures from it, both families: its receive MSS derivation inputs.
NATIVE_RECEIVE = 65535
NATIVE_REASSEMBLY = 65535


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
                mtu=1500, native_mtu=native_link["mtu"], static_neighbor="02:00:00:00:00:02", offload="disabled on owned veths")


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
    evidence = icmp.child(case, proof, TUN_ECHO, Peer, command, emit, staged_binary=STAGED, driver_binary=DRIVER)
    emit("T9_ICMP_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                              kernel_version=os.uname().version, evidence=evidence,
                              build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                         commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def options_child(case, proof):
    evidence = options.child(case, proof, dict(native=BINARY, tun_echo=TUN_ECHO), Peer, command, setup)
    emit("T14_OPTIONS_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                                  kernel_version=os.uname().version, evidence=evidence,
                                  build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                             commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def mss_child(case, proof):
    evidence = mss.child(case, proof, TWO_LINK, Peer, command)
    emit("T16_MSS_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                              kernel_version=os.uname().version, evidence=evidence,
                              build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                         commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def admin_child(case, proof):
    run_case = dict(refuse=admin.refuse_child, reenable=admin.reenable_child).get(case["scenario"], admin.child)
    evidence = run_case(case, proof, TUN_ECHO, PATHCTL, Peer, command, emit)
    emit("T12_ADMIN_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                                kernel_version=os.uname().version, evidence=evidence,
                                build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                           commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def native_admin_child(case, proof):
    """ntcp-pathctl against the native runtime (this harness's AfPacket
    embedding, serving control.socket on its owner thread) while it carries
    real TCP exchanges with a Linux listener through its default route (an
    Ethernet next hop, i.e. a Forwarder). A disabled IPv6 route caps native
    output at 1280; a disabled IPv4 route clears DF, leases an Identification
    for every packet and limits packets to 576 octets without an
    administrative value (RFC 1122 3.3.3 EMTU_S); re-enabling restores DF and
    the full size."""
    family = case["family"]
    kernel, native = ("198.18.0.1", "198.18.0.2") if family == 4 else ("fd54:3500::1", "fd54:3500::2")
    settings = setup(family, kernel, native)
    bridge = Bridge()
    peers = []
    directory = tempfile.mkdtemp(prefix="t12-native-control-")
    socket_path = Path(directory) / "control.sock"
    evidence = dict(case=case)
    try:
        os.environ["T12_CONTROL_SOCKET"] = str(socket_path)
        try:
            # The control socket also makes the binary state io.source_quiet
            # = never (harness-created address in a fresh namespace).
            n = Peer([BINARY, "client", native, kernel, "hmac", 65536, 3_600_000_000, 1, 0])
        finally:
            os.environ.pop("T12_CONTROL_SOCKET")
        peers.append(n)
        k = Peer([sys.executable, HERE / "linux_peer.py", "server", kernel, native, 0])
        peers.append(k)
        ctl = admin.Pathctl(PATHCTL, socket_path)

        def exchange(name, during=None):
            start = bridge.configure("none", "native-to-kernel")
            k.send("accept")
            n.send("connect blocking")
            concurrent = during() if during else None
            c, s = n.read(), k.read()
            validate_stream(s, c)
            events, count = bridge.snapshot(start)
            assert count == 0
            out = [e for e in events if e["direction"] == "native-to-kernel"]
            assert out and any(e["payload"] for e in out), name
            return out, concurrent

        def summary(out):
            return dict(packets=len(out), max_ip_length=max(e["ip_length"] for e in out),
                        df=sorted({e["df"] for e in out}, key=str), payload_packets=sum(e["payload"] > 0 for e in out))

        # The runtime (and its control server) starts with the first socket.
        baseline, _ = exchange("baseline")
        assert max(e["ip_length"] for e in baseline) == 1500, summary(baseline)
        assert family == 6 or all(e["df"] for e in baseline), summary(baseline)
        mode, directory_mode = os.stat(socket_path).st_mode, os.stat(directory).st_mode
        assert stat.S_ISSOCK(mode) and stat.S_IMODE(mode) == 0o600 and stat.S_IMODE(directory_mode) == 0o700
        routes = ctl.routes()
        # The runtime's one default route resolves through its Ethernet
        # next hop (a Forwarder): the destination is not on a connected
        # network as far as the Host knows.
        assert len(routes) == 1 and routes[0]["next_hop"].startswith("forwarder:"), routes
        route = routes[0]
        before = ctl.routes()

        # During traffic: a query and a refused stale compare-and-set.
        def during():
            paths = ctl.paths()
            stale = ctl.run("set", "route", route["token"], int(route["generation"]) + 7, "disable", expect=1)
            return paths, stale.stderr.strip()
        _, (paths, stale) = exchange("refused", during)
        assert stale == "status=stale", stale
        assert ctl.routes() == before, "a refused request changed nothing"
        target = next(p for p in paths if p["destination"] == kernel)
        assert target["route"] == route["token"], (target, route)

        disabled = ctl.run("disable", "route", route["token"])
        state = next(r for r in ctl.routes() if r["token"] == route["token"])
        assert state["disabled"] == "1" and int(state["generation"]) > int(route["generation"]), state
        off, _ = exchange("disabled")
        if family == 6:
            assert max(e["ip_length"] for e in off) <= 1280, summary(off)
            ids = None
        else:
            assert not any(e["df"] for e in off), ("DF clear on the disabled route", summary(off))
            ids = [e["ip_id"] for e in off]
            assert all(ids) and len(set(ids)) == len(ids), ("leased Identification", ids[:16])
            assert max(e["ip_length"] for e in off) <= 576, summary(off)
        ctl.run("enable", "route", route["token"])
        on, _ = exchange("re-enabled")
        assert max(e["ip_length"] for e in on) == 1500, summary(on)
        assert family == 6 or all(e["df"] for e in on), summary(on)
        evidence.update(settings=settings, routes=routes, path=target, stale=stale, disabled_route=state,
                        utility=disabled.stdout.strip(), baseline=summary(baseline), disabled=summary(off),
                        leased_ids=len(ids) if ids else None, reenabled=summary(on),
                        control_socket_mode=oct(stat.S_IMODE(mode)), utility_requests=len(ctl.log),
                        allow_list="default (the owner's effective uid)", source_quiet="never",
                        source_quiet_assertion="harness-created address in a fresh namespace: no earlier emission")
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for peer in peers:
            try:
                peer.close()
            except Exception as e:
                errors.append(str(e))
        bridge.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        os.rmdir(directory)
        if errors:
            emit("T12_ADMIN_CLEANUP", dict(case=case, errors=errors))
            if not primary:
                raise RuntimeError(errors)
    emit("T12_ADMIN_CASE", dict(schema_version=1, case=case, namespace=proof, kernel=os.uname().release,
                                kernel_version=os.uname().version, evidence=evidence,
                                build=dict(source_sha256=os.environ.get("T5_SOURCE_SHA256"),
                                           commit=os.environ.get("T5_BUILD_COMMIT")), exit=0))


def child(case):
    proof = namespace_guard()  # Must precede every link/sysctl/neighbor/route mutation.
    if case.get("kind") == "icmp":
        return icmp_child(case, proof)
    if case.get("kind") == "admin":
        return admin_child(case, proof)
    if case.get("kind") == "native-admin":
        return native_admin_child(case, proof)
    if case.get("kind") == "ip-options":
        return options_child(case, proof)
    if case.get("kind") == "mss":
        return mss_child(case, proof)
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
            # The native runtime's offer is its Host's derivation from the
            # queried port MTU, the AF_PACKET receive bound and reassembly.
            native_segment = wire["initial_syn"] if direction == "native-to-kernel" else wire["synack"]
            offer = icmp.receive_mss(family, [(settings["native_mtu"], NATIVE_RECEIVE)], NATIVE_REASSEMBLY)
            assert native_segment["mss"] == offer, (offer, native_segment)
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
    pathctl_build = ["cargo", "build", "--locked", "-p", "ntcp-path-control", "--bin", "ntcp-pathctl",
                     "--target-dir", str(BINARY.parents[1])]
    p = subprocess.run(pathctl_build, cwd=ROOT, env=env, timeout=600)
    assert p.returncode == 0, dict(command=pathctl_build, exit=p.returncode)
    source = fingerprint()
    commit = command(["git", "rev-parse", "HEAD"]).strip()
    cases = matrix()
    icmp_cases = icmp.cases()
    admin_cases = admin.cases()
    option_cases = options.cases()
    mss_cases = mss.cases()
    emit("T5_NETWORK_BUILD", dict(schema_version=1, command=build, commit=commit,
                                  source_sha256=source, binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                                  icmp_command=echo_build, icmp_cases=icmp_cases,
                                  admin_command=pathctl_build, admin_cases=admin_cases, option_cases=option_cases,
                                  mss_cases=mss_cases,
                                  pathctl_sha256=hashlib.sha256(PATHCTL.read_bytes()).hexdigest(),
                                  tun_echo_sha256=hashlib.sha256(TUN_ECHO.read_bytes()).hexdigest(),
                                  ptb_stage_sha256=hashlib.sha256(STAGED.read_bytes()).hexdigest(),
                                  datagram_drive_sha256=hashlib.sha256(DRIVER.read_bytes()).hexdigest(),
                                  two_link_sha256=hashlib.sha256(TWO_LINK.read_bytes()).hexdigest(),
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
    admin_completed = 0
    option_completed = 0
    mss_completed = 0
    for case in icmp_cases + admin_cases + option_cases + mss_cases + cases:
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
            tag = ("T9_ICMP_CASE " if case in icmp_cases else "T12_ADMIN_CASE " if case in admin_cases
                   else "T14_OPTIONS_CASE " if case in option_cases
                   else "T16_MSS_CASE " if case in mss_cases else "T5_NETWORK_CASE ")
            summaries = [json.loads(line.split(" ", 1)[1]) for line in out.splitlines() if line.startswith(tag)]
            assert len(summaries) == 1 and summaries[0]["case"] == case, "missing case summary"
            summary = summaries[0]
            if case in icmp_cases:
                namespace_ids.append(summary["namespace"])
                icmp_completed += 1
                continue
            if case in admin_cases:
                namespace_ids.append(summary["namespace"])
                admin_completed += 1
                continue
            if case in option_cases:
                namespace_ids.append(summary["namespace"])
                option_completed += 1
                continue
            if case in mss_cases:
                namespace_ids.append(summary["namespace"])
                mss_completed += 1
                continue
            stream_count += summary["streams"]
            refusal_count += summary["completions"] - summary["streams"]
            namespace_ids.append(summary["namespace"])
            completed += 1
        finally:
            for fd in fds:
                os.close(fd)
    assert completed == len(cases) and stream_count > 0 and refusal_count == 12
    assert icmp_completed == len(icmp_cases) == 23
    assert admin_completed == len(admin_cases) == 7
    assert option_completed == len(option_cases) == 5
    assert mss_completed == len(mss_cases) == 4
    emit("T5_NETWORK_SUMMARY", dict(exit=0, cases=completed, streams=stream_count, refusals=refusal_count,
                                    icmp_cases=icmp_completed, admin_cases=admin_completed,
                                    option_cases=option_completed, mss_cases=mss_completed,
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
