# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""TCP quiet time at startup through the native runtime (T20).

The native runtime runs on an address this harness created, so it was never
used; the configuration states the weaker true fact io.source_quiet = S with
2*MSL - S short, through the production key. A plain Linux peer holds both
ends of the exchange. The runtime starts with its first socket, whose
nonblocking connect returns EINPROGRESS; the runtime's listener and a Linux
client's SYNs then wait out the deadline.

Required on the wire: no native TCP segment before the deadline (no SYN, no
SYN-ACK, no RST), the native SYN once it passes, and a SYN-ACK to a Linux SYN
retransmitted after it. Both streams complete with their hashes.

The deadline is known to lie between the two provider samples around the
runtime's start, each giving the later of the restart and boot floors. A
frame's capture time follows its emission, by the forwarder's scheduling
delay.
"""
import errno
from pathlib import Path
import select
import sys
import time

from bridge import Bridge

HERE = Path(__file__).resolve().parent
# 2*MSL of the default configuration.
QUIET_US = 240_000_000
# The owner loop's timer wakes after the deadline, by scheduling delay only.
TIMER_SLACK_US = 3_000_000
SOURCE_QUIET = 228
PORT = 18080
ADDRESSES = {4: ("198.18.0.1", "198.18.0.2", 24), 6: ("fd54:3500::1", "fd54:3500::2", 64)}


def cases():
    return [dict(kind="quiet-time", family=family, scenario="startup", source_quiet=SOURCE_QUIET)
            for family in (4, 6)]


def config(family, quiet):
    """The runtime's production configuration. The fixed next hop is the
    Linux port: no Neighbor Discovery shares the quiet interval."""
    _, native, prefix = ADDRESSES[family]
    return (f"io.backend = af-packet\nio.interface = t5n\nio.address = {native}\nio.prefix = {prefix}\n"
            f"io.next_hop_mac = 02:00:00:00:00:01\nio.source_quiet = {quiet}\n")


def deadline_us(sample, quiet):
    """The admission deadline of a lifecycle starting at SAMPLE: the later of
    the restart floor from the stated fact and the host's boot floor."""
    boot = sample["ticks"] - sample["boot_age_us"]
    return max(sample["ticks"] + QUIET_US - quiet * 1_000_000, boot + QUIET_US)


def judge(events, origin_ns, earliest, latest):
    """The capture's verdict. Event times less ORIGIN_NS are transport time;
    EARLIEST and LATEST bound the deadline in transport microseconds."""
    def at(event):
        return (event["time_ns"] - origin_ns) // 1000

    assert all(e["checksum_valid"] for e in events), "capture checksum"
    native = sorted((e for e in events if e["direction"] == "native-to-kernel"), key=at)
    assert native, "no native TCP segment"
    assert at(native[0]) >= earliest, ("native TCP segment before the deadline", native[0], earliest)
    opens = [e for e in native if e["flags"] & 0x12 == 2]
    assert opens and at(opens[0]) <= latest + TIMER_SLACK_US, ("native SYN after the deadline", opens[:1], latest)
    assert not any(e["flags"] & 4 for e in native), "native RST"

    syns = sorted((e for e in events if e["direction"] == "kernel-to-native"
                   and e["flags"] & 0x12 == 2 and e["dport"] == 18080), key=at)
    assert syns, "no Linux SYN"
    client_port = syns[0]["sport"]
    syns = [e for e in syns if e["sport"] == client_port]
    assert len({e["seq"] for e in syns}) == 1, "one Linux connection attempt"
    early = [e for e in syns if at(e) < earliest]
    # Silence across a retransmission, not one SYN that raced the start.
    assert len(early) >= 2, ("quiet time not observed by Linux SYNs", len(early))
    replies = sorted((e for e in native if e["flags"] & 0x12 == 0x12 and e["dport"] == client_port), key=at)
    assert replies, "no SYN-ACK to the Linux client"
    reply = replies[0]
    accepted = [e for e in syns if earliest <= at(e) <= at(reply)]
    assert accepted, ("SYN-ACK without a SYN after the deadline", reply)
    assert reply["ack"] == (syns[0]["seq"] + 1) & 0xffffffff, reply
    return dict(linux_syns_during_quiet=len(early), linux_syn_times_us=[at(e) for e in syns],
                accepted_syn_us=at(accepted[-1]), synack_us=at(reply), first_native_us=at(native[0]),
                native_syn_us=at(opens[0]), first_native_after_earliest_us=at(native[0]) - earliest)


def native_client(n):
    """The request/response exchange linux_peer.py serves."""
    steps = ("send a 8192 7", "recv a 6144 11", "send a 3072 19", "shutdown a", "recv a 1024 23", "eof a", "close a")
    received = []
    for step in steps:
        n.send(step)
        event = n.read()
        if event["event"] == "received":
            received.append(event["hash"])
    return dict(event="stream", eof=True, tx=11264, rx=7168, first_hash=received[0], second_hash=received[1])


def native_server(n):
    """The exchange linux_peer.py's client drives."""
    steps = ("accept b", "recv b 8192 7", "send b 6144 11", "recv b 3072 19", "eof b", "send b 1024 23",
             "shutdown b", "close b")
    received = []
    for step in steps:
        n.send(step)
        event = n.read()
        if event["event"] == "received":
            received.append(event["hash"])
    return dict(event="stream", eof=True, tx=7168, rx=11264, first_hash=received[0], second_hash=received[1])


def transport_origin():
    """Bridge monotonic nanoseconds less CLOCK_BOOTTIME nanoseconds."""
    return time.monotonic_ns() - time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def clock(n):
    n.send("clock")
    return n.read()


def child(case, binary, Peer, setup, validate_stream):
    family, quiet = case["family"], case["source_quiet"]
    kernel, native, _ = ADDRESSES[family]
    settings = setup(family, kernel, native)
    bridge = Bridge()
    peers = []
    try:
        k = Peer([sys.executable, HERE / "linux_peer.py", "server", kernel, native, 0])
        peers.append(k)
        c = Peer([sys.executable, HERE / "linux_peer.py", "client", kernel, native, 0])
        peers.append(c)
        n = Peer([binary, "phased", config(family, quiet)])
        peers.append(n)
        start = bridge.configure("none", "kernel-to-native")
        origin = transport_origin()
        k.send("accept")
        before = clock(n)
        # The first socket starts the runtime, and so its lifecycle.
        n.send(f"start a {kernel} {PORT}")
        started = n.read()
        after = clock(n)
        assert (started["result"], started["errno"]) == (-1, errno.EINPROGRESS), started
        earliest, latest = deadline_us(before, quiet), deadline_us(after, quiet)
        assert earliest - after["ticks"] < 60_000_000, ("deadline beyond the case limit", earliest, after)
        n.send(f"listen {PORT}")
        listening = n.read()
        c.send("connect blocking")
        time.sleep(2)
        n.send("pending a")
        pending = n.read()
        assert not pending["revents"] & select.POLLOUT and pending["so_error"] == 0, pending
        assert clock(n)["ticks"] < earliest, "the pending check belongs to the quiet time"
        n.send("finish a")
        finished = n.read()
        assert finished["so_error"] == 0, finished
        connected = clock(n)
        assert connected["ticks"] >= earliest, ("connect completed before the deadline", connected, earliest)
        native_active = native_client(n)
        linux_server = k.read()
        validate_stream(linux_server, native_active)
        native_passive = native_server(n)
        linux_client = c.read()
        validate_stream(native_passive, linux_client)
        events, _ = bridge.snapshot(start)
        assert abs(transport_origin() - origin) < 1_000_000_000, "a suspend during the case"
        wire = judge(events, origin, earliest, latest)
        frames = [{key: value for key, value in e.items() if key not in ("raw", "egress_raw")} for e in events]
        syn_timeouts = Path("/proc/sys/net/ipv4/tcp_syn_linear_timeouts")
        return dict(settings=settings, source_quiet=quiet, interval_us=QUIET_US, before=before, after=after,
                    deadline_earliest_us=earliest, deadline_latest_us=latest, started=started,
                    listening=listening, pending=pending, finished=finished, connected=connected,
                    wire=wire, frames=frames[:256], frame_count=len(frames),
                    tcp_syn_linear_timeouts=syn_timeouts.read_text().strip() if syn_timeouts.exists() else None,
                    streams=dict(linux_server=linux_server, native_client=native_active,
                                 native_server=native_passive, linux_client=linux_client))
    finally:
        primary = sys.exc_info()[0] is not None
        errors = []
        for peer in peers:
            try:
                peer.close()
            except Exception as e:
                errors.append(str(e))
        bridge.close()
        if errors and not primary:
            raise RuntimeError(errors)
