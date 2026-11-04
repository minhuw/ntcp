# SPDX-License-Identifier: MIT AND GPL-2.0-or-later
"""Two-link receive MSS and send-space cases (T16).

The ICMP topology (icmp.setup: router namespace, Linux peer namespace, a
1280-octet egress veth toward the peer) with its TUN lowered to SMALL_MTU
and a second, larger TUN in the router. The harness-only two_link driver
opens both after namespace_guard, registers both in one Host with their
queried MTUs and its receive buffers, configures reassembly and routes only
through the smaller link. Every handshake is captured on the smaller TUN.

receive-offer: the passive SYN-ACK offers the derivation from the larger
link (not the smaller link the route uses, nor the driver's send ceiling);
the echo's full-sized segments draw real router PTBs for the 1280 egress and
the driver's Host lowers the send PMTU; the SYNs of later active connections
offer the same MSS while their send MSS and data follow the learned PMTU.

send-space: the egress is 1500, so the path stays at the smaller link and the
segment size Q is fixed. The send buffer B is a non-multiple of Q whose
rounded ceiling C = floor(B/Q)*Q is below the peer window and the initial
congestion window; the stream is larger than B. The distinct unacknowledged
payload bytes on the wire reach C before the first acknowledgment of data
and never exceed it; the Linux receiver gets every byte (length and hash).
"""
import json
import sys

import icmp
from icmp import ADDRESSES, Capture, public
from linux_peer import fnv, pattern

LARGE_TUN = "t16big"
SMALL_MTU = 1400
LARGE_MTU = 9000
# The driver's per-link receive buffers and its reassembly capacity.
DRIVER_RECEIVE = 65575
DRIVER_REASSEMBLY = {4: 65535, 6: 65575}
LARGE_ADDRESS = {4: ("198.18.4.1", "24"), 6: ("2001:db8:94::1", "64")}
ECHO_BYTES = 4096
TRANSFER = 20000
STREAM = 40000
# send-space: the peer's ACKs to ntcp are delayed by netem on its ingress veth.
ACK_DELAY_MS = 50
SCENARIOS = ("receive-offer", "send-space")


def cases():
    return [dict(kind="mss", family=family, scenario=scenario) for family in (4, 6) for scenario in SCENARIOS]


def send_space(capacity, quantum):
    """RFC 1191 section 6.4 rounding with the sub-segment disposition."""
    return capacity if capacity < quantum else capacity // quantum * quantum


def handshake(events, sport=None, dport=None):
    """The SYN and SYN-ACK of one connection, oldest first, as captured."""
    syns = [e for e in events if e.get("protocol") == 6 and e["flags"] & 0x12 == 2
            and (sport is None or e["sport"] == sport) and (dport is None or e["dport"] == dport)]
    assert syns, "no SYN captured"
    syn = syns[0]
    replies = [e for e in events if e.get("protocol") == 6 and e["flags"] & 0x12 == 0x12
               and (e["sport"], e["dport"]) == (syn["dport"], syn["sport"])]
    assert replies, ("no SYN-ACK captured", public(syn))
    return syn, replies[0]


def options(segment):
    return {k: segment[k] for k in ("mss", "window_scale", "sack_permitted", "timestamp", "window")}


def outstanding(events, ports, base):
    """Distinct unacknowledged payload bytes after every captured event of
    one flow (ntcp ports[0] -> peer ports[1]), in capture order: payload
    bytes sent at least once and above the highest cumulative ACK seen.
    Retransmissions add no new bytes; SYN and FIN occupy no payload. Returns
    (per-event counts, index of the first ACK that acknowledges data)."""
    sent, acked, counts, first_advance = set(), 0, [], None
    for e in events:
        if e.get("protocol") != 6:
            continue
        if e["direction"] == "from-ntcp" and (e["sport"], e["dport"]) == ports and e["payload"]:
            start = (e["seq"] - base) & 0xffffffff
            sent.update(range(start, start + e["payload"]))
        elif e["direction"] == "to-ntcp" and (e["sport"], e["dport"]) == ports[::-1] and e["flags"] & 0x10:
            ack = (e["ack"] - base) & 0xffffffff
            if ack < 1 << 31 and ack > acked:
                if first_advance is None:
                    first_advance = len(counts)
                acked = ack
        else:
            continue
        counts.append(sum(1 for b in sent if b >= acked))
    return counts, first_advance


def setup(family, scenario, command, peer_pid):
    settings = icmp.setup(family, 1280 if scenario == "receive-offer" else 1500, command, peer_pid)
    address, prefix = LARGE_ADDRESS[family]
    nodad = [] if family == 4 else ["nodad"]
    command(["ip", "link", "set", icmp.TUN, "mtu", str(SMALL_MTU)])
    command(["ip", "tuntap", "add", "dev", LARGE_TUN, "mode", "tun"])
    command(["ip", "link", "set", LARGE_TUN, "mtu", str(LARGE_MTU)])
    command(["ethtool", "-K", LARGE_TUN, "tx", "off", "rx", "off", "tso", "off", "gso", "off", "gro", "off"])
    command(["ip", "addr", "add", address + "/" + prefix, "dev", LARGE_TUN, *nodad])
    command(["ip", "link", "set", LARGE_TUN, "up"])
    links = {link["ifname"]: link["mtu"] for link in json.loads(command(["ip", "-j", "link", "show"]))}
    assert (links[icmp.TUN], links[LARGE_TUN]) == (SMALL_MTU, LARGE_MTU), links
    settings.update(tun_mtu=dict(small=links[icmp.TUN], large=links[LARGE_TUN]))
    return settings


def child(case, proof, binary, Peer, command):
    family, scenario = case["family"], case["scenario"]
    a = ADDRESSES[family]
    hl = icmp.header_len(family)
    peer = Peer(["unshare", "--net", sys.executable, "-B", icmp.HERE / "icmp_peer.py", a["peer"], a["ntcp"], icmp.PORT])
    driver = capture = large = None
    evidence = dict(case=case)

    def remote(port):
        return f"[{a['peer']}]:{port}" if family == 6 else f"{a['peer']}:{port}"

    def call(process, line, event):
        process.send(line)
        result = process.read()
        assert result["event"] == event, result
        return result

    try:
        assert peer.ready["namespace"] not in (proof["net"]["parent"], proof["net"]["current"]), peer.ready
        settings = setup(family, scenario, command, peer.p.pid)
        capture, large = Capture(icmp.TUN), Capture(LARGE_TUN)
        driver = Peer([binary, icmp.TUN, LARGE_TUN, a["ntcp"]])
        ready = driver.ready
        links = [(link["mtu"], link["max_ip_packet"]) for link in ready["links"]]
        assert links == [(SMALL_MTU, DRIVER_RECEIVE), (LARGE_MTU, DRIVER_RECEIVE)], ready
        assert ready["emtu_r"] == DRIVER_REASSEMBLY[family] > LARGE_MTU, ready
        derived = icmp.receive_mss(family, links, ready["emtu_r"])
        # The larger link sets the offer; the route's link, the send ceiling
        # and the reassembly capacity are all different values.
        assert ready["receive_mss"] == derived == LARGE_MTU - hl - 20, (derived, ready)
        assert ready["config_mss"] == SMALL_MTU - hl - 20 < derived, ready
        evidence.update(settings=settings, driver=ready, derived_mss=derived)

        def ntcp_tcp(events):
            items = [e for e in events if e["direction"] == "from-ntcp" and e.get("protocol") == 6]
            for e in items:
                assert not e["fragmented"] and e["checksum_valid"] and e["ip_checksum_valid"], public(e)
                assert family == 6 or e["df"], ("IPv4 DF is required", public(e))
            return items

        if scenario == "receive-offer":
            # Passive: the Linux client's SYN, the driver's SYN-ACK.
            call(driver, f"listen {icmp.PORT}", "listening")
            mark = capture.mark()
            driver.send("accept")
            echoed = call(peer, f"tcp {ECHO_BYTES} 61", "tcp")
            assert (echoed["rx"], echoed["hash"]) == (ECHO_BYTES, fnv(pattern(ECHO_BYTES, 61))), echoed
            accepted = driver.read()
            assert accepted["event"] == "accepted" and accepted["echoed"] == ECHO_BYTES, accepted
            syn, synack = handshake(capture.since(mark), dport=icmp.PORT)
            assert synack["direction"] == "from-ntcp" and synack["mss"] == derived, public(synack)
            assert synack["window_scale"] is not None and synack["timestamp"] is not None, public(synack)
            assert synack["timestamp"][1] == syn["timestamp"][0] and synack["sack_permitted"], public(synack)
            assert accepted["info"]["advertised_mss"] == derived and accepted["info"]["window_scaling"], accepted
            assert accepted["info"]["receive_window_scale"] == synack["window_scale"], accepted
            passive = dict(syn=options(syn), synack=options(synack), info=accepted["info"])

            # The echo's full-sized segments for the smaller link exceed the
            # 1280 egress: real router PTBs lower the driver's send PMTU.
            wire = capture.since(0)
            ptbs = [e for e in wire if e["direction"] == "to-ntcp" and e.get("ptb")]
            assert ptbs and all(p["mtu"] == 1280 and p["source"] == a["router"] and p["checksum_valid"] for p in ptbs), (
                [public(p) for p in ptbs])
            full = [e for e in ntcp_tcp(wire) if e["payload"] and e["length"] == SMALL_MTU]
            assert full and all(any(icmp.quotes(p["quote"], o["raw"]) for o in full) for p in ptbs), "PTB quotes"

            # Active, after the learned decrease: the SYN still offers the
            # derivation; the send MSS and data follow the learned 1280.
            call(peer, "listen 18082", "listening")
            mark = capture.mark()
            opened = call(driver, f"connect {remote(18082)}", "established")
            filled = call(driver, f"fill 65536 {TRANSFER} 62", "filled")
            call(driver, "close", "closed")
            collected = call(peer, f"collect {TRANSFER}", "collect")
            assert (collected["rx"], collected["hash"]) == (TRANSFER, fnv(pattern(TRANSFER, 62))), collected
            events = capture.since(mark)
            syn, synack = handshake(events, sport=opened["local_port"])
            assert syn["direction"] == "from-ntcp" and syn["mss"] == derived, public(syn)
            assert syn["window_scale"] is not None and syn["timestamp"] is not None and syn["sack_permitted"], public(syn)
            assert synack["timestamp"][1] == syn["timestamp"][0], public(synack)
            assert opened["info"]["send_window_scale"] == synack["window_scale"], opened
            assert opened["info"]["mss"] == 1280 - hl - 20 - 12, ("send MSS after the learned PMTU", opened)
            data = [e for e in ntcp_tcp(events) if e["payload"]]
            assert data and max(e["length"] for e in data) == 1280, [public(e) for e in data[:4]]
            # An established connection never sends another MSS option.
            assert all(e["mss"] is None for e in ntcp_tcp(wire + events) if not e["flags"] & 2)
            active = dict(syn=options(syn), synack=options(synack), info=opened["info"],
                          ptb=[dict(mtu=p["mtu"], ptb_hex=p["raw"][:96].hex()) for p in ptbs],
                          full_sized_before_ptb=len(full), largest_ip=max(e["length"] for e in data),
                          transfer=collected, fill=filled)

            # A new connection after the learned decrease: the same offer,
            # while its send MSS follows the learned 1280 PMTU.
            call(peer, "listen 18083", "listening")
            mark = capture.mark()
            later = call(driver, f"connect {remote(18083)}", "established")
            call(driver, "close", "closed")
            empty = call(peer, "collect 0", "collect")
            assert empty["rx"] == 0, empty
            syn, synack = handshake(capture.since(mark), sport=later["local_port"])
            assert syn["direction"] == "from-ntcp" and syn["mss"] == derived, public(syn)
            assert later["info"]["advertised_mss"] == derived, later
            assert later["info"]["mss"] == 1280 - hl - 20 - 12, ("send MSS after the learned PMTU", later)
            after = dict(syn=options(syn), synack=options(synack), info=later["info"])
            evidence.update(passive=passive, active=active, after_ptb=after)
        else:
            call(peer, "listen 18082", "listening")
            mark = capture.mark()
            opened = call(driver, f"connect {remote(18082)}", "established")
            # Delay the peer's ACK path only (t9pa), so the first output pass
            # is on the wire before any acknowledgment of its data can be.
            peer_ns = ["nsenter", "-t", str(peer.p.pid), "-n"]
            command([*peer_ns, "tc", "qdisc", "add", "dev", "t9pa", "root", "netem", "delay", f"{ACK_DELAY_MS}ms"])
            netem = [q for q in json.loads(command([*peer_ns, "tc", "-j", "qdisc", "show", "dev", "t9pa"]))
                     if q["kind"] == "netem"]
            assert len(netem) == 1, netem
            info = opened["info"]
            quantum = info["mss"]
            assert info["timestamps"] and quantum == SMALL_MTU - hl - 20 - 12, info
            capacity = 2 * quantum + quantum // 2
            ceiling = send_space(capacity, quantum)
            assert capacity % quantum and ceiling == 2 * quantum, (capacity, quantum)
            assert ceiling < info["cwnd"] and ceiling < info["max_send_window"], (ceiling, info)
            filled = call(driver, f"fill {capacity} {STREAM} 63", "filled")
            assert filled["resized"]["send_capacity"] == capacity, filled
            assert filled["resized"]["send_space"] == ceiling, filled
            assert filled["first_admitted"] == ceiling and filled["largest_send_used"] <= ceiling, filled
            assert filled["after_first_pass"]["send_used"] == ceiling, filled
            assert filled["after"]["send_capacity"] == capacity, filled
            call(driver, "close", "closed")
            collected = call(peer, f"collect {STREAM}", "collect")
            assert (collected["rx"], collected["hash"]) == (STREAM, fnv(pattern(STREAM, 63))), collected
            events = capture.since(mark)
            syn, synack = handshake(events, sport=opened["local_port"])
            assert syn["mss"] == derived, public(syn)
            ports = (opened["local_port"], 18082)
            counts, first_advance = outstanding(events, ports, (syn["seq"] + 1) & 0xffffffff)
            assert first_advance is not None and max(counts) == ceiling, (max(counts), ceiling)
            assert max(counts[:first_advance]) == ceiling, ("C reached before ACK advancement", counts[:first_advance])
            data = [e for e in ntcp_tcp(events) if e["payload"]]
            assert sum(e["payload"] for e in data) >= STREAM and max(e["length"] for e in data) <= SMALL_MTU
            # The peer's offered window stayed above C throughout.
            windows = [e["window"] << (synack["window_scale"] or 0) for e in events if e["direction"] == "to-ntcp"
                       and e.get("protocol") == 6 and (e["sport"], e["dport"]) == ports[::-1] and not e["flags"] & 2]
            assert windows and min(windows) > ceiling, (min(windows), ceiling)
            evidence.update(netem=netem[0], syn=options(syn), synack=options(synack), established=info, quantum=quantum,
                            capacity=capacity, ceiling=ceiling, literal_multiple=capacity // (SMALL_MTU - 40) * (SMALL_MTU - 40),
                            fill=filled, distinct_outstanding_max=max(counts),
                            before_first_ack=max(counts[:first_advance]), data_packets=len(data),
                            smallest_peer_window=min(windows), transfer=collected)
        # Nothing of ntcp's TCP left through the larger link.
        assert not [e for e in large.since(0) if e["direction"] == "from-ntcp" and e.get("protocol") == 6]
        evidence.update(large_link_frames=len(large.since(0)))
    finally:
        primary = sys.exc_info()[0] is not None
        if primary and capture:
            # The captured wire of a failing case, for diagnosis.
            trace = [{k: v for k, v in public(e).items() if k not in ("data",)} for e in capture.events[:60]]
            print(json.dumps(dict(case=case, trace=trace), default=str), file=sys.stderr)
        errors = []
        for close in (driver and driver.close, peer.close, capture and capture.close, large and large.close):
            if close:
                try:
                    close()
                except Exception as e:
                    errors.append(f"{type(e).__name__}: {e}")
        if errors:
            evidence.update(cleanup_errors=errors)
            print(json.dumps(dict(case=case, cleanup_errors=errors)), file=sys.stderr)
            if not primary:
                raise RuntimeError(errors)
    return evidence
