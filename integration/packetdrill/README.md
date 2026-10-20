# Known exceptions

The 14 selected upstream loss-recovery tests are accounted for: **12 pass**, and **2 fail with the documented differences below**.

### Application-limited slow start

- `slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt`
- `slow_start/slow-start-app-limited-9-packets-out.pkt`

**Accepted window-growth mismatch: 12 MSS expected at the first data ACK, 10 MSS observed.**

Both start with a 10-MSS window and send only 6 or 9 MSS. Linux's slow-start heuristic allows growth toward twice the actual flight peak: 12 or 18 MSS. ntcp follows [RFC 9438 §5.8](https://www.rfc-editor.org/rfc/rfc9438.html#section-5.8), keeping the window at 10 MSS while application-limited.

### `cubic/cubic-rto-ss-ca-cwnd-bump.pkt`

**Accepted TLP timing mismatch: 300–303 ms expected, ~250 ms observed.**

After two 100-ms RTT samples, [RFC 6298 §2.3](https://www.rfc-editor.org/rfc/rfc6298.html#section-2) gives ntcp `RTTVAR = 37.5 ms` and `RTO = 100 + 4 × 37.5 = 250 ms`. Linux retains a 200-ms variation allowance, yielding a 300-ms RTO. [RFC 8985 §7.2](https://www.rfc-editor.org/rfc/rfc8985.html#section-7.2) caps each stack's TLP deadline at its RTO, producing the observed difference.

A diagnostic run with adjusted timing subsequently reaches the 200,000-byte write, which exceeds the current 65,535-byte packet-backend I/O limit. That interface limit remains separate from this accepted timing difference.

### `fastopen/client/nonblocking-sendto-over-mss.pkt`

**Accepted Nagle timing mismatch: the 660-byte tail arrives ~20 ms later than expected.**

ntcp implements original Nagle, not Minshall's variant. When Nagle is enabled, a short segment waits while any previously sent data remains unacknowledged. After two full-sized segments, this test's 660-byte tail is held until TLP releases it roughly 20 ms later. Tracing confirmed Nagle as the blocking condition and TLP firing on time.

Linux uses Minshall's variant, which holds a short segment only when a previously sent **short** segment remains unacknowledged. Outstanding full-sized segments therefore do not block this tail. [RFC 9293 §3.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7.4) describes original Nagle; [Appendix A.3](https://www.rfc-editor.org/rfc/rfc9293.html#appendix-A.3) discusses Minshall's modification without incorporating it into the standard algorithm.

This exception covers only the observed short-tail timing difference, not initial SYN allocation delays or other failures in this script.

### `inq/client.pkt`

**Accepted timeout: the script waits for an ACK to data missing negotiated timestamps.**

Linux accepts these packets, accommodating devices that strip TCP options. ntcp follows [RFC 7323 §3.2](https://www.rfc-editor.org/rfc/rfc7323.html#section-3.2): senders MUST include timestamps after negotiation; receivers SHOULD silently drop packets that omit them, preserving PAWS protection against old duplicates. Adding timestamps to the incoming data and FIN in a diagnostic copy passes all unchanged INQ/EOF assertions.

### `ts_recent/invalid_ack.pkt`

**Accepted extra ACK: ntcp replies to an ACK beyond `SND.NXT`.**

[RFC 9293 §3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4) requires replying with ACK and discarding the segment, preserving the rule from RFC 793. ntcp follows this rule; Linux v6.12's established-state path silently discards it, matching the script's expectation.

[Linux's patch discussion](https://lists.openwall.net/netdev/2022/03/19/74) identifies ACK-loop DoS and side-channel risks and recommends rate-limiting replies. ntcp currently sends this reply through its immediate-ACK path.

### `fast_recovery/prr-ss-ack-below-snd_una-cubic.pkt`

**Accepted recovery mismatch: 3 MSS expected, 2 MSS sent.**

At ACK4001, [RFC 8985 §6.2](https://www.rfc-editor.org/rfc/rfc8985.html#section-6.2) processes newly acknowledged packets in transmission-time order, leaving a **12 ms** RACK RTT. Linux 6.12.19 processes them in sequence order, leaving **22 ms**, as verified by runtime tracing.

With a 2.5 ms reordering allowance, the tail packet sent at 10 ms expires at **24.5 ms in ntcp**, versus **34.5 ms in Linux**. The ACK arrives at 32 ms: ntcp detects fresh loss; Linux keeps waiting. Under [RFC 9937 §6.2](https://www.rfc-editor.org/rfc/rfc9937.html#section-6.2), fresh loss suppresses PRR's extra SafeACK MSS, yielding **2 MSS versus 3 MSS**. ntcp retains the RFC processing order.

The first mismatch occurs before the script sends the reordered ACK below `SND.UNA`. A separate deterministic continuation confirms that `ACK=3001` with SACK `5001:7001` contributes 2000 newly delivered bytes without moving `SND.UNA` or the send window backward; repeating it adds no delivery. Its two-MSS allowance repairs `7001:8001` and the RACK-lost tail `9001:10001`, rather than sending the new data expected by the script. The original prefix's retransmission about 200 ms later is an RTO after no further ACK feedback, not evidence that the old ACK was discarded.

Keep failures matching this cause out of actionable regression lists; retain raw failure counts. Reopen this case only for a different cause, such as lost SACK information or incorrect delivery accounting, rather than changing RACK order or granting an unconditional SafeACK bonus to match the script.

### `cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt`

**Accepted historical PRR mismatch: 4 MSS expected on ECN CWR entry, 5 MSS observed.**

The connection starts with a 10-MSS congestion window and sends four 1000-byte segments. The first ECE ACK acknowledges one MSS, leaving three MSS in flight. CUBIC's reduced target is seven MSS. Under [RFC 9937 §6.2](https://www.rfc-editor.org/rfc/rfc9937.html#section-6.2), this ACK satisfies SafeACK: the cumulative ACK advances and no new loss is indicated. ECE signals congestion, but does not by itself indicate a new packet loss. PRR therefore grants `min(7 - 3, max(1 - 0, 1) + 1) = 2 MSS`, giving a temporary admission window of `3 + 2 = 5 MSS`. This remains below the original window and the fixed seven-MSS target; it is not ordinary congestion-avoidance growth. [RFC 9937 §§4–5](https://www.rfc-editor.org/rfc/rfc9937.html#section-4) describe PRR's use for ECN window reductions.

[Linux v4.9's PRR implementation](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/tcp_input.c#L2526-L2552) grants the extra MSS only when an ACK acknowledges retransmitted data. This ACK acknowledges original data, so that historical formula grants one MSS and yields the script's four-MSS window. [Linux v6.12's implementation](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/ipv4/tcp_input.c#L2704-L2729) instead tests cumulative ACK advancement and absence of newly lost packets, predicting the same five-MSS result as ntcp; this comparison is based on source analysis.

Keep the original assertion and raw failure count. Exclude failures matching this historical SafeACK difference from actionable regression lists; investigate different causes, including incorrect ECN reduction targets, delivery accounting, or repeated reductions within one congestion-response window.

### `fast_retransmit/fr-4pkt-fack-last-mss.pkt`

**Accepted timing mismatch: 40 ms expected, ~25 ms observed.**

- **ntcp:** RFC 8985's initial reordering window is `min_RTT / 4`, giving `100 ms / 4 = 25 ms` after SACK.
- **Linux:** The script was validated on Linux 6.1, which adds two clock ticks of padding to its RACK timer. A tick is one kernel clock interval. At 250 Hz, that padding adds **8 ms**; tick rounding and timer-wheel alignment bring the total to **~36–40 ms**. The padding accounts for most of the extra delay in this example.

### Fast Open PMTU: independent receive MSS

- `fastopen/client/syn-data-icmp-unreach-frag-needed.pkt`
- `fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq.pkt`

**Accepted receive-advertisement mismatch: the retransmitted SYN advertises MSS 1460 rather than 760 or 800.**

An ICMP fragmentation-needed message describes the path from ntcp to its peer. ntcp lowers its sending limit and immediately falls back from SYN-data to a plain SYN, while keeping its receive MSS independent. This feedback does not establish a PMTU for the reverse path or reduce ntcp's receive capacity.

| Case | Reported outbound MTU | Script's retransmitted-SYN MSS | ntcp's retransmitted-SYN MSS | ntcp's subsequent 1000-byte repair |
|---|---:|---:|---:|---|
| Without explicit quoted sequence | 800 | 760 | 1460 | 760 + 240 bytes |
| With explicit quoted sequence | 840 | 800 | 1460 | 800 + 200 bytes |

[RFC 1191 §6.4](https://www.rfc-editor.org/rfc/rfc1191#section-6.4) states: "PMTU Discovery does not affect the value sent in the TCP MSS option, because that value is used by the other end of the connection, which may be using an unrelated PMTU value." ntcp retains this directional separation. Its actual output still obeys the smaller of the peer's MSS and the outbound IP allowance, as required by [RFC 9293 §3.7.1](https://www.rfc-editor.org/rfc/rfc9293#section-3.7.1).

Linux 6.12.19 was observed to advertise 760/800 in these traces. Its `tcp_advertise_mss()` consults the route's advertised-MSS metric; when that metric is unset, `ipv4_default_advmss()` derives it from the updated route PMTU. ntcp deliberately keeps its receive advertisement separate. This is a retained policy choice, not a requirement to emulate Linux's route-metric coupling.

Diagnostic copies changing only the retransmitted-SYN MSS expectation to 1460 complete both scripts with their original TCP_INFO option, packet, syscall and timing assertions. Separate counter checks verify delivery counts of 1 after the SYN ACK, 3 after both repair segments are acknowledged, and 4 after the FIN ACK, matching the Linux runtime trace.

Keep both original scripts in `upstream`, with unchanged assertions and raw failure counts. Exclude failures matching only this receive-MSS advertisement difference from actionable lists. Reopen for a different cause, including oversized output, acceptance of invalid ICMP feedback, missing SYN fallback, or incorrect TCP_INFO flags or delivery accounting.

## Buffer-accounting expectations

ntcp accounts send-buffer capacity in payload bytes. Linux accounts queued
`sk_buff` memory, including metadata, and may fill an already allocated buffer
past its allocation threshold. A Linux-specific partial-write length is therefore
not a TCP requirement. We preserve ntcp's own storage model and test it with
explicit, reviewed expectations.

The suites have disjoint ownership:

```text
--suite upstream --variant ipv4  # 103 cases; ported originals excluded
--suite ntcp-ported              # 2 reviewed IPv4 ports
```

Both use the same common `upstream` transport profile. The two source-derived
fixtures belong only to `ntcp-ported`; they are excluded from upstream pass,
failure, unsupported and executed-total counts. `ported_exclusions` and
`excluded_cases` retain their source identities and exclusion reasons. Explicit
`--script` filtering cannot override suite ownership. A selection containing only
ported sources executes no upstream cases and is not reported as a passing suite.

The pinned checkout and setup-only adaptation remain unchanged.
[expectations.json](expectations.json) records the original source hash,
setup-adapted input hash, ported fixture hash, semantic changes and invariants.
The closed port registry must match that manifest. A port with a stale hash or
failing assertion remains owned by `ntcp-ported`; it does not fall back into
upstream execution. Its failure is reported in the ported suite.

Reports identify the suite and per-case `expectation_kind`. Ported fixtures remain
marked `ntcp-accounting` with `assertions_preserved: false`, retaining their source
provenance without claiming unchanged upstream assertions. The former
`--expectations` switch is removed: run `ntcp-ported` to test these ports.
`upstream-raw` remains the full pinned source inventory for inspection, separate
from the selected upstream suite's counts.

### Cases owned by ntcp-ported

| Case | Linux-specific assumption | ntcp expectation and retained purpose |
|---|---|---|
| `timestamping/partial.pkt` | `SO_SNDBUF=1000` permits exactly 2964 payload bytes under Linux's object accounting. | The native capacity is `max(2*1000, 4608) = 4608`; a 10000-byte nonblocking write still returns a partial prefix. The last-byte timestamp ID is 4607 for all three phases. |
| `tcp_info/tcp-info-sndbuf-limited.pkt` | The 150000-byte write and ACKs through 30001, 70001 and 95001 assume Linux's batching, growth and memory budget. | A 60000-byte blocking write uses the 20000-byte payload buffer. ACKs follow actual transmitted frontiers, and a real 20 ms buffer-starvation interval is still required. |

The [partial-write fixture](ntcp-expectations/timestamping/partial.pkt) advertises
an initial peer window of `2 * 988 = 1976` bytes. Keeping it segment-aligned avoids
coupling a timestamp test to Linux's intermediate PUSH policy. It checks the first
two segments, the remaining 2632-byte aggregate, and final ACK 4609. Full-buffer
finalization releases the remaining data after the 20 ms ACK, so the original
SCHED/SND time of 20 ms, ACK time of 30 ms, and RTT bounds remain. The timestamp
ID changes from 2963 to 4607 because it must identify the last accepted byte.

The [buffer-limited fixture](ntcp-expectations/tcp_info/tcp-info-sndbuf-limited.pkt)
uses ntcp's unpaced window growth of 10 to 18 to 26 MSS. Its cumulative ACKs are
10001 at 110 ms, 28001 at 120 ms, 48001 at 140 ms, and 60001 at 170 ms; they never
acknowledge unsent data. Between 120 and 140 ms, the writer is blocked, the full
20000-byte buffer has been transmitted, and the congestion window permits more.
The 140 ms ACK admits the final 12000 bytes and ends that limitation.

The deterministic
[adapter replay](../../crates/adapters/ntcp-socket/src/runtime_accounting_expectations_tests.rs)
asserts exactly 20000 microseconds of buffer limitation, 50000/70000 microseconds
of busy time, and zero receive-window limitation. The realtime fixture uses
16000–24000 microseconds for the positive buffer-limited interval, matching the
existing 4000-microsecond packet-event tolerance around 20 ms and allowing the
asynchronous owner to copy and submit data. Busy-time bounds remain
49000–52000 and 69000–73000 microseconds; receive-window-limited time remains zero.
A zero counter in this valid trace is a failure, not an accepted difference.

Failures of the original two scripts caused by these accounting assumptions are
compatibility differences. Reopen them for a different cause, such as an incorrect
last-byte ID, missing timestamp phase, invalid ACK acceptance, or missing positive
buffer-limited accounting. Do not change transport counters or memory costs to
match a Linux object layout.

### Inventory of selected buffer-dependent cases

The 105 audited source entries now have 103 upstream and 2 ported owners. The
inventory in [expectations.json](expectations.json) covers all 22 entries containing `SO_SNDBUF`, `TCP_NOTSENT_LOWAT`, `tcp_notsent_lowat`, or
`tcpi_sndbuf_limited`. The audit checks both membership and original source hashes.

| Disposition | Cases |
|---|---|
| Owned by `ntcp-ported`; excluded from `upstream` | `timestamping/partial.pkt`; `tcp_info/tcp-info-sndbuf-limited.pkt` |
| Original expectations retained; passing | `notsent_lowat/notsent-lowat-setsockopt.pkt`; `notsent_lowat/notsent-lowat-sysctl.pkt`; `slow_start/slow-start-app-limited.pkt` |
| Original expectations retained; accepted for a different cause above | `cubic/cubic-rto-ss-ca-cwnd-bump.pkt` (TLP timing); `slow_start/slow-start-app-limited-9-packets-out.pkt` (application-limited growth) |
| Unsupported setup/backend; unchanged | `blocking/blocking-write.pkt`; `cubic/cubic-bulk-166k-idle-restart.pkt`; `cubic/cubic-bulk-166k.pkt`; `cubic/cubic-hystart-delay-min-rtt-jumps-downward.pkt`; `cubic/cubic-hystart-delay-rtt-jumps-upward.pkt` |
| Unsupported setup/backend; unchanged | `slow_start/slow-start-ack-per-1pkt.pkt`; `slow_start/slow-start-ack-per-2pkt.pkt`; `slow_start/slow-start-ack-per-4pkt.pkt`; `slow_start/slow-start-after-idle.pkt`; `slow_start/slow-start-after-win-update.pkt`; `slow_start/slow-start-fq-ack-per-2pkt.pkt` |
| Unsupported setup/backend; unchanged | `epoll/epoll_out_edge.pkt`; `epoll/epoll_out_edge_default_notsent_lowat.pkt`; `epoll/epoll_out_edge_notsent_lowat.pkt`; `notsent_lowat/notsent-lowat-default.pkt` |

Mentioning a buffer option does not by itself justify an adjustment or a waiver.
The 15 unsupported cases stay unsupported, and the existing congestion-control
and retransmission-timing differences retain their separate explanations.
