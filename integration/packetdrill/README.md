# Packetdrill compatibility

The packetdrill runner tests ntcp through its socket plugin. Upstream scripts use
one common `upstream` configuration, with explicit options for script-specific
setup. Linux setup commands are translated through
[adaptations.json](adaptations.json); they are not executed on the host.

## Suites

| Suite | Purpose |
|---|---|
| `upstream` | Pinned upstream scripts with audited setup adaptations and original assertions. |
| `ntcp-ported` | Source-derived tests with expectations adapted to ntcp's buffer accounting. |
| `upstream-raw` | Full pinned upstream inventory without setup adaptations. |
| `smoke`, `sack` | Native ntcp fixtures. |

Use `--suite upstream --variant ipv4` for the adapted upstream tests. A script
owned by `ntcp-ported` is excluded from `upstream`, including explicit `--script`
selection. [expectations.json](expectations.json) records the ported fixtures,
source hashes, and changed expectations.

## Known exceptions

Upstream scripts encode Linux implementation choices as well as TCP requirements.
The following differences reflect transport policies retained by ntcp.

### Application-limited slow start

ntcp does not grow CUBIC's window for an application-limited flight, following
[RFC 9438 §5.8](https://www.rfc-editor.org/rfc/rfc9438#section-5.8). Linux's
slow-start heuristic can grow the window toward twice the peak flight size.

Scripts: `slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt`,
`slow_start/slow-start-app-limited-9-packets-out.pkt`.

### Slow-start growth under reordering

ntcp grows the window on cumulative ACK progress and discounts previously SACKed
bytes from that growth. SACK information still contributes to delivery accounting
and loss recovery. This is a conservative policy permitted by
[RFC 5681 §3](https://www.rfc-editor.org/rfc/rfc5681#section-3), used with
[HyStart++ byte-counted growth](https://www.rfc-editor.org/rfc/rfc9406#section-4.2).

Linux can also grow the window on new SACK information when its measured
reordering degree exceeds the default threshold. Its
[maintainer's explanation](https://mailarchive.ietf.org/arch/msg/tcpm/cFjRyYXAqNx05249r02UWi9Uf_E/)
describes this as a deliberate extension to the classic growth rules. For a
10-MSS flight with two segments already SACKed, ntcp adds eight MSS on the final
cumulative ACK; Linux's high-reordering path can add one MSS earlier, yielding
18 versus 19 MSS. RFC 9406 does not explicitly specify this SACK-only growth
exception.

Script: `cubic/cubic-rack-reo-timeout-retrans-failed-incoming-data.pkt`.

### RTO and tail-loss probe timing

ntcp calculates RTO using [RFC 6298 §2.3](https://www.rfc-editor.org/rfc/rfc6298#section-2)
and caps the tail-loss probe deadline at RTO, as specified by
[RFC 8985 §7.2](https://www.rfc-editor.org/rfc/rfc8985#section-7.2). Differences
from Linux's RTT-variation estimator can therefore change probe timing.

Script: `cubic/cubic-rto-ss-ca-cwnd-bump.pkt`.

### Nagle policy

ntcp uses original Nagle: a short segment waits while previously sent data is
unacknowledged. Linux uses Minshall's variant, which allows the short segment
when only full-sized segments remain outstanding.
[RFC 9293 §3.7.4](https://www.rfc-editor.org/rfc/rfc9293#section-3.7.4) specifies
original Nagle; [Appendix A.3](https://www.rfc-editor.org/rfc/rfc9293#appendix-A.3)
discusses Minshall's modification.

Script: `fastopen/client/nonblocking-sendto-over-mss.pkt`.

### Soft ICMP errors during a passive handshake

ntcp reports IPv4 host-unreachable as a soft error and retains the pending
handshake, following
[RFC 9293 §3.9.2.2](https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2).
Linux may discard the pending request, causing the later handshake ACK to elicit
a reset. [RFC 5461 §4.1](https://www.rfc-editor.org/rfc/rfc5461#section-4.1)
describes early connection aborts as a departure from standard soft-error handling.

Script: `fastopen/server/icmp-baseline.pkt`.

### Missing negotiated timestamps

ntcp silently drops data, FIN, and final handshake ACK packets that omit
negotiated timestamps. [RFC 7323 §3.2](https://www.rfc-editor.org/rfc/rfc7323#section-3.2)
requires senders to include timestamps in every non-RST segment after negotiation
and recommends that receivers silently discard segments missing the option.
Dropping such a final ACK leaves the passive handshake pending. Linux may accept
these packets; the corresponding scripts depend on that tolerance.

Scripts: `inq/client.pkt`, `fastopen/server/pure-syn-data.pkt`,
`fastopen/server/opt34/pure-syn-data.pkt`.

### ACKs beyond sent data

ntcp responds with its current ACK and discards a segment acknowledging data beyond
`SND.NXT`, as specified by
[RFC 9293 §3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293#section-3.10.7.4).
Linux's established-state path may silently discard the segment.

Script: `ts_recent/invalid_ack.pkt`.

### RACK RTT sample order

ntcp processes newly acknowledged packets in transmission-time order, following
[RFC 8985 §6.2](https://www.rfc-editor.org/rfc/rfc8985#section-6.2). Linux's
sequence-order processing can leave a different RTT sample when one ACK covers
both retransmitted and original data. The resulting loss deadline can make ntcp
identify fresh loss on an ACK that Linux treats as loss-free. Fresh loss suppresses
the extra PRR SafeACK allowance under
[RFC 9937 §6.2](https://www.rfc-editor.org/rfc/rfc9937#section-6.2).

Script: `fast_recovery/prr-ss-ack-below-snd_una-cubic.pkt`.

### PRR on ECN window reduction

Under [RFC 9937 §6.2](https://www.rfc-editor.org/rfc/rfc9937#section-6.2), an ACK
that advances the cumulative acknowledgment without indicating fresh loss
qualifies for SafeACK credit. ECE alone does not indicate packet loss. Older Linux
PRR formulas restricted the extra credit to ACKs of retransmitted data, producing
a smaller temporary sending allowance in this script.

Script: `cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt`.

### RACK timer granularity

ntcp uses the initial RACK reordering window of `min_RTT / 4` from
[RFC 8985 §6.3](https://www.rfc-editor.org/rfc/rfc8985#section-6.3). Linux versions
that add timer padding and round to kernel ticks can retransmit later.

Script: `fast_retransmit/fr-4pkt-fack-last-mss.pkt`.

### Independent send and receive MSS

An ICMP fragmentation-needed message constrains the path from ntcp to its peer.
ntcp reduces outbound packet size while preserving its independent receive MSS
advertisement. [RFC 1191 §6.4](https://www.rfc-editor.org/rfc/rfc1191#section-6.4)
explicitly separates PMTU discovery from the MSS advertised to the peer, whose
traffic may follow a different path. Linux's route-derived advertised MSS can
change with the outbound PMTU.

Scripts: `fastopen/client/syn-data-icmp-unreach-frag-needed.pkt`,
`fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq.pkt`.

## Buffer-accounting expectations

ntcp accounts send-buffer capacity in payload bytes. Linux accounts queued
`sk_buff` memory, including metadata, and may fill an allocated buffer beyond its
allocation threshold. Partial-write lengths and writable notifications can differ
between the two models.

The `ntcp-ported` suite tests ntcp's accounting with source-derived fixtures:

| Fixture | Adaptation |
|---|---|
| [timestamping/partial.pkt](ntcp-expectations/timestamping/partial.pkt) | Partial-write lengths use ntcp's payload capacity; timestamp IDs identify the last accepted byte. |
| [tcp_info/tcp-info-sndbuf-limited.pkt](ntcp-expectations/tcp_info/tcp-info-sndbuf-limited.pkt) | ACKs follow actual transmitted data, and the counter measures a real interval of send-buffer backpressure. |

These fixtures retain checks for timestamp phases, error-queue notifications,
positive buffer-limited time, and receive-window accounting. The
[adapter replay](../../crates/adapters/ntcp-socket/src/runtime_accounting_expectations_tests.rs)
checks the same accounting with a deterministic clock.
