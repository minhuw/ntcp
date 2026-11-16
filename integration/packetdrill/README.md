# Packetdrill compatibility

The packetdrill runner tests ntcp through its socket plugin. Upstream scripts use
one common `upstream` configuration, with explicit options for script-specific
setup. Linux setup commands are translated through
[adaptations.json](adaptations.json); they are not executed on the host.

## Suites

| Suite | Purpose |
|---|---|
| `upstream` | Pinned upstream scripts with audited setup adaptations and original assertions. |
| `ntcp-ported` | Source-derived tests with expectations adapted to ntcp's accounting or transport policies. |
| `upstream-raw` | Full pinned upstream inventory without setup adaptations. |
| `smoke`, `sack` | Native ntcp fixtures. |

Use `--suite upstream --variant ipv4` for the adapted upstream tests. A script
owned by `ntcp-ported` is excluded from `upstream`, including explicit `--script`
selection. [expectations.json](expectations.json) records the ported fixtures,
source hashes, and changed expectations.

## Running

The Nix dev shell provides the pinned upstream source and the patched runner.
[flake.lock](../../flake.lock) locks the packetdrill revision of
[upstream.json](upstream.json) with its NAR hash, and the flake's
`packetdrill-runner` package builds that source with
[code-sockopt.patch](code-sockopt.patch). Build the plugin in the same shell, so
the runner, the plugin and Python share one glibc:

```sh
nix develop -c cargo build -p ntcp-packetdrill --profile packetdrill
nix develop -c python3 integration/packetdrill/run.py --suite upstream --variant ipv4
```

The `packetdrill` cargo profile is `release` with debug assertions and overflow
checks enabled. Scripts time packets to the millisecond, and an unoptimized plugin
segments a large send too slowly: the last segment of a ten-segment flight leaves
several milliseconds late, which fails the expected packet's timing. `run.py`
loads `target/packetdrill/libntcp_packetdrill.so` by default; pass `--plugin`
for a plugin built in another target directory.

`run.py` checks the source tree against the NAR hash in `flake.lock`, and the
runner against the provenance file beside it: source revision and NAR hash, patch
hash and executable hash. The Python tests use the same source and runner.

`--checkout DIR` selects a Git checkout of the pinned revision instead, verified
with `git rev-parse` and `git diff`. It uses the checkout's own runner unless
`--runner` names one built by `build_runner.py --checkout DIR`. Build that runner
and the plugin, and run `run.py`, in one environment, since the plugin is loaded
into the runner and into Python.

## Known exceptions

Upstream scripts encode Linux implementation choices as well as TCP requirements.
The following differences reflect transport policies retained by ntcp.

### Application-limited slow start

ntcp does not grow CUBIC's window for an application-limited flight, following
[RFC 9438 §5.8](https://www.rfc-editor.org/rfc/rfc9438#section-5.8). Linux's
slow-start heuristic can grow the window toward twice the peak flight size.

Scripts: `slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt`,
`slow_start/slow-start-app-limited-9-packets-out.pkt`.

### HyStart++ and classic Linux HyStart

ntcp's CUBIC startup uses
[HyStart++ (RFC 9406)](https://www.rfc-editor.org/rfc/rfc9406#section-4.2).
These scripts select classic Linux HyStart through `hystart_detect=3`, which has
no ntcp setup mapping; they remain unsupported.

For non-paced output, ntcp selects a limit of sixteen MSS per ACK, using the
tuning permission in [RFC 9406 §4.3](https://www.rfc-editor.org/rfc/rfc9406#section-4.3).
This favors window growth under coalesced ACKs over the recommended eight-MSS
limit, with a larger burst allowance and possible additional loss. An ACK covering
ten MSS can grow a window from ten to twenty MSS. Actually paced output retains
the uncapped limit; startup bursts and protocol probes do not qualify as paced.

When delay increases, HyStart++ enters Conservative Slow Start (CSS), with
one-quarter of ordinary slow-start growth. A qualifying RTT decrease can return
the connection to ordinary slow start. Persistent delay leads to congestion
avoidance after five CSS rounds, including the partial entry round. Classic
HyStart can enter congestion avoidance directly on delay detection, so its
window and exit assertions describe a different startup algorithm.

Scripts: `cubic/cubic-hystart-delay-min-rtt-jumps-downward.pkt`,
`cubic/cubic-hystart-delay-rtt-jumps-upward.pkt`.

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

### Loss response

ntcp's response to loss follows RFC 5681, RFC 6298 and RFC 9937 rather than
Linux. This is a deliberate choice, not a gap awaiting a port.

- The slow-start threshold is computed from FlightSize, as
  [RFC 5681 §3.1](https://www.rfc-editor.org/rfc/rfc5681#section-3.1) equation (4)
  specifies, on SACK and RACK loss recovery and on a retransmission timeout. CUBIC
  applies its β of 0.7 to FlightSize
  ([RFC 9438 §4.6](https://www.rfc-editor.org/rfc/rfc9438#section-4.6)). Linux
  computes it from the congestion window (`tcp_recalc_ssthresh`; CUBIC's
  `max(cwnd × β, 2)`). Linux also shrinks a window an application left unused
  for an RTO (`tcp_cwnd_application_limited`: cwnd becomes the mean of cwnd and
  the window used). ntcp implements neither, nor RFC 7661's window validation.
  CUBIC does not grow its window while application-limited
  ([RFC 9438 §5.8](https://www.rfc-editor.org/rfc/rfc9438#section-5.8)). CUBIC's
  reductions for non-SACK fast retransmit and ECN use the window as their base,
  as RFC 9438 §4.6 permits under that condition.
- PRR divides by RecoverFS, the flight that the target was taken from
  ([RFC 9937 §6.1](https://www.rfc-editor.org/rfc/rfc9937#section-6.1)). Linux
  divides by the window before recovery (`prior_cwnd`).
- The RTO is `SRTT + max(G, 4 × RTTVAR)`, rounded up to a 200 ms floor
  ([RFC 6298 §2.3–2.4](https://www.rfc-editor.org/rfc/rfc6298#section-2), with
  Linux's `TCP_RTO_MIN` replacing the 1 s floor). Linux applies the floor to the
  variance term instead (`rttvar = max(mdev, rto_min)`), so its RTO is at least
  SRTT + 200 ms. With a 10 ms SRTT, ntcp's RTO is 200 ms and Linux's is about
  210 ms.

An application-limited flow therefore leaves recovery with a smaller window than
under Linux. Take a CUBIC flow whose window is 20 MSS but which has only 8 MSS in
flight when SACK recovery starts. ntcp sets ssthresh to 0.7 × 8 = 5.6 MSS and
leaves recovery at that window. Linux sets 0.7 × 20 = 14 MSS. If the flow has been
application-limited for a whole RTO, Linux first reduces the window to
(20 + 10) / 2 = 15 MSS, where 10 is the initial window, and sets ssthresh to 10
MSS. The same rule applies after a timeout with one 1000-byte segment
outstanding and a 10-MSS window: ntcp's ssthresh is 2 MSS (0.7 × 1, raised to
the 2-MSS minimum), and Linux's is 7.

### RTO and tail-loss probe timing

ntcp calculates RTO as described under [Loss response](#loss-response) and caps
the tail-loss probe deadline at RTO, as specified by
[RFC 8985 §7.2](https://www.rfc-editor.org/rfc/rfc8985#section-7.2). Linux floors
the RTT-variation term, not the RTO, so ntcp's RTO is shorter by up to SRTT.
This changes when tail-loss probes, retransmission timeouts and zero-window
probes fire. Like Linux, ntcp sends the first zero-window probe one RTO after
the window closes
([RFC 9293 §3.8.6.1](https://www.rfc-editor.org/rfc/rfc9293#section-3.8.6.1)).

`cubic/cubic-rto-ss-ca-cwnd-bump.pkt` first fails on the tail-loss probe's
timing. With Linux's RTO it would fail on the ssthresh after the timeout
instead: ntcp sets 2 MSS where the script expects 7 (see
[Loss response](#loss-response)). Both differences come from the loss-response
choice.

In `tcp_info/tcp-info-rwnd-limited.pkt`, the SYN-ACK gives a 10 ms SRTT, so
ntcp's RTO is 200 ms. ntcp sends a zero-window probe 200 ms after the write,
before the scripted window update arrives at that time. Linux's first probe
fires at about 211 ms, after the update, and the script expects no probe.

Scripts: `cubic/cubic-rto-ss-ca-cwnd-bump.pkt`,
`tcp_info/tcp-info-rwnd-limited.pkt`.

### Delayed ACK of data with FIN

When a segment carrying data and FIN moves an established connection to
CLOSE-WAIT, ntcp delays the ACK by the delayed-ACK timeout (40 ms), as Linux
6.12 does. Linux's `tcp_fin` enters ping-pong mode, expecting the application's
reply to carry the ACK. While the segment's data is unread,
`__tcp_ack_snd_check` does not send the ACK at once. The script, written in
2019, expects an immediate ACK. Linux 6.12 fails the same assertion with the
same 40 ms delay.

Script: `ioctl/ioctl-siocinq-fin.pkt`.

### Fast Open negative-response caching

When a validated SYN-ACK acknowledges the SYN but none of its data, ntcp caches
that negative response and temporarily disables Fast Open for the service.
[RFC 7413 §4.1.3.1](https://www.rfc-editor.org/rfc/rfc7413#section-4.1.3.1)
explicitly includes unacknowledged SYN data among the negative responses clients
MUST cache and recommends temporarily disabling Fast Open after such responses.

ntcp retains the cookie and learned peer MSS, but applies a 60-second cooldown
keyed by local IP, remote IP, and remote service port, across local ephemeral
ports. The duration and cache scope are local policy. Successfully retransmitting
the data after the handshake does not clear this evidence: ordinary TCP delivery
does not establish that the server or path accepts SYN data. Fast Open becomes
eligible again when the cooldown expires.

The script expects the next connection to reuse Fast Open immediately. ntcp
instead sends an ordinary SYN; the nonblocking `MSG_FASTOPEN` call returns
`EINPROGRESS` without accepting initial data.

Script: `fastopen/client/syn-data-only-syn-acked.pkt`.

### Soft ICMP errors during a passive handshake

ntcp reports IPv4 host-unreachable as a soft error and retains the pending
handshake, following
[RFC 9293 §3.9.2.2](https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2.2).
Linux may discard the pending request, causing the later handshake ACK to elicit
a reset. [RFC 5461 §4.1](https://www.rfc-editor.org/rfc/rfc5461#section-4.1)
describes early connection aborts as a departure from standard soft-error handling.

The same policy applies to cookie-authenticated Fast Open requests. Buffered SYN
data remains readable through the accepted child, and the pending handshake can
still complete. Before accept, the soft error is available through the listener's
`SO_ERROR`; draining the early data does not turn it into a fatal read error.

The option-34 script also checks Linux's `TcpExtOutOfWindowIcmps` through `nstat`.
That counter has no audited native query mapping, so the script remains
unsupported independently of the soft-error policy.

Scripts: `fastopen/server/icmp-baseline.pkt`,
`fastopen/server/opt34/icmp-before-accept.pkt`.

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

## Transport-policy expectations

The [Fast Open recovery fixture](ntcp-expectations/fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt)
checks recovery after a lost final handshake ACK and missing response data. It
retains the upstream timestamp, SACK, recovery-state and congestion-window checks,
while checking ntcp's actual software-group PSH boundaries, scalar repair flags
and receive-window advertisement. Group flush hints do not become application
PUSH marks retained for retransmission.

The [server-cookie fixture](ntcp-expectations/fastopen/server/opt34/simple3.pkt)
checks the configured key and address-bound cookie across a listener restart,
then verifies a full 10 KB response before the final handshake ACK. Its second
SYN advertises 10001 bytes: ntcp retains the unacknowledged SYN in sequence-space
window accounting, leaving 10000 payload positions. The fixture also checks the
read-triggered receive-window expansion and actual software-group PSH boundaries.

The [multi-iovec copied-fallback fixture](ntcp-expectations/zerocopy/maxfrags.pkt)
checks ordinary and `MSG_ZEROCOPY` sends with the original iovec arrays and copied
completion IDs. ntcp gathers copied data into its byte buffer, so the small
18-byte and 64-byte sends each fit in one TCP segment. Linux skb page-fragment
limits do not define native segment boundaries. For the unregistered iovecs in
this fixture, `MSG_ZEROCOPY` reports `SO_EE_CODE_ZEROCOPY_COPIED`; its notification
releases the application's buffer ownership obligation rather than reporting
network delivery.

Like accounting ports, these fixtures belong exclusively to `ntcp-ported`;
`upstream` excludes their source identities. Their changes and source hashes are
recorded in [expectations.json](expectations.json).
