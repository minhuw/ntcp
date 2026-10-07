# Known exceptions

The 14 selected upstream loss-recovery tests are accounted for: **12 pass**, and **2 fail with the documented differences below**.

### `ts_recent/invalid_ack.pkt`

**Accepted extra ACK: ntcp replies to an ACK beyond `SND.NXT`.**

[RFC 9293 §3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4) requires replying with ACK and discarding the segment, preserving the rule from RFC 793. ntcp follows this rule; Linux v6.12's established-state path silently discards it, matching the script's expectation.

[Linux's patch discussion](https://lists.openwall.net/netdev/2022/03/19/74) identifies ACK-loop DoS and side-channel risks and recommends rate-limiting replies. ntcp currently sends this reply through its immediate-ACK path.

### `fast_recovery/prr-ss-ack-below-snd_una-cubic.pkt`

**Accepted recovery mismatch: 3 MSS expected, 2 MSS sent.**

At ACK4001, [RFC 8985 §6.2](https://www.rfc-editor.org/rfc/rfc8985.html#section-6.2) processes newly acknowledged packets in transmission-time order, leaving a **12 ms** RACK RTT. Linux 6.12.19 processes them in sequence order, leaving **22 ms**, as verified by runtime tracing.

With a 2.5 ms reordering allowance, the tail packet sent at 10 ms expires at **24.5 ms in ntcp**, versus **34.5 ms in Linux**. The ACK arrives at 32 ms: ntcp detects fresh loss; Linux keeps waiting. Under [RFC 9937 §6.2](https://www.rfc-editor.org/rfc/rfc9937.html#section-6.2), fresh loss suppresses PRR's extra SafeACK MSS, yielding **2 MSS versus 3 MSS**. ntcp retains the RFC processing order.

### `fast_retransmit/fr-4pkt-fack-last-mss.pkt`

**Accepted timing mismatch: 40 ms expected, ~25 ms observed.**

- **ntcp:** RFC 8985's initial reordering window is `min_RTT / 4`, giving `100 ms / 4 = 25 ms` after SACK.
- **Linux:** The script was validated on Linux 6.1, which adds two clock ticks of padding to its RACK timer. A tick is one kernel clock interval. At 250 Hz, that padding adds **8 ms**; tick rounding and timer-wheel alignment bring the total to **~36–40 ms**. The padding accounts for most of the extra delay in this example.
