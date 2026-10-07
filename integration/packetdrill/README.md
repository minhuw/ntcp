# Known exceptions

### `ts_recent/invalid_ack.pkt`

**Accepted extra ACK: ntcp replies to an ACK beyond `SND.NXT`.**

[RFC 9293 §3.10.7.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4) requires replying with ACK and discarding the segment, preserving the rule from RFC 793. ntcp follows this rule; Linux v6.12's established-state path silently discards it, matching the script's expectation.

[Linux's patch discussion](https://lists.openwall.net/netdev/2022/03/19/74) identifies ACK-loop DoS and side-channel risks and recommends rate-limiting replies. ntcp currently sends this reply through its immediate-ACK path.

### `fast_retransmit/fr-4pkt-fack-last-mss.pkt`

**Accepted timing mismatch: 40 ms expected, ~25 ms observed.**

- **ntcp:** RFC 8985's initial reordering window is `min_RTT / 4`, giving `100 ms / 4 = 25 ms` after SACK.
- **Linux:** The script was validated on Linux 6.1, which adds two clock ticks of padding to its RACK timer. A tick is one kernel clock interval. At 250 Hz, that padding adds **8 ms**; tick rounding and timer-wheel alignment bring the total to **~36–40 ms**. The padding accounts for most of the extra delay in this example.
