# Known exceptions

### `fast_retransmit/fr-4pkt-fack-last-mss.pkt`

**Accepted timing mismatch: 40 ms expected, ~25 ms observed.**

- **ntcp:** RFC 8985's initial reordering window is `min_RTT / 4`, giving `100 ms / 4 = 25 ms` after SACK.
- **Linux:** The script was validated on Linux 6.1, which adds two clock ticks of padding to its RACK timer. A tick is one kernel clock interval. At 250 Hz, that padding adds **8 ms**; tick rounding and timer-wheel alignment bring the total to **~36–40 ms**. The padding accounts for most of the extra delay in this example.
