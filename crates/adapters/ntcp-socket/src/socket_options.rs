// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Core-independent Linux socket policy/ABI helpers. Standalone checks:
// rustc --edition=2024 --test socket_options.rs -o /tmp/socket-options && /tmp/socket-options
pub(crate) const EDGE_BITS: [i32; 5] = [1, 4, 8, 16, 0x2000]; // Linux EPOLL{IN,OUT,ERR,HUP,RDHUP}

// Linux v6.12 include/net/tcp.h: zero selects the namespace default, UINT_MAX.
pub(crate) fn effective_notsent_lowat(value: u32) -> u32 {
    if value == 0 { u32::MAX } else { value }
}
pub(crate) fn notsent_writable(notsent: usize, lowat: u32) -> bool {
    // tcp_poll uses tcp_stream_memory_free(wake=1): half-lowwater hysteresis.
    (notsent as u64).saturating_mul(2) < u64::from(effective_notsent_lowat(lowat))
}
pub(crate) fn edge_changed(ready: u32, seen: Option<[u64; 5]>, observed: [u64; 5]) -> bool {
    ready != 0
        && seen.is_none_or(|seen| {
            EDGE_BITS.into_iter().enumerate().any(|(i, bit)| {
                ready & bit as u32 != 0 && {
                    // Concurrent waiters can stage an older snapshot before a
                    // newer one commits. Never rewind seen state on copyout.
                    let distance = observed[i].wrapping_sub(seen[i]);
                    distance != 0 && distance < (1 << 63)
                }
            })
        })
}

// Linux v6.12 net/core/scm.c put_cmsg. The supported 64-bit ABIs use a
// size_t followed by two ints, size_t alignment, and SOL_TCP/TCP_CM_INQ=6/36.
// Padding is reported but not written, just as in Linux.
pub(crate) fn inq_control(capacity: usize, has_control: bool, inq: i32) -> (Vec<u8>, usize, bool) {
    let header = std::mem::size_of::<usize>() + 8;
    let len = header + 4;
    let space = len.next_multiple_of(std::mem::align_of::<usize>());
    if !has_control || capacity < header {
        return (Vec::new(), 0, true);
    }
    let written = capacity.min(len);
    let mut control = vec![0; written];
    control[..std::mem::size_of::<usize>()].copy_from_slice(&written.to_ne_bytes());
    control[header - 8..header - 4].copy_from_slice(&6i32.to_ne_bytes());
    control[header - 4..header].copy_from_slice(&36i32.to_ne_bytes());
    control[header..].copy_from_slice(&inq.to_ne_bytes()[..written - header]);
    (control, capacity.min(space), written < len)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lowwater_uint_and_wake_hysteresis() {
        assert_eq!(effective_notsent_lowat(0), u32::MAX);
        assert_eq!(effective_notsent_lowat((-1i32) as u32), u32::MAX);
        assert_eq!(effective_notsent_lowat(i32::MIN as u32), 1 << 31);
        assert!(notsent_writable(1999, 4000));
        assert!(!notsent_writable(2000, 4000));
        assert!(notsent_writable(0, 1));
        assert!(!notsent_writable(1, 1));
        assert!(!notsent_writable(usize::MAX, 0));
    }
    #[test]
    fn edge_delivery_is_per_registration_and_interested_bit() {
        let observed = [1, 2, 0, 0, 0];
        assert!(edge_changed(5, None, observed));
        assert!(!edge_changed(5, Some(observed), observed));
        assert!(edge_changed(5, Some(observed), [2, 2, 0, 0, 0]));
        assert!(!edge_changed(4, Some(observed), [2, 2, 0, 0, 0]));
        assert!(edge_changed(4, Some(observed), [1, 3, 0, 0, 0]));
        assert!(!edge_changed(0, None, observed));
        // A failed copyout leaves seen untouched, so retry still delivers.
        assert!(edge_changed(5, None, observed));
        // MOD/ONESHOT rearm resets seen, even without new socket events.
        assert!(edge_changed(5, None, observed));
        assert!(edge_changed(1, Some([u64::MAX; 5]), [0; 5]));
        assert!(!edge_changed(1, Some([2; 5]), [1; 5]));
    }
    #[test]
    fn inq_cmsg_lengths_alignment_and_truncation() {
        for capacity in 0..=32 {
            let (bytes, used, truncated) = inq_control(capacity, true, 9000);
            if capacity < 16 {
                assert!(bytes.is_empty());
                assert_eq!(used, 0);
                assert!(truncated);
            } else {
                assert_eq!(bytes.len(), capacity.min(20));
                assert_eq!(used, capacity.min(24));
                assert_eq!(truncated, capacity < 20);
                assert_eq!(
                    usize::from_ne_bytes(bytes[..8].try_into().unwrap()),
                    bytes.len()
                );
                assert_eq!(&bytes[8..12], &6i32.to_ne_bytes());
                assert_eq!(&bytes[12..16], &36i32.to_ne_bytes());
                assert_eq!(&bytes[16..], &9000i32.to_ne_bytes()[..bytes.len() - 16]);
            }
        }
        assert_eq!(inq_control(24, false, 1), (Vec::new(), 0, true));
    }
}
