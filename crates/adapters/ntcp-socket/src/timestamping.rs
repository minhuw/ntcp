// SPDX-License-Identifier: GPL-2.0-or-later
// Linux-only ABI preparation; NOT wired into socket options until native TX/RX
// contracts are complete. No timestamp generation or core clock conversion here.
// Check: cargo test -p ntcp-socket timestamping
// Verified against Linux v6.12 net/core/sock.c sock_set_timestamping,
// __sock_cmsg_send, and sk_getsockopt. The supported socket ABIs are 64-bit.

const OLD: i32 = 37;
const NEW: i32 = 65;
const TX_HARDWARE: u32 = 1;
const TX_SOFTWARE: u32 = 1 << 1;
const RX_HARDWARE: u32 = 1 << 2;
const RX_SOFTWARE: u32 = 1 << 3;
const SOFTWARE: u32 = 1 << 4;
const SYS_HARDWARE: u32 = 1 << 5;
const RAW_HARDWARE: u32 = 1 << 6;
const OPT_ID: u32 = 1 << 7;
const TX_SCHED: u32 = 1 << 8;
const TX_ACK: u32 = 1 << 9;
const OPT_CMSG: u32 = 1 << 10;
const OPT_TSONLY: u32 = 1 << 11;
const OPT_STATS: u32 = 1 << 12;
const OPT_PKTINFO: u32 = 1 << 13;
const OPT_TX_SWHW: u32 = 1 << 14;
const BIND_PHC: u32 = 1 << 15;
const OPT_ID_TCP: u32 = 1 << 16;
const OPT_RX_FILTER: u32 = 1 << 17;
const MASK: u32 = (1 << 18) - 1;
const TX_RECORD: u32 = TX_HARDWARE | TX_SOFTWARE | TX_SCHED | TX_ACK;
const UNSUPPORTED: u32 = OPT_CMSG | OPT_STATS | OPT_PKTINFO | BIND_PHC;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Options {
    flags: u32,
    new_abi: bool,
}

impl Options {
    // Validate without mutation: caller commits only after native reservations
    // and ID-base acquisition succeed. `active` excludes TCP_CLOSE/TCP_LISTEN.
    fn updated(self, name: i32, flags: u32, active: bool) -> Result<Self, i32> {
        if !matches!(name, OLD | NEW)
            || flags & !MASK != 0
            || flags & OPT_ID_TCP != 0 && flags & OPT_ID == 0
            || flags & OPT_STATS != 0 && flags & OPT_TSONLY == 0
            || flags & OPT_ID != 0 && self.flags & OPT_ID == 0 && !active
        {
            return Err(EINVAL);
        }
        if flags & UNSUPPORTED != 0 {
            return Err(EOPNOTSUPP);
        }
        Ok(Self {
            flags,
            new_abi: name == NEW,
        })
    }

    fn get(self, name: i32) -> Result<[u8; 8], i32> {
        if !matches!(name, OLD | NEW) {
            return Err(EINVAL);
        }
        let mut value = [0; 8]; // struct so_timestamping, unsupported bind_phc=0
        // OLD reads flags regardless of selected ABI; NEW is deliberately strict.
        if name == OLD || self.new_abi {
            value[..4].copy_from_slice(&self.flags.to_ne_bytes());
        }
        Ok(value)
    }

    fn per_send(self, override_flags: u32) -> Result<u32, i32> {
        if override_flags & !TX_RECORD != 0 {
            return Err(EINVAL);
        }
        Ok((self.flags & !TX_RECORD) | override_flags)
    }

    fn resets_id(self, next: Self) -> bool {
        self.flags & OPT_ID == 0 && next.flags & OPT_ID != 0
    }
}

// Inputs must already be verified realtime nanoseconds or calibrated raw-device
// nanoseconds by the integration. This helper never accepts/converts device ticks.
// ts[1] (deprecated SYS_HARDWARE) is always zero. OLD and NEW coincide on 64-bit.
fn timestamps(software_ns: Option<u64>, hardware_ns: Option<u64>) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (slot, nanos) in [(0, software_ns), (2, hardware_ns)] {
        if let Some(nanos) = nanos {
            let at = slot * 16;
            bytes[at..at + 8].copy_from_slice(&((nanos / 1_000_000_000) as i64).to_ne_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&((nanos % 1_000_000_000) as i64).to_ne_bytes());
        }
    }
    bytes
}

// sock_extended_err plus AF_UNSPEC sockaddr_in offender, matching zero-copy's
// current errorqueue layout. `id` is Linux's byte ID, never a native core cookie.
fn extended_error(stage: u32, id: u32) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&42u32.to_ne_bytes()); // ENOMSG
    bytes[4] = 4; // SO_EE_ORIGIN_TIMESTAMPING
    bytes[8..12].copy_from_slice(&stage.to_ne_bytes()); // SCM_TSTAMP_{SND,SCHED,ACK}
    bytes[12..16].copy_from_slice(&id.to_ne_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_new_readback_and_validation_are_transactional() {
        let empty = Options::default();
        assert_eq!(empty.updated(OLD, OPT_ID, false), Err(EINVAL));
        assert_eq!(empty.updated(OLD, OPT_ID_TCP, true), Err(EINVAL));
        assert_eq!(empty.updated(OLD, OPT_STATS, true), Err(EINVAL));
        assert_eq!(
            empty.updated(OLD, OPT_STATS | OPT_TSONLY, true),
            Err(EOPNOTSUPP)
        );
        for bit in [OPT_CMSG, OPT_PKTINFO, BIND_PHC] {
            assert_eq!(empty.updated(OLD, bit, true), Err(EOPNOTSUPP));
        }
        for flags in [1 << 18, 1 << 31, u32::MAX] {
            assert_eq!(empty.updated(OLD, flags, true), Err(EINVAL));
        }
        let flags = TX_RECORD
            | RX_HARDWARE
            | RX_SOFTWARE
            | SOFTWARE
            | RAW_HARDWARE
            | SYS_HARDWARE
            | OPT_ID
            | OPT_TSONLY
            | OPT_TX_SWHW
            | OPT_ID_TCP
            | OPT_RX_FILTER;
        let old = empty.updated(OLD, flags, true).unwrap();
        assert_eq!(&old.get(OLD).unwrap()[..4], &flags.to_ne_bytes());
        assert_eq!(old.get(NEW).unwrap(), [0; 8]);
        let new = old.updated(NEW, flags, true).unwrap();
        assert_eq!(new.get(OLD), new.get(NEW));
        assert_eq!(&new.get(NEW).unwrap()[4..], &[0; 4]);
        assert_eq!(new.updated(NEW, 1 << 31, true), Err(EINVAL));
        assert_eq!(new.flags, flags);
        assert_eq!(empty.get(66), Err(EINVAL));
        assert_eq!(empty.updated(66, 0, true), Err(EINVAL));
    }

    #[test]
    fn per_send_replaces_generation_not_reporting_and_id_only_resets_on_enable() {
        let base = Options::default();
        let enabled = base
            .updated(OLD, TX_SOFTWARE | SOFTWARE | OPT_ID, true)
            .unwrap();
        assert!(base.resets_id(enabled));
        let changed = enabled
            .updated(NEW, SOFTWARE | OPT_ID | OPT_ID_TCP, true)
            .unwrap();
        assert!(!enabled.resets_id(changed));
        let off = changed.updated(NEW, SOFTWARE, true).unwrap();
        assert!(off.resets_id(enabled));
        // The accepted byte ID is snapshotted per request by the integration;
        // this option transition must never rewrite already-pending events.
        assert_eq!(enabled.per_send(0), Ok(SOFTWARE | OPT_ID));
        assert_eq!(enabled.per_send(TX_ACK), Ok(SOFTWARE | OPT_ID | TX_ACK));
        for invalid in [SOFTWARE, RX_SOFTWARE, OPT_ID, SYS_HARDWARE, 1 << 31] {
            assert_eq!(enabled.per_send(invalid), Err(EINVAL));
        }
    }

    #[test]
    fn injected_hardware_is_only_in_raw_slot_and_extended_error_is_linux_abi() {
        let sw = 1_700_000_000_123_456_789;
        let hw = 123_987_654_321;
        let bytes = timestamps(Some(sw), Some(hw));
        for (at, value) in [
            (0, 1_700_000_000i64),
            (8, 123_456_789),
            (32, 123),
            (40, 987_654_321),
        ] {
            assert_eq!(&bytes[at..at + 8], &value.to_ne_bytes());
        }
        assert_eq!(&bytes[16..32], &[0; 16]);
        assert_eq!(&timestamps(None, Some(hw))[..32], &[0; 32]);
        assert_eq!(&timestamps(Some(sw), None)[16..], &[0; 32]);
        assert_eq!(timestamps(None, None), [0; 48]);
        for stage in 0..=2 {
            let err = extended_error(stage, u32::MAX);
            assert_eq!(&err[..4], &42u32.to_ne_bytes());
            assert_eq!(&err[4..8], &[4, 0, 0, 0]);
            assert_eq!(&err[8..12], &stage.to_ne_bytes());
            assert_eq!(&err[12..16], &u32::MAX.to_ne_bytes());
            assert_eq!(&err[16..], &[0; 16]);
        }
    }

    #[test]
    fn two_cmsgs_truncate_at_every_boundary_for_both_abis() {
        use crate::socket_options::cmsg_control;
        for kind in [OLD, NEW] {
            for capacity in 0..=120 {
                let (stamp, first, t1) =
                    cmsg_control(capacity, true, 1, kind, &timestamps(Some(123), None));
                let (error, second, t2) =
                    cmsg_control(capacity - first, true, 0, 11, &extended_error(2, 99));
                assert!(first + second <= capacity);
                assert_eq!(t1 || t2, capacity < 112);
                assert_eq!(
                    stamp.len(),
                    if capacity < 16 { 0 } else { capacity.min(64) }
                );
                assert_eq!(
                    error.len(),
                    if capacity < 80 {
                        0
                    } else {
                        (capacity - 64).min(48)
                    }
                );
                if !stamp.is_empty() {
                    assert_eq!(&stamp[12..16], &kind.to_ne_bytes());
                }
                if capacity >= 112 {
                    assert_eq!(&error[28..32], &99u32.to_ne_bytes());
                }
            }
        }
    }
}
