//! Ephemeral port selection for active opens: RFC 6056's Algorithm 4, as
//! Linux's __inet_hash_connect (net/ipv4/inet_hashtables.c) implements it.
//! The adapter that owns the local ports decides which ports are suitable;
//! this decides the order it tries them in.
extern crate alloc;

use alloc::vec::Vec;
use core::{
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
};

use crate::{CallerTimebase, Instant};

// The increments are separated into 2^16 spaces, Linux's table_perturb
// (INET_TABLE_PERTURB_ORDER 16) rather than RFC 6056's suggested ten: with
// few spaces, an attacker who sees the ports of connections to its own
// hosts learns how many a victim opened elsewhere in the same space.
const SPACES: usize = 1 << 16;
// Linux's EPHEMERAL_PORT_SHUFFLE_PERIOD: the offset of a destination
// changes every ten seconds, so that ports seen at one time say nothing of
// the ones that follow.
const SHUFFLE_US: u64 = 10_000_000;

/// The state of ephemeral port selection: a secret key and the per-space
/// increments, 256 KiB allocated whole (`Endpoint::ephemeral_ports`).
pub struct EphemeralPorts {
    key: [u8; 16],
    increments: Vec<u32>,
    draws: u64,
    shuffle: u64,
}

impl EphemeralPorts {
    pub(crate) fn new(key: [u8; 16], timebase: CallerTimebase) -> Result<Self, ()> {
        let mut increments = Vec::new();
        increments.try_reserve_exact(SPACES).map_err(|_| ())?;
        increments.resize(SPACES, 0);
        Ok(Self {
            key,
            increments,
            draws: 0,
            shuffle: timebase.ticks_from_us(SHUFFLE_US),
        })
    }

    fn hash(&self, write: impl FnOnce(&mut siphasher::sip::SipHasher13)) -> u64 {
        let mut hash = siphasher::sip::SipHasher13::new_with_key(&self.key);
        write(&mut hash);
        hash.finish()
    }

    // A value the key keeps unpredictable, a fresh one for every draw.
    fn draw(&mut self) -> u64 {
        self.draws += 1;
        let draws = self.draws;
        self.hash(|hash| {
            hash.write_u8(b'R');
            hash.write_u64(draws);
        })
    }

    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.3
    //# Ephemeral port selection algorithms SHOULD obfuscate the selection of
    //# their ephemeral ports, since this helps to mitigate a number of
    //# attacks that depend on the attacker's ability to guess or know the
    //# five-tuple that identifies the transport-protocol instance to be
    //# attacked.
    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.3.3
    //# The function should use both IP addresses, the remote
    //# port, and a secret key value to compute the offset.
    /// The first port of `range` that `suitable` takes, for an active open
    /// from `local` to `remote` at `now`, or None when it takes none.
    ///
    /// Each destination (local address, remote address and port) starts at
    /// an offset of its own, a keyed hash that changes every ten seconds,
    /// plus the increment of one of 2^16 spaces the hash also selects, which
    /// grows by the ports tried each time a port is found, and by a random
    /// 0 to 7 besides. Consecutive opens to one destination thus take
    /// increasing ports, as RFC 6056 Algorithm 4 intends, without showing
    /// how many opens went elsewhere, and an observer who knows neither the
    /// secret nor the increments cannot tell the next port. Ports of the
    /// range's lower parity are tried first, then the others (Linux leaves
    /// the odd ports to bind(port 0)); every port of the range is offered,
    /// where Linux drops the last of a range of an odd number of ports.
    ///
    /// `suitable` decides whether a port can be the open's: that its
    /// 4-tuple is unique (`Endpoint::tuple_in_use`) and that no application
    /// bound the port. It is asked at most once per port of the range.
    pub fn select(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        range: RangeInclusive<u16>,
        mut suitable: impl FnMut(u16) -> bool,
    ) -> Option<u16> {
        // Algorithm 4's port = min_ephemeral + (offset + table[index]) %
        // num_ephemeral, from which the scan steps until check_suitable_port.
        let (space, offset) = self.destination(now, local, remote);
        let (port, tried) = scan(range, 0, offset / 2, &mut suitable)?;
        self.advance(space, tried, 2);
        Some(port)
    }

    /// The first of `count` candidates, by index, that `suitable` takes for
    /// an active open from `local` to `remote` at `now`, or None when it
    /// takes none: `select` for a set of ports that is no range, such as a
    /// member's tagged ports, tried one after another from the
    /// destination's offset, without the parity passes. `suitable` is asked
    /// at most once per index.
    pub fn select_among(
        &mut self,
        now: Instant,
        local: IpAddr,
        remote: SocketAddr,
        count: usize,
        mut suitable: impl FnMut(usize) -> bool,
    ) -> Option<usize> {
        let count = u32::try_from(count).ok().filter(|&n| n != 0)?;
        let (space, offset) = self.destination(now, local, remote);
        let first = offset % count;
        let found = (0..count).find(|&tried| suitable(((first + tried) % count) as usize))?;
        self.advance(space, found, 1);
        Some(((first + found) % count) as usize)
    }

    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.3.4
    //# The array "table[]" assures that successive transport-protocol
    //# instances with the same remote endpoint will use increasing ephemeral
    //# port numbers.
    // Algorithm 4's table[index]++. After a port is found `tried` steps of `step` from the start: the
    // space's increment grows by those, as Linux adds, at least a random
    // few (get_random_u32_below(8)), so that consecutive ports to a
    // destination do not count the opens.
    fn advance(&mut self, space: usize, tried: u32, step: u32) {
        let increment = tried.max((self.draw() % 8) as u32 * step) + step;
        self.increments[space] = self.increments[space].wrapping_add(increment);
    }

    // The increment space of the destination of an open from `local` to
    // `remote` at `now`, and its offset, increment included.
    fn destination(&self, now: Instant, local: IpAddr, remote: SocketAddr) -> (usize, u32) {
        // Linux's secure_ipv4_port_ephemeral, its 64-bit siphash: the low
        // bits choose the space, the high ones the offset.
        let epoch = now / self.shuffle.max(1);
        let hash = self.hash(|hash| {
            for address in [local, remote.ip()] {
                match address {
                    IpAddr::V4(a) => {
                        hash.write_u8(4);
                        hash.write(&a.octets());
                    }
                    IpAddr::V6(a) => {
                        hash.write_u8(6);
                        hash.write(&a.octets());
                    }
                }
            }
            hash.write_u16(remote.port());
            hash.write_u64(epoch);
        });
        let space = hash as usize & (SPACES - 1);
        // RFC 6056 initializes the table at random; the key stands in for
        // that, each space's start a keyed hash of its index.
        let start = self.hash(|hash| {
            hash.write_u8(b'T');
            hash.write_u32(space as u32);
        }) as u32;
        let offset = start
            .wrapping_add(self.increments[space])
            .wrapping_add((hash >> 32) as u32);
        (space, offset)
    }

    // Not RFC 6056 section 3.5's Algorithm 2 (an exception in
    // duvet/rfc6056-todos.toml), but Linux's random start and scan.
    /// The first port of `range` that `suitable` takes for a local port
    /// with no destination yet, bind(port 0) or listen on an unbound
    /// socket, or None when it takes none: Linux's
    /// inet_csk_find_open_port. With no destination to separate, the search
    /// starts at random, at a port of the range's upper parity, and tries
    /// those first, leaving the others to active opens (`select`). With
    /// `reuse` (SO_REUSEADDR) it searches the lower half of the range
    /// first, then the upper. `suitable` decides whether a port is free,
    /// as for `select`, and is asked at most once per port of the range.
    pub fn select_unbound(
        &mut self,
        range: RangeInclusive<u16>,
        reuse: bool,
        mut suitable: impl FnMut(u16) -> bool,
    ) -> Option<u16> {
        let (low, high) = (*range.start(), *range.end());
        if low > high {
            return None;
        }
        let count = u32::from(high - low) + 1;
        let halves = if reuse && count >= 4 {
            let half = low + ((count >> 2) << 1) as u16;
            [Some(low..=half - 1), Some(half..=high)]
        } else {
            [Some(range), None]
        };
        for half in halves.into_iter().flatten() {
            let start = (self.draw() % u64::from(count)) as u32;
            if let Some((port, _)) = scan(half, 1, start, &mut suitable) {
                return Some(port);
            }
        }
        None
    }
}

// The first port of `range` that `suitable` takes, and the ports the scan
// stepped over to it: those whose offset from the range's start has parity
// `first` from the `start`-th of them on, round, then the others, each at
// most once. Linux scans so, in steps of two, but drops the last port of a
// range of an odd number of ports, which this offers.
fn scan(
    range: RangeInclusive<u16>,
    first: u32,
    start: u32,
    suitable: &mut impl FnMut(u16) -> bool,
) -> Option<(u16, u32)> {
    let (low, high) = (u32::from(*range.start()), u32::from(*range.end()));
    if low > high {
        return None;
    }
    let count = high - low + 1;
    for parity in [first, 1 - first] {
        // The ports of the parity: offsets parity, parity + 2, ...
        let ports = (count + 1 - parity) / 2;
        for tried in 0..ports {
            let offset = 2 * ((start % ports + tried) % ports) + parity;
            let port = (low + offset) as u16;
            if suitable(port) {
                return Some((port, 2 * tried));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports() -> EphemeralPorts {
        EphemeralPorts::new([7; 16], CallerTimebase::default()).unwrap()
    }
    fn remote(last: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from([192, 0, 2, last]), port)
    }
    const LOCAL: IpAddr = IpAddr::V4(core::net::Ipv4Addr::new(10, 0, 0, 1));

    // Every port of an even-sized range is asked once, lower parity first,
    // and an exhausted range gives None.
    #[test]
    fn every_port_is_tried_once_lower_parity_first() {
        let mut ports = ports();
        let mut asked = Vec::new();
        let found = ports.select(0, LOCAL, remote(1, 80), 32768..=32799, |port| {
            asked.push(port);
            false
        });
        assert_eq!(found, None);
        assert_eq!(asked.len(), 32);
        assert!(asked[..16].iter().all(|port| port % 2 == 0));
        assert!(asked[16..].iter().all(|port| port % 2 == 1));
        asked.sort_unstable();
        assert!(asked.iter().copied().eq(32768..=32799));
    }

    // One port, and an odd range, every port of which is offered.
    #[test]
    fn small_ranges() {
        let mut ports = ports();
        assert_eq!(
            ports.select(0, LOCAL, remote(1, 80), 40000..=40000, |_| true),
            Some(40000)
        );
        let mut asked = Vec::new();
        ports.select(0, LOCAL, remote(1, 80), 40000..=40002, |port| {
            asked.push(port);
            false
        });
        asked.sort_unstable();
        assert_eq!(asked, [40000, 40001, 40002]);
        let mut asked = Vec::new();
        ports.select_unbound(40000..=40002, false, |port| {
            asked.push(port);
            false
        });
        assert_eq!(asked[0], 40001);
        asked.sort_unstable();
        assert_eq!(asked, [40000, 40001, 40002]);
        assert_eq!(
            ports.select(0, LOCAL, remote(1, 80), 65535..=65535, |_| true),
            Some(65535)
        );
        assert_eq!(
            ports.select_unbound(65534..=65535, false, |_| true),
            Some(65535)
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.3.4
    //= type=test
    //# The array "table[]" assures that successive transport-protocol
    //# instances with the same remote endpoint will use increasing ephemeral
    //# port numbers.
    // Opens to one destination take increasing ports (mod the range), each
    // further on than the last; the step is never more than eight ports
    // ahead of the ports tried.
    #[test]
    fn a_destination_takes_increasing_ports() {
        let mut ports = ports();
        let range = 32768..=60999;
        let span = 60999 - 32768 + 1;
        let mut last = ports
            .select(0, LOCAL, remote(1, 80), range.clone(), |_| true)
            .unwrap();
        for _ in 0..100 {
            let next = ports
                .select(0, LOCAL, remote(1, 80), range.clone(), |_| true)
                .unwrap();
            let ahead = (u32::from(next) + span - u32::from(last)) % span;
            assert!(
                ahead != 0 && ahead <= 16 && ahead % 2 == 0,
                "{last} -> {next}"
            );
            last = next;
        }
    }

    // The offset depends on the key, the destination and the ten-second
    // epoch: other keys, destinations or epochs start elsewhere.
    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.3
    //= type=test
    //# Ephemeral port selection algorithms SHOULD obfuscate the selection of
    //# their ephemeral ports, since this helps to mitigate a number of
    //# attacks that depend on the attacker's ability to guess or know the
    //# five-tuple that identifies the transport-protocol instance to be
    //# attacked.
    //= https://www.rfc-editor.org/rfc/rfc6056#section-3.4
    //= type=test
    //# To protect against this, the secret key should be of a reasonable
    //# length.  Key lengths of 128 bits should be adequate.
    #[test]
    fn the_offset_is_keyed_per_destination_and_epoch() {
        let range = 32768..=60999;
        let first = |ports: &mut EphemeralPorts, now, remote| {
            ports
                .select(now, LOCAL, remote, range.clone(), |_| true)
                .unwrap()
        };
        let a = first(&mut ports(), 0, remote(1, 80));
        assert_eq!(a, first(&mut ports(), 9_999_999, remote(1, 80)));
        let others = [
            first(&mut ports(), 0, remote(2, 80)),
            first(&mut ports(), 0, remote(1, 81)),
            first(&mut ports(), 10_000_000, remote(1, 80)),
            first(
                &mut EphemeralPorts::new([8; 16], CallerTimebase::default()).unwrap(),
                0,
                remote(1, 80),
            ),
        ];
        assert!(others.iter().all(|&port| port != a), "{a} {others:?}");
    }

    // Candidates that are no range: each index once, consecutively from the
    // destination's offset, and increasing for one destination.
    #[test]
    fn candidates_by_index() {
        let mut ports = ports();
        let mut asked = Vec::new();
        assert_eq!(
            ports.select_among(0, LOCAL, remote(1, 80), 5, |index| {
                asked.push(index);
                false
            }),
            None
        );
        assert_eq!(asked.len(), 5);
        assert!(asked.windows(2).all(|w| w[1] == (w[0] + 1) % 5));
        assert_eq!(
            ports.select_among(0, LOCAL, remote(1, 80), 0, |_| true),
            None
        );
        let mut last = ports
            .select_among(0, LOCAL, remote(1, 80), 1000, |_| true)
            .unwrap();
        for _ in 0..50 {
            let next = ports
                .select_among(0, LOCAL, remote(1, 80), 1000, |_| true)
                .unwrap();
            let ahead = (next + 1000 - last) % 1000;
            assert!(ahead != 0 && ahead <= 8, "{last} -> {next}");
            last = next;
        }
    }

    // A port with no destination starts at random among the upper parity,
    // then tries the lower, each port once; with SO_REUSEADDR it tries the
    // lower half of the range first.
    #[test]
    fn unbound_ports_start_at_random_upper_parity_first() {
        let mut ports = ports();
        let mut asked = Vec::new();
        assert_eq!(
            ports.select_unbound(32768..=32799, false, |port| {
                asked.push(port);
                false
            }),
            None
        );
        assert_eq!(asked.len(), 32);
        assert!(asked[..16].iter().all(|port| port % 2 == 1));
        assert!(asked[16..].iter().all(|port| port % 2 == 0));
        asked.sort_unstable();
        assert!(asked.iter().copied().eq(32768..=32799));
        let firsts: Vec<_> = (0..8)
            .map(|_| {
                ports
                    .select_unbound(32768..=60999, false, |_| true)
                    .unwrap()
            })
            .collect();
        assert!(firsts.iter().any(|&port| port != firsts[0]), "{firsts:?}");
        let mut asked = Vec::new();
        ports.select_unbound(32768..=32799, true, |port| {
            asked.push(port);
            false
        });
        assert_eq!(asked.len(), 32);
        assert!(asked[..16].iter().all(|&port| port < 32784));
        assert!(asked[16..].iter().all(|&port| port >= 32784));
        assert_eq!(
            ports.select_unbound(40000..=40000, false, |_| true),
            Some(40000)
        );
    }

    // Opens to other destinations do not move a destination's sequence
    // unless they share its space: with 2^16 spaces, 100 other destinations
    // leave the next port of the first where it would have been.
    #[test]
    fn other_destinations_leave_a_sequence_alone() {
        let range = 32768..=60999;
        let mut alone = ports();
        let mut busy = ports();
        alone.select(0, LOCAL, remote(1, 80), range.clone(), |_| true);
        busy.select(0, LOCAL, remote(1, 80), range.clone(), |_| true);
        for last in 2..102 {
            busy.select(0, LOCAL, remote(last, 80), range.clone(), |_| true);
        }
        assert_eq!(
            alone.select(0, LOCAL, remote(1, 80), range.clone(), |_| true),
            busy.select(0, LOCAL, remote(1, 80), range.clone(), |_| true)
        );
    }
}
