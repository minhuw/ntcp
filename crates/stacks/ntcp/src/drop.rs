// SPDX-License-Identifier: MIT
//! Why a frame or segment was discarded, counted per reason, and an opt-in
//! feed of the individual discards: Linux's `enum skb_drop_reason`
//! (include/net/dropreason-core.h), its per-reason drop statistics and the
//! drop_monitor feed dropwatch reads.
//!
//! Each layer that discards (Endpoint, Host, an adapter) owns a
//! `DropRecorder` and records every discard at the place it happens, as
//! Linux calls kfree_skb_reason there. A discard costs one counter
//! increment and one branch on whether the feed is enabled; nothing is
//! recorded, built or allocated on a path that discards nothing.
use core::net::{IpAddr, SocketAddr};

use crate::Instant;

macro_rules! drop_reasons {
    ($($(#[$doc:meta])* $variant:ident = $name:literal,)*) => {
        /// Why a frame, datagram or segment was discarded. The names are
        /// Linux's `SKB_DROP_REASON_*` where Linux has the same reason; the
        /// others are ntcp's, for discards Linux does not name or does not
        /// have.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[repr(u8)]
        pub enum DropReason {
            $($(#[$doc])* $variant,)*
        }

        impl DropReason {
            /// Every reason, in counter order.
            pub const ALL: [DropReason; DropReason::COUNT] = [$(DropReason::$variant,)*];

            /// The reason's name as dropwatch and the `skb:kfree_skb`
            /// tracepoint print it (without `SKB_DROP_REASON_`).
            pub const fn name(self) -> &'static str {
                match self {
                    $(DropReason::$variant => $name,)*
                }
            }
        }
    };
}

drop_reasons! {
    /// A discard no more specific reason describes (Linux's
    /// NOT_SPECIFIED): an embedding error refusing a received frame.
    NotSpecified = "NOT_SPECIFIED",
    // Device and link layer.
    /// The backend reported a received frame it could not deliver whole
    /// (truncated, bad metadata).
    DevHdr = "DEV_HDR",
    /// The frame's link-layer destination is not this port.
    OtherHost = "OTHERHOST",
    /// Neither IPv4, IPv6 nor ARP, or an IP version this port does not
    /// receive.
    UnhandledProto = "UNHANDLED_PROTO",
    /// Shorter than its headers.
    PktTooSmall = "PKT_TOO_SMALL",
    /// Larger than the link's packet limit, or (output) a stateless reply
    /// larger than its path's MTU.
    PktTooBig = "PKT_TOO_BIG",
    /// A member of shared flows could not hand a packet to the member that
    /// owns its flow (inbox full, or no member of that number), as Linux's
    /// enqueue_to_backlog drops one for another CPU.
    CpuBacklog = "CPU_BACKLOG",
    /// Received for a connection whose output was reserved while the pool
    /// of retained input was full (Linux's backlog of a socket the user
    /// owns).
    SocketBacklog = "SOCKET_BACKLOG",
    /// A SYN a member of shared flows could not hand to a listening member:
    /// its share of redirected flows was full.
    RedirectTableFull = "REDIRECT_TABLE_FULL",
    /// An ARP frame refused: malformed, of another hardware or protocol
    /// type, or on a port without ARP.
    ArpInvalid = "ARP_INVALID",
    // IP.
    IpCsum = "IP_CSUM",
    /// Any other error in an IPv4 header or its options (Linux's Ip
    /// InHdrErrors).
    IpInhdr = "IP_INHDR",
    /// The destination is no address this host owns on the arrival link.
    IpInaddrerrors = "IP_INADDRERRORS",
    /// A multicast, broadcast or unspecified source.
    IpInvalidSource = "IP_INVALID_SOURCE",
    /// A broadcast, multicast or unspecified destination for unicast
    /// transport, or a family mismatch.
    IpInvalidDest = "IP_INVALID_DEST",
    /// A protocol this host does not process.
    IpNoproto = "IP_NOPROTO",
    /// An IPv6 extension header refused or unsupported.
    Ipv6BadExthdr = "IPV6_BAD_EXTHDR",
    /// A source-routed packet that policy refuses (Linux discards one
    /// without a reason when accept_source_route is off).
    IpSourceRouteRefused = "IP_SOURCE_ROUTE_REFUSED",
    /// The embedding's address policy refused the addresses.
    AddressPolicy = "ADDRESS_POLICY",
    // Fragments.
    FragReasmTimeout = "FRAG_REASM_TIMEOUT",
    /// A fragment duplicating or overlapping one held.
    DupFrag = "DUP_FRAG",
    /// A fragment invalid in itself or contradicting its assembly (empty,
    /// misaligned, oversize, incomplete IPv6 header chain, options or ECN
    /// disagreeing, an IPv6 datagram already rejected).
    FragInvalid = "FRAG_INVALID",
    /// Reassembly storage (assemblies, fragments or bytes) or the
    /// reconstructed datagram's capacity was exceeded.
    FragReasmCapacity = "FRAG_REASM_CAPACITY",
    /// A fragment where this port does no reassembly.
    FragUnsupported = "FRAG_UNSUPPORTED",
    // ICMP.
    IcmpCsum = "ICMP_CSUM",
    /// A malformed ICMP message, or one this host does not accept here.
    IcmpInvalid = "ICMP_INVALID",
    /// An ICMP Source Quench, discarded (RFC 6633).
    IcmpSourceQuench = "ICMP_SOURCE_QUENCH",
    /// An ICMP error or Echo Reply that names no connection, submission or
    /// probe of this host, or more than one.
    IcmpNoSocket = "ICMP_NO_SOCKET",
    /// An ICMP error quoting a sequence outside its connection's sent
    /// space (Linux's OutOfWindowIcmps).
    IcmpOutOfWindow = "ICMP_OUT_OF_WINDOW",
    /// An ICMP message this host generates (an Echo Reply or an error) not
    /// queued: output disabled, too large, or no slot.
    IcmpOutputDropped = "ICMP_OUTPUT_DROPPED",
    // UDP.
    UdpCsum = "UDP_CSUM",
    /// A UDP datagram too large for its flow's receive slots, or for a
    /// full receive queue.
    SocketRcvbuff = "SOCKET_RCVBUFF",
    // TCP input.
    TcpCsum = "TCP_CSUM",
    /// No connection, TIME-WAIT record or listener: answered by a reset.
    NoSocket = "NO_SOCKET",
    /// A TCP option ntcp cannot parse.
    TcpInvalidOption = "TCP_INVALID_OPTION",
    /// Flags not acceptable in the connection's state (no ACK, no SYN in
    /// SYN-SENT, ACK or no SYN at a listener).
    TcpFlags = "TCP_FLAGS",
    /// The connection is closed, or its terminal reset is pending.
    TcpClose = "TCP_CLOSE",
    /// A reset outside the window, or not exactly at RCV.NXT (challenged).
    TcpReset = "TCP_RESET",
    /// A SYN where none is acceptable (challenged).
    TcpInvalidSyn = "TCP_INVALID_SYN",
    /// Entirely below RCV.NXT: a duplicate.
    TcpOldSequence = "TCP_OLD_SEQUENCE",
    /// Beyond the receive window.
    TcpInvalidSequence = "TCP_INVALID_SEQUENCE",
    /// An ACK that does not acknowledge the SYN.
    TcpInvalidAckSequence = "TCP_INVALID_ACK_SEQUENCE",
    /// An ACK below SND.UNA by more than the largest window sent.
    TcpTooOldAck = "TCP_TOO_OLD_ACK",
    /// An ACK beyond SND.NXT.
    TcpAckUnsentData = "TCP_ACK_UNSENT_DATA",
    /// A timestamp older than TS.Recent (RFC 7323 PAWS), or a SYN-ACK
    /// echoing a timestamp never sent.
    TcpRfc7323Paws = "TCP_RFC7323_PAWS",
    /// PAWS at a TIME-WAIT connection.
    TcpRfc7323TwPaws = "TCP_RFC7323_TW_PAWS",
    /// No Timestamps option on a connection that negotiated them (RFC 7323
    /// section 3.2); Linux accepts such segments.
    TcpMissingTimestamp = "TCP_MISSING_TIMESTAMP",
    /// The listener's accept queue is full: a SYN, or the last ACK of a
    /// handshake whose child cannot join it.
    TcpListenOverflow = "TCP_LISTEN_OVERFLOW",
    /// The listener's SYN queue is full (Linux's ListenDrops without
    /// syncookies).
    TcpSynQueueOverflow = "TCP_SYN_QUEUE_OVERFLOW",
    /// A SYN refused for want of a connection slot.
    TcpConnectionLimit = "TCP_CONNECTION_LIMIT",
    /// A SYN refused because the buffer budget or the allocator refused its
    /// connection's storage.
    MemoryRefused = "MEMORY_REFUSED",
    /// Text arriving while the receive window is zero.
    TcpZeroWindow = "TCP_ZEROWINDOW",
    /// Text wholly beyond the receive window, or after the peer's FIN.
    TcpOverWindow = "TCP_OVERWINDOW",
    /// Text wholly received before (a spurious retransmission).
    TcpOldData = "TCP_OLD_DATA",
    /// Out-of-order text wholly held already.
    TcpOfoMerge = "TCP_OFOMERGE",
    /// New text after the application closed the receive side: the
    /// connection is reset.
    TcpAbortOnData = "TCP_ABORT_ON_DATA",
    /// Embedding-supplied receive metadata or time the Endpoint refused.
    InvalidMetadata = "INVALID_METADATA",
    // Output.
    /// No route or path to send on: a SYN whose answer has no path, a
    /// stateless reply whose link is gone.
    IpOutnoroutes = "IP_OUTNOROUTES",
    /// The backend synchronously refused the frame (`TxOutcome::Rejected`).
    BackendRefused = "BACKEND_REFUSED",
    /// The next hop's resolution failed.
    NeighFailed = "NEIGH_FAILED",
    /// No neighbour entry or held-frame record was free for the next hop.
    NeighQueueFull = "NEIGH_QUEUEFULL",
    /// A stateless reply whose path changed before it was submitted.
    StaleEgress = "STALE_EGRESS",
    /// Prepared output of a connection aborted before it was submitted.
    SocketClose = "SOCKET_CLOSE",
}

impl DropReason {
    /// The number of reasons.
    pub const COUNT: usize = DropReason::SocketClose as usize + 1;
}

impl core::fmt::Display for DropReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Discards counted by reason: a fixed array indexed by `DropReason`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropCounts([u64; DropReason::COUNT]);

impl Default for DropCounts {
    fn default() -> Self {
        Self([0; DropReason::COUNT])
    }
}

impl DropCounts {
    pub const fn get(&self, reason: DropReason) -> u64 {
        self.0[reason as usize]
    }
    /// Every discard, whatever its reason.
    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }
    /// The reasons with their counts, in `DropReason::ALL` order.
    pub fn iter(&self) -> impl Iterator<Item = (DropReason, u64)> + '_ {
        DropReason::ALL
            .iter()
            .map(|&reason| (reason, self.get(reason)))
    }
}

impl core::ops::Index<DropReason> for DropCounts {
    type Output = u64;
    fn index(&self, reason: DropReason) -> &u64 {
        &self.0[reason as usize]
    }
}

impl core::ops::Add for DropCounts {
    type Output = Self;
    fn add(mut self, other: Self) -> Self {
        self += other;
        self
    }
}

impl core::ops::AddAssign for DropCounts {
    fn add_assign(&mut self, other: Self) {
        for (count, add) in self.0.iter_mut().zip(other.0) {
            *count += add;
        }
    }
}

/// What a discard was of, as far as the layer that discarded it knew.
/// Received packets name the remote end as source; output names the local
/// end as source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropSubject {
    /// Nothing parsed: no link layer header or IP header to name.
    Unknown,
    /// A frame not taken as IP, by its EtherType.
    Link { ethertype: u16 },
    Ip {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    },
    /// A TCP or UDP packet whose ports were read.
    Transport {
        protocol: u8,
        source: SocketAddr,
        destination: SocketAddr,
    },
}

impl DropSubject {
    /// The subject of an IP packet, as much of it as its headers hold: its
    /// ports when its IPv4 or IPv6 base header is followed by at least the
    /// ports of a TCP or UDP header.
    pub fn of_ip_packet(packet: &[u8]) -> Self {
        let (source, destination, protocol, header): (IpAddr, IpAddr, u8, usize) =
            match packet.first().map(|b| b >> 4) {
                Some(4) if packet.len() >= 20 => {
                    let s: [u8; 4] = packet[12..16].try_into().unwrap();
                    let d: [u8; 4] = packet[16..20].try_into().unwrap();
                    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
                    let header = if fragment == 0 {
                        usize::from(packet[0] & 15) * 4
                    } else {
                        usize::MAX
                    };
                    (s.into(), d.into(), packet[9], header)
                }
                Some(6) if packet.len() >= 40 => {
                    let s: [u8; 16] = packet[8..24].try_into().unwrap();
                    let d: [u8; 16] = packet[24..40].try_into().unwrap();
                    (s.into(), d.into(), packet[6], 40)
                }
                _ => return Self::Unknown,
            };
        match (protocol, packet.get(header..header.saturating_add(4))) {
            (6 | 17, Some(ports)) => Self::Transport {
                protocol,
                source: SocketAddr::new(source, u16::from_be_bytes([ports[0], ports[1]])),
                destination: SocketAddr::new(destination, u16::from_be_bytes([ports[2], ports[3]])),
            },
            _ => Self::Ip {
                source,
                destination,
                protocol,
            },
        }
    }

    /// The subject of an Ethernet frame: its IP packet's, or its EtherType.
    pub fn of_ethernet_frame(frame: &[u8]) -> Self {
        match frame.get(12..14).map(|t| u16::from_be_bytes([t[0], t[1]])) {
            Some(0x0800 | 0x86dd) => Self::of_ip_packet(&frame[14..]),
            Some(ethertype) => Self::Link { ethertype },
            None => Self::Unknown,
        }
    }
}

/// One discard, as the feed reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropEvent {
    pub reason: DropReason,
    /// The discarding layer's clock when it discarded.
    pub at: Instant,
    pub subject: DropSubject,
    /// Octets of what was discarded where it was discarded: the frame, IP
    /// packet or TCP segment.
    pub len: usize,
}

// The feed's storage, allocated whole when enabled: never grown, so a
// discard never allocates. Past `capacity` waiting events a discard is only
// counted lost, as drop_monitor counts an alert its full queue refuses.
#[derive(Debug)]
struct DropFeed {
    events: alloc::collections::VecDeque<DropEvent>,
    capacity: usize,
    lost: u64,
}

/// A layer's per-reason discard counts and, while enabled, its feed of
/// individual discards.
#[derive(Debug, Default)]
pub struct DropRecorder {
    counts: DropCounts,
    // The sum of `counts`, for a caller that reads it often.
    total: u64,
    feed: Option<alloc::boxed::Box<DropFeed>>,
    // The error the last call returned was recorded here (`record_error`).
    error_recorded: bool,
}

impl DropRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one discard and, with the feed enabled, report it. `subject`
    /// is only evaluated for the feed.
    #[inline]
    pub fn record(
        &mut self,
        reason: DropReason,
        at: Instant,
        len: usize,
        subject: impl FnOnce() -> DropSubject,
    ) {
        self.counts.0[reason as usize] += 1;
        self.total += 1;
        if let Some(feed) = &mut self.feed {
            feed.push(DropEvent {
                reason,
                at,
                subject: subject(),
                len,
            });
        }
    }

    /// `record` the discard an error about to be returned stands for, so
    /// that the caller that swallows the error does not record it again
    /// (`take_error_recorded`).
    pub fn record_error(
        &mut self,
        reason: DropReason,
        at: Instant,
        len: usize,
        subject: impl FnOnce() -> DropSubject,
    ) {
        self.record(reason, at, len, subject);
        self.error_recorded = true;
    }

    /// Whether the error the last call returned was recorded already;
    /// clears it.
    pub fn take_error_recorded(&mut self) -> bool {
        core::mem::take(&mut self.error_recorded)
    }

    pub fn counts(&self) -> DropCounts {
        self.counts
    }

    /// Every discard recorded: `counts().total()`, without the sum.
    pub fn total(&self) -> u64 {
        debug_assert_eq!(self.total, self.counts.total());
        self.total
    }

    /// Enable the feed with room for `capacity` waiting events, discarding
    /// any waiting; 0 disables it and frees its storage. Err leaves the feed
    /// disabled when its storage cannot be allocated.
    pub fn set_feed(&mut self, capacity: usize) -> Result<(), crate::Error> {
        self.feed = None;
        if capacity == 0 {
            return Ok(());
        }
        let mut events = alloc::collections::VecDeque::new();
        events
            .try_reserve_exact(capacity)
            .map_err(|_| crate::Error::NoMemory)?;
        self.feed = Some(alloc::boxed::Box::new(DropFeed {
            events,
            capacity,
            lost: 0,
        }));
        Ok(())
    }

    /// The feed's capacity; 0 while disabled.
    pub fn feed_capacity(&self) -> usize {
        self.feed.as_ref().map_or(0, |f| f.capacity)
    }

    /// Discards the enabled feed had no room to report.
    pub fn feed_lost(&self) -> u64 {
        self.feed.as_ref().map_or(0, |f| f.lost)
    }

    /// The oldest waiting event's time.
    pub fn next_event_at(&self) -> Option<Instant> {
        self.feed.as_ref()?.events.front().map(|e| e.at)
    }

    /// Take the oldest waiting event.
    pub fn take_event(&mut self) -> Option<DropEvent> {
        self.feed.as_mut()?.events.pop_front()
    }
}

impl DropFeed {
    #[cold]
    fn push(&mut self, event: DropEvent) {
        if self.events.len() < self.capacity {
            self.events.push_back(event);
        } else {
            self.lost += 1;
        }
    }
}

/// Take the waiting events of several recorders oldest first (the earlier
/// recorder first among equal times), until `f` has had them all.
pub fn drain_drop_events(recorders: &mut [&mut DropRecorder], mut f: impl FnMut(DropEvent)) {
    loop {
        let mut next: Option<(usize, Instant)> = None;
        for (index, recorder) in recorders.iter().enumerate() {
            if let Some(at) = recorder.next_event_at()
                && next.is_none_or(|(_, earliest)| at < earliest)
            {
                next = Some((index, at));
            }
        }
        let Some((index, _)) = next else {
            return;
        };
        f(recorders[index].take_event().unwrap());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn record(r: &mut DropRecorder, reason: DropReason, at: Instant) {
        r.record(reason, at, 40, || DropSubject::Unknown);
    }

    #[test]
    fn reasons_are_listed_once_in_counter_order_with_distinct_names() {
        for (index, reason) in DropReason::ALL.iter().enumerate() {
            assert_eq!(*reason as usize, index);
        }
        let mut names: Vec<_> = DropReason::ALL.iter().map(|r| r.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), DropReason::COUNT);
    }

    #[test]
    fn counts_sum_to_the_total_without_a_feed() {
        let mut r = DropRecorder::new();
        let mut evaluated = false;
        r.record(DropReason::TcpCsum, 1, 40, || {
            evaluated = true;
            DropSubject::Unknown
        });
        record(&mut r, DropReason::TcpCsum, 2);
        record(&mut r, DropReason::NoSocket, 3);
        // Disabled, the feed neither evaluates the subject nor keeps events.
        assert!(!evaluated);
        assert_eq!(r.take_event(), None);
        assert_eq!((r.feed_capacity(), r.feed_lost()), (0, 0));
        let counts = r.counts();
        assert_eq!(counts[DropReason::TcpCsum], 2);
        assert_eq!(counts[DropReason::NoSocket], 1);
        assert_eq!(counts.total(), 3);
        assert_eq!(r.total(), 3);
        assert_eq!(counts.iter().map(|(_, n)| n).sum::<u64>(), 3);
        assert_eq!((counts + counts).total(), 6);
    }

    #[test]
    fn the_feed_keeps_at_most_its_capacity_and_counts_the_rest() {
        let mut r = DropRecorder::new();
        r.set_feed(2).unwrap();
        assert_eq!(r.feed_capacity(), 2);
        for at in 0..5 {
            record(&mut r, DropReason::DupFrag, at);
        }
        assert_eq!(r.feed_lost(), 3);
        assert_eq!(r.take_event().map(|e| e.at), Some(0));
        // Room again for one.
        record(&mut r, DropReason::PktTooSmall, 9);
        assert_eq!(r.take_event().map(|e| e.at), Some(1));
        let last = r.take_event().unwrap();
        assert_eq!(
            (last.reason, last.at, last.len),
            (DropReason::PktTooSmall, 9, 40)
        );
        assert_eq!(r.take_event(), None);
        assert_eq!(r.counts().total(), 6);
        // Disabled again, nothing waits and nothing is kept.
        r.set_feed(0).unwrap();
        record(&mut r, DropReason::DupFrag, 10);
        assert_eq!(r.take_event(), None);
        assert_eq!((r.feed_capacity(), r.feed_lost()), (0, 0));
    }

    #[test]
    fn several_feeds_drain_oldest_first() {
        let (mut a, mut b) = (DropRecorder::new(), DropRecorder::new());
        a.set_feed(4).unwrap();
        b.set_feed(4).unwrap();
        record(&mut a, DropReason::NoSocket, 1);
        record(&mut b, DropReason::OtherHost, 0);
        record(&mut a, DropReason::NoSocket, 3);
        record(&mut b, DropReason::OtherHost, 3);
        let mut order = Vec::new();
        drain_drop_events(&mut [&mut a, &mut b], |e| order.push((e.at, e.reason)));
        assert_eq!(
            order,
            [
                (0, DropReason::OtherHost),
                (1, DropReason::NoSocket),
                (3, DropReason::NoSocket),
                (3, DropReason::OtherHost),
            ]
        );
    }

    #[test]
    fn subjects_name_what_the_headers_hold() {
        let mut ipv4 = [0u8; 24];
        ipv4[0] = 0x45;
        ipv4[9] = 6;
        ipv4[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ipv4[16..20].copy_from_slice(&[192, 0, 2, 2]);
        ipv4[20..24].copy_from_slice(&[0x9c, 0x40, 0, 80]);
        assert_eq!(
            DropSubject::of_ip_packet(&ipv4),
            DropSubject::Transport {
                protocol: 6,
                source: "192.0.2.1:40000".parse().unwrap(),
                destination: "192.0.2.2:80".parse().unwrap(),
            }
        );
        // A later fragment holds no ports.
        ipv4[7] = 1;
        assert!(matches!(
            DropSubject::of_ip_packet(&ipv4),
            DropSubject::Ip { protocol: 6, .. }
        ));
        assert_eq!(DropSubject::of_ip_packet(&ipv4[..10]), DropSubject::Unknown);
        let mut frame = [0u8; 60];
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(
            DropSubject::of_ethernet_frame(&frame),
            DropSubject::Link { ethertype: 0x0806 }
        );
    }
}
