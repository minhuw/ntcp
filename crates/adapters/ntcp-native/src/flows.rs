// The TCP flows of the IPv4 addresses that the Networks on one port's
// queues serve, divided among them by one ownership function that every
// member computes alike. A member takes in a packet that arrives on its
// queue only for a flow it owns; any other it copies into the owner's inbox,
// which the owner drains as it drives. Steering by the NIC, when the port
// has it, only spares the copy: a NIC that delivers a packet to the wrong
// queue, or one that cannot steer at all, costs a handoff, never a
// connection. An ICMP error belongs to the flow it quotes, and a fragment
// to the member that reassembles its datagram, which hands the reassembled
// datagram to the flow's owner.
//
// The owner takes a handoff in as if its own queue had received it and asks
// no other member about it: the function partitions the tuples, and active
// opens choose local ports whose flows they own, so a segment for which the
// owner has no connection is one no member has. The members' listening
// ports are counted here so that no member's active open takes one.
use crate::{Error, Result, inbox::Inbox, toeplitz::Toeplitz};
use std::{
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    ops::RangeInclusive,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

pub use crate::toeplitz::DEFAULT_KEY as DEFAULT_FLOW_KEY;

/// How the members of a `SharedFlows` divide its flows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowOwnership {
    /// Every member has its own IPv4 address: a flow belongs to the member
    /// whose address is the flow's local address, and a fragment is
    /// reassembled by the member it is addressed to.
    ByAddress,
    /// Every member serves one IPv4 address. The flow between `local` and
    /// `remote` belongs to member `table[h & (table.len() - 1)]`, `h` being
    /// the Toeplitz hash under `key` of remote address, local address,
    /// remote port and local port: RSS's IPv4 TCP input for a packet the
    /// port receives. A fragment is reassembled by member
    /// `table[h2 & (table.len() - 1)]`, `h2` hashing source and destination
    /// address only, as RSS hashes an IPv4 packet without ports. When the
    /// NIC hashes with this key, `table` maps its indirection table's
    /// queues to their members, and packets arrive at their owners. Only
    /// a member the table names joins (`Network::with_shared_flows`): any
    /// other would own no flow, and could neither open nor accept a
    /// connection.
    Hash { key: Vec<u8>, table: Vec<usize> },
    /// Every member serves one IPv4 address, as under `Hash { key, table }`,
    /// except for the flows of a tagged local port: a port `p` with
    /// `p & prefix_mask == prefix` and `p & low` below the member count,
    /// `low` being the least `2^b - 1` not below the highest member number.
    /// Its flows belong to member `p & low` whatever the remote, and a
    /// member's active opens take only its own tagged ports. A NIC rule on
    /// the TCP destination port (`SharedFlows::port_rule`) then steers the
    /// replies to a member's active opens to its queue, where under Hash
    /// the member would search ports for one the NIC's hash puts there,
    /// and RSS with `key` and `table` steers the rest. Only its member
    /// listens on a tagged port (`Network::with_shared_flows`). A member
    /// the table does not name owns the flows of its tagged ports alone,
    /// which is enough to open connections and to accept them there.
    /// `prefix_mask` is nonzero and spares the bits of `low`, and `prefix`
    /// lies within it.
    TaggedPorts {
        key: Vec<u8>,
        table: Vec<usize>,
        prefix: u16,
        prefix_mask: u16,
    },
}

/// Storage of a `SharedFlows`, allocated by `SharedFlows::new`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedFlowLimits {
    /// Members, numbered from 0; `FlowOwnership::Hash` tables name them.
    pub members: usize,
    /// Packets each member's inbox holds. A handoff to a full inbox is
    /// dropped and counted, as a NIC drops when a queue overflows.
    pub inbox_packets: usize,
    /// Octets preallocated for each inbox packet, so that a handoff copies
    /// into a buffer it never allocates: at least the largest IP packet a
    /// member takes in, its MTU or, unless ownership is
    /// `FlowOwnership::ByAddress`, the larger datagram it reassembles
    /// (`Network::with_shared_flows` refuses a member otherwise). Only a
    /// packet beyond that, which the owner's Host refuses, allocates.
    pub packet_bytes: usize,
}

/// The divided flows of one port, shared by the Networks built on it with
/// `Network::with_shared_flows`, one per queue and worker thread. Clones
/// name the same flows.
#[derive(Clone)]
pub struct SharedFlows {
    shared: Arc<Shared>,
}

struct Shared {
    ownership: Ownership,
    limits: SharedFlowLimits,
    slots: Box<[Slot]>,
    registry: Mutex<Registry>,
}

enum Ownership {
    ByAddress,
    Hash {
        hash: Toeplitz,
        table: Box<[usize]>,
    },
    TaggedPorts {
        hash: Toeplitz,
        table: Box<[usize]>,
        tags: Tags,
    },
}

// The local ports of `FlowOwnership::TaggedPorts` that are tagged with a
// member.
struct Tags {
    prefix: u16,
    mask: u16,
    // The bits that number the member.
    low: u16,
    members: usize,
}

impl Tags {
    fn new(prefix: u16, mask: u16, members: usize) -> Result<Self> {
        let low = members
            .checked_next_power_of_two()
            .and_then(|n| u16::try_from(n - 1).ok());
        match low {
            Some(low) if mask != 0 && mask & low == 0 && prefix & !mask == 0 => Ok(Self {
                prefix,
                mask,
                low,
                members,
            }),
            _ => Err(Error::InvalidConfig(
                "a port tag is a prefix within a nonzero mask that spares the member bits",
            )),
        }
    }
    // The member local port `port` is tagged with.
    fn member(&self, port: u16) -> Option<usize> {
        let member = usize::from(port & self.low);
        (port & self.mask == self.prefix && member < self.members).then_some(member)
    }
    fn rule(&self, member: usize) -> Option<PortRule> {
        if member >= self.members {
            return None;
        }
        // A member number is within `low`, a u16.
        let tag = u16::try_from(member).ok()?;
        Some(PortRule {
            value: self.prefix | tag,
            mask: self.mask | self.low,
        })
    }
}

/// The local ports whose bits under `mask` are `value`: the tagged ports of
/// one member of `FlowOwnership::TaggedPorts`, which a rule on the TCP
/// destination port steers to its queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortRule {
    value: u16,
    mask: u16,
}

impl PortRule {
    /// The least port in `ports` that the rule takes, found from the bits
    /// of its bounds without visiting the ports between.
    pub(crate) fn first_in(self, ports: RangeInclusive<u16>) -> Option<u16> {
        let (start, end) = ports.into_inner();
        let near = start & !self.mask | self.value;
        // The highest bit where `start` differs from the rule's value.
        let first = match (near ^ start).checked_ilog2() {
            None => start,
            // The value sets it: `start`'s free bits above it, none below.
            Some(top) if near > start => near & !(!self.mask & ((1 << top) - 1)),
            // `start` sets it: its free bits above it advance by one, and
            // none below are set.
            Some(top) => {
                let carried = (start | self.mask | u16::MAX >> (15 - top)).checked_add(1)?;
                carried & !self.mask | self.value
            }
        };
        (first <= end).then_some(first)
    }
}

// The key and table of hashed flows.
fn hashing(key: &[u8], table: Vec<usize>, members: usize) -> Result<(Toeplitz, Box<[usize]>)> {
    if !table.len().is_power_of_two() || table.iter().any(|&m| m >= members) {
        return Err(Error::InvalidConfig(
            "a flow table has a power-of-two length and names members",
        ));
    }
    let hash = Toeplitz::new(key).ok_or(Error::InvalidConfig(
        "a flow key covers IPv4 addresses and ports",
    ))?;
    Ok((hash, table.into_boxed_slice()))
}

// One member's place in the flows.
struct Slot {
    // The member's address as `present` encodes it, or 0 while no member
    // has the slot. Changed under the registry's lock; read without it by
    // the members that hand off and by `SharedFlows::owner`.
    address: AtomicU64,
    inbox: Inbox<Handoff>,
    // A handoff arrived since the member's drive last looked: the first one
    // after that writes its wake descriptor.
    woken: AtomicBool,
    wake: Mutex<Option<Arc<File>>>,
}

struct Registry {
    // The local ports members listen on, ascending, each with the number of
    // members listening; room for every member's listeners is reserved
    // when it joins.
    listening: Vec<(u16, usize)>,
    reserved: usize,
    // Per member, once it declared it (`Member::reassemble`), the IPv4
    // datagram capacity it reassembles up to, None without reassembly.
    reassembly: Vec<Option<Option<usize>>>,
}

impl Registry {
    fn unlisten(&mut self, port: u16) {
        if let Ok(at) = self.listening.binary_search_by_key(&port, |&(p, _)| p) {
            self.listening[at].1 -= 1;
            if self.listening[at].1 == 0 {
                self.listening.remove(at);
            }
        }
    }
}

const PACKET_BYTES: Error =
    Error::InvalidConfig("the packets of shared flows hold a member's largest IP packet");

// A slot's word for a member with `address`: never 0.
fn present(address: Ipv4Addr) -> u64 {
    1 << 32 | u64::from(u32::from(address))
}

// A member that panicked while holding a lock leaves nothing half changed:
// every change under it completes before the lock is released.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SharedFlows {
    pub fn new(ownership: FlowOwnership, limits: SharedFlowLimits) -> Result<Self> {
        if limits.members == 0 || limits.inbox_packets == 0 || limits.packet_bytes == 0 {
            return Err(Error::InvalidConfig(
                "shared flows need members, inbox packets and packet octets",
            ));
        }
        let ownership = match ownership {
            FlowOwnership::ByAddress => Ownership::ByAddress,
            FlowOwnership::Hash { key, table } => {
                let (hash, table) = hashing(&key, table, limits.members)?;
                Ownership::Hash { hash, table }
            }
            FlowOwnership::TaggedPorts {
                key,
                table,
                prefix,
                prefix_mask,
            } => {
                let (hash, table) = hashing(&key, table, limits.members)?;
                let tags = Tags::new(prefix, prefix_mask, limits.members)?;
                Ownership::TaggedPorts { hash, table, tags }
            }
        };
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.members)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..limits.members {
            slots.push(Slot {
                address: AtomicU64::new(0),
                inbox: Inbox::new(limits.inbox_packets, limits.packet_bytes)?,
                woken: AtomicBool::new(false),
                wake: Mutex::new(None),
            });
        }
        let mut reassembly = Vec::new();
        reassembly
            .try_reserve_exact(limits.members)
            .map_err(|_| Error::Capacity)?;
        reassembly.resize(limits.members, None);
        let registry = Registry {
            listening: Vec::new(),
            reserved: 0,
            reassembly,
        };
        Ok(Self {
            shared: Arc::new(Shared {
                ownership,
                limits,
                slots: slots.into_boxed_slice(),
                registry: Mutex::new(registry),
            }),
        })
    }

    pub fn limits(&self) -> SharedFlowLimits {
        self.shared.limits
    }

    /// The member that owns the TCP flow between `local` and `remote`. Under
    /// `FlowOwnership::ByAddress`, None unless a member serves `local`'s
    /// address; under `FlowOwnership::Hash` and `FlowOwnership::TaggedPorts`,
    /// None unless the members' address is `local`'s.
    pub fn owner(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<usize> {
        self.shared
            .route(*local.ip(), None, Some(local.port()), |hash| {
                hash.ipv4_ports(*remote.ip(), *local.ip(), remote.port(), local.port())
            })
    }

    /// The member that reassembles a fragment from `source` to
    /// `destination`, under the same conditions as `owner`.
    pub fn reassembler(&self, source: Ipv4Addr, destination: Ipv4Addr) -> Option<usize> {
        self.shared.route(destination, None, None, |hash| {
            hash.ipv4(source, destination)
        })
    }

    /// Under `FlowOwnership::TaggedPorts`, the rule on the TCP destination
    /// port that steers member `member`'s tagged ports to its queue: the
    /// value the port has under the mask, `(prefix | member, prefix_mask |
    /// low)`, as the DPDK and AF_XDP backends' `steer_tcp_port` take them.
    /// None under other ownership, or for no member.
    pub fn port_rule(&self, member: usize) -> Option<(u16, u16)> {
        self.tagged(member).map(|rule| (rule.value, rule.mask))
    }

    /// Member `member`'s tagged ports, under `FlowOwnership::TaggedPorts`.
    pub(crate) fn tagged(&self, member: usize) -> Option<PortRule> {
        self.shared.tagged(member)
    }

    // Member `index`, serving `address` with packets of up to `mtu` octets,
    // with room to register `listeners` listening ports.
    pub(crate) fn join(
        &self,
        index: usize,
        address: IpAddr,
        mtu: usize,
        listeners: usize,
    ) -> Result<Member> {
        let IpAddr::V4(address) = address else {
            return Err(Error::Unsupported("shared flows of IPv6 addresses"));
        };
        let shared = &self.shared;
        let slot = shared.slots.get(index).ok_or(Error::InvalidConfig(
            "members of shared flows are numbered below their count",
        ))?;
        if let Ownership::Hash { table, .. } = &shared.ownership
            && !table.contains(&index)
        {
            return Err(Error::InvalidConfig(
                "members of hashed shared flows are named by their table",
            ));
        }
        if mtu > shared.limits.packet_bytes {
            return Err(PACKET_BYTES);
        }
        let mut registry = lock(&shared.registry);
        if slot.address.load(Ordering::Relaxed) != 0 {
            return Err(Error::InvalidConfig(
                "a member of shared flows joins them once",
            ));
        }
        let word = present(address);
        let mut joined = shared
            .slots
            .iter()
            .map(|s| s.address.load(Ordering::Relaxed))
            .filter(|&a| a != 0);
        match shared.ownership {
            Ownership::ByAddress if joined.any(|a| a == word) => {
                return Err(Error::InvalidConfig(
                    "members of shared flows by address have distinct addresses",
                ));
            }
            Ownership::Hash { .. } | Ownership::TaggedPorts { .. } if joined.any(|a| a != word) => {
                return Err(Error::InvalidConfig(
                    "members of hashed shared flows serve one address",
                ));
            }
            _ => {}
        }
        let mut listening = Vec::new();
        listening
            .try_reserve_exact(listeners)
            .map_err(|_| Error::Capacity)?;
        let reserved = registry
            .reserved
            .checked_add(listeners)
            .ok_or(Error::Capacity)?;
        let len = registry.listening.len();
        registry
            .listening
            .try_reserve_exact(reserved - len)
            .map_err(|_| Error::Capacity)?;
        registry.reserved = reserved;
        // Handoffs to an earlier member of the slot are not this one's: its
        // connections left with it.
        slot.inbox.drain(shared.limits.inbox_packets, |_, _| {});
        slot.woken.store(false, Ordering::Relaxed);
        slot.address.store(word, Ordering::Release);
        Ok(Member {
            shared: shared.clone(),
            index,
            address,
            listeners,
            listening,
        })
    }
}

impl Shared {
    // The member that owns what `hash` selects among the flows of local
    // address `address`, or the flows of tagged local port `port`. `me`, a
    // member and its own address, answers for that address without reading
    // the slots: under Hash and TaggedPorts every member's address is the
    // group's.
    fn route(
        &self,
        address: Ipv4Addr,
        me: Option<(usize, Ipv4Addr)>,
        port: Option<u16>,
        hash: impl FnOnce(&Toeplitz) -> u32,
    ) -> Option<usize> {
        match &self.ownership {
            Ownership::ByAddress => match me {
                Some((index, own)) if own == address => Some(index),
                _ => self.serving(address),
            },
            Ownership::Hash {
                hash: toeplitz,
                table,
            } => self
                .serves(address, me)
                .then(|| table[hash(toeplitz) as usize & (table.len() - 1)]),
            Ownership::TaggedPorts {
                hash: toeplitz,
                table,
                tags,
            } => self.serves(address, me).then(|| {
                port.and_then(|p| tags.member(p))
                    .unwrap_or_else(|| table[hash(toeplitz) as usize & (table.len() - 1)])
            }),
        }
    }
    // Whether the members of hashed flows serve `address`.
    fn serves(&self, address: Ipv4Addr, me: Option<(usize, Ipv4Addr)>) -> bool {
        match me {
            Some((_, own)) => own == address,
            None => self.serving(address).is_some(),
        }
    }
    fn tagged(&self, member: usize) -> Option<PortRule> {
        match &self.ownership {
            Ownership::TaggedPorts { tags, .. } => tags.rule(member),
            _ => None,
        }
    }
    // The member that serves `address`, the first of them under Hash.
    fn serving(&self, address: Ipv4Addr) -> Option<usize> {
        let word = present(address);
        self.slots
            .iter()
            .position(|s| s.address.load(Ordering::Acquire) == word)
    }
}

/// What decides which member takes in an IPv4 packet that arrives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Key {
    /// No flow of the members: the receiving member's Host decides.
    Local,
    /// A fragment, which the member of its addresses reassembles.
    Fragment {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    /// A segment of, or an ICMP error about, the TCP flow between `local`
    /// and `remote`.
    Flow {
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
}

const ICMP: u8 = 1;
const TCP: u8 = 6;
// More Fragments, and the fragment offset.
const MORE: u16 = 0x2000;
const OFFSET: u16 = 0x1fff;

// The fields of an IPv4 header the key is made of.
struct Header {
    len: usize,
    fragment: u16,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

// None unless `packet` begins with a whole IPv4 header.
fn header(packet: &[u8]) -> Option<Header> {
    let first = *packet.first()?;
    let len = usize::from(first & 15) * 4;
    if first >> 4 != 4 || len < 20 || packet.len() < len {
        return None;
    }
    let address =
        |at: usize| Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]);
    Some(Header {
        len,
        fragment: u16::from_be_bytes([packet[6], packet[7]]),
        protocol: packet[9],
        source: address(12),
        destination: address(16),
    })
}

fn ports(transport: &[u8]) -> Option<(u16, u16)> {
    let ports = transport.get(..4)?;
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

/// The key of one IPv4 packet as it arrived (L3 octets, an Ethernet frame's
/// padding allowed). A fragment is keyed by its addresses whatever it
/// carries: only the reassembled datagram has a flow. A packet that is not
/// IPv4 or whose header or length is malformed is Local: the Host refuses
/// it as it would any.
pub(crate) fn key(packet: &[u8]) -> Key {
    let Some(header) = header(packet) else {
        return Key::Local;
    };
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let Some(payload) = packet.get(header.len..total) else {
        return Key::Local;
    };
    if header.fragment & (MORE | OFFSET) != 0 {
        return Key::Fragment {
            source: header.source,
            destination: header.destination,
        };
    }
    match header.protocol {
        TCP => match ports(payload) {
            Some((source, destination)) => Key::Flow {
                local: SocketAddrV4::new(header.destination, destination),
                remote: SocketAddrV4::new(header.source, source),
            },
            None => Key::Local,
        },
        ICMP => quoted(payload).unwrap_or(Key::Local),
        _ => Key::Local,
    }
}

// The flow of an ICMP error about a TCP segment a member sent: Destination
// Unreachable, Source Quench, Redirect, Time Exceeded or Parameter Problem
// quoting the IPv4 header of a segment that is no fragment after the first,
// and the 64 bits of its TCP header that follow (RFC 792). The quoted
// source is the member's side. Echo and every other message are the
// receiving member's.
fn quoted(message: &[u8]) -> Option<Key> {
    if !matches!(message.first()?, 3 | 4 | 5 | 11 | 12) {
        return None;
    }
    let quote = message.get(8..)?;
    let header = header(quote)?;
    if header.protocol != TCP || header.fragment & OFFSET != 0 {
        return None;
    }
    let (source, destination) = ports(quote.get(header.len..header.len + 8)?)?;
    Some(Key::Flow {
        local: SocketAddrV4::new(header.source, source),
        remote: SocketAddrV4::new(header.destination, destination),
    })
}

/// Whether `packet`, as it arrived, is an IPv4 fragment: a datagram the
/// Host completes on it is a reassembled one.
pub(crate) fn fragment(packet: &[u8]) -> bool {
    header(packet).is_some_and(|h| h.fragment & (MORE | OFFSET) != 0)
}

/// What a member hands over with a packet: its receive metadata as the
/// backend reported it, which the owner reads against its own clocks, and
/// for a datagram the sender reassembled its envelope (`Host::adopt_datagram`).
#[derive(Clone, Copy)]
pub(crate) struct Handoff {
    pub(crate) timestamps: ntcp_io::PacketTimestamps,
    pub(crate) tcp_segment_size: Option<NonZeroU16>,
    pub(crate) reassembled: Option<ntcp_host::Envelope>,
}

/// One Network's membership in shared flows. Dropping it leaves them: its
/// slot is free, handoffs to it are refused, and its listening ports no
/// longer count.
pub(crate) struct Member {
    shared: Arc<Shared>,
    index: usize,
    address: Ipv4Addr,
    listeners: usize,
    // The ports this member registered as listening, as many times as it
    // listens on each.
    listening: Vec<u16>,
}

/// A member's inbox, held apart from its Network while the Network takes in
/// what it drains.
pub(crate) struct Inlet {
    shared: Arc<Shared>,
    index: usize,
}

impl Inlet {
    pub(crate) fn drain(&self, budget: usize, f: impl FnMut(&[u8], Handoff)) -> usize {
        self.shared.slots[self.index].inbox.drain(budget, f)
    }
}

impl Member {
    fn me(&self) -> Option<(usize, Ipv4Addr)> {
        Some((self.index, self.address))
    }
    fn flow(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<usize> {
        self.shared
            .route(*local.ip(), self.me(), Some(local.port()), |hash| {
                hash.ipv4_ports(*remote.ip(), *local.ip(), remote.port(), local.port())
            })
    }
    /// The other member that takes in a packet of `key`. None for this
    /// member's own, and for one of an address no member serves, which this
    /// member's Host decides.
    pub(crate) fn elsewhere(&self, key: Key) -> Option<usize> {
        let owner = match key {
            Key::Local => None,
            Key::Fragment {
                source,
                destination,
            } => self.shared.route(destination, self.me(), None, |hash| {
                hash.ipv4(source, destination)
            }),
            Key::Flow { local, remote } => self.flow(local, remote),
        };
        owner.filter(|&m| m != self.index)
    }
    /// Whether the flow from this member's local `port` to `peer` is its
    /// own. An IPv6 peer is no flow of the members; the endpoint refuses it.
    pub(crate) fn owns(&self, port: u16, peer: SocketAddr) -> bool {
        let SocketAddr::V4(peer) = peer else {
            return true;
        };
        self.flow(SocketAddrV4::new(self.address, port), peer)
            .is_none_or(|m| m == self.index)
    }
    /// Under `FlowOwnership::TaggedPorts`, this member's tagged ports: the
    /// only ports its active opens take.
    pub(crate) fn tagged(&self) -> Option<PortRule> {
        self.shared.tagged(self.index)
    }
    /// Whether this member may listen on local `port`: not on a port tagged
    /// with another member, which owns every connection to it.
    pub(crate) fn may_listen(&self, port: u16) -> bool {
        match &self.shared.ownership {
            Ownership::TaggedPorts { tags, .. } => {
                tags.member(port).is_none_or(|m| m == self.index)
            }
            _ => true,
        }
    }
    /// Copies `packet` into member `to`'s inbox and wakes it; false, keeping
    /// nothing, when `to` is no member or its inbox is full.
    pub(crate) fn hand_off(&self, to: usize, packet: &[u8], handoff: Handoff) -> bool {
        let slot = &self.shared.slots[to];
        if slot.address.load(Ordering::Acquire) == 0 || !slot.inbox.push(packet, handoff) {
            return false;
        }
        // The swap orders the push before the owner's `begin`, which reads
        // it: an owner that took the flag sees the packet, and one that
        // cleared it first is woken.
        if !slot.woken.swap(true, Ordering::Release)
            && let Some(file) = &*lock(&slot.wake)
        {
            // An eventfd's count only grows; a descriptor that would block
            // is already readable.
            let _ = (&**file).write(&1u64.to_ne_bytes());
        }
        true
    }
    /// The start of a drive's look at the inbox: a handoff after it wakes
    /// the member again.
    pub(crate) fn begin(&self) {
        self.shared.slots[self.index]
            .woken
            .swap(false, Ordering::Acquire);
    }
    /// Handoffs wait in the inbox.
    pub(crate) fn pending(&self) -> bool {
        !self.shared.slots[self.index].inbox.is_empty()
    }
    pub(crate) fn inlet(&self) -> Inlet {
        Inlet {
            shared: self.shared.clone(),
            index: self.index,
        }
    }
    /// This member reassembles IPv4 datagrams up to `capacity` (None: it
    /// does not reassemble). A fragment is reassembled by the member its
    /// addresses select and the datagram taken in by its flow's owner,
    /// within the owner's capacity. Only by address are the two always one
    /// member; otherwise every member declares the same.
    pub(crate) fn reassemble(&self, capacity: Option<usize>) -> Result<()> {
        if matches!(self.shared.ownership, Ownership::ByAddress) {
            return Ok(());
        }
        // Another member hands over the datagrams it reassembles.
        if capacity.is_some_and(|c| c > self.shared.limits.packet_bytes) {
            return Err(PACKET_BYTES);
        }
        let mut registry = lock(&self.shared.registry);
        if registry.reassembly.iter().flatten().any(|&c| c != capacity) {
            return Err(Error::InvalidConfig(
                "members of hashed shared flows reassemble alike",
            ));
        }
        registry.reassembly[self.index] = Some(capacity);
        Ok(())
    }
    pub(crate) fn set_wake(&self, file: Arc<File>) {
        *lock(&self.shared.slots[self.index].wake) = Some(file);
    }
    /// Some member listens on local `port`.
    pub(crate) fn listened(&self, port: u16) -> bool {
        lock(&self.shared.registry)
            .listening
            .binary_search_by_key(&port, |&(p, _)| p)
            .is_ok()
    }
    /// This member listens on `port` (once more), within the listeners it
    /// joined with.
    pub(crate) fn listen(&mut self, port: u16) {
        debug_assert!(self.listening.len() < self.listeners);
        let mut registry = lock(&self.shared.registry);
        match registry.listening.binary_search_by_key(&port, |&(p, _)| p) {
            Ok(at) => registry.listening[at].1 += 1,
            Err(at) => registry.listening.insert(at, (port, 1)),
        }
        self.listening.push(port);
    }
    /// One of this member's listeners on `port` is gone.
    pub(crate) fn unlisten(&mut self, port: u16) {
        let Some(at) = self.listening.iter().position(|&p| p == port) else {
            return;
        };
        self.listening.swap_remove(at);
        lock(&self.shared.registry).unlisten(port);
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        let slot = &self.shared.slots[self.index];
        let mut registry = lock(&self.shared.registry);
        for &port in &self.listening {
            registry.unlisten(port);
        }
        registry.reserved -= self.listeners;
        registry.reassembly[self.index] = None;
        slot.address.store(0, Ordering::Release);
        *lock(&slot.wake) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);

    // An IPv4 header of `len` octets (options zero) for a packet of `total`
    // octets, with the flags and offset word `fragment`.
    fn ipv4(
        len: usize,
        total: usize,
        fragment: u16,
        protocol: u8,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Vec<u8> {
        let mut header = vec![0; len];
        header[0] = 0x40 | (len / 4) as u8;
        header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        header[6..8].copy_from_slice(&fragment.to_be_bytes());
        header[8] = 64;
        header[9] = protocol;
        header[12..16].copy_from_slice(&source.octets());
        header[16..20].copy_from_slice(&destination.octets());
        header
    }
    // A TCP segment's first `len` octets: ports, then zero.
    fn tcp(source: u16, destination: u16, len: usize) -> Vec<u8> {
        let mut segment = vec![0; len.max(4)];
        segment[..2].copy_from_slice(&source.to_be_bytes());
        segment[2..4].copy_from_slice(&destination.to_be_bytes());
        segment.truncate(len);
        segment
    }
    fn packet(fragment: u16, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = ipv4(20, 20 + payload.len(), fragment, protocol, REMOTE, LOCAL);
        packet.extend_from_slice(payload);
        packet
    }
    // An ICMP message of `kind` from a router, quoting `quote`.
    fn icmp(kind: u8, quote: &[u8]) -> Vec<u8> {
        let mut message = vec![kind, 0, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(quote);
        let mut packet = ipv4(20, 20 + message.len(), 0, ICMP, ROUTER, LOCAL);
        packet.extend_from_slice(&message);
        packet
    }
    // The header and first `transport` octets of a segment this host sent
    // from port 40000 to the remote's port 80, with `fragment`.
    fn sent(len: usize, fragment: u16, protocol: u8, transport: usize) -> Vec<u8> {
        let mut quote = ipv4(len, 1500, fragment, protocol, LOCAL, REMOTE);
        quote.extend_from_slice(&tcp(40000, 80, transport));
        quote
    }
    fn flow(local: (Ipv4Addr, u16), remote: (Ipv4Addr, u16)) -> Key {
        Key::Flow {
            local: SocketAddrV4::new(local.0, local.1),
            remote: SocketAddrV4::new(remote.0, remote.1),
        }
    }

    #[test]
    fn a_segment_is_keyed_by_its_flow_from_the_receivers_side() {
        let segment = packet(0, TCP, &tcp(40000, 80, 20));
        assert_eq!(key(&segment), flow((LOCAL, 80), (REMOTE, 40000)));
        // Don't Fragment changes nothing.
        let segment = packet(0x4000, TCP, &tcp(40000, 80, 20));
        assert_eq!(key(&segment), flow((LOCAL, 80), (REMOTE, 40000)));
        // Options before the segment, and Ethernet padding after it.
        let mut segment = ipv4(28, 32, 0, TCP, REMOTE, LOCAL);
        segment.extend_from_slice(&tcp(1, 2, 4));
        segment.resize(46, 0xee);
        assert_eq!(key(&segment), flow((LOCAL, 2), (REMOTE, 1)));
        assert!(!fragment(&segment));
    }

    #[test]
    fn malformed_and_foreign_packets_are_the_receivers() {
        let segment = packet(0, TCP, &tcp(40000, 80, 20));
        // Truncated below the header, or below its total length.
        assert_eq!(key(&segment[..19]), Key::Local);
        assert_eq!(key(&segment[..39]), Key::Local);
        assert_eq!(key(&[]), Key::Local);
        // Ports beyond the total length, though padding follows.
        let mut short = ipv4(20, 22, 0, TCP, REMOTE, LOCAL);
        short.extend_from_slice(&tcp(40000, 80, 4));
        assert_eq!(key(&short), Key::Local);
        // A total length shorter than the header.
        let mut bad = segment.clone();
        bad[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(key(&bad), Key::Local);
        // An IHL below five words, or beyond the packet.
        for ihl in [0, 4, 15] {
            let mut bad = segment.clone();
            bad[0] = 0x40 | ihl;
            assert_eq!(key(&bad), Key::Local, "ihl {ihl}");
        }
        // IPv6, and other versions.
        let mut six = segment.clone();
        six[0] = 0x60;
        assert_eq!(key(&six), Key::Local);
        assert!(!fragment(&six));
        // UDP and Echo.
        assert_eq!(key(&packet(0, 17, &tcp(53, 53, 8))), Key::Local);
        assert_eq!(key(&icmp(8, &[0; 8])), Key::Local);
        assert_eq!(key(&icmp(0, &sent(20, 0, TCP, 8))), Key::Local);
    }

    #[test]
    fn fragments_are_keyed_by_their_addresses_whatever_they_carry() {
        let fragments = [
            // The first: More Fragments, offset zero, ports present.
            (MORE, TCP),
            // A middle one, and the last.
            (MORE | 185, TCP),
            (370, TCP),
            // With Don't Fragment set, of UDP and of ICMP errors.
            (0x4000 | 3, TCP),
            (MORE, 17),
            (MORE, ICMP),
        ];
        for (word, protocol) in fragments {
            let piece = packet(word, protocol, &tcp(40000, 80, 24));
            assert_eq!(
                key(&piece),
                Key::Fragment {
                    source: REMOTE,
                    destination: LOCAL
                },
                "{word:#x}"
            );
            assert!(fragment(&piece));
        }
    }

    #[test]
    fn an_icmp_error_is_keyed_by_the_flow_it_quotes() {
        for kind in [3, 4, 5, 11, 12] {
            assert_eq!(
                key(&icmp(kind, &sent(20, 0, TCP, 8))),
                flow((LOCAL, 40000), (REMOTE, 80)),
                "type {kind}"
            );
        }
        // A quoted header with options, the first fragment of a segment,
        // and Don't Fragment.
        for (len, word) in [(24, 0), (20, MORE), (20, 0x4000), (32, MORE | 0x4000)] {
            assert_eq!(
                key(&icmp(3, &sent(len, word, TCP, 8))),
                flow((LOCAL, 40000), (REMOTE, 80)),
                "{len} {word:#x}"
            );
        }
        // Fewer than 64 bits of the segment, or a quote cut in its header.
        assert_eq!(key(&icmp(3, &sent(20, 0, TCP, 7))), Key::Local);
        assert_eq!(key(&icmp(3, &sent(24, 0, TCP, 0)[..22])), Key::Local);
        // A later fragment has no TCP header; UDP is no flow of the members.
        assert_eq!(key(&icmp(3, &sent(20, 185, TCP, 8))), Key::Local);
        assert_eq!(key(&icmp(3, &sent(20, MORE | 1, TCP, 8))), Key::Local);
        assert_eq!(key(&icmp(11, &sent(20, 0, 17, 8))), Key::Local);
        // A quote that is no IPv4 header.
        let mut six = sent(20, 0, TCP, 8);
        six[0] = 0x65;
        assert_eq!(key(&icmp(3, &six)), Key::Local);
        // Cut before the quote.
        assert_eq!(key(&icmp(3, &[])), Key::Local);
    }

    const MTU: usize = 64;
    fn limits(members: usize) -> SharedFlowLimits {
        SharedFlowLimits {
            members,
            inbox_packets: 2,
            packet_bytes: MTU,
        }
    }
    fn hashed(members: usize, table: Vec<usize>) -> SharedFlows {
        let ownership = FlowOwnership::Hash {
            key: DEFAULT_FLOW_KEY.to_vec(),
            table,
        };
        SharedFlows::new(ownership, limits(members)).unwrap()
    }
    fn handoff() -> Handoff {
        Handoff {
            timestamps: Default::default(),
            tcp_segment_size: None,
            reassembled: None,
        }
    }

    #[test]
    fn hashed_flows_follow_the_table_for_the_members_address_only() {
        let flows = hashed(2, vec![0, 1, 1, 0]);
        let toeplitz = Toeplitz::new(&DEFAULT_FLOW_KEY).unwrap();
        let local = SocketAddrV4::new(LOCAL, 80);
        let remote = SocketAddrV4::new(REMOTE, 40000);
        // No member serves the address yet.
        assert_eq!(flows.owner(local, remote), None);
        assert_eq!(flows.reassembler(REMOTE, LOCAL), None);
        let a = flows.join(0, LOCAL.into(), MTU, 1).unwrap();
        let b = flows.join(1, LOCAL.into(), MTU, 1).unwrap();
        let table = [0, 1, 1, 0];
        let owner = table[toeplitz.ipv4_ports(REMOTE, LOCAL, 40000, 80) as usize & 3];
        assert_eq!(flows.owner(local, remote), Some(owner));
        let reassembler = table[toeplitz.ipv4(REMOTE, LOCAL) as usize & 3];
        assert_eq!(flows.reassembler(REMOTE, LOCAL), Some(reassembler));
        // Each member agrees, and names only the other.
        for member in [&a, &b] {
            let elsewhere = (owner != member.index).then_some(owner);
            assert_eq!(
                member.elsewhere(key(&packet(0, TCP, &tcp(40000, 80, 20)))),
                elsewhere
            );
            let fragment = (reassembler != member.index).then_some(reassembler);
            assert_eq!(member.elsewhere(key(&packet(MORE, TCP, &[0; 8]))), fragment);
            assert_eq!(member.owns(80, remote.into()), owner == member.index);
            assert_eq!(member.elsewhere(Key::Local), None);
        }
        // Another address is no member's.
        let other = SocketAddrV4::new(ROUTER, 80);
        assert_eq!(flows.owner(other, remote), None);
        assert_eq!(
            a.elsewhere(Key::Flow {
                local: other,
                remote
            }),
            None
        );
        // Every member serves the one address.
        let c = hashed(3, vec![0, 1, 2, 0]);
        let _c0 = c.join(0, LOCAL.into(), MTU, 0).unwrap();
        assert!(matches!(
            c.join(1, REMOTE.into(), MTU, 0),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn flows_by_address_belong_to_the_member_addressed() {
        let flows = SharedFlows::new(FlowOwnership::ByAddress, limits(3)).unwrap();
        let a = flows.join(0, LOCAL.into(), MTU, 1).unwrap();
        let b = flows.join(2, ROUTER.into(), MTU, 1).unwrap();
        let remote = SocketAddrV4::new(REMOTE, 1234);
        assert_eq!(flows.owner(SocketAddrV4::new(LOCAL, 80), remote), Some(0));
        assert_eq!(flows.owner(SocketAddrV4::new(ROUTER, 80), remote), Some(2));
        assert_eq!(flows.reassembler(REMOTE, ROUTER), Some(2));
        assert_eq!(flows.reassembler(LOCAL, REMOTE), None);
        assert_eq!(
            b.elsewhere(key(&packet(0, TCP, &tcp(1234, 80, 20)))),
            Some(0)
        );
        assert_eq!(a.elsewhere(key(&packet(MORE, TCP, &[0; 8]))), None);
        assert!(a.owns(1, remote.into()) && b.owns(1, remote.into()));
        // Distinct addresses; IPv6 is not supported; one member per slot.
        assert!(matches!(
            flows.join(1, LOCAL.into(), MTU, 0),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            flows.join(1, "2001:db8::1".parse().unwrap(), MTU, 0),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            flows.join(2, REMOTE.into(), MTU, 0),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            flows.join(3, REMOTE.into(), MTU, 0),
            Err(Error::InvalidConfig(_))
        ));
        // A member that leaves serves its address no longer.
        drop(b);
        assert_eq!(flows.owner(SocketAddrV4::new(ROUTER, 80), remote), None);
        assert_eq!(
            a.elsewhere(key(&icmp(3, &{
                let mut quote = ipv4(20, 40, 0, TCP, ROUTER, REMOTE);
                quote.extend_from_slice(&tcp(80, 1234, 8));
                quote
            }))),
            None
        );
        let _b = flows.join(2, REMOTE.into(), MTU, 0).unwrap();
    }

    #[test]
    fn handoffs_reach_present_members_until_their_inbox_is_full() {
        let flows = hashed(2, vec![0, 1]);
        let a = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        assert!(!b.pending());
        b.begin();
        assert!(a.hand_off(1, &[1, 2, 3], handoff()));
        assert!(a.hand_off(1, &[4], handoff()));
        // Two packets fill it.
        assert!(!a.hand_off(1, &[5], handoff()));
        assert!(b.pending());
        let mut taken = Vec::new();
        assert_eq!(b.inlet().drain(8, |bytes, _| taken.push(bytes.to_vec())), 2);
        assert_eq!(taken, [vec![1, 2, 3], vec![4]]);
        assert!(!b.pending());
        // Left: refused, and a new member starts with an empty inbox.
        assert!(a.hand_off(1, &[6], handoff()));
        drop(b);
        assert!(!a.hand_off(1, &[7], handoff()));
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        assert!(!b.pending());
    }

    #[cfg(unix)]
    #[test]
    fn the_first_handoff_after_a_drive_looks_writes_the_wake() {
        use std::io::Read;
        let flows = hashed(2, vec![0, 1]);
        let a = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        let (mut reader, writer) = std::io::pipe().unwrap();
        b.set_wake(Arc::new(File::from(std::os::fd::OwnedFd::from(writer))));
        b.begin();
        for _ in 0..2 {
            assert!(a.hand_off(1, &[1], handoff()));
        }
        b.begin();
        b.inlet().drain(8, |_, _| {});
        assert!(a.hand_off(1, &[2], handoff()));
        // One write per look: two of eight octets.
        drop(b);
        drop(flows);
        drop(a);
        let mut written = Vec::new();
        reader.read_to_end(&mut written).unwrap();
        assert_eq!(written.len(), 16);
    }

    #[test]
    fn listening_ports_count_every_member_until_it_leaves() {
        let flows = hashed(2, vec![0, 1]);
        let mut a = flows.join(0, LOCAL.into(), MTU, 2).unwrap();
        let mut b = flows.join(1, LOCAL.into(), MTU, 1).unwrap();
        a.listen(80);
        b.listen(80);
        a.listen(443);
        assert!(a.listened(80) && b.listened(443));
        a.unlisten(80);
        assert!(b.listened(80));
        b.unlisten(80);
        assert!(!a.listened(80));
        // Another member's ports leave with it.
        b.listen(8080);
        drop(b);
        assert!(!a.listened(8080) && a.listened(443));
        a.unlisten(443);
        assert!(!a.listened(443));
    }

    #[test]
    fn a_member_joins_named_by_its_table_with_room_for_its_packets() {
        // Under Hash a member the table never names would own no flow.
        let flows = hashed(3, vec![0, 1, 0, 1]);
        assert!(matches!(
            flows.join(2, LOCAL.into(), MTU, 0),
            Err(Error::InvalidConfig(_))
        ));
        let _a = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        // Under TaggedPorts its tagged ports are its own.
        let tags = tagged(3, vec![0, 1], 0xc000, 0xc000).unwrap();
        let _c = tags.join(2, LOCAL.into(), MTU, 0).unwrap();
        let tagged_port = SocketAddrV4::new(LOCAL, 0xc002);
        let remote = SocketAddrV4::new(REMOTE, 80);
        assert_eq!(tags.owner(tagged_port, remote), Some(2));
        // The inbox's buffers hold a packet of the member's MTU, and unless
        // by address the datagrams it reassembles, which other members
        // hand over.
        assert!(matches!(
            flows.join(1, LOCAL.into(), MTU + 1, 0),
            Err(Error::InvalidConfig(_))
        ));
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        assert!(matches!(
            b.reassemble(Some(MTU + 1)),
            Err(Error::InvalidConfig(_))
        ));
        b.reassemble(Some(MTU)).unwrap();
        let flows = SharedFlows::new(FlowOwnership::ByAddress, limits(1)).unwrap();
        let member = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        member.reassemble(Some(MTU + 1)).unwrap();
    }

    fn tagged(members: usize, table: Vec<usize>, prefix: u16, mask: u16) -> Result<SharedFlows> {
        let ownership = FlowOwnership::TaggedPorts {
            key: DEFAULT_FLOW_KEY.to_vec(),
            table,
            prefix,
            prefix_mask: mask,
        };
        SharedFlows::new(ownership, limits(members))
    }

    #[test]
    fn tagged_ports_are_their_members_and_other_flows_hash() {
        let toeplitz = Toeplitz::new(&DEFAULT_FLOW_KEY).unwrap();
        let remotes = [
            SocketAddrV4::new(REMOTE, 80),
            SocketAddrV4::new(ROUTER, 40000),
        ];
        // The member bits of 1, 2, 3, 4 and 8 members. Of 3, ports whose
        // member bits are 3 are tagged with no member, and hash.
        for (n, low) in [(1, 0), (2, 1), (3, 3), (4, 3), (8, 7)] {
            let table: Vec<usize> = (0..8).map(|i| i % n).collect();
            let flows = tagged(n, table.clone(), 0xc000, 0xc000).unwrap();
            let members: Vec<_> = (0..n)
                .map(|k| flows.join(k, LOCAL.into(), MTU, 0).unwrap())
                .collect();
            for k in 0..n {
                let rule = (0xc000 | k as u16, 0xc000 | low);
                assert_eq!(flows.port_rule(k), Some(rule), "{n} members");
            }
            assert_eq!(flows.port_rule(n), None);
            for port in 0..=u16::MAX {
                let tag =
                    Some(usize::from(port & low)).filter(|&m| port & 0xc000 == 0xc000 && m < n);
                let ruled = (0..n).filter(|&k| {
                    let (value, mask) = flows.port_rule(k).unwrap();
                    port & mask == value
                });
                assert!(ruled.eq(tag), "{n} members, port {port}");
                for member in &members {
                    assert_eq!(
                        member.may_listen(port),
                        tag.is_none_or(|m| m == member.index)
                    );
                }
                // Every 61st port's flows, and every tagged one's of the
                // highest prefix.
                if port % 61 != 0 && port < 0xfff0 {
                    continue;
                }
                let local = SocketAddrV4::new(LOCAL, port);
                for remote in remotes {
                    let hash = toeplitz.ipv4_ports(*remote.ip(), LOCAL, remote.port(), port);
                    let owner = tag.unwrap_or(table[hash as usize & 7]);
                    assert_eq!(flows.owner(local, remote), Some(owner), "{local} {remote}");
                    for member in &members {
                        let elsewhere = (owner != member.index).then_some(owner);
                        let segment = {
                            let mut segment = ipv4(20, 40, 0, TCP, *remote.ip(), LOCAL);
                            segment.extend_from_slice(&tcp(remote.port(), port, 20));
                            segment
                        };
                        assert_eq!(member.elsewhere(key(&segment)), elsewhere);
                        assert_eq!(member.owns(port, remote.into()), owner == member.index);
                    }
                }
            }
            // Fragments hash; another address is no member's.
            let reassembler = table[toeplitz.ipv4(REMOTE, LOCAL) as usize & 7];
            assert_eq!(flows.reassembler(REMOTE, LOCAL), Some(reassembler));
            let other = SocketAddrV4::new(ROUTER, 0xc000);
            assert_eq!(flows.owner(other, remotes[0]), None);
            if n > 1 {
                assert!(matches!(
                    flows.join(n - 1, REMOTE.into(), MTU, 0),
                    Err(Error::InvalidConfig(_))
                ));
            }
            for member in &members {
                let rule = flows.port_rule(member.index).unwrap();
                assert_eq!(member.tagged().map(|r| (r.value, r.mask)), Some(rule));
            }
        }
        // Other ownership tags no port.
        let flows = hashed(2, vec![0, 1]);
        let member = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        assert_eq!(flows.port_rule(0), None);
        assert!(member.tagged().is_none() && member.may_listen(0xc001));
        let flows = SharedFlows::new(FlowOwnership::ByAddress, limits(2)).unwrap();
        assert_eq!(flows.port_rule(0), None);
    }

    #[test]
    fn a_port_tag_lies_under_a_nonzero_mask_that_spares_the_member_bits() {
        for (n, prefix, mask) in [
            (1, 0x0001, 0x0001),
            (2, 0x0000, 0x8000),
            (4, 0x8000, 0xfffc),
            (5, 0xc000, 0xfff8),
        ] {
            assert!(tagged(n, vec![0], prefix, mask).is_ok(), "{n} {prefix:#x}");
        }
        for (n, prefix, mask) in [
            // No mask, and a prefix beyond it.
            (2, 0x0000, 0x0000),
            (2, 0xc000, 0x8000),
            // A mask that takes a member bit.
            (2, 0xc001, 0xc001),
            (3, 0xc000, 0xc002),
            (4, 0xc000, 0xc002),
            (8, 0xc004, 0xc004),
            // More members than the bits that spare a mask can number.
            (1 << 16, 0x0000, 0x8000),
            ((1 << 16) + 1, 0x0000, 0x8000),
        ] {
            assert!(
                matches!(
                    tagged(n, vec![0], prefix, mask),
                    Err(Error::InvalidConfig(_))
                ),
                "{n} {prefix:#x} {mask:#x}"
            );
        }
        // The key and table are those of Hash.
        for table in [vec![0, 1, 0], vec![0, 2]] {
            assert!(matches!(
                tagged(2, table, 0xc000, 0xc000),
                Err(Error::InvalidConfig(_))
            ));
        }
        let ownership = FlowOwnership::TaggedPorts {
            key: vec![0; 15],
            table: vec![0],
            prefix: 0xc000,
            prefix_mask: 0xc000,
        };
        assert!(matches!(
            SharedFlows::new(ownership, limits(1)),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn the_first_tagged_port_of_a_range_follows_from_its_bounds() {
        let rules = [
            (0xc000, 0xc000),
            (0xc002, 0xc003),
            (0xc005, 0xc007),
            (0x0005, 0x000f),
            (0x8001, 0x8001),
            (0x0000, 0x0001),
            (0x1040, 0x5a5a),
            (0x0000, 0xffff),
            (0xffff, 0xffff),
        ];
        for (value, mask) in rules {
            let rule = PortRule { value, mask };
            // The least port the rule takes from each port on, swept down.
            let mut least = None;
            for start in (0..=u16::MAX).rev() {
                if start & mask == value {
                    least = Some(start);
                }
                assert_eq!(
                    rule.first_in(start..=u16::MAX),
                    least,
                    "{value:#x}/{mask:#x} from {start}"
                );
                if let Some(port) = least {
                    assert_eq!(rule.first_in(start..=port), Some(port));
                    if port > start {
                        assert_eq!(rule.first_in(start..=port - 1), None);
                    }
                }
            }
        }
        let empty = RangeInclusive::new(5, 4);
        assert_eq!(PortRule { value: 0, mask: 1 }.first_in(empty), None);
    }

    #[test]
    fn an_icmp_error_about_a_tagged_port_is_its_members() {
        let flows = tagged(4, vec![0, 1, 2, 3], 0xc000, 0xc000).unwrap();
        let members: Vec<_> = (0..4)
            .map(|k| flows.join(k, LOCAL.into(), MTU, 0).unwrap())
            .collect();
        for tag in 0..4 {
            // A segment member `tag` sent from one of its tagged ports, and
            // the errors about it, whatever their source.
            let port = 0xd000 | tag as u16;
            let mut quote = ipv4(20, 1500, 0x4000, TCP, LOCAL, REMOTE);
            quote.extend_from_slice(&tcp(port, 80, 8));
            for kind in [3, 4, 5, 11, 12] {
                let error = icmp(kind, &quote);
                assert_eq!(key(&error), flow((LOCAL, port), (REMOTE, 80)));
                for member in &members {
                    let elsewhere = (member.index != tag).then_some(tag);
                    assert_eq!(member.elsewhere(key(&error)), elsewhere, "type {kind}");
                }
            }
            let local = SocketAddrV4::new(LOCAL, port);
            let remote = SocketAddrV4::new(REMOTE, 80);
            assert_eq!(flows.owner(local, remote), Some(tag));
        }
    }
}
