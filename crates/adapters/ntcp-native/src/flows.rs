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
//
// The one exception is a SYN that would find no listener at its owner on a
// port another member listens on, as while a group starts or one member
// restarts its listener. A SO_REUSEPORT group on Linux hands such a SYN to
// one of the sockets that listen (reuseport_select_sock), and the owner
// does likewise: it hands it to a listening member and records the flow as
// that member's in its share's table of redirected flows, which every
// member consults, while the table holds any, for the segments of its
// flows. The holder removes the record once the connection is reclaimed.
use crate::{Error, Result, inbox::Inbox, toeplitz::Toeplitz};
use std::{
    collections::hash_map::RandomState,
    fs::File,
    hash::BuildHasher,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    ops::{Range, RangeInclusive},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence},
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

/// Storage of a `SharedFlows`, allocated by `SharedFlows::new`, and the
/// buffer memory its members share. `SharedFlowLimits::new` and `Default`
/// (whose counts are zero, which `SharedFlows::new` refuses, for struct
/// literals ending in `..Default::default()`) set the memory fields to
/// their defaults: one budget, the sum of the members' own, charged in
/// 1 MiB batches.
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
    /// Flows of each member's share that other members may hold at once,
    /// having taken their SYNs when it did not listen on their port (unless
    /// ownership is `FlowOwnership::ByAddress`, where every member listens
    /// on its own address). A SYN beyond that is dropped, as a listener
    /// with a full queue drops one, rather than reset by a member that
    /// does not listen (`Counters::redirects_dropped`), and its peer sends
    /// it again.
    pub redirected_flows: usize,
    /// The thresholds of the buffer memory the members share
    /// (`ntcp::SharedBufferMemory`), as Linux's tcp_mem is one for every
    /// CPU: the hard cap, and where pressure begins and ends, for the
    /// members' charges together. None (the default) sums the thresholds
    /// of the members present (`EndpointConfig::buffer_memory` of each
    /// one's `tcp`), so the group holds what its members held apart.
    pub buffer_memory: Option<ntcp::BufferMemory>,
    /// The bytes a member charges or returns before it publishes them to
    /// the shared count: Linux's net.core.mem_pcpu_rsv, by default its
    /// SK_MEMORY_PCPU_RESERVE of 1 MiB (`ntcp::SharedBufferMemory::
    /// DEFAULT_BATCH`). What a member sees of the others' charge lags by at
    /// most members × batch. 0 gives each member its own budget instead,
    /// as a lone Network has.
    pub memory_batch_bytes: usize,
}

impl SharedFlowLimits {
    /// Limits with the default buffer memory: one budget summing the
    /// members', charged in batches of 1 MiB.
    pub fn new(
        members: usize,
        inbox_packets: usize,
        packet_bytes: usize,
        redirected_flows: usize,
    ) -> Self {
        Self {
            members,
            inbox_packets,
            packet_bytes,
            redirected_flows,
            ..Self::default()
        }
    }
}

impl Default for SharedFlowLimits {
    fn default() -> Self {
        Self {
            members: 0,
            inbox_packets: 0,
            packet_bytes: 0,
            redirected_flows: 0,
            buffer_memory: None,
            memory_batch_bytes: ntcp::SharedBufferMemory::DEFAULT_BATCH,
        }
    }
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
    // Bit `p` is set while some member listens on local port `p`: written
    // under the registry's lock, read without it for a SYN its owner has
    // no listener for, which then takes no lock unless a member listens.
    listened: Box<[AtomicU64]>,
    // The members' shared buffer memory, unless each keeps its own.
    memory: Option<ntcp::SharedBufferMemory>,
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
    // A table whose entries all name one member, as a group of one's does
    // whatever its length, selects it whatever the hash: it is kept as
    // that one entry, for `select`.
    let table = match table[..] {
        [first, ..] if table.iter().all(|&m| m == first) => vec![first],
        _ => table,
    };
    Ok((hash, table.into_boxed_slice()))
}

// The member of `table` that `hash` selects. A table of one entry names its
// member whatever the hash, which is then not computed: a group of one
// hashes none of the packets it can only take in itself.
fn select(table: &[usize], toeplitz: &Toeplitz, hash: impl FnOnce(&Toeplitz) -> u32) -> usize {
    match table {
        [member] => *member,
        _ => table[hash(toeplitz) as usize & (table.len() - 1)],
    }
}

// One member's place in the flows.
struct Slot {
    // The member's address as `present` encodes it, or 0 while no member
    // has the slot. Changed under the registry's lock; read without it by
    // the members that hand off and by `SharedFlows::owner`.
    address: AtomicU64,
    // The flows in `redirected`, written under its lock and read without
    // it on every segment of the share's flows: while it is 0, as when
    // every member listens, nothing is looked up.
    held: AtomicUsize,
    redirected: Mutex<Redirected>,
    inbox: Inbox<Handoff>,
    wake: Wake,
}

// The flows of one member's share whose SYNs it handed to a listening
// member, keyed by remote address, remote port and local port (`flow_key`),
// with the member that holds each. Open addressing with linear probing
// over at least twice the bound, so that a probe ends at an empty entry
// within a few; a keyed SipHash, so that peers, who choose their addresses
// and ports, cannot choose colliding keys; and removal by backward shift,
// which leaves no tombstones to lengthen later probes.
struct Redirected {
    keys: RandomState,
    entries: Box<[(u64, usize)]>,
    len: usize,
    bound: usize,
}

// An entry's member while it is empty.
const EMPTY: usize = usize::MAX;

impl Redirected {
    fn new(bound: usize) -> Result<Self> {
        let len = match bound {
            0 => 0,
            _ => bound
                .checked_mul(2)
                .and_then(usize::checked_next_power_of_two)
                .ok_or(Error::Capacity)?,
        };
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(len)
            .map_err(|_| Error::Capacity)?;
        entries.resize(len, (0, EMPTY));
        Ok(Self {
            keys: RandomState::new(),
            entries: entries.into_boxed_slice(),
            len: 0,
            bound,
        })
    }
    fn home(&self, key: u64) -> usize {
        self.keys.hash_one(key) as usize & (self.entries.len() - 1)
    }
    // The entry of `key`, or the empty entry its probe ends at.
    fn find(&self, key: u64) -> usize {
        let mask = self.entries.len() - 1;
        let mut at = self.home(key);
        while self.entries[at].1 != EMPTY && self.entries[at].0 != key {
            at = (at + 1) & mask;
        }
        at
    }
    fn get(&self, key: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let (_, member) = self.entries[self.find(key)];
        (member != EMPTY).then_some(member)
    }
    // Records `key` as `member`'s, unless it is already some member's,
    // which is returned, or the table is full.
    fn insert(&mut self, key: u64, member: usize) -> Result<usize> {
        if let Some(holder) = self.get(key) {
            return Ok(holder);
        }
        if self.len == self.bound {
            return Err(Error::Capacity);
        }
        let at = self.find(key);
        self.entries[at] = (key, member);
        self.len += 1;
        Ok(member)
    }
    // Removes `key` if `member` holds it.
    fn remove(&mut self, key: u64, member: usize) -> bool {
        if self.get(key) != Some(member) {
            return false;
        }
        self.remove_at(self.find(key));
        true
    }
    // Removes every flow `member` holds. Removal shifts later entries of a
    // probe back, never one not yet visited before the one at hand: a pass
    // that looks at an entry again once it removed one visits them all.
    fn purge(&mut self, member: usize) {
        let mut at = 0;
        while at < self.entries.len() {
            if self.entries[at].1 == member {
                self.remove_at(at);
            } else {
                at += 1;
            }
        }
    }
    fn remove_at(&mut self, at: usize) {
        let mask = self.entries.len() - 1;
        let mut hole = at;
        let mut next = hole;
        loop {
            next = (next + 1) & mask;
            let (key, member) = self.entries[next];
            if member == EMPTY {
                break;
            }
            // An entry whose home lies cyclically after the hole and up to
            // its own place stays; any other moves into the hole, whose
            // probe would otherwise end before it.
            let home = self.home(key);
            if (next.wrapping_sub(home) & mask) >= (next.wrapping_sub(hole) & mask) {
                self.entries[hole] = (key, member);
                hole = next;
            }
        }
        self.entries[hole] = (0, EMPTY);
        self.len -= 1;
    }
}

// The key of the flow between `local` and `remote` in a `Redirected`: the
// local address is every member's.
fn flow_key(local: SocketAddrV4, remote: SocketAddrV4) -> u64 {
    u64::from(u32::from(*remote.ip())) << 32
        | u64::from(remote.port()) << 16
        | u64::from(local.port())
}

// How a handoff wakes a member that blocks, on lines of its own: the
// member's drive clears `woken` and the first handoff after that sets it,
// while every handoff reads the slot's address and the inbox's bounds. Two
// lines, because x86 prefetches lines in adjacent pairs.
//
// A handoff pushes its packet and then reads `woken`; the member's drive
// clears `woken` (`Inlet::begin`) and then reads the inbox, through its
// drains and `Inlet::pending`. A sequentially consistent fence between the
// write and the read on each side lets no more than one side miss the
// other's write (the store-buffering pattern): the drive takes or reports
// the packet, or the handoff reads `woken` clear and swaps it set, and the
// one swap that finds it clear writes the descriptor. A drive that reads
// `woken` clear leaves it so and needs no fence: an earlier drive cleared
// it before its own fence (or the join before the member's address was
// published), so a handoff this drive misses reads that clear or a later
// set, and the handoff whose swap set it wrote the descriptor after the
// embedding last reset it, or this drive, after that reset, would have
// read it set. A handoff that reads `woken` set
// writes nothing and takes no read-modify-write, and without a descriptor
// (`armed` clear) the swap that finds it clear takes no lock.
#[repr(align(128))]
struct Wake {
    // A handoff arrived since the member's drive last cleared this.
    woken: AtomicBool,
    // `file` holds a descriptor.
    armed: AtomicBool,
    file: Mutex<Option<Arc<File>>>,
}

impl Wake {
    // Sets `woken`, and writes the descriptor if this set it.
    fn wake(&self) {
        if !self.woken.load(Ordering::Relaxed)
            && !self.woken.swap(true, Ordering::Relaxed)
            && self.armed.load(Ordering::Relaxed)
            && let Some(file) = &*lock(&self.file)
        {
            // An eventfd's count only grows; a descriptor that would block
            // is already readable.
            let _ = (&**file).write(&1u64.to_ne_bytes());
        }
    }
}

struct Registry {
    // The local ports members listen on, ascending, each with a member
    // that listens on it, once per listener: the sockets of a port's
    // reuseport group. Room for every member's listeners is reserved when
    // it joins.
    listening: Vec<(u16, usize)>,
    reserved: usize,
    // Per member, once it declared it (`Member::reassemble`), the IPv4
    // datagram capacity it reassembles up to, None without reassembly.
    reassembly: Vec<Option<Option<usize>>>,
}

impl Registry {
    // The entries of the members listening on `port`.
    fn listeners(&self, port: u16) -> Range<usize> {
        let start = self.listening.partition_point(|&(p, _)| p < port);
        start..self.listening.partition_point(|&(p, _)| p <= port)
    }
    fn listen(&mut self, port: u16, member: usize, listened: &[AtomicU64]) {
        let at = self
            .listening
            .partition_point(|&entry| entry < (port, member));
        self.listening.insert(at, (port, member));
        listened[usize::from(port) / 64].fetch_or(1 << (port % 64), Ordering::Release);
    }
    fn unlisten(&mut self, port: u16, member: usize, listened: &[AtomicU64]) {
        if let Ok(at) = self.listening.binary_search(&(port, member)) {
            self.listening.remove(at);
            if self.listeners(port).is_empty() {
                listened[usize::from(port) / 64].fetch_and(!(1 << (port % 64)), Ordering::Release);
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
                held: AtomicUsize::new(0),
                redirected: Mutex::new(Redirected::new(limits.redirected_flows)?),
                inbox: Inbox::new(limits.inbox_packets, limits.packet_bytes)?,
                wake: Wake {
                    woken: AtomicBool::new(false),
                    armed: AtomicBool::new(false),
                    file: Mutex::new(None),
                },
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
        let mut listened = Vec::new();
        listened
            .try_reserve_exact(1 << 10)
            .map_err(|_| Error::Capacity)?;
        listened.resize_with(1 << 10, AtomicU64::default);
        let memory = match limits.memory_batch_bytes {
            0 => None,
            batch => Some(
                ntcp::SharedBufferMemory::new(limits.members, limits.buffer_memory, batch)
                    .map_err(|_| {
                        Error::InvalidConfig("shared buffer memory needs low < pressure <= its cap")
                    })?,
            ),
        };
        Ok(Self {
            shared: Arc::new(Shared {
                ownership,
                limits,
                slots: slots.into_boxed_slice(),
                registry: Mutex::new(registry),
                listened: listened.into_boxed_slice(),
                memory,
            }),
        })
    }

    pub fn limits(&self) -> SharedFlowLimits {
        self.shared.limits
    }

    /// The buffer memory the members share, None if each keeps its own
    /// (`SharedFlowLimits::memory_batch_bytes` 0).
    pub fn buffer_memory(&self) -> Option<&ntcp::SharedBufferMemory> {
        self.shared.memory.as_ref()
    }

    /// The member that owns the TCP flow between `local` and `remote`. Under
    /// `FlowOwnership::ByAddress`, None unless a member serves `local`'s
    /// address; under `FlowOwnership::Hash` and `FlowOwnership::TaggedPorts`,
    /// None unless the members' address is `local`'s. A flow whose SYN its
    /// owner handed to a listening member, not listening on its port
    /// itself, is that member's until its connection is gone.
    pub fn owner(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<usize> {
        self.shared
            .flow(local, remote, None)
            .map(|(member, _)| member)
    }

    /// The flows of member `member`'s share that other members hold, their
    /// SYNs having come while it did not listen on their port, of at most
    /// `SharedFlowLimits::redirected_flows`.
    pub fn redirected(&self, member: usize) -> usize {
        self.shared
            .slots
            .get(member)
            .map_or(0, |slot| slot.held.load(Ordering::Acquire))
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
        // Each member serves its own address by address: no member's
        // listening port is a port another must not open from.
        let listeners = if shared.registers() { listeners } else { 0 };
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
        // What reached the slot after its earlier member left was for
        // connections that left with it. A handoff that read the earlier
        // member's address and is still being copied in lands after this,
        // and is taken in as any: under Hash and TaggedPorts its flow is
        // this member's, which answers it as a restarted host would, and by
        // address the Host refuses another address. Either way its producer
        // counted it handed off (`Counters::handed_off`).
        slot.inbox.drain(shared.limits.inbox_packets, |_, _| {});
        slot.wake.woken.store(false, Ordering::Relaxed);
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
    // The member that takes in the TCP flow between `local` and `remote`,
    // and whether it holds the flow for its owner, which handed it the
    // flow's SYN (`Redirected`).
    fn flow(
        &self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        me: Option<(usize, Ipv4Addr)>,
    ) -> Option<(usize, bool)> {
        let owner = self.route(*local.ip(), me, Some(local.port()), |hash| {
            hash.ipv4_ports(*remote.ip(), *local.ip(), remote.port(), local.port())
        })?;
        let slot = &self.slots[owner];
        if slot.held.load(Ordering::Acquire) == 0 {
            return Some((owner, false));
        }
        Some(match lock(&slot.redirected).get(flow_key(local, remote)) {
            Some(holder) => (holder, true),
            None => (owner, false),
        })
    }
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
                .then(|| select(table, toeplitz, hash)),
            Ownership::TaggedPorts {
                hash: toeplitz,
                table,
                tags,
            } => self.serves(address, me).then(|| {
                port.and_then(|p| tags.member(p))
                    .unwrap_or_else(|| select(table, toeplitz, hash))
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
    // Whether the members' listening ports are registered: on one address
    // they are ports every member's active opens avoid.
    fn registers(&self) -> bool {
        !matches!(self.ownership, Ownership::ByAddress)
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
    /// and `remote`; `syn` for a segment that may open a connection, with
    /// SYN set and neither ACK nor RST.
    Flow {
        local: SocketAddrV4,
        remote: SocketAddrV4,
        syn: bool,
    },
}

/// Where a packet goes (`Member::elsewhere`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    pub(crate) to: Option<usize>,
    pub(crate) held: bool,
}

/// What becomes of a SYN its owner does not listen for (`Member::redirect`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Redirect {
    /// Handed to this member, which holds its flow.
    To(usize),
    /// Dropped: the owner's share already has as many flows held elsewhere
    /// as `SharedFlowLimits::redirected_flows`.
    Full,
    /// No member listens on its port: the owner answers it.
    Nobody,
}

/// A flow of another member's share that a member holds, having taken its
/// SYN (`Member::held`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Held {
    owner: usize,
    key: u64,
}

const ICMP: u8 = 1;
const TCP: u8 = 6;
// SYN, and SYN with ACK or RST, of a TCP header's flags.
const SYN: u8 = 0x02;
const SYN_ACK_RST: u8 = 0x16;
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
                syn: payload.get(13).is_some_and(|f| f & SYN_ACK_RST == SYN),
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
        syn: false,
    })
}

/// What a member hands over with a packet: its receive metadata as the
/// backend reported it, which the owner reads against its own clocks;
/// whether it is a fragment, whose datagram the receiver keys once it
/// completes it; and for a datagram the sender reassembled its envelope
/// (`Host::adopt_datagram`). `syn` and `held` are the packet's `Key::Flow`
/// SYN and `Route` held, which spare the receiver keying it again.
#[derive(Clone, Copy)]
pub(crate) struct Handoff {
    pub(crate) timestamps: ntcp_io::PacketTimestamps,
    pub(crate) tcp_segment_size: Option<NonZeroU16>,
    pub(crate) fragment: bool,
    pub(crate) reassembled: Option<ntcp_host::Envelope>,
    pub(crate) syn: bool,
    pub(crate) held: bool,
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

/// A member's inbox, held apart from its membership so that its Network
/// can take in what it drains; made once, when the member joins.
pub(crate) struct Inlet {
    shared: Arc<Shared>,
    index: usize,
}

impl Inlet {
    /// The start of a drive's look at the inbox: a handoff after it wakes
    /// the member again (`Wake`).
    pub(crate) fn begin(&self) {
        let wake = &self.shared.slots[self.index].wake;
        if wake.woken.load(Ordering::Relaxed) {
            wake.woken.store(false, Ordering::Relaxed);
            fence(Ordering::SeqCst);
        }
    }
    /// Handoffs wait in the inbox.
    pub(crate) fn pending(&self) -> bool {
        !self.shared.slots[self.index].inbox.is_empty()
    }
    pub(crate) fn drain(&self, budget: usize, f: impl FnMut(&[u8], Handoff)) -> usize {
        self.shared.slots[self.index].inbox.drain(budget, f)
    }
}

impl Member {
    fn me(&self) -> Option<(usize, Ipv4Addr)> {
        Some((self.index, self.address))
    }
    /// The member that takes in a packet of `key`: `to`, None for this
    /// member's own and for one of an address no member serves, which this
    /// member's Host decides; and `held`, that the flow's owner handed its
    /// SYN to that member (`Member::redirect`).
    pub(crate) fn elsewhere(&self, key: Key) -> Route {
        let (to, held) = match key {
            Key::Local => (None, false),
            Key::Fragment {
                source,
                destination,
            } => {
                let to = self.shared.route(destination, self.me(), None, |hash| {
                    hash.ipv4(source, destination)
                });
                (to, false)
            }
            Key::Flow { local, remote, .. } => match self.shared.flow(local, remote, self.me()) {
                Some((to, held)) => (Some(to), held),
                None => (None, false),
            },
        };
        Route {
            to: to.filter(|&m| m != self.index),
            held,
        }
    }
    /// Whether the flow from this member's local `port` to `peer` is its
    /// own. An IPv6 peer is no flow of the members; the endpoint refuses it.
    pub(crate) fn owns(&self, port: u16, peer: SocketAddr) -> bool {
        let SocketAddr::V4(peer) = peer else {
            return true;
        };
        self.shared
            .flow(SocketAddrV4::new(self.address, port), peer, self.me())
            .is_none_or(|(m, _)| m == self.index)
    }
    /// Whether a SYN for local `port` that this member owns and has no
    /// connection for is another member's to answer: this member does not
    /// listen on the port, and some other member does.
    pub(crate) fn unheard(&self, port: u16) -> bool {
        !self.listening.contains(&port) && self.listened(port)
    }
    /// The listening member that takes the SYN of the flow between `local`
    /// and `remote`, one this member owns but that is `unheard`, and holds
    /// the flow until its connection is gone (`release`). Among the
    /// listeners on the port, a member once per listener, the flow's hash
    /// picks one as Linux's reuseport_select_sock does (`reciprocal_scale`
    /// over the group's sockets), so that each takes a like share. A flow
    /// already redirected stays with its holder, a SYN sent again for it
    /// included.
    pub(crate) fn redirect(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Redirect {
        let shared = &*self.shared;
        let registry = lock(&shared.registry);
        let listeners = &registry.listening[registry.listeners(local.port())];
        if listeners.is_empty() {
            return Redirect::Nobody;
        }
        let hash = match &shared.ownership {
            Ownership::Hash { hash, .. } | Ownership::TaggedPorts { hash, .. } => {
                hash.ipv4_ports(*remote.ip(), *local.ip(), remote.port(), local.port())
            }
            Ownership::ByAddress => return Redirect::Nobody,
        };
        let pick = ((u64::from(hash) * listeners.len() as u64) >> 32) as usize;
        let (_, listener) = listeners[pick];
        debug_assert_ne!(listener, self.index);
        let slot = &shared.slots[self.index];
        let mut redirected = lock(&slot.redirected);
        match redirected.insert(flow_key(local, remote), listener) {
            Ok(holder) => {
                slot.held.store(redirected.len, Ordering::Release);
                Redirect::To(holder)
            }
            Err(_) => Redirect::Full,
        }
    }
    /// The flow between `local` and `remote`, which this member took in,
    /// if it holds it for its owner.
    pub(crate) fn held(&self, local: SocketAddrV4, remote: SocketAddrV4) -> Option<Held> {
        let owner = self
            .shared
            .route(*local.ip(), self.me(), Some(local.port()), |hash| {
                hash.ipv4_ports(*remote.ip(), *local.ip(), remote.port(), local.port())
            })?;
        (owner != self.index).then(|| Held {
            owner,
            key: flow_key(local, remote),
        })
    }
    /// This member no longer holds `held`: its later segments are its
    /// owner's again.
    pub(crate) fn release(&self, held: Held) {
        let slot = &self.shared.slots[held.owner];
        let mut redirected = lock(&slot.redirected);
        if redirected.remove(held.key, self.index) {
            slot.held.store(redirected.len, Ordering::Release);
        }
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
        // The fences order the push before the read of `woken` here and the
        // owner's clear before its reads of the inbox (`Wake`); the swap
        // only elects the one handoff that writes.
        fence(Ordering::SeqCst);
        slot.wake.wake();
        true
    }
    /// This member's endpoint joins the members' shared buffer memory, if
    /// they share one.
    pub(crate) fn share_buffer_memory(&self, endpoint: &mut ntcp::Endpoint) -> Result<()> {
        if let Some(memory) = &self.shared.memory {
            endpoint.share_buffer_memory(memory, self.index)?;
        }
        Ok(())
    }
    /// This member returned memory to the shared budget: wake every other
    /// member whose writers wait for memory, which looks again as its next
    /// drive begins (`Endpoint::poll_shared_memory`). The return was
    /// published before the flags are read (`SharedBufferMemory::waiting`).
    pub(crate) fn wake_memory_waiters(&self) {
        let Some(memory) = &self.shared.memory else {
            return;
        };
        for (index, slot) in self.shared.slots.iter().enumerate() {
            if index != self.index && memory.waiting(index) {
                slot.wake.wake();
            }
        }
    }
    /// Whether this member may hand SYNs to listening members and hold
    /// flows of other members' shares: unless ownership is by address.
    pub(crate) fn redirects(&self) -> bool {
        self.shared.registers()
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
        let wake = &self.shared.slots[self.index].wake;
        *lock(&wake.file) = Some(file);
        wake.armed.store(true, Ordering::Relaxed);
    }
    /// Some member on this member's address listens on local `port`.
    pub(crate) fn listened(&self, port: u16) -> bool {
        self.shared.listened[usize::from(port) / 64].load(Ordering::Acquire) & 1 << (port % 64) != 0
    }
    /// This member listens on `port` (once more), within the listeners it
    /// joined with.
    pub(crate) fn listen(&mut self, port: u16) {
        if !self.shared.registers() {
            return;
        }
        debug_assert!(self.listening.len() < self.listeners);
        lock(&self.shared.registry).listen(port, self.index, &self.shared.listened);
        self.listening.push(port);
    }
    /// One of this member's listeners on `port` is gone.
    pub(crate) fn unlisten(&mut self, port: u16) {
        let Some(at) = self.listening.iter().position(|&p| p == port) else {
            return;
        };
        self.listening.swap_remove(at);
        lock(&self.shared.registry).unlisten(port, self.index, &self.shared.listened);
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        let slot = &self.shared.slots[self.index];
        let mut registry = lock(&self.shared.registry);
        for &port in &self.listening {
            registry.unlisten(port, self.index, &self.shared.listened);
        }
        // The flows this member held end with its connections: their later
        // segments are their owners' again, whose answer is a restarted
        // host's. A pass over every share's table, as a member leaves.
        for other in &self.shared.slots {
            let mut redirected = lock(&other.redirected);
            if other.held.load(Ordering::Relaxed) != 0 {
                redirected.purge(self.index);
                other.held.store(redirected.len, Ordering::Release);
            }
        }
        registry.reserved -= self.listeners;
        registry.reassembly[self.index] = None;
        slot.address.store(0, Ordering::Release);
        slot.wake.armed.store(false, Ordering::Relaxed);
        *lock(&slot.wake.file) = None;
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
            syn: false,
        }
    }
    impl Member {
        // The other member that takes in a packet of `key`.
        fn to(&self, key: Key) -> Option<usize> {
            self.elsewhere(key).to
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
            redirected_flows: 2,
            ..SharedFlowLimits::default()
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
            fragment: false,
            reassembled: None,
            syn: false,
            held: false,
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
                member.to(key(&packet(0, TCP, &tcp(40000, 80, 20)))),
                elsewhere
            );
            let fragment = (reassembler != member.index).then_some(reassembler);
            assert_eq!(member.to(key(&packet(MORE, TCP, &[0; 8]))), fragment);
            assert_eq!(member.owns(80, remote.into()), owner == member.index);
            assert_eq!(member.to(Key::Local), None);
        }
        // Another address is no member's.
        let other = SocketAddrV4::new(ROUTER, 80);
        assert_eq!(flows.owner(other, remote), None);
        assert_eq!(
            a.to(Key::Flow {
                local: other,
                remote,
                syn: false,
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
    fn a_table_of_one_member_gives_it_every_hashed_flow() {
        // A group of one, and under TaggedPorts two members of which the
        // table names one: member 1 owns its tagged ports alone. A table of
        // one entry, and a longer one that names one member.
        for table in [vec![0], vec![0; 8]] {
            let one = hashed(1, table.clone());
            let a = one.join(0, LOCAL.into(), MTU, 0).unwrap();
            let two = tagged(2, table, 0xc000, 0xc000).unwrap();
            let b = two.join(0, LOCAL.into(), MTU, 0).unwrap();
            let c = two.join(1, LOCAL.into(), MTU, 0).unwrap();
            for port in (0..=u16::MAX).step_by(61).chain([0xc000, 0xc001]) {
                let local = SocketAddrV4::new(LOCAL, port);
                let tag = (port & 0xc000 == 0xc000).then_some(usize::from(port & 1));
                for remote in [
                    SocketAddrV4::new(REMOTE, 80),
                    SocketAddrV4::new(ROUTER, 40000),
                ] {
                    let segment = {
                        let mut segment = ipv4(20, 40, 0, TCP, *remote.ip(), LOCAL);
                        segment.extend_from_slice(&tcp(remote.port(), port, 20));
                        segment
                    };
                    assert_eq!(one.owner(local, remote), Some(0), "{local} {remote}");
                    assert_eq!(a.to(key(&segment)), None);
                    assert!(a.owns(port, remote.into()));
                    let owner = tag.unwrap_or(0);
                    assert_eq!(two.owner(local, remote), Some(owner), "{local} {remote}");
                    for member in [&b, &c] {
                        let elsewhere = (owner != member.index).then_some(owner);
                        assert_eq!(member.to(key(&segment)), elsewhere);
                        assert_eq!(member.owns(port, remote.into()), owner == member.index);
                    }
                }
            }
            // Fragments too.
            let fragment = key(&packet(MORE, TCP, &[0; 8]));
            assert_eq!(one.reassembler(REMOTE, LOCAL), Some(0));
            assert_eq!(a.to(fragment), None);
            assert_eq!(two.reassembler(REMOTE, LOCAL), Some(0));
            assert_eq!((b.to(fragment), c.to(fragment)), (None, Some(0)));
        }
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
        assert_eq!(b.to(key(&packet(0, TCP, &tcp(1234, 80, 20)))), Some(0));
        assert_eq!(a.to(key(&packet(MORE, TCP, &[0; 8]))), None);
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
            a.to(key(&icmp(3, &{
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
        let inlet = b.inlet();
        assert!(!inlet.pending());
        inlet.begin();
        assert!(a.hand_off(1, &[1, 2, 3], handoff()));
        assert!(a.hand_off(1, &[4], handoff()));
        // Two packets fill it.
        assert!(!a.hand_off(1, &[5], handoff()));
        assert!(inlet.pending());
        let mut taken = Vec::new();
        assert_eq!(inlet.drain(8, |bytes, _| taken.push(bytes.to_vec())), 2);
        assert_eq!(taken, [vec![1, 2, 3], vec![4]]);
        assert!(!inlet.pending());
        // Left: refused, and a new member starts with an empty inbox.
        assert!(a.hand_off(1, &[6], handoff()));
        drop((b, inlet));
        assert!(!a.hand_off(1, &[7], handoff()));
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        assert!(!b.inlet().pending());
    }

    #[cfg(unix)]
    #[test]
    fn the_first_handoff_after_a_drive_looks_writes_the_wake() {
        use std::io::Read;
        let flows = hashed(2, vec![0, 1]);
        let a = flows.join(0, LOCAL.into(), MTU, 0).unwrap();
        let b = flows.join(1, LOCAL.into(), MTU, 0).unwrap();
        let (mut reader, writer) = std::io::pipe().unwrap();
        // Without a descriptor a handoff writes nothing.
        assert!(a.hand_off(1, &[0], handoff()));
        b.set_wake(Arc::new(File::from(std::os::fd::OwnedFd::from(writer))));
        let inlet = b.inlet();
        inlet.begin();
        inlet.drain(8, |_, _| {});
        for _ in 0..2 {
            assert!(a.hand_off(1, &[1], handoff()));
        }
        inlet.begin();
        inlet.drain(8, |_, _| {});
        // A look that finds no handoff since the last leaves the next one
        // to write.
        inlet.begin();
        assert!(a.hand_off(1, &[2], handoff()));
        // One write per look: two of eight octets.
        drop((b, inlet));
        drop(flows);
        drop(a);
        let mut written = Vec::new();
        reader.read_to_end(&mut written).unwrap();
        assert_eq!(written.len(), 16);
    }

    // The table of redirected flows against a map, under insertions and
    // removals that cluster its probes and wrap them around its end.
    #[test]
    fn redirected_flows_keep_their_holders_through_removals() {
        let mut table = Redirected::new(48).unwrap();
        assert_eq!(table.entries.len(), 128);
        let mut model = std::collections::HashMap::new();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for round in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Few keys, so that most operations find one present.
            let key = state % 80;
            let member = (state >> 8) as usize % 3;
            match (state >> 16) % 4 {
                0 if member == 2 => {
                    table.purge(1);
                    model.retain(|_, &mut m| m != 1);
                }
                0 | 1 => {
                    let removed = table.remove(key, member);
                    assert_eq!(removed, model.get(&key) == Some(&member), "{round}");
                    if removed {
                        model.remove(&key);
                    }
                }
                _ => match table.insert(key, member) {
                    Ok(holder) => assert_eq!(holder, *model.entry(key).or_insert(member)),
                    Err(_) => assert!(model.len() == 48 && !model.contains_key(&key)),
                },
            }
            assert_eq!(table.len, model.len());
            for key in 0..80 {
                assert_eq!(table.get(key), model.get(&key).copied(), "{round} {key}");
            }
        }
        // A bound of none holds nothing.
        let mut none = Redirected::new(0).unwrap();
        assert!(none.insert(1, 0).is_err());
        assert_eq!(none.get(1), None);
        assert!(!none.remove(1, 0));
        none.purge(0);
    }

    // A SYN its owner does not listen for goes to a listener of its port
    // and stays there, its flow the holder's until it is released; a full
    // share drops the next.
    #[test]
    fn a_syn_no_owner_listens_for_is_held_by_a_listening_member() {
        let flows = hashed(3, vec![0, 1, 2, 0]);
        let mut members: Vec<Member> = (0..3)
            .map(|k| flows.join(k, LOCAL.into(), MTU, 2).unwrap())
            .collect();
        let local = SocketAddrV4::new(LOCAL, 80);
        let remotes: Vec<SocketAddrV4> = (40000..)
            .map(|p| SocketAddrV4::new(REMOTE, p))
            .filter(|&r| flows.owner(local, r) == Some(0))
            .take(3)
            .collect();
        // No member listens: the owner answers.
        assert!(!members[0].unheard(80));
        assert_eq!(members[0].redirect(local, remotes[0]), Redirect::Nobody);
        members[1].listen(80);
        members[2].listen(80);
        assert!(members[0].unheard(80) && !members[1].unheard(80));
        let toeplitz = Toeplitz::new(&DEFAULT_FLOW_KEY).unwrap();
        let mut holders = Vec::new();
        for &remote in &remotes[..2] {
            let hash = toeplitz.ipv4_ports(REMOTE, LOCAL, remote.port(), 80);
            let expected = 1 + ((u64::from(hash) * 2) >> 32) as usize;
            assert_eq!(members[0].redirect(local, remote), Redirect::To(expected));
            // Again, as for a SYN sent again, after either stops listening.
            members[3 - expected].unlisten(80);
            assert_eq!(members[0].redirect(local, remote), Redirect::To(expected));
            members[3 - expected].listen(80);
            assert_eq!(flows.owner(local, remote), Some(expected));
            let route = members[0].elsewhere(Key::Flow {
                local,
                remote,
                syn: false,
            });
            assert_eq!(
                route,
                Route {
                    to: Some(expected),
                    held: true
                }
            );
            assert!(
                members[expected].owns(80, remote.into()) && !members[0].owns(80, remote.into())
            );
            holders.push(expected);
        }
        assert_eq!(flows.redirected(0), 2);
        assert_eq!(members[0].redirect(local, remotes[2]), Redirect::Full);
        // The holder releases one; the other member's release changes
        // nothing.
        let held = members[holders[0]].held(local, remotes[0]).unwrap();
        members[3 - holders[0]].release(held);
        assert_eq!(flows.redirected(0), 2);
        members[holders[0]].release(held);
        assert_eq!(flows.redirected(0), 1);
        assert_eq!(flows.owner(local, remotes[0]), Some(0));
        assert_eq!(members[0].held(local, remotes[0]), None);
        // A holder that leaves takes its flows' records with it.
        let holder = holders[1];
        drop(members.remove(holder));
        assert_eq!(flows.redirected(0), 0);
        assert_eq!(flows.owner(local, remotes[1]), Some(0));
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
        // By address no member's port is another's to avoid: each listens
        // on its own address.
        let flows = SharedFlows::new(FlowOwnership::ByAddress, limits(2)).unwrap();
        let mut a = flows.join(0, LOCAL.into(), MTU, 1).unwrap();
        let b = flows.join(1, ROUTER.into(), MTU, 1).unwrap();
        a.listen(80);
        assert!(!b.listened(80));
        a.unlisten(80);
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
                        assert_eq!(member.to(key(&segment)), elsewhere);
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
                    assert_eq!(member.to(key(&error)), elsewhere, "type {kind}");
                }
            }
            let local = SocketAddrV4::new(LOCAL, port);
            let remote = SocketAddrV4::new(REMOTE, 80);
            assert_eq!(flows.owner(local, remote), Some(tag));
        }
    }
}
