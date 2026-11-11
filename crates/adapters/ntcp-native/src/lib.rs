#![forbid(unsafe_code)]

mod config;
mod driver;
mod flows;
mod inbox;
mod shared;
mod toeplitz;
mod types;
pub use config::{EthernetNextHop, Link, NetworkConfig};
pub use flows::{DEFAULT_FLOW_KEY, FlowOwnership, SharedFlowLimits, SharedFlows};
pub use ntcp_host::ReassemblyCounters;
pub use shared::{SharedNeighborLimits, SharedNeighbors};
pub use types::*;

use ntcp::{AddressValidation, Endpoint, EndpointError, Tuple};
use ntcp_host::{Host, IngressContext, path};
use ntcp_io::PacketIo;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

struct Connection {
    core: ntcp::ConnectionId,
    local: SocketAddr,
    peer: SocketAddr,
    state: State,
    reason: Option<CloseReason>,
    close_requested: bool,
    abort_requested: bool,
    released: bool,
    read_cursor: u64,
    trace_count: usize,
    connected_event: bool,
    closed_event: bool,
    readable_event: bool,
    read_waiting: bool,
    // Data or the peer's FIN arrived since the connection was last
    // refreshed: it raises Readable whether or not a read is armed, as
    // Linux wakes a socket for every segment it queues (sk_data_ready).
    arrived: bool,
    write_waiting: Option<TxTimestampRequest>,
}
struct Slot<T> {
    generation: u64,
    value: Option<T>,
}
struct Listener {
    core: ntcp::ListenerId,
    port: u16,
    closing: bool,
    acceptable: bool,
}

// All transport and backend access is confined to the constructing thread.
// Endpoint's local address-policy callback also makes this owner !Send/!Sync.
pub struct Network<P: PacketIo> {
    config: NetworkConfig,
    instance: u64,
    io: P,
    endpoint: Endpoint,
    host: Host,
    ingress: IngressContext,
    now: Instant,
    next_port: u16,
    // The local port of every occupied slot of `connections` and
    // `listeners`: a port counts from install or listen until its slot is
    // freed, a released connection's until the endpoint reclaims it, so
    // through TIME-WAIT.
    ports: PortUsers,
    connections: Vec<Slot<Connection>>,
    connection_map: HashMap<ntcp::ConnectionId, usize>,
    listeners: Vec<Slot<Listener>>,
    listener_map: HashMap<ntcp::ListenerId, usize>,
    // Occupied slots of `connections` and `listeners`, ascending. The passes
    // of every drive and event drain visit these, not every configured slot:
    // a free slot holds no state, event or work.
    live_connections: Vec<usize>,
    live_listeners: Vec<usize>,
    // Free slots of `connections` and `listeners`, the one the next open
    // takes last: an open finds a slot without a pass over the table.
    free_connections: Vec<usize>,
    free_listeners: Vec<usize>,
    events: VecDeque<Event>,
    event_capacity: usize,
    // Connection slots, then listener slots at `max_connections + slot`,
    // whose events a change may have raised since drain_events last looked.
    ready: SlotQueue,
    // Connection slots with a close or abort to carry on, and listener
    // slots (as in `ready`) with a close.
    maintain: SlotQueue,
    // Connection slots whose TX timestamps may be ready to drain.
    stamped: SlotQueue,
    // Released connection slots, kept until the endpoint reclaims their
    // connections, and the endpoint's reclaim count they were last checked
    // at.
    releasing: Vec<usize>,
    reclaimed: u64,
    staged_timestamp: Option<TimestampEvent>,
    backend_clocks: Vec<(u64, ntcp_io::ClockDescriptor)>,
    tx: Vec<driver::TxSlot>,
    // Slots in `tx` holding a pending frame.
    tx_pending: usize,
    // Slots in `tx` holding a frame whose next hop ARP is resolving.
    tx_held: usize,
    // Slots in `tx` holding a frame, held or not, ascending.
    tx_frames: Vec<usize>,
    // An ARP packet was taken in since held output was last released: a
    // resolution may have ended.
    arp_input: bool,
    // IPv4 next hops resolve through a port's shared table
    // (`with_shared_neighbors`), not the Host's own.
    shared_neighbors: bool,
    // Membership in a port's shared flows (`with_shared_flows`), and its
    // inbox.
    flows: Option<flows::Member>,
    inlet: Option<flows::Inlet>,
    tx_cursor: usize,
    // The one transmit slot of ARP control frames (empty without ARP).
    control: Vec<u8>,
    rx: Vec<u8>,
    completed: Vec<u8>,
    retained: VecDeque<driver::RetainedInput>,
    receive_free: Vec<Vec<u8>>,
    counters: Counters,
    stopped: bool,
    stopped_event: bool,
    failure: Option<io::Error>,
}

fn table<T>(capacity: usize) -> Result<Vec<Slot<T>>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    result.resize_with(capacity, || Slot {
        generation: 0,
        value: None,
    });
    Ok(result)
}
// An empty sorted set of slot indices (`live_connections` and the like)
// with room for every slot, so that `occupy` never allocates.
fn indices(capacity: usize) -> Result<Vec<usize>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    Ok(result)
}
// Every slot of a table of `capacity`, free, slot 0 to be taken first.
// The slot freed last is taken next, as a slab cache hands out the object
// it was given back last: an open reuses a slot of recent connections, not
// one never touched, while there is one.
fn free_slots(capacity: usize) -> Result<Vec<usize>> {
    let mut result = indices(capacity)?;
    result.extend((0..capacity).rev());
    Ok(result)
}
// Gives vacated `slot` back to `free`, unless its generation is spent: the
// slot then retires, so that no two of its handles are alike.
fn give_back<T>(free: &mut Vec<usize>, slots: &[Slot<T>], slot: usize) {
    debug_assert!(slots[slot].value.is_none() && free.len() < free.capacity());
    if slots[slot].generation < u64::MAX {
        free.push(slot);
    }
}
// The full-scan form of a free list, for debug builds: the slots that are
// neither occupied nor retired, each once.
fn listed_free<T>(free: &[usize], slots: &[Slot<T>]) -> bool {
    let mut listed = vec![false; slots.len()];
    free.iter()
        .all(|&s| !std::mem::replace(&mut listed[s], true))
        && (0..slots.len())
            .all(|i| listed[i] == (slots[i].value.is_none() && slots[i].generation < u64::MAX))
}
fn occupy(live: &mut Vec<usize>, slot: usize) {
    let at = live.partition_point(|&s| s < slot);
    debug_assert!(live.get(at) != Some(&slot) && live.len() < live.capacity());
    live.insert(at, slot);
}
fn vacate(live: &mut Vec<usize>, slot: usize) {
    let at = live.partition_point(|&s| s < slot);
    debug_assert_eq!(live.get(at), Some(&slot));
    live.remove(at);
}
// The first occupied slot at or after `from`. A pass that steps with it
// visits what a pass over every slot in order would find occupied.
fn next_live(live: &[usize], from: usize) -> Option<usize> {
    live.get(live.partition_point(|&s| s < from)).copied()
}
fn occupied<T>(slots: &[Slot<T>]) -> impl Iterator<Item = usize> + '_ {
    (0..slots.len()).filter(|&i| slots[i].value.is_some())
}

// Slots a change may have given work, oldest first, each queued at most
// once, as on epoll's ready list. A consumer checks again each slot it
// takes, so a change that left nothing to do costs one check, and a slot
// freed or reused while queued needs no removal.
struct SlotQueue {
    order: VecDeque<usize>,
    queued: Vec<bool>,
}
impl SlotQueue {
    fn new(slots: usize) -> Result<Self> {
        let mut order = VecDeque::new();
        order
            .try_reserve_exact(slots)
            .map_err(|_| Error::Capacity)?;
        let mut queued = Vec::new();
        queued
            .try_reserve_exact(slots)
            .map_err(|_| Error::Capacity)?;
        queued.resize(slots, false);
        Ok(Self { order, queued })
    }
    fn push(&mut self, slot: usize) {
        if !std::mem::replace(&mut self.queued[slot], true) {
            self.order.push_back(slot);
        }
    }
    fn pop(&mut self) -> Option<usize> {
        let slot = self.order.pop_front()?;
        self.queued[slot] = false;
        Some(slot)
    }
    fn len(&self) -> usize {
        self.order.len()
    }
    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}
// The number of slots using each local port, as Linux's bind hash keeps a
// bucket per port with its owners: an open finds whether a port is taken
// without a pass over the slots. A counter per port, not a set of ports,
// because the connections a listener accepts share its port. Indexed by
// the port, not hashed: every port has its counter, allocated whole when
// the network is built (256 KiB), so taking one never allocates or
// rehashes.
struct PortUsers {
    users: Vec<u32>,
}
impl PortUsers {
    // Room for `slots` users of one port.
    fn new(slots: usize) -> Result<Self> {
        u32::try_from(slots).map_err(|_| Error::Capacity)?;
        let ports = usize::from(u16::MAX) + 1;
        let mut users = Vec::new();
        users
            .try_reserve_exact(ports)
            .map_err(|_| Error::Capacity)?;
        users.resize(ports, 0);
        Ok(Self { users })
    }
    fn take(&mut self, port: u16) {
        self.users[usize::from(port)] += 1;
    }
    fn give(&mut self, port: u16) {
        self.users[usize::from(port)] -= 1;
    }
    fn users(&self, port: u16) -> u32 {
        self.users[usize::from(port)]
    }
}
fn bytes(capacity: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    result.resize(capacity, 0);
    Ok(result)
}

// ARP draws each ReachableTime at random so that stations do not probe in
// step. The draws are a keyed SipHash of a counter under std's per-process
// random keys: unpredictable without a system call per draw, of which TCP
// progress makes one per confirmation.
pub(crate) fn entropy() -> ntcp_host::Entropy {
    use std::hash::BuildHasher;
    let keys = std::collections::hash_map::RandomState::new();
    let mut counter = 0u64;
    Box::new(move |out: &mut [u8]| {
        for chunk in out.chunks_mut(8) {
            counter = counter.wrapping_add(1);
            let value = keys.hash_one(counter).to_be_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
        Ok(())
    })
}

impl<P: PacketIo> Network<P> {
    // The embedding supplies a confidential CSPRNG-generated TCP secret and
    // monotonic caller ticks in config.tcp.connection.timebase. Device/queue
    // ownership and any borrowed EAL/pool lifetime remain backend contracts.
    pub fn new(config: NetworkConfig, io: P, secret: [u8; 32], now: Instant) -> Result<Self> {
        Self::build(config, io, secret, now, None, None)
    }
    /// A Network on one queue of an Ethernet port whose IPv4 next hops
    /// `neighbors` resolves for every Network on the port: the link must be
    /// `EthernetNextHop::Arp` with the table's MAC, and caller time must
    /// come from the clock, units and origin every member uses
    /// (`SharedNeighbors`). The Network answers ARP for its address and
    /// takes ARP input for every member; `neighbor_entries` sizes the front
    /// cache of mappings it resolves without the table's lock, and its
    /// static neighbors become the port's. Dropping it leaves the table.
    pub fn with_shared_neighbors(
        config: NetworkConfig,
        io: P,
        secret: [u8; 32],
        now: Instant,
        neighbors: &SharedNeighbors,
    ) -> Result<Self> {
        Self::build(config, io, secret, now, Some(neighbors), None)
    }
    /// Member `member` of `flows`, a Network on one queue of a port whose
    /// queues divide the flows of the members' IPv4 addresses. It takes in
    /// only the packets of flows it owns and hands any other it receives to
    /// the owner; its active opens choose local ports whose flows it owns.
    /// Every member that should accept a port's connections listens on it.
    ///
    /// `member` is a free member number of `flows`, under
    /// `FlowOwnership::Hash` one its table names, and the local address is
    /// IPv4: under `FlowOwnership::ByAddress` no other member's, under
    /// `FlowOwnership::Hash` and `FlowOwnership::TaggedPorts` every
    /// member's. `SharedFlowLimits::packet_bytes` holds the largest IP
    /// packet the member takes in. On an `EthernetNextHop::Arp` link
    /// `neighbors` is the port's shared table, joined as by
    /// `with_shared_neighbors`: ARP arrives on whichever queue the port
    /// steers it to, and a member that resolved alone would never see the
    /// replies that reach the other members' queues. An IP link or a fixed
    /// next hop needs no table. Joining otherwise is `Error::InvalidConfig`
    /// and joins nothing.
    ///
    /// Ephemeral ports avoid the listening ports of every member on the
    /// local address, and `connect_from` refuses a local port whose flow to
    /// the peer another member owns (`Error::InvalidConfig`), opening
    /// nothing: `SharedFlows::owner` names the member to open it on. A
    /// blocking embedding learns of handoffs through the descriptor of
    /// `set_neighbor_wake_fd`.
    ///
    /// Every member should be given the same `secret`, as one host has one.
    /// A TCP Fast Open cookie authenticates its client's address under it,
    /// and that client's next connection may be another member's. And a
    /// member that joins a number another left then derives the initial
    /// sequence numbers of the same flows (RFC 6528) as the earlier member
    /// did, which keep old segments of its connections, whose TIME-WAIT
    /// state left with it, out of new ones.
    ///
    /// A member's flows are its own for the life of `flows`: the ownership
    /// function never changes, and no other member takes them over.
    /// Dropping the Network leaves the flows, and its connections end with
    /// it unannounced. Until a member joins its number again the others
    /// drop what they receive of its flows (`Counters::handoffs_dropped`;
    /// by address, the receiving member's Host refuses the address no
    /// member serves), so its peers retransmit until they time out and SYNs
    /// of its flows go unanswered. A member that joins the number owns the
    /// same flows (by address, those of its own address) and answers what
    /// remains of the earlier member's connections with resets, as a
    /// restarted host does. Its queue goes with it too: whatever arrives
    /// there for other members' flows (all of them on a port that steers
    /// nothing) is no longer handed over, so a member whose queue receives
    /// traffic keeps driving while other members serve connections.
    ///
    /// Under `FlowOwnership::TaggedPorts` ephemeral ports are the member's
    /// own tagged ports within `ephemeral_ports`, which must hold one
    /// (`Error::InvalidConfig`). A tagged port's connections are its
    /// member's whatever the remote, so that member alone listens on it: a
    /// listening port of its own, whose connections its port rule steers
    /// straight to its queue. Another member's listener there would never
    /// see a SYN, which the port's member would answer with a reset, so
    /// `listen` refuses it (`Error::InvalidConfig`). A service every member
    /// accepts listens on a port outside the tags.
    ///
    /// Unless ownership is `FlowOwnership::ByAddress`, a member reassembles
    /// the datagrams of every member's flows, which their owner takes in
    /// only within its own reassembly capacity, so the members reassemble
    /// alike: all with the same capacity, which the MTU sets, as members
    /// of one MTU do by default (`NetworkConfig::reassembly_datagrams`
    /// itself may differ), or none, each having set it to 0. Joining
    /// otherwise, or with a capacity beyond
    /// `SharedFlowLimits::packet_bytes`, is `Error::InvalidConfig`.
    pub fn with_shared_flows(
        config: NetworkConfig,
        io: P,
        secret: [u8; 32],
        now: Instant,
        neighbors: Option<&SharedNeighbors>,
        flows: &SharedFlows,
        member: usize,
    ) -> Result<Self> {
        if flows
            .tagged(member)
            .is_some_and(|tagged| tagged.first_in(config.ephemeral_ports.clone()).is_none())
        {
            return Err(Error::InvalidConfig(
                "the ephemeral ports of a member of tagged flows hold one of its tagged ports",
            ));
        }
        if neighbors.is_none() && config.arp().is_some() {
            return Err(Error::InvalidConfig(
                "members of shared flows on an ARP link share its neighbor table",
            ));
        }
        Self::build(config, io, secret, now, neighbors, Some((flows, member)))
    }
    fn build(
        config: NetworkConfig,
        io: P,
        secret: [u8; 32],
        now: Instant,
        neighbors: Option<&SharedNeighbors>,
        flows: Option<(&SharedFlows, usize)>,
    ) -> Result<Self> {
        config.validate(&io)?;
        if config.tcp.ipv4_options_enabled {
            return Err(Error::Unsupported(
                "IPv4 option origination on native fixed-hop ports",
            ));
        }
        let reassembly = config.reassembly().ok_or(Error::Capacity)?;
        let flows = match flows {
            Some((flows, member)) => {
                let member = flows.join(
                    member,
                    config.local_address,
                    config.mtu as usize,
                    config.tcp.max_listeners,
                )?;
                member.reassemble(reassembly.datagram_capacity(false))?;
                Some(member)
            }
            None => None,
        };
        let inlet = flows.as_ref().map(flows::Member::inlet);
        let instance = NEXT_INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Capacity)?;
        let local = config.local_address;
        let arp = config.arp();
        let routes = match arp {
            Some((_, _, Some(_))) => 2,
            _ => 1,
        };
        let (path_limits, mut limits) = ntcp_host::managed_limits(&config.tcp, 1, 1, 1, routes, 0)?;
        limits.reassembly = reassembly;
        let owners = config
            .tcp
            .max_connections
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let member = match (neighbors, arp, config.link) {
            (None, _, _) => None,
            (Some(neighbors), Some(_), Link::Ethernet { local_mac, .. }) => {
                if local_mac != neighbors.local_mac() {
                    return Err(Error::InvalidConfig(
                        "a shared neighbor table serves the one MAC of its port",
                    ));
                }
                if config.tcp.connection.timebase.units_per_second != neighbors.units_per_second() {
                    return Err(Error::InvalidConfig(
                        "members of a shared neighbor table use its time units",
                    ));
                }
                Some(neighbors.join(owners, config.neighbor_entries)?)
            }
            _ => {
                return Err(Error::InvalidConfig(
                    "a shared neighbor table resolves IPv4 next hops by ARP",
                ));
            }
        };
        if arp.is_some() && member.is_none() {
            // One held attempt per output lane; a reply per requester, each
            // of which the request also adds as an entry.
            limits.ipv4_neighbors = ntcp_host::NeighborLimits {
                entries: config
                    .neighbor_entries
                    .checked_add(config.static_neighbors.len())
                    .ok_or(Error::Capacity)?,
                pending_packets: owners,
                addresses: 1,
                answers: config.neighbor_entries,
            };
        }
        let mut host = Host::new(
            path::ContextId::new(instance),
            path_limits,
            limits,
            config.tcp.connection.timebase,
        )?;
        let shared_neighbors = member.is_some();
        if let Some(member) = member {
            host.set_ipv4_neighbor_table(Box::new(member))?;
        }
        let receive = ntcp_host::ReceiveCapabilities {
            max_ip_packet: config.mtu as usize,
            ipv4: if local.is_ipv4() {
                ntcp_host::Ipv4Receive::Enabled {
                    interpretation: false,
                    source_routes: false,
                }
            } else {
                ntcp_host::Ipv4Receive::Disabled
            },
            ipv6: if local.is_ipv6() {
                ntcp_host::Ipv6Receive::Extensions
            } else {
                ntcp_host::Ipv6Receive::Disabled
            },
            gro: false,
        };
        let ingress = match (arp, config.link) {
            (Some((local, prefix_len, gateway)), Link::Ethernet { local_mac, .. }) => {
                host.set_entropy(entropy());
                let ingress = host.register_neighbor_port(
                    path::InterfaceKey(1),
                    config.mtu,
                    receive,
                    ntcp_host::NdPort::new(local_mac),
                )?;
                let link = ingress.link();
                host.add_neighbor_address(link, local)?;
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(prefix_len))
                    .unwrap_or(0);
                let prefix = std::net::Ipv4Addr::from(u32::from(local) & mask);
                let gateway = gateway.map(|g| {
                    path::NextHop::Gateway(
                        path::ScopedAddress::new(std::net::IpAddr::V4(g), None)
                            .expect("validated gateway"),
                    )
                });
                for (prefix, prefix_len, next_hop) in [
                    (prefix, prefix_len, Some(path::NextHop::OnLink)),
                    (std::net::Ipv4Addr::UNSPECIFIED, 0, gateway),
                ] {
                    let Some(next_hop) = next_hop else {
                        continue;
                    };
                    host.add_route(path::Route {
                        destination: path::IpPrefix::new(prefix.into(), prefix_len)
                            .map_err(|e| Error::Host(e.into()))?,
                        source: None,
                        dscp: None,
                        link,
                        next_hop,
                        metric: 0,
                    })?;
                }
                for &(address, mac) in &config.static_neighbors {
                    host.add_static_neighbor(link, address.into(), mac, now)?;
                }
                ingress
            }
            _ => Self::fixed_link(&mut host, &config, receive)?,
        };
        let mut endpoint =
            Endpoint::new(
                config.tcp.clone(),
                secret,
                now,
                move |request| match request {
                    AddressValidation::Bind { local: address }
                    | AddressValidation::Open { local: address, .. } => address == local,
                    AddressValidation::Incoming { destination, .. } => destination == local,
                    AddressValidation::Route { source, .. } => source == local,
                },
            )?;
        host.attach(&mut endpoint)?;
        endpoint.enable_output_reservations_with_capacity(owners)?;
        let retained = config.retained_receive_packets.unwrap_or(owners);
        let ip_capacity = config.mtu as usize;
        // A reassembled datagram is completed into `completed` and may be
        // retained, so both hold the largest the Host completes.
        let datagram_capacity = config.datagram_capacity();
        let mut tx = Vec::new();
        tx.try_reserve_exact(owners).map_err(|_| Error::Capacity)?;
        for _ in 0..owners {
            tx.push(driver::TxSlot {
                bytes: bytes((ip_capacity + config.link.offset()).max(60))?,
                pending: None,
            });
        }
        // An ARP frame: 14 octets of header and the 28-octet body, padded.
        let control = if arp.is_some() {
            bytes(60)?
        } else {
            Vec::new()
        };
        let mut receive_free = Vec::new();
        receive_free
            .try_reserve_exact(retained)
            .map_err(|_| Error::Capacity)?;
        for _ in 0..retained {
            receive_free.push(bytes(datagram_capacity)?);
        }
        let mut retained_input = VecDeque::new();
        retained_input
            .try_reserve_exact(retained)
            .map_err(|_| Error::Capacity)?;
        let event_capacity = config
            .tcp
            .max_connections
            .checked_add(config.tcp.max_control_packets)
            .and_then(|n| n.checked_add(config.tcp.max_listeners))
            .ok_or(Error::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(event_capacity)
            .map_err(|_| Error::Capacity)?;
        let mut connection_map = HashMap::new();
        connection_map
            .try_reserve(config.tcp.max_connections)
            .map_err(|_| Error::Capacity)?;
        let mut listener_map = HashMap::new();
        listener_map
            .try_reserve(config.tcp.max_listeners)
            .map_err(|_| Error::Capacity)?;
        let mut backend_clocks = Vec::new();
        backend_clocks
            .try_reserve_exact(config.timestamp_clock_capacity)
            .map_err(|_| Error::Capacity)?;
        let connections = table(config.tcp.max_connections)?;
        let listeners = table(config.tcp.max_listeners)?;
        let live_connections = indices(config.tcp.max_connections)?;
        let live_listeners = indices(config.tcp.max_listeners)?;
        let free_connections = free_slots(config.tcp.max_connections)?;
        let free_listeners = free_slots(config.tcp.max_listeners)?;
        let tx_frames = indices(owners)?;
        let slots = config.tcp.max_connections + config.tcp.max_listeners;
        let ports = PortUsers::new(slots)?;
        let (ready, maintain) = (SlotQueue::new(slots)?, SlotQueue::new(slots)?);
        let stamped = SlotQueue::new(config.tcp.max_connections)?;
        let releasing = indices(config.tcp.max_connections)?;
        let next_port = *config.ephemeral_ports.start();
        Ok(Self {
            config,
            instance,
            io,
            endpoint,
            host,
            ingress,
            now,
            next_port,
            ports,
            connections,
            connection_map,
            listeners,
            listener_map,
            live_connections,
            live_listeners,
            free_connections,
            free_listeners,
            events,
            event_capacity,
            ready,
            maintain,
            stamped,
            releasing,
            reclaimed: 0,
            staged_timestamp: None,
            backend_clocks,
            tx,
            tx_pending: 0,
            tx_held: 0,
            tx_frames,
            arp_input: false,
            shared_neighbors,
            flows,
            inlet,
            tx_cursor: 0,
            control,
            // Capture an oversized physical frame safely before the Host rejects it.
            rx: bytes(65575 + 14)?,
            completed: bytes(datagram_capacity)?,
            retained: retained_input,
            receive_free,
            counters: Counters::default(),
            stopped: false,
            stopped_event: false,
            failure: None,
        })
    }
    // A link whose fixed MAC or L3 endpoint is the forwarder of every
    // destination: the owned address and a default route through it.
    fn fixed_link(
        host: &mut Host,
        config: &NetworkConfig,
        receive: ntcp_host::ReceiveCapabilities,
    ) -> Result<IngressContext> {
        let local = config.local_address;
        let ingress = host.register_link(
            path::InterfaceKey(1),
            config.mtu,
            receive,
            ntcp_host::Forwarding::Forwarder(path::ForwarderId(1)),
        )?;
        let zone = local.is_ipv6()
            && match local {
                std::net::IpAddr::V6(a) => a.is_unicast_link_local(),
                _ => false,
            };
        host.register_source(
            path::ScopedAddress::new(local, zone.then_some(ingress.link()))
                .map_err(|e| Error::Host(e.into()))?,
            ingress.link(),
        )?;
        host.add_route(path::Route {
            destination: path::IpPrefix::new(
                if local.is_ipv4() {
                    "0.0.0.0".parse().unwrap()
                } else {
                    "::".parse().unwrap()
                },
                0,
            )
            .map_err(|e| Error::Host(e.into()))?,
            source: None,
            dscp: None,
            link: ingress.link(),
            next_hop: path::NextHop::Forwarder(path::ForwarderId(1)),
            metric: 0,
        })?;
        Ok(ingress)
    }
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }
    pub fn now(&self) -> Instant {
        self.now
    }
    pub fn counters(&self) -> Counters {
        Counters {
            retained_input: self.retained.len(),
            resolution_failures: self.host.arp_counters().resolution_failures,
            listen_overflows: self.endpoint.listen_overflows(),
            listen_drops: self.endpoint.listen_drops(),
            time_wait_connections: self.endpoint.time_wait_connections(),
            ..self.counters
        }
    }
    /// Fragments held, datagrams completed and every discard by reason,
    /// by which to size `NetworkConfig::reassembly_datagrams`. While
    /// reassembly is disabled a discarded fragment counts in
    /// `discarded.assemblies`.
    pub fn reassembly_counters(&self) -> ReassemblyCounters {
        self.host.reassembly_counters()
    }
    pub fn failure(&self) -> Option<&io::Error> {
        self.failure.as_ref()
    }
    /// For a member of a shared neighbor table or of shared flows: an
    /// eventfd to signal (one 8-octet write adding 1) when another member
    /// ends a resolution that holds this Network's output, reports a
    /// neighbor lost or hands this Network a packet, so that a blocking
    /// embedding's poll set wakes for the drive that releases or takes it.
    /// One descriptor serves both memberships, so that one poll set entry
    /// covers every wake from the port's other queues. The embedding creates
    /// the descriptor and resets it as it polls; a write that would block
    /// is not retried, the descriptor then being readable already. A
    /// busy-polling embedding needs none: each drive takes its wakes.
    ///
    /// A drive reports the work of its own Network, not what it handed to
    /// or resolved for other members. An embedding that blocks waits on
    /// every member's descriptor, also when one thread drives several
    /// members: a member it drove earlier in a round may be handed packets
    /// later in the round, after it reported no more work.
    #[cfg(unix)]
    pub fn set_neighbor_wake_fd(&mut self, fd: std::os::fd::OwnedFd) -> Result<()> {
        let neighbors = shared::member(&mut self.host);
        if neighbors.is_none() && self.flows.is_none() {
            return Err(Error::Unsupported(
                "a wake descriptor needs a shared neighbor table or shared flows",
            ));
        }
        let file = std::sync::Arc::new(std::fs::File::from(fd));
        if let Some(member) = neighbors {
            member.set_wake(file.clone());
        }
        if let Some(flows) = &self.flows {
            flows.set_wake(file);
        }
        Ok(())
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn backend(&self) -> &P {
        &self.io
    }
    pub fn timestamp_capabilities(&self) -> TimestampSupport {
        let rx = self.io.timestamp_capabilities();
        TimestampSupport {
            scheduled: self.config.tx_timestamp_phases != 0,
            acknowledged: self.config.tx_timestamp_phases != 0,
            software_transmit: false,
            hardware_transmit: false,
            software_receive: self.config.rx_timestamp_ranges != 0 && rx.rx_software,
            hardware_receive: self.config.rx_timestamp_ranges != 0 && rx.rx_hardware,
        }
    }
    // Device clock IDs in read metadata name the full original descriptor,
    // including its raw-unit calibration identity. They are not Unix time.
    pub fn backend_clock(&self, clock: TimestampClock) -> Option<ntcp_io::ClockDescriptor> {
        match clock {
            TimestampClock::DeviceTicks { identity, .. } => self
                .backend_clocks
                .iter()
                .find(|(id, _)| *id == identity)
                .map(|(_, c)| *c),
            TimestampClock::RealtimeNanoseconds => Some(ntcp_io::ClockDescriptor {
                domain: ntcp_io::ClockDomain::Realtime,
                unit: ntcp_io::TimestampUnit::Nanoseconds,
            }),
            _ => None,
        }
    }

    // Advances logical time without servicing timers or touching packet I/O.
    pub fn advance_time(&mut self, now: Instant) -> Result<()> {
        self.running()?;
        self.endpoint.on_timeout(now, 0)?;
        self.now = now;
        Ok(())
    }
    fn running(&self) -> Result<()> {
        if self.stopped {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
    // The full-scan form of the occupied-slot indexes, for debug builds.
    fn check_live(&self) {
        debug_assert!(
            self.live_connections
                .iter()
                .copied()
                .eq(occupied(&self.connections))
        );
        debug_assert!(
            self.live_listeners
                .iter()
                .copied()
                .eq(occupied(&self.listeners))
        );
        debug_assert!(listed_free(&self.free_connections, &self.connections));
        debug_assert!(listed_free(&self.free_listeners, &self.listeners));
        debug_assert!(
            self.tx_frames
                .iter()
                .copied()
                .eq((0..self.tx.len()).filter(|&i| self.tx[i].pending.is_some()))
        );
    }
    fn conn(&self, id: ConnId) -> Result<&Connection> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.connections
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_ref())
            .ok_or(Error::InvalidHandle)
    }
    fn conn_mut(&mut self, id: ConnId) -> Result<&mut Connection> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.connections
            .get_mut(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_mut())
            .ok_or(Error::InvalidHandle)
    }
    fn conn_id(&self, slot: usize) -> ConnId {
        ConnId {
            instance: self.instance,
            slot,
            generation: self.connections[slot].generation,
        }
    }
    fn listener(&self, id: ListenerId) -> Result<&Listener> {
        if id.instance != self.instance {
            return Err(Error::InvalidHandle);
        }
        self.listeners
            .get(id.slot)
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.value.as_ref())
            .ok_or(Error::InvalidHandle)
    }
    // The connection slot the next install takes.
    fn free_connection_slot(&self) -> Result<usize> {
        self.free_connections.last().copied().ok_or(Error::Capacity)
    }
    fn install(&mut self, slot: usize, core: ntcp::ConnectionId) -> Result<ConnId> {
        let tuple = self.endpoint.tuple(core)?;
        let state = self.endpoint.state(core)?;
        self.connections[slot].generation += 1;
        self.connections[slot].value = Some(Connection {
            core,
            local: tuple.local,
            peer: tuple.remote,
            state,
            reason: None,
            close_requested: false,
            abort_requested: false,
            released: false,
            read_cursor: 0,
            trace_count: 0,
            connected_event: state == State::Established,
            closed_event: false,
            readable_event: false,
            read_waiting: true,
            arrived: false,
            write_waiting: None,
        });
        let taken = self.free_connections.pop();
        debug_assert_eq!(taken, Some(slot));
        occupy(&mut self.live_connections, slot);
        self.ports.take(tuple.local.port());
        self.connection_map.insert(core, slot);
        self.touch(slot);
        self.check_live();
        Ok(self.conn_id(slot))
    }
    // A change to connection `slot` that drain_events, and a close or abort
    // in progress, must look at again.
    fn touch(&mut self, slot: usize) {
        self.ready.push(slot);
        if self.connections[slot]
            .value
            .as_ref()
            .is_some_and(|c| (c.close_requested || c.abort_requested) && !c.released)
        {
            self.maintain.push(slot);
        }
    }
    fn port_in_use(&self, port: u16) -> bool {
        // The full-scan form of `ports`, for debug builds.
        debug_assert_eq!(
            self.ports.users(port) as usize,
            self.connections
                .iter()
                .filter_map(|s| s.value.as_ref())
                .filter(|c| c.local.port() == port)
                .count()
                + self
                    .listeners
                    .iter()
                    .filter_map(|s| s.value.as_ref())
                    .filter(|l| l.port == port)
                    .count()
        );
        self.ports.users(port) != 0
    }
    fn scoped(&self, tuple: Tuple) -> ntcp::ScopedTuple {
        let link_local = [tuple.local.ip(), tuple.remote.ip()]
            .into_iter()
            .any(|ip| matches!(ip, std::net::IpAddr::V6(a) if a.is_unicast_link_local()));
        ntcp::ScopedTuple::new(tuple, link_local.then_some(self.ingress.link()))
            .expect("single-port tuple scope")
    }
    fn allocate_port(&mut self, peer: SocketAddr) -> Result<u16> {
        if let Some(tagged) = self.flows.as_ref().and_then(|f| f.tagged()) {
            return self.allocate_tagged(tagged);
        }
        let start = self.next_port;
        loop {
            let candidate = self.next_port;
            self.next_port = if candidate == *self.config.ephemeral_ports.end() {
                *self.config.ephemeral_ports.start()
            } else {
                candidate + 1
            };
            // A member of shared flows takes a port whose flow to the peer
            // it owns, about one candidate in as many as there are members,
            // and none another member listens on.
            if self
                .flows
                .as_ref()
                .is_none_or(|f| f.owns(candidate, peer) && !f.listened(candidate))
                && !self.port_in_use(candidate)
            {
                return Ok(candidate);
            }
            if self.next_port == start {
                return Err(Error::Capacity);
            }
        }
    }
    // A member of tagged flows takes its own tagged ports only, each a port
    // whose flows it owns, stepping from one to the next by their bits: it
    // tries no other port of the range. No other member listens on them
    // (`listen` refuses), so the ports in use here, its own listeners
    // included, are the only ones it skips.
    fn allocate_tagged(&mut self, tagged: flows::PortRule) -> Result<u16> {
        let last = *self.config.ephemeral_ports.end();
        let first = tagged
            .first_in(self.config.ephemeral_ports.clone())
            .ok_or(Error::Capacity)?;
        let start = tagged.first_in(self.next_port..=last).unwrap_or(first);
        let mut candidate = start;
        loop {
            let next = candidate
                .checked_add(1)
                .and_then(|p| tagged.first_in(p..=last))
                .unwrap_or(first);
            if !self.port_in_use(candidate) {
                self.next_port = next;
                return Ok(candidate);
            }
            if next == start {
                return Err(Error::Capacity);
            }
            candidate = next;
        }
    }
    pub fn connect(&mut self, peer: SocketAddr) -> Result<ConnId> {
        self.connect_from(peer, None)
    }
    pub fn connect_from(&mut self, peer: SocketAddr, local_port: Option<u16>) -> Result<ConnId> {
        self.running()?;
        if matches!(peer, SocketAddr::V6(a) if a.scope_id() != 0 || a.flowinfo() != 0) {
            return Err(Error::Unsupported(
                "OS socket scope IDs and flow labels; native groups select their own link",
            ));
        }
        let slot = self.free_connection_slot()?;
        let port = match local_port {
            Some(0) => return Err(Error::InvalidConfig("zero local port")),
            Some(p) if self.flows.as_ref().is_some_and(|f| !f.owns(p, peer)) => {
                return Err(Error::InvalidConfig(
                    "another member of the shared flows owns this local port's flow",
                ));
            }
            Some(p) if self.port_in_use(p) => return Err(Error::Tcp(EndpointError::AddressInUse)),
            Some(p) => p,
            None => self.allocate_port(peer)?,
        };
        let local = SocketAddr::new(self.config.local_address, port);
        let options = ntcp::ManagedOpenOptions {
            transport: ntcp::ActiveOpenOptions::from(&self.config.tcp.connection),
            dscp: self.config.tcp.dscp,
            ipv4_options: Default::default(),
            registration: None,
            receive_authority: None,
        };
        let scoped = self.scoped(Tuple {
            local,
            remote: peer,
        });
        let core = self.endpoint.connect_scoped_with_path_provider(
            self.now,
            scoped,
            options,
            &mut self.host,
        )?;
        if let Err(e) = self
            .endpoint
            .set_tx_timestamp_capacity(core, self.config.tx_timestamp_phases)
            .and_then(|_| {
                self.endpoint
                    .set_rx_timestamp_capacity(core, self.config.rx_timestamp_ranges)
            })
        {
            let _ = self.endpoint.abort(core);
            let _ = self.endpoint.release(core);
            self.host.collect(&self.endpoint)?;
            return Err(e.into());
        }
        self.install(slot, core)
    }
    pub fn listen(&mut self, port: u16, backlog: usize) -> Result<ListenerId> {
        self.running()?;
        if self.flows.as_ref().is_some_and(|f| !f.may_listen(port)) {
            return Err(Error::InvalidConfig(
                "another member of the shared flows owns this tagged port",
            ));
        }
        let slot = *self.free_listeners.last().ok_or(Error::Capacity)?;
        let address = SocketAddr::new(self.config.local_address, port);
        let zone = match address.ip() {
            std::net::IpAddr::V6(a) if a.is_unicast_link_local() => Some(self.ingress.link()),
            _ => None,
        };
        let core = self.endpoint.listen_scoped(address, zone, backlog)?;
        if let Err(e) = self
            .endpoint
            .set_listener_rx_timestamp_capacity(core, self.config.rx_timestamp_ranges)
        {
            let _ = self.endpoint.close_listener(core);
            return Err(e.into());
        }
        self.listeners[slot].generation += 1;
        self.listeners[slot].value = Some(Listener {
            core,
            port,
            closing: false,
            acceptable: false,
        });
        let taken = self.free_listeners.pop();
        debug_assert_eq!(taken, Some(slot));
        occupy(&mut self.live_listeners, slot);
        self.ports.take(port);
        self.listener_map.insert(core, slot);
        if let Some(flows) = &mut self.flows {
            flows.listen(port);
        }
        self.check_live();
        Ok(ListenerId {
            instance: self.instance,
            slot,
            generation: self.listeners[slot].generation,
        })
    }
    pub fn accept(&mut self, listener: ListenerId) -> Result<ConnId> {
        self.running()?;
        let slot = self.free_connection_slot()?;
        let listener_state = self.listener(listener)?;
        if listener_state.closing {
            return Err(Error::InvalidHandle);
        }
        let core_listener = listener_state.core;
        let core = match self.endpoint.accept(core_listener) {
            Ok(core) => core,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                return Err(Error::WouldBlock(BlockReason::Accept));
            }
            Err(e) => return Err(e.into()),
        };
        if let Err(e) = self
            .endpoint
            .set_tx_timestamp_capacity(core, self.config.tx_timestamp_phases)
        {
            let _ = self.endpoint.abort(core);
            let _ = self.endpoint.release(core);
            return Err(e.into());
        }
        let acceptable = self.endpoint.listener_queue_info(core_listener)?.0 != 0;
        self.listeners[listener.slot]
            .value
            .as_mut()
            .unwrap()
            .acceptable = acceptable;
        if acceptable {
            self.ready.push(self.connections.len() + listener.slot);
        }
        let id = self.install(slot, core)?;
        self.refresh_connection(slot);
        Ok(id)
    }
    pub fn close_listener(&mut self, listener: ListenerId) -> Result<()> {
        self.running()?;
        self.listener(listener)?;
        self.listeners[listener.slot]
            .value
            .as_mut()
            .unwrap()
            .closing = true;
        self.maintain.push(self.connections.len() + listener.slot);
        Ok(())
    }
    pub fn connection_info(&self, id: ConnId) -> Result<ConnectionInfo> {
        let c = self.conn(id)?;
        // The endpoint's own state, not the one events were derived from: a
        // FIN sent or acknowledged, or TIME-WAIT ending, raises no event. A
        // released connection, or one of a stopped network, keeps its last.
        let (state, reason) = match self.endpoint.state(c.core) {
            Ok(state) if !c.released && !self.stopped => {
                (state, self.endpoint.close_reason(c.core).ok().flatten())
            }
            _ => (c.state, c.reason),
        };
        Ok(ConnectionInfo {
            local: c.local,
            peer: c.peer,
            state,
            reason,
            application_closed: c.close_requested || c.abort_requested,
            network_stopped: self.stopped,
        })
    }
    /// What connection `id` is ready for now, as poll(2) reports a socket,
    /// for an embedding that offers level-triggered readiness: events tell
    /// of changes, this of the state. A condition it reports false is armed
    /// as a refused read or write arms it, so the change that makes it true
    /// raises Readable or Writable. An embedding that keeps the connections
    /// it found ready and asks again before it reports them, as Linux's
    /// level-triggered epoll does, can drop one when it is no longer ready:
    /// its next change is an event. Asking changes nothing else.
    pub fn readiness(&mut self, id: ConnId) -> Result<Readiness> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        let core = c.core;
        let state = self.endpoint.state(core)?;
        let read_closed = matches!(
            state,
            State::CloseWait | State::Closing | State::LastAck | State::TimeWait | State::Closed
        );
        let closed = matches!(
            state,
            State::Closing | State::LastAck | State::TimeWait | State::Closed
        );
        // As refresh_connection raises Readable, and next_connection_event
        // Writable.
        let readable = !self.endpoint.is_output_reserved(core)
            && (read_closed
                || self.endpoint.readable_bytes(core).unwrap_or(0) != 0
                || self.endpoint.terminal_readable_bytes(core).unwrap_or(0) != 0);
        let open = matches!(state, State::Established | State::CloseWait);
        let writable = open
            && self
                .endpoint
                .check_write_admission(core, None, TxTimestampRequest::default())
                .is_ok_and(|n| n != 0);
        let c = self.conn_mut(id)?;
        // Data a reserved output keeps from being read is not readable; the
        // end of the reservation raises Readable only for an armed read.
        if !readable {
            c.read_waiting = true;
        }
        // A connection still connecting is told writable by Connected.
        if open && !writable && c.write_waiting.is_none() {
            c.write_waiting = Some(TxTimestampRequest::default());
        }
        Ok(Readiness {
            readable,
            writable,
            read_closed,
            closed,
        })
    }
    /// Whether `accept` on `listener` would give a connection now, for an
    /// embedding that offers level-triggered readiness. Nothing needs
    /// arming: every connection that joins the queue raises Acceptable.
    pub fn acceptable(&self, listener: ListenerId) -> Result<bool> {
        self.running()?;
        let l = self.listener(listener)?;
        if l.closing {
            return Err(Error::InvalidHandle);
        }
        Ok(self.endpoint.listener_queue_info(l.core)?.0 != 0)
    }
    pub fn send_progress(&self, id: ConnId) -> Result<SendProgress> {
        Ok(self.endpoint.send_progress(self.conn(id)?.core)?)
    }
    pub fn rx_timestamp_status(&self, id: ConnId) -> Result<RxTimestampStatus> {
        Ok(self.endpoint.rx_timestamp_status(self.conn(id)?.core)?)
    }
    fn writable_core(&self, id: ConnId) -> Result<ntcp::ConnectionId> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::Tcp(EndpointError::Connection(
                ntcp::Error::InvalidState,
            )));
        }
        match self.endpoint.state(c.core)? {
            State::SynSent | State::SynReceived => Err(Error::WouldBlock(BlockReason::Connecting)),
            State::Established | State::CloseWait => Ok(c.core),
            _ => Err(Error::ConnectionClosed(self.endpoint.close_reason(c.core)?)),
        }
    }
    pub fn try_write(
        &mut self,
        id: ConnId,
        data: &[u8],
        options: WriteOptions,
    ) -> Result<WriteReceipt> {
        // This first native service supports core Scheduled/ACK observations.
        // No backend timestamp source is advertised without its completion plumbing.
        if options.timestamps.software_transmit || options.timestamps.hardware_transmit {
            return Err(Error::Unsupported("native backend transmit timestamps"));
        }
        let core = self.writable_core(id)?;
        let before = self.endpoint.send_progress(core)?.queued_end;
        if data.is_empty() {
            return Ok(WriteReceipt {
                accepted: 0,
                range: TxStreamRange {
                    start: before,
                    end: before,
                },
            });
        }
        let phases = usize::from(options.timestamps.scheduled)
            + usize::from(options.timestamps.acknowledged);
        if phases > self.config.tx_timestamp_phases {
            return Err(Error::Unsupported(
                "requested timestamp phases exceed the configured capacity",
            ));
        }
        if phases
            > self
                .config
                .tx_timestamp_phases
                .saturating_sub(self.conn(id)?.trace_count)
        {
            self.conn_mut(id)?.write_waiting = Some(options.timestamps);
            return Err(Error::WouldBlock(BlockReason::TimestampCapacity));
        }
        let result =
            self.endpoint
                .write_with_timestamp(core, data, false, false, None, options.timestamps);
        let accepted = match result {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                self.conn_mut(id)?.write_waiting = Some(options.timestamps);
                return Err(Error::WouldBlock(BlockReason::SendBuffer));
            }
            Err(EndpointError::OutputReserved) => {
                self.conn_mut(id)?.write_waiting = Some(options.timestamps);
                return Err(Error::WouldBlock(BlockReason::OutputReserved));
            }
            Err(e) => return Err(e.into()),
        };
        self.conn_mut(id)?.trace_count += phases;
        Ok(WriteReceipt {
            accepted,
            range: TxStreamRange {
                start: before,
                end: before + accepted as u64,
            },
        })
    }
    pub fn try_read(&mut self, id: ConnId, out: &mut [u8]) -> Result<ReadOutcome> {
        let result = self.read_once(id, out);
        // What the read left to read, or the end of the stream, is queued
        // now, in the order it became ready again. A read that left nothing
        // is queued by the change that next gives it something.
        if self.conn(id).is_ok() {
            self.refresh_connection(id.slot);
            if self.connection_has_event(id.slot) {
                self.ready.push(id.slot);
            }
        }
        result
    }
    fn read_once(&mut self, id: ConnId, out: &mut [u8]) -> Result<ReadOutcome> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        if out.is_empty() {
            return Ok(ReadOutcome::EmptyBuffer);
        }
        let core = c.core;
        let state = self.endpoint.state(core)?;
        if matches!(state, State::SynSent | State::SynReceived) {
            return Err(Error::WouldBlock(BlockReason::Connecting));
        }
        let start = c.read_cursor;
        self.conn_mut(id)?.readable_event = false;
        self.conn_mut(id)?.read_waiting = true;
        let terminal = state == State::Closed;
        let available = if terminal {
            self.endpoint.terminal_readable_bytes(core)?
        } else {
            self.endpoint.readable_bytes(core)?
        };
        let count = out.len().min(available);
        let metadata = if count != 0 {
            self.endpoint.peek_rx_timestamps(core, count)?
        } else {
            None
        };
        let result = if terminal {
            self.endpoint.read_terminal(core, out)
        } else {
            self.endpoint.read(core, out)
        };
        let len = match result {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                return Err(Error::WouldBlock(BlockReason::Receive));
            }
            Err(EndpointError::Connection(ntcp::Error::InvalidState))
                if terminal
                    && count == 0
                    && self.endpoint.close_reason(core)? == Some(CloseReason::Normal) =>
            {
                0
            }
            Err(e) => return Err(e.into()),
        };
        if len == 0 {
            if terminal && self.endpoint.close_reason(core)? != Some(CloseReason::Normal) {
                return Err(Error::ConnectionClosed(self.endpoint.close_reason(core)?));
            }
            return Ok(ReadOutcome::Eof);
        }
        self.conn_mut(id)?.read_cursor += len as u64;
        Ok(ReadOutcome::Data {
            len,
            range: TxStreamRange {
                start,
                end: start + len as u64,
            },
            last_byte_timestamps: metadata,
        })
    }
    // Shared admission retains immutable storage in TCP. The packet backend
    // may still copy it; the remaining suffix stays in the caller's Payload.
    pub fn try_write_shared(&mut self, id: ConnId, payload: &mut Payload) -> Result<WriteReceipt> {
        let core = self.writable_core(id)?;
        let start = self.endpoint.send_progress(core)?.queued_end;
        if payload.is_empty() {
            return Ok(WriteReceipt {
                accepted: 0,
                range: TxStreamRange { start, end: start },
            });
        }
        let accepted = match self
            .endpoint
            .write_shared(core, payload.clone(), false, false, None)
        {
            Ok(n) => n,
            Err(EndpointError::Connection(ntcp::Error::WouldBlock)) => {
                self.conn_mut(id)?.write_waiting = Some(TxTimestampRequest::default());
                return Err(Error::WouldBlock(BlockReason::SendBuffer));
            }
            Err(EndpointError::OutputReserved) => {
                self.conn_mut(id)?.write_waiting = Some(TxTimestampRequest::default());
                return Err(Error::WouldBlock(BlockReason::OutputReserved));
            }
            Err(e) => return Err(e.into()),
        };
        *payload = payload
            .slice(accepted..payload.len())
            .expect("accepted payload prefix");
        Ok(WriteReceipt {
            accepted,
            range: TxStreamRange {
                start,
                end: start + accepted as u64,
            },
        })
    }
    pub fn set_nodelay(&mut self, id: ConnId, enabled: bool) -> Result<()> {
        self.running()?;
        self.endpoint.set_nagle(self.conn(id)?.core, !enabled)?;
        Ok(())
    }
    pub fn shutdown_write(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn(id)?;
        if c.close_requested || c.abort_requested || c.released {
            return Err(Error::InvalidHandle);
        }
        self.endpoint.shutdown(c.core)?;
        Ok(())
    }
    pub fn close(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn_mut(id)?;
        c.close_requested = true;
        c.readable_event = false;
        c.read_waiting = false;
        c.arrived = false;
        c.write_waiting = None;
        self.touch(id.slot);
        Ok(())
    }
    pub fn abort(&mut self, id: ConnId) -> Result<()> {
        self.running()?;
        let c = self.conn_mut(id)?;
        c.abort_requested = true;
        c.readable_event = false;
        c.read_waiting = false;
        c.arrived = false;
        c.write_waiting = None;
        self.touch(id.slot);
        Ok(())
    }

    fn refresh_connection(&mut self, slot: usize) {
        if self.stopped {
            return;
        }
        let Some(c) = self.connections[slot].value.as_mut() else {
            return;
        };
        if c.released {
            return;
        }
        if let Ok(state) = self.endpoint.state(c.core) {
            if matches!(state, State::Established | State::CloseWait)
                && matches!(c.state, State::SynSent | State::SynReceived)
            {
                c.connected_event = true;
            }
            if matches!(state, State::Closed | State::TimeWait)
                && !matches!(c.state, State::Closed | State::TimeWait)
            {
                c.closed_event = true;
            }
            c.state = state;
            c.reason = self.endpoint.close_reason(c.core).ok().flatten();
            if (c.read_waiting || c.arrived) && !self.endpoint.is_output_reserved(c.core) {
                c.arrived = false;
                c.readable_event = self.endpoint.readable_bytes(c.core).unwrap_or(0) != 0
                    || self.endpoint.terminal_readable_bytes(c.core).unwrap_or(0) != 0
                    || matches!(
                        state,
                        State::CloseWait
                            | State::Closing
                            | State::LastAck
                            | State::TimeWait
                            | State::Closed
                    );
            }
        }
    }
    fn collect_core_events(&mut self) {
        while self.events.len() < self.event_capacity {
            match self.endpoint.next_event() {
                Some(ntcp::Event::Connection(core, events)) => {
                    if let Some(&slot) = self.connection_map.get(&core) {
                        if (events.readable || events.half_closed)
                            && let Some(c) = self.connections[slot].value.as_mut()
                            && !(c.close_requested || c.abort_requested || c.released)
                        {
                            c.arrived = true;
                        }
                        self.touch(slot);
                        if events.tx_timestamps {
                            self.stamped.push(slot);
                        }
                    }
                }
                Some(ntcp::Event::Acceptable(core)) => {
                    if let Some(&slot) = self.listener_map.get(&core)
                        && let Some(l) = &mut self.listeners[slot].value
                    {
                        l.acceptable = true;
                        self.ready.push(self.connections.len() + slot);
                    }
                }
                Some(ntcp::Event::PassiveError {
                    listener,
                    tuple,
                    error,
                }) => {
                    if let Some(&slot) = self.listener_map.get(&listener) {
                        self.events.push_back(Event::PassiveError {
                            listener: ListenerId {
                                instance: self.instance,
                                slot,
                                generation: self.listeners[slot].generation,
                            },
                            peer: tuple.remote,
                            error,
                        });
                    }
                }
                Some(ntcp::Event::RouteAdvice(tuple)) => {
                    self.events.push_back(Event::RouteAdvice {
                        local: tuple.local,
                        peer: tuple.remote,
                    })
                }
                None => break,
            }
        }
    }
    fn next_connection_event(&mut self, slot: usize) -> Option<Event> {
        self.refresh_connection(slot);
        let id = self.conn_id(slot);
        let c = self.connections[slot].value.as_mut()?;
        if c.connected_event {
            c.connected_event = false;
            return Some(Event::Connected(id));
        }
        if c.closed_event {
            c.closed_event = false;
            return Some(Event::Closed {
                connection: id,
                reason: c.reason,
            });
        }
        if c.readable_event {
            c.readable_event = false;
            c.read_waiting = false;
            return Some(Event::Readable(id));
        }
        if let Some(request) = c.write_waiting {
            let phases = usize::from(request.scheduled) + usize::from(request.acknowledged);
            if !self.stopped
                && phases
                    <= self
                        .config
                        .tx_timestamp_phases
                        .saturating_sub(c.trace_count)
                && self
                    .endpoint
                    .check_write_admission(c.core, None, request)
                    .is_ok_and(|n| n != 0)
            {
                c.write_waiting = None;
                return Some(Event::Writable(id));
            }
        }
        None
    }
    pub fn drain_events(&mut self, out: &mut [Event]) -> DrainReport {
        self.collect_core_events();
        let mut written = 0;
        while written < out.len() {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            out[written] = event;
            written += 1;
        }
        if written < out.len() && self.stopped_event {
            out[written] = Event::NetworkStopped;
            written += 1;
            self.stopped_event = false;
        }
        self.check_live();
        // The slots queued when the drain began give at most one event each,
        // oldest change first; one with another event goes back to the tail
        // for a later drain. A slot is queued only by a change, so the queue
        // left behind is exactly the slots with events still to give.
        let connections = self.connections.len();
        for _ in 0..self.ready.len() {
            if written == out.len() {
                break;
            }
            let slot = self.ready.pop().unwrap();
            let event = if slot < connections {
                self.next_connection_event(slot)
            } else {
                let index = slot - connections;
                let generation = self.listeners[index].generation;
                self.listeners[index]
                    .value
                    .as_mut()
                    .filter(|l| l.acceptable && !l.closing)
                    .map(|l| {
                        l.acceptable = false;
                        Event::Acceptable(ListenerId {
                            instance: self.instance,
                            slot: index,
                            generation,
                        })
                    })
            };
            let Some(event) = event else {
                continue;
            };
            out[written] = event;
            written += 1;
            if slot < connections {
                if self.connection_has_event(slot) {
                    self.ready.push(slot);
                }
                // A close or abort waits for its connection's events to be
                // taken.
                if self.connections[slot]
                    .value
                    .as_ref()
                    .is_some_and(|c| c.close_requested || c.abort_requested)
                {
                    self.maintain.push(slot);
                }
            }
        }
        let more = !self.events.is_empty() || self.stopped_event || !self.ready.is_empty();
        if !more {
            self.check_ready();
        }
        DrainReport { written, more }
    }
    // The full-scan form of the ready queue, for debug builds: when a drain
    // leaves nothing queued, no live connection or listener has an event a
    // refresh would raise.
    fn check_ready(&self) {
        if !cfg!(debug_assertions) || self.stopped {
            return;
        }
        for &slot in &self.live_connections {
            debug_assert!(
                !self.unqueued_event(slot),
                "connection slot {slot} has an event but is not queued"
            );
        }
        for &slot in &self.live_listeners {
            let l = self.listeners[slot].value.as_ref().unwrap();
            debug_assert!(
                !(l.acceptable && !l.closing),
                "listener slot {slot} is acceptable but not queued"
            );
        }
    }
    // Whether refreshing connection `slot` and asking it for an event would
    // give one, without doing either.
    fn unqueued_event(&self, slot: usize) -> bool {
        let c = self.connections[slot].value.as_ref().unwrap();
        if c.released {
            return false;
        }
        let Ok(state) = self.endpoint.state(c.core) else {
            return false;
        };
        let connected = matches!(state, State::Established | State::CloseWait)
            && matches!(c.state, State::SynSent | State::SynReceived);
        let closed = matches!(state, State::Closed | State::TimeWait)
            && !matches!(c.state, State::Closed | State::TimeWait);
        let readable = (c.read_waiting || c.arrived)
            && !self.endpoint.is_output_reserved(c.core)
            && (self.endpoint.readable_bytes(c.core).unwrap_or(0) != 0
                || self.endpoint.terminal_readable_bytes(c.core).unwrap_or(0) != 0
                || matches!(
                    state,
                    State::CloseWait
                        | State::Closing
                        | State::LastAck
                        | State::TimeWait
                        | State::Closed
                ));
        connected || closed || readable || self.connection_has_event(slot)
    }
    // Whether next_connection_event would give an event, without taking it.
    fn connection_has_event(&self, slot: usize) -> bool {
        let c = self.connections[slot].value.as_ref().unwrap();
        c.connected_event
            || c.closed_event
            || c.readable_event
            || c.write_waiting.is_some_and(|request| {
                !self.stopped
                    && usize::from(request.scheduled) + usize::from(request.acknowledged)
                        <= self
                            .config
                            .tx_timestamp_phases
                            .saturating_sub(c.trace_count)
                    && self
                        .endpoint
                        .check_write_admission(c.core, None, request)
                        .is_ok_and(|n| n != 0)
            })
    }
    fn stage_timestamp(&mut self) -> bool {
        if self.staged_timestamp.is_some() {
            return true;
        }
        // Connections take turns, in the order their observations became
        // ready: one that gives an observation goes back to the tail, and one
        // with none left leaves the queue.
        while let Some(slot) = self.stamped.pop() {
            let Some(c) = self.connections[slot].value.as_ref() else {
                continue;
            };
            if !c.released
                && let Ok(Some(observation)) = self.endpoint.next_tx_timestamp(c.core)
            {
                self.stamped.push(slot);
                self.staged_timestamp = Some(TimestampEvent {
                    connection: self.conn_id(slot),
                    observation,
                });
                return true;
            }
        }
        false
    }
    pub fn drain_timestamps(&mut self, out: &mut [TimestampEvent]) -> DrainReport {
        // Observations that became ready since the last drive are announced
        // by their connections' events.
        self.collect_core_events();
        let mut written = 0;
        while written < out.len() && self.stage_timestamp() {
            let event = self.staged_timestamp.take().unwrap();
            if let Ok(c) = self.conn_mut(event.connection) {
                c.trace_count -= 1;
                // The freed phase may admit a waiting write or let a close
                // release the connection.
                self.touch(event.connection.slot);
            }
            out[written] = event;
            written += 1;
        }
        DrainReport {
            written,
            more: self.stage_timestamp(),
        }
    }
    // A pending observation can be cancelled explicitly; its Cancelled outcome
    // remains charged and drainable, just like a successful observation.
    pub fn cancel_timestamps(&mut self, id: ConnId) -> Result<()> {
        self.endpoint.cancel_tx_timestamps(self.conn(id)?.core)?;
        self.stamped.push(id.slot);
        Ok(())
    }
}
