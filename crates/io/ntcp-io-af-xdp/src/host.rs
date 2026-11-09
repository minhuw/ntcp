//! Opt-in AF_XDP host: attaches an XDP program to one interface, keeps the
//! set of IPv4 addresses that belong to ntcp, optionally steers frames to RX
//! queues with ethtool ntuple rules, and hands each queue to one worker
//! thread as a `HostedQueue` (an `AfXdp` socket registered with the program).
//!
//! The program (src/steer.bpf.c) sends an IPv4 frame whose destination, or an
//! Ethernet/IPv4 ARP frame whose target address, is one of the port's
//! addresses to the AF_XDP socket of the queue it arrived on, and passes all
//! other frames to the kernel: the interface keeps its kernel addresses and
//! traffic, and the kernel answers no ARP for ntcp's addresses. An ntcp frame
//! arriving on a queue without a socket is dropped and counted
//! (`Port::unsteered`). The address set records only which addresses are
//! ntcp's, not which queue serves them: the queue a frame arrives on alone
//! chooses its socket, and rules only change which queue that is.
//!
//! So an address needs no rule when every RX queue the device delivers its
//! frames on has a hosted queue, for example when every enabled RX queue
//! (`Port::enabled_queues`) is hosted, or on a device with one enabled RX
//! queue such as a default veth. Several Networks then share the address,
//! one per queue, and each receives what the device puts on its queue: the
//! embedding hands on frames whose flow another Network owns (ntcp-native's
//! shared flows do), and the Networks share one neighbour table, as ARP for
//! the address may arrive on any of them. Rules are needed when some of
//! those queues are not hosted, or when frames must reach a particular
//! queue: `steer_ipv4` sends an address to one queue (one Network per
//! address), `steer_tcp_port` the TCP destination ports of an address that
//! match a mask, and `steer_arp` sends ARP to one hosted queue. Frames no
//! rule matches arrive where the device puts them without rules. A frame
//! that both a port rule and an address rule match should take the port
//! rule: `steer_tcp_port` places its rule ahead of the others where the
//! driver lets the port choose (see there).
//!
//! The program is attached through a BPF link: it is detached when the last
//! handle of the port drops, and by the kernel if the process exits. ntuple
//! rules are deleted when their `Rule` drops; a rule left behind by a killed
//! process only steers frames between the device's own queues.
//!
//! Interfaces, the program and rules are resolved in the network namespace of
//! the thread that calls `Port::attach`.

use crate::{
    AfXdp, Config, Rss, RssFields,
    ethtool::{self, Placement},
};
use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[repr(C)]
struct BpfObject {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfMap {
    _private: [u8; 0],
}
#[repr(C)]
struct BpfProgram {
    _private: [u8; 0],
}

// struct bpf_link_create_opts up to `flags`; libbpf reads later fields as zero.
#[repr(C)]
struct LinkCreateOpts {
    sz: usize,
    flags: u32,
}

unsafe extern "C" {
    fn bpf_object__open_mem(
        buffer: *const c_void,
        size: usize,
        opts: *const c_void,
    ) -> *mut BpfObject;
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_object__find_program_by_name(
        object: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_map__set_max_entries(map: *mut BpfMap, entries: u32) -> c_int;
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__close(object: *mut BpfObject);
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_program__fd(program: *const BpfProgram) -> c_int;
    fn bpf_link_create(
        program: c_int,
        target: c_int,
        attach_type: u32,
        opts: *const LinkCreateOpts,
    ) -> c_int;
    fn bpf_map_update_elem(
        map: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_delete_elem(map: c_int, key: *const c_void) -> c_int;
    fn bpf_map_lookup_elem(map: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn libbpf_num_possible_cpus() -> c_int;
}

const BPF_XDP: u32 = 37;
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const IFLA_ADDRESS: u16 = 1;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const ETH_P_ARP: u16 = 0x0806;

#[repr(C, align(8))]
struct Aligned<T: ?Sized>(T);

// libelf reads the ELF headers in place.
static OBJECT: &Aligned<[u8]> = &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/steer.bpf.o")));

// libbpf 1.x: negative errno from int APIs, NULL and errno from pointer APIs.
fn bpf_result(context: &str, result: c_int) -> io::Result<c_int> {
    if result < 0 {
        let error = io::Error::from_raw_os_error(-result);
        return Err(io::Error::new(error.kind(), format!("{context}: {error}")));
    }
    Ok(result)
}

fn bpf_pointer<T>(context: &str, pointer: *mut T) -> io::Result<NonNull<T>> {
    NonNull::new(pointer).ok_or_else(|| {
        let error = io::Error::last_os_error();
        io::Error::new(error.kind(), format!("{context}: {error}"))
    })
}

// A descriptor that outlives the libbpf object owning the original.
fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fd is open (owned by a live libbpf object); F_DUPFD_CLOEXEC
    // returns a new descriptor that we own.
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: newly created, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

struct Object(NonNull<BpfObject>);

impl Object {
    fn open() -> io::Result<Self> {
        // SAFETY: a complete, static, 8-aligned ELF image; NULL opts.
        let object = unsafe {
            bpf_object__open_mem(OBJECT.0.as_ptr().cast(), OBJECT.0.len(), std::ptr::null())
        };
        bpf_pointer("bpf_object__open_mem", object).map(Self)
    }

    fn map(&self, name: &str) -> io::Result<NonNull<BpfMap>> {
        let name = CString::new(name).unwrap();
        // SAFETY: open object; NUL-terminated name.
        let map = unsafe { bpf_object__find_map_by_name(self.0.as_ptr(), name.as_ptr()) };
        bpf_pointer("bpf_object__find_map_by_name", map)
    }

    fn program(&self) -> io::Result<NonNull<BpfProgram>> {
        // SAFETY: open object; NUL-terminated name.
        let program =
            unsafe { bpf_object__find_program_by_name(self.0.as_ptr(), c"ntcp_steer".as_ptr()) };
        bpf_pointer("bpf_object__find_program_by_name", program)
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: opened by us, closed once; closes libbpf's descriptors only.
        unsafe { bpf_object__close(self.0.as_ptr()) };
    }
}

// The loaded program and its maps, owned independently of libbpf.
struct Loaded {
    program: OwnedFd,
    addresses: OwnedFd,
    sockets: OwnedFd,
    unsteered: OwnedFd,
}

impl Loaded {
    // Both the address and the socket map hold one entry per RX queue: each
    // hosted queue serves one Network, and a Network has one address.
    fn load(queues: u32) -> io::Result<Self> {
        let object = Object::open()?;
        for name in ["ntcp_addresses", "ntcp_sockets"] {
            // SAFETY: map of the open, not yet loaded object.
            let result = unsafe { bpf_map__set_max_entries(object.map(name)?.as_ptr(), queues) };
            bpf_result("bpf_map__set_max_entries", result)?;
        }
        // SAFETY: open object, loaded once.
        bpf_result("bpf_object__load", unsafe {
            bpf_object__load(object.0.as_ptr())
        })?;
        let map_fd = |name| -> io::Result<OwnedFd> {
            // SAFETY: map of the loaded object.
            let fd = unsafe { bpf_map__fd(object.map(name)?.as_ptr()) };
            duplicate(bpf_result("bpf_map__fd", fd)?)
        };
        // SAFETY: program of the loaded object.
        let program = unsafe { bpf_program__fd(object.program()?.as_ptr()) };
        Ok(Self {
            program: duplicate(bpf_result("bpf_program__fd", program)?)?,
            addresses: map_fd("ntcp_addresses")?,
            sockets: map_fd("ntcp_sockets")?,
            unsteered: map_fd("ntcp_unsteered")?,
        })
    }
}

fn update(map: &OwnedFd, key: &[u8], value: &[u8], flags: u64) -> c_int {
    // SAFETY: key and value buffers have the map's key and value sizes.
    unsafe {
        bpf_map_update_elem(
            map.as_raw_fd(),
            key.as_ptr().cast(),
            value.as_ptr().cast(),
            flags,
        )
    }
}

fn delete(map: &OwnedFd, key: &[u8]) -> c_int {
    // SAFETY: key buffer has the map's key size.
    unsafe { bpf_map_delete_elem(map.as_raw_fd(), key.as_ptr().cast()) }
}

/// How the program attaches to the interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpMode {
    /// In the driver (XDP_FLAGS_DRV_MODE). Fails on a driver without native
    /// XDP support rather than falling back to generic mode.
    Native,
    /// On the kernel's socket buffers (XDP_FLAGS_SKB_MODE), for any device.
    Generic,
}

/// Port setup. Construct with `PortConfig::new` and adjust fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortConfig {
    /// Interface name in the calling thread's network namespace.
    pub interface: String,
    pub mode: XdpMode,
    /// UMEM and ring sizes of every hosted queue's socket; see `Config`.
    pub frame_size: u32,
    pub frame_count: u32,
    pub ring_size: u32,
    pub headroom: u32,
    pub mtu: u32,
}

impl PortConfig {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            mode: XdpMode::Native,
            frame_size: 4096,
            // Half the frames fill the RX rings, half are free for TX.
            frame_count: 2048,
            ring_size: 1024,
            headroom: 0,
            mtu: 1500,
        }
    }
}

struct PortInner {
    // Drop order: the link first, detaching the program; then its maps.
    _link: OwnedFd,
    addresses: OwnedFd,
    sockets: OwnedFd,
    unsteered: OwnedFd,
    // SIOCETHTOOL requests go to the namespace this socket was created in.
    control: OwnedFd,
    ifindex: u32,
    mode: XdpMode,
    taken: Box<[AtomicBool]>,
    socket: Config,
}

/// The XDP program attached to one interface, with its address and socket
/// maps. Addresses, rules and queues hold the port; the program is detached
/// when the last of them and the port itself are dropped.
pub struct Port {
    inner: Arc<PortInner>,
}

impl Port {
    pub fn attach(config: PortConfig) -> io::Result<Port> {
        let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidInput, message);
        let name = CString::new(config.interface.as_str())
            .map_err(|_| invalid("interface name contains NUL".into()))?;
        // SAFETY: NUL-terminated name.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("interface {}: {error}", config.interface),
            ));
        }
        let socket = Config {
            ifindex,
            queue_id: 0,
            frame_size: config.frame_size,
            frame_count: config.frame_count,
            ring_size: config.ring_size,
            headroom: config.headroom,
            mtu: config.mtu,
        };
        socket.validate()?;
        let queues = rx_queues(ifindex)?;
        let loaded = Loaded::load(queues)?;
        let flags = match config.mode {
            XdpMode::Native => XDP_FLAGS_DRV_MODE,
            XdpMode::Generic => XDP_FLAGS_SKB_MODE,
        };
        let opts = LinkCreateOpts {
            sz: size_of::<LinkCreateOpts>(),
            flags,
        };
        // SAFETY: loaded XDP program; ifindex as the target; opts is valid
        // for its stated size.
        let link = unsafe {
            bpf_link_create(loaded.program.as_raw_fd(), ifindex as c_int, BPF_XDP, &opts)
        };
        let link = bpf_result(
            &format!(
                "attach XDP program to {} ({:?})",
                config.interface, config.mode
            ),
            link,
        )?;
        // SAFETY: bpf_link_create returned a new descriptor that we own.
        let link = unsafe { OwnedFd::from_raw_fd(link) };
        // SAFETY: socket returns a new descriptor, checked before wrapping.
        let control =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if control < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Port {
            inner: Arc::new(PortInner {
                _link: link,
                addresses: loaded.addresses,
                sockets: loaded.sockets,
                unsteered: loaded.unsteered,
                // SAFETY: as above.
                control: unsafe { OwnedFd::from_raw_fd(control) },
                ifindex,
                mode: config.mode,
                taken: (0..queues).map(|_| AtomicBool::new(false)).collect(),
                socket,
            }),
        })
    }

    pub fn ifindex(&self) -> u32 {
        self.inner.ifindex
    }

    pub fn mode(&self) -> XdpMode {
        self.inner.mode
    }

    /// RX queues the device allocated (IFLA_NUM_RX_QUEUES at attach): queue
    /// indices below this may be taken; a socket binds only to a queue the
    /// device has enabled.
    pub fn queues(&self) -> u32 {
        self.inner.taken.len() as u32
    }

    /// RX queues the device has enabled (`ethtool -l`: RX and combined
    /// channels), at the time of the call. Unsupported by drivers without
    /// channel reporting.
    pub fn enabled_queues(&self) -> io::Result<u32> {
        ethtool::rx_channels(&self.inner.control, self.inner.ifindex)
    }

    /// The RSS key, indirection table and hash function of the device's
    /// default RSS context (`ethtool -x IF`), at the time of the call. None if
    /// the driver has no RSS, or reports neither a key nor a table.
    pub fn rss(&self) -> io::Result<Option<Rss>> {
        ethtool::rss(&self.inner.control, self.inner.ifindex)
    }

    /// The packet fields the device's default RSS context hashes for
    /// TCP/IPv4 (`ethtool -n IF rx-flow-hash tcp4`), at the time of the
    /// call. None if the driver does not report them. A query of its own, as
    /// drivers support it apart from `rss` (ETHTOOL_GRXFH, not GRSSH).
    pub fn rss_tcp4_fields(&self) -> io::Result<Option<RssFields>> {
        ethtool::rss_tcp4_fields(&self.inner.control, self.inner.ifindex)
    }

    /// The interface's MAC address, as the kernel reports it at the time of
    /// the call.
    pub fn mac_address(&self) -> io::Result<[u8; 6]> {
        ntcp_io::linux::with_link(self.inner.ifindex, |attributes| {
            ntcp_io::linux::attribute(attributes, IFLA_ADDRESS)?
                .and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "interface has no MAC address")
                })
        })
    }

    /// Hand frames for `address` to the hosted queues (and no longer to the
    /// kernel) until the `Address` drops. The port holds one address per RX
    /// queue.
    pub fn add_ipv4(&self, address: Ipv4Addr) -> io::Result<Address> {
        let result = update(&self.inner.addresses, &address.octets(), &[1], BPF_NOEXIST);
        if result == -libc::EEXIST {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{address} already added"),
            ));
        }
        if result == -libc::E2BIG {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "address map full: one address per RX queue",
            ));
        }
        bpf_result("add address", result)?;
        Ok(Address {
            port: self.inner.clone(),
            address,
        })
    }

    /// Steer IPv4 frames with destination `address` to RX queue `queue`
    /// (`ethtool -N IF flow-type ip4 dst-ip ADDRESS action QUEUE`) until the
    /// `Rule` drops. Unsupported without ntuple filters in the driver; some
    /// drivers also need them enabled (`ethtool -K IF ntuple on`), mlx5 does
    /// not.
    pub fn steer_ipv4(&self, address: Ipv4Addr, queue: u32) -> io::Result<Rule> {
        let rule = ethtool::Match::Ipv4Destination(address);
        self.steer(rule, queue, Placement::Last)
    }

    /// Steer ARP frames to RX queue `queue` (`ethtool -N IF flow-type ether
    /// proto 0x0806 action QUEUE`) until the `Rule` drops. The kernel still
    /// receives the ARP frames that are not for ntcp, on that queue.
    pub fn steer_arp(&self, queue: u32) -> io::Result<Rule> {
        let rule = ethtool::Match::EtherType(ETH_P_ARP);
        self.steer(rule, queue, Placement::Last)
    }

    /// Steer TCP/IPv4 frames with destination `address` whose destination
    /// port equals `port` in the bits set in `mask` to RX queue `queue`
    /// (`ethtool -N IF flow-type tcp4 dst-ip ADDRESS dst-port PORT action
    /// QUEUE`, with a port mask) until the `Rule` drops. `port` must have no
    /// bits outside `mask`. Unsupported without ntuple filters in the driver;
    /// drivers may refuse partial port masks.
    ///
    /// Where it overlaps a `steer_ipv4` rule for the same address, this is
    /// the more specific rule, so it takes the first free location and the
    /// others the last: drivers that rank rules by location (lower first,
    /// as the UAPI describes RX_CLS_LOC_FIRST) then apply it first. mlx5
    /// ranks rules by the number of fields they match instead (a flow table
    /// per count, en_fs_ethtool.c), which puts it first as well: address,
    /// port and TCP against address and IPv4. Drivers that choose locations
    /// themselves rank rules their own way.
    pub fn steer_tcp_port(
        &self,
        address: Ipv4Addr,
        port: u16,
        mask: u16,
        queue: u32,
    ) -> io::Result<Rule> {
        if port & !mask != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP port has bits outside its mask",
            ));
        }
        let rule = ethtool::Match::TcpIpv4Destination {
            address,
            port,
            mask,
        };
        self.steer(rule, queue, Placement::First)
    }

    fn steer(&self, rule: ethtool::Match, queue: u32, placement: Placement) -> io::Result<Rule> {
        if queue >= self.queues() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "steering target queue out of range",
            ));
        }
        let location = ethtool::insert(
            &self.inner.control,
            self.inner.ifindex,
            rule,
            queue,
            placement,
        )?;
        Ok(Rule {
            port: self.inner.clone(),
            location,
        })
    }

    /// Frames for the port's addresses that arrived on a queue without a
    /// socket and were dropped, since attach.
    pub fn unsteered(&self) -> io::Result<u64> {
        unsteered(&self.inner.unsteered)
    }

    /// Hand out queue `index` unless a handle or a hosted queue holds it;
    /// dropping either returns the index.
    pub fn take_queue(&self, index: u32) -> io::Result<QueueHandle> {
        let taken = self.inner.taken.get(index as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "queue index out of range")
        })?;
        if taken.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "queue already taken",
            ));
        }
        Ok(QueueHandle {
            claim: Claim {
                port: self.inner.clone(),
                queue: index,
            },
        })
    }
}

fn rx_queues(ifindex: u32) -> io::Result<u32> {
    let queues = ntcp_io::linux::with_link(ifindex, |attributes| {
        Ok(ntcp_io::linux::attribute(attributes, IFLA_NUM_RX_QUEUES)?
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_ne_bytes))
    })?;
    queues.filter(|&n| n != 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "interface reports no RX queue count",
        )
    })
}

fn unsteered(map: &OwnedFd) -> io::Result<u64> {
    // SAFETY: no arguments; libbpf reads the possible-CPU list.
    let cpus = bpf_result("libbpf_num_possible_cpus", unsafe {
        libbpf_num_possible_cpus()
    })?;
    // A per-CPU lookup copies one 8-aligned value per possible CPU.
    let mut values = vec![0u64; cpus as usize];
    // SAFETY: key 0 has the map's 4-byte key size; values holds every CPU's.
    let result = unsafe {
        bpf_map_lookup_elem(
            map.as_raw_fd(),
            (&0u32 as *const u32).cast(),
            values.as_mut_ptr().cast(),
        )
    };
    bpf_result("read unsteered count", result)?;
    Ok(values.iter().sum())
}

/// An IPv4 address of the port; frames for it go to the hosted queues until
/// it drops.
pub struct Address {
    port: Arc<PortInner>,
    address: Ipv4Addr,
}

impl Address {
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
}

impl Drop for Address {
    fn drop(&mut self) {
        delete(&self.port.addresses, &self.address.octets());
    }
}

/// An ethtool RX classification rule of the port's device, deleted on drop.
pub struct Rule {
    port: Arc<PortInner>,
    location: u32,
}

impl Rule {
    /// The rule's location in the device's table (`ethtool -n IF`).
    pub fn location(&self) -> u32 {
        self.location
    }
}

impl Drop for Rule {
    fn drop(&mut self) {
        let _ = ethtool::delete(&self.port.control, self.port.ifindex, self.location);
    }
}

struct Claim {
    port: Arc<PortInner>,
    queue: u32,
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.port.taken[self.queue as usize].store(false, Ordering::Release);
    }
}

/// Exclusive right to one RX/TX queue pair; move it to the worker thread and
/// attach.
pub struct QueueHandle {
    claim: Claim,
}

impl QueueHandle {
    pub fn queue(&self) -> u32 {
        self.claim.queue
    }

    /// Run on the worker thread that will poll the queue: opens a copy-mode
    /// AF_XDP socket on the queue and registers it with the program.
    pub fn attach(self) -> io::Result<HostedQueue> {
        let port = &self.claim.port;
        let io = AfXdp::new(Config {
            queue_id: self.claim.queue,
            ..port.socket
        })?;
        let result = update(
            &port.sockets,
            &self.claim.queue.to_ne_bytes(),
            &io.as_raw_fd().to_ne_bytes(),
            BPF_ANY,
        );
        bpf_result("register AF_XDP socket", result)?;
        Ok(HostedQueue {
            io,
            claim: self.claim,
        })
    }
}

/// One queue pair served on its worker thread: PacketIo over an `AfXdp`
/// socket registered with the port's program, keeping the port alive.
/// !Send, like `AfXdp`.
pub struct HostedQueue {
    // Drop: unregister (Drop below), close the socket, then release the queue.
    io: AfXdp,
    claim: Claim,
}

impl HostedQueue {
    pub fn queue(&self) -> u32 {
        self.claim.queue
    }

    pub fn ifindex(&self) -> u32 {
        self.claim.port.ifindex
    }
}

impl Drop for HostedQueue {
    fn drop(&mut self) {
        delete(&self.claim.port.sockets, &self.claim.queue.to_ne_bytes());
    }
}

impl PacketIo for HostedQueue {
    fn layer(&self) -> PacketLayer {
        self.io.layer()
    }
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        self.io.local_ip_mtu()
    }
    fn max_packet_len(&self) -> Option<usize> {
        self.io.max_packet_len()
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.io.receive(out)
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        self.io.transmit(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn bpf_map__type(map: *const BpfMap) -> u32;
        fn bpf_map__key_size(map: *const BpfMap) -> u32;
        fn bpf_map__value_size(map: *const BpfMap) -> u32;
        fn bpf_map__max_entries(map: *const BpfMap) -> u32;
        fn bpf_program__type(program: *const BpfProgram) -> u32;
        fn bpf_prog_test_run_opts(program: c_int, opts: *mut TestRunOpts) -> c_int;
    }

    #[repr(C)]
    struct TestRunOpts {
        sz: usize,
        data_in: *const c_void,
        data_out: *mut c_void,
        data_size_in: u32,
        data_size_out: u32,
        ctx_in: *const c_void,
        ctx_out: *mut c_void,
        ctx_size_in: u32,
        ctx_size_out: u32,
        retval: u32,
        repeat: i32,
        duration: u32,
        flags: u32,
        cpu: u32,
        batch_size: u32,
    }

    const BPF_PROG_TYPE_XDP: u32 = 6;
    const BPF_MAP_TYPE_HASH: u32 = 1;
    const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    const BPF_MAP_TYPE_XSKMAP: u32 = 17;
    const XDP_DROP: u32 = 1;
    const XDP_PASS: u32 = 2;

    // Opening parses the embedded ELF without the bpf() syscall.
    #[test]
    fn embedded_program_and_maps() {
        let object = Object::open().unwrap();
        // SAFETY: program and maps of the open object.
        unsafe {
            assert_eq!(
                bpf_program__type(object.program().unwrap().as_ptr()),
                BPF_PROG_TYPE_XDP
            );
            for (name, kind, key, value) in [
                ("ntcp_addresses", BPF_MAP_TYPE_HASH, 4, 1),
                ("ntcp_sockets", BPF_MAP_TYPE_XSKMAP, 4, 4),
                ("ntcp_unsteered", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8),
            ] {
                let map = object.map(name).unwrap().as_ptr();
                assert_eq!(
                    (
                        bpf_map__type(map),
                        bpf_map__key_size(map),
                        bpf_map__value_size(map)
                    ),
                    (kind, key, value),
                    "{name}"
                );
            }
            let map = object.map("ntcp_addresses").unwrap().as_ptr();
            assert_eq!(bpf_map__set_max_entries(map, 8), 0);
            assert_eq!(bpf_map__max_entries(map), 8);
        }
        assert!(object.map("missing").is_err());
    }

    fn run(program: &OwnedFd, frame: &[u8]) -> u32 {
        let mut out = [0u8; 256];
        let mut opts = TestRunOpts {
            sz: size_of::<TestRunOpts>(),
            data_in: frame.as_ptr().cast(),
            data_out: out.as_mut_ptr().cast(),
            data_size_in: frame.len() as u32,
            data_size_out: out.len() as u32,
            ctx_in: std::ptr::null(),
            ctx_out: std::ptr::null_mut(),
            ctx_size_in: 0,
            ctx_size_out: 0,
            retval: u32::MAX,
            repeat: 1,
            duration: 0,
            flags: 0,
            cpu: 0,
            batch_size: 0,
        };
        // SAFETY: input and output buffers live for the call with the given sizes.
        let result = unsafe { bpf_prog_test_run_opts(program.as_raw_fd(), &mut opts) };
        bpf_result("bpf_prog_test_run_opts", result).unwrap();
        opts.retval
    }

    fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&ether_type.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(destination: [u8; 4]) -> Vec<u8> {
        let mut header = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1];
        header.extend_from_slice(&destination);
        ethernet(0x0800, &header)
    }

    fn arp(target: [u8; 4], plen: u8) -> Vec<u8> {
        let mut body = vec![0, 1, 8, 0, 6, plen, 0, 1, 2, 0, 0, 0, 0, 2, 10, 0, 0, 1];
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&target);
        ethernet(0x0806, &body)
    }

    // The program's verdicts, through BPF_PROG_TEST_RUN. No socket is
    // registered, so ntcp frames take the unsteered path.
    #[test]
    #[ignore = "requires CAP_BPF and CAP_NET_ADMIN (BPF_PROG_LOAD, BPF_PROG_TEST_RUN)"]
    fn program_verdicts() {
        let loaded = Loaded::load(1).unwrap();
        let ours = [10, 80, 0, 12];
        let other = [10, 80, 0, 13];
        assert_eq!(update(&loaded.addresses, &ours, &[1], BPF_NOEXIST), 0);
        assert_eq!(
            update(&loaded.addresses, &other, &[1], BPF_NOEXIST),
            -libc::E2BIG
        );
        let count = || unsteered(&loaded.unsteered).unwrap();
        assert_eq!(count(), 0);
        assert_eq!(run(&loaded.program, &ipv4(ours)), XDP_DROP);
        assert_eq!(run(&loaded.program, &arp(ours, 4)), XDP_DROP);
        assert_eq!(count(), 2);
        let mut truncated = ipv4(ours);
        truncated.pop();
        let mut arp_truncated = arp(ours, 4);
        arp_truncated.pop();
        let mut tagged = ipv4(ours);
        tagged.splice(12..12, [0x81, 0x00, 0x00, 0x01]);
        let mut ipv6 = ipv4(ours);
        ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
        for frame in [
            ipv4(other),
            arp(other, 4),
            // Not Ethernet/IPv4 ARP: the target is not an IPv4 address.
            arp(ours, 16),
            truncated,
            arp_truncated,
            tagged,
            ipv6,
            ethernet(0x0800, &[]),
        ] {
            assert_eq!(run(&loaded.program, &frame), XDP_PASS, "{frame:02x?}");
        }
        assert_eq!(count(), 2);
        assert_eq!(delete(&loaded.addresses, &ours), 0);
        assert_eq!(run(&loaded.program, &ipv4(ours)), XDP_PASS);
        assert_eq!(count(), 2);
    }
}
