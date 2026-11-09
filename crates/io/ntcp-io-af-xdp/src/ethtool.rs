// ethtool channel counts (`ethtool -l`), RSS configuration (`ethtool -x`)
// and RX classification rules (`ethtool -N`), through SIOCETHTOOL.

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    net::Ipv4Addr,
    os::fd::{AsRawFd, OwnedFd},
};

const ETHTOOL_GCHANNELS: u32 = 0x3c;
const ETHTOOL_GRXCLSRLCNT: u32 = 0x2e;
const ETHTOOL_GRXCLSRLALL: u32 = 0x30;
const ETHTOOL_SRXCLSRLDEL: u32 = 0x31;
const ETHTOOL_SRXCLSRLINS: u32 = 0x32;
const ETHTOOL_GRSSH: u32 = 0x46;
const TCP_V4_FLOW: u32 = 0x01;
const IP_USER_FLOW: u32 = 0x0d;
const ETHER_FLOW: u32 = 0x12;
const ETH_RX_NFC_IP4: u8 = 1;
const RX_CLS_LOC_SPECIAL: u64 = 0x8000_0000;
const RX_CLS_LOC_ANY: u32 = 0xffff_ffff;
// ETH_RSS_HASH_* come from the kernel's include/linux/ethtool.h (the UAPI
// header has no names for hfunc values); RXH_XFRM_* from the UAPI header.
const ETH_RSS_HASH_TOP: u8 = 1 << 0;
const ETH_RSS_HASH_XOR: u8 = 1 << 1;
const ETH_RSS_HASH_CRC32: u8 = 1 << 2;
const RXH_XFRM_SYM_XOR: u8 = 1 << 0;
const RXH_XFRM_NO_CHANGE: u8 = 0xff;

/// What a rule matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Match {
    Ipv4Destination(Ipv4Addr),
    EtherType(u16),
    /// TCP/IPv4 to `address` whose destination port equals `port` in the
    /// bits set in `mask`.
    TcpIpv4Destination {
        address: Ipv4Addr,
        port: u16,
        mask: u16,
    },
}

/// The RSS configuration of a device's default RSS context (`ethtool -x
/// IF`), as its driver reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rss {
    /// The hash key; empty if the driver reports none.
    pub key: Vec<u8>,
    /// The indirection table: the RX queue of each entry. Empty if the driver
    /// reports none.
    pub table: Vec<u32>,
    pub function: RssFunction,
    /// The driver XORs source and destination fields before hashing
    /// (RXH_XFRM_SYM_XOR, `ethtool -x` "symmetric-xor"), so the hash input is
    /// not the received packet's fields in order.
    pub symmetric_xor: bool,
}

/// The RSS hash function (ETH_RSS_HASH_*).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RssFunction {
    Toeplitz,
    Xor,
    Crc32,
    /// Not reported (0) or a value this crate does not know.
    Other(u8),
}

impl RssFunction {
    fn from_hfunc(hfunc: u8) -> Self {
        match hfunc {
            ETH_RSS_HASH_TOP => Self::Toeplitz,
            ETH_RSS_HASH_XOR => Self::Xor,
            ETH_RSS_HASH_CRC32 => Self::Crc32,
            other => Self::Other(other),
        }
    }
}

// struct ethtool_rx_flow_spec. The flow unions are byte arrays: the
// usr_ip4_spec and ether_spec layouts are written at their UAPI offsets.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowSpec {
    flow_type: u32,
    h_u: [u8; 52],
    h_ext: [u8; 20],
    m_u: [u8; 52],
    m_ext: [u8; 20],
    ring_cookie: u64,
    location: u32,
}

// struct ethtool_rxnfc, without the trailing rule_locs array.
#[repr(C)]
#[derive(Clone, Copy)]
struct Rxnfc {
    cmd: u32,
    flow_type: u32,
    data: u64,
    fs: FlowSpec,
    rule_cnt: u32,
}

// struct ethtool_rxfh, without the trailing rss_config array: indir_size
// u32 queue indices, then key_size key octets.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rxfh {
    cmd: u32,
    rss_context: u32,
    indir_size: u32,
    key_size: u32,
    hfunc: u8,
    input_xfrm: u8,
    rsvd8: [u8; 2],
    rsvd32: u32,
}

#[repr(C)]
struct Ifreq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: *mut c_void,
    _union_rest: [u8; 16],
}

impl Rxnfc {
    fn new(cmd: u32) -> Self {
        // SAFETY: plain integers and byte arrays; all-zero is the empty request.
        Self {
            cmd,
            ..unsafe { std::mem::zeroed() }
        }
    }
}

fn spec(rule: Match, queue: u32, location: u32) -> FlowSpec {
    let mut spec = FlowSpec {
        flow_type: 0,
        h_u: [0; 52],
        h_ext: [0; 20],
        m_u: [0; 52],
        m_ext: [0; 20],
        ring_cookie: u64::from(queue),
        location,
    };
    match rule {
        Match::Ipv4Destination(address) => {
            // usr_ip4_spec: ip4src at 0, ip4dst at 4, l4_4_bytes, tos, ip_ver at 13.
            spec.flow_type = IP_USER_FLOW;
            spec.h_u[4..8].copy_from_slice(&address.octets());
            spec.h_u[13] = ETH_RX_NFC_IP4;
            spec.m_u[4..8].fill(0xff);
        }
        Match::EtherType(ether_type) => {
            // ether_spec (struct ethhdr): h_proto at 12.
            spec.flow_type = ETHER_FLOW;
            spec.h_u[12..14].copy_from_slice(&ether_type.to_be_bytes());
            spec.m_u[12..14].fill(0xff);
        }
        Match::TcpIpv4Destination {
            address,
            port,
            mask,
        } => {
            // tcp_ip4_spec: ip4src at 0, ip4dst at 4, psrc at 8, pdst at 10,
            // tos at 12. Mask bits set are compared, as for usr_ip4_spec.
            spec.flow_type = TCP_V4_FLOW;
            spec.h_u[4..8].copy_from_slice(&address.octets());
            spec.h_u[10..12].copy_from_slice(&port.to_be_bytes());
            spec.m_u[4..8].fill(0xff);
            spec.m_u[10..12].copy_from_slice(&mask.to_be_bytes());
        }
    }
    spec
}

// Without driver-chosen locations, take the last free one, as ethtool does
// for `loc` unspecified: the end of the table has the lowest priority.
fn free_location(size: u32, used: &[u32]) -> Option<u32> {
    (0..size).rev().find(|location| !used.contains(location))
}

fn ioctl(socket: &OwnedFd, ifindex: u32, data: *mut c_void) -> io::Result<()> {
    let mut request = Ifreq {
        name: [0; libc::IFNAMSIZ],
        data,
        _union_rest: [0; 16],
    };
    // Resolved at each call: rules belong to the interface, not to its name.
    // SAFETY: the buffer holds IFNAMSIZ bytes, as if_indextoname requires.
    if unsafe { libc::if_indextoname(ifindex, request.name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid ifreq whose data points at a live ethtool command
    // buffer, sized for the command, for the duration of the call.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCETHTOOL as _, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn context(error: io::Error, what: &str) -> io::Error {
    let kind = match error.raw_os_error() {
        Some(libc::EOPNOTSUPP) => io::ErrorKind::Unsupported,
        _ => error.kind(),
    };
    io::Error::new(kind, format!("{what}: {error}"))
}

/// RX queues the device has enabled: its RX-only and combined channels.
pub(crate) fn rx_channels(socket: &OwnedFd, ifindex: u32) -> io::Result<u32> {
    // struct ethtool_channels: cmd, four maxima, then rx, tx, other and
    // combined counts.
    let mut channels = [0u32; 9];
    channels[0] = ETHTOOL_GCHANNELS;
    ioctl(socket, ifindex, channels.as_mut_ptr().cast())
        .map_err(|e| context(e, "ETHTOOL_GCHANNELS"))?;
    Ok(channels[5].saturating_add(channels[8]))
}

/// The RSS key, indirection table and hash function of RSS context 0. None
/// if the driver has no RSS (EOPNOTSUPP) or reports neither a key nor a
/// table. A table that changes size between the two requests fails with
/// InvalidInput (EINVAL).
pub(crate) fn rss(socket: &OwnedFd, ifindex: u32) -> io::Result<Option<Rss>> {
    // Sizes first: zero sizes ask for the sizes only.
    let mut sizes = Rxfh {
        cmd: ETHTOOL_GRSSH,
        ..Rxfh::default()
    };
    match ioctl(socket, ifindex, (&mut sizes as *mut Rxfh).cast()) {
        Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => return Ok(None),
        result => result.map_err(|e| context(e, "ETHTOOL_GRSSH"))?,
    }
    if sizes.indir_size == 0 && sizes.key_size == 0 {
        return Ok(None);
    }
    // rxfh followed by the table and the key, in a u32 buffer for alignment.
    let header = size_of::<Rxfh>() / 4;
    let table = sizes.indir_size as usize;
    let key = sizes.key_size as usize;
    let mut buffer = vec![0u32; header + table + key.div_ceil(4)];
    // SAFETY: the buffer is 4-aligned and holds an Rxfh.
    unsafe {
        buffer.as_mut_ptr().cast::<Rxfh>().write(Rxfh {
            cmd: ETHTOOL_GRSSH,
            indir_size: sizes.indir_size,
            key_size: sizes.key_size,
            ..Rxfh::default()
        });
    }
    ioctl(socket, ifindex, buffer.as_mut_ptr().cast()).map_err(|e| context(e, "ETHTOOL_GRSSH"))?;
    // SAFETY: as above; the kernel wrote the reply header in place.
    let reply = unsafe { buffer.as_ptr().cast::<Rxfh>().read() };
    Ok(Some(decode_rss(&reply, &buffer[header..], table, key)))
}

// The kernel writes the table and key it was asked for, then the key size
// the driver left, which a reply may lower (to zero for an RSS context
// without its own key). RXH_XFRM_NO_CHANGE (all bits) reports no transform.
fn decode_rss(reply: &Rxfh, config: &[u32], table: usize, key: usize) -> Rss {
    let key = key.min(reply.key_size as usize);
    Rss {
        key: config[table..]
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .take(key)
            .collect(),
        table: config[..table].to_vec(),
        function: RssFunction::from_hfunc(reply.hfunc),
        symmetric_xor: reply.input_xfrm != RXH_XFRM_NO_CHANGE
            && reply.input_xfrm & RXH_XFRM_SYM_XOR != 0,
    }
}

/// Insert a rule steering `rule` to RX queue `queue`; returns its location.
/// Another writer of the same table between the location query and the
/// insertion may take the location first; drivers that replace a rule at
/// an occupied location (mlx5) then replace that writer's rule, as ethtool
/// itself would.
pub(crate) fn insert(socket: &OwnedFd, ifindex: u32, rule: Match, queue: u32) -> io::Result<u32> {
    let mut count = Rxnfc::new(ETHTOOL_GRXCLSRLCNT);
    ioctl(socket, ifindex, (&mut count as *mut Rxnfc).cast())
        .map_err(|e| context(e, "ETHTOOL_GRXCLSRLCNT"))?;
    let location = if count.data & RX_CLS_LOC_SPECIAL != 0 {
        RX_CLS_LOC_ANY
    } else {
        // rxnfc followed by rule_cnt locations, in a u64 buffer for alignment.
        let words = (size_of::<Rxnfc>() + 4 * count.rule_cnt as usize).div_ceil(8);
        let mut buffer = vec![0u64; words];
        let header = buffer.as_mut_ptr().cast::<Rxnfc>();
        // SAFETY: the buffer is 8-aligned and holds an Rxnfc.
        unsafe {
            header.write(Rxnfc {
                rule_cnt: count.rule_cnt,
                ..Rxnfc::new(ETHTOOL_GRXCLSRLALL)
            });
        }
        ioctl(socket, ifindex, buffer.as_mut_ptr().cast())
            .map_err(|e| context(e, "ETHTOOL_GRXCLSRLALL"))?;
        // SAFETY: the kernel wrote at most the rule_cnt it was given, after
        // the header (offset 188, inside the buffer); u32 alignment holds.
        let (size, used) = unsafe {
            let returned = (*header).rule_cnt.min(count.rule_cnt) as usize;
            // The table size as this reply reports it: drivers such as mlx5
            // report it here only, and ethtool reads it here.
            let size = ((*header).data & !RX_CLS_LOC_SPECIAL) as u32;
            let used = std::slice::from_raw_parts(
                buffer.as_ptr().cast::<u8>().add(188).cast::<u32>(),
                returned,
            );
            (size, used)
        };
        free_location(size, used).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::StorageFull,
                "no free RX classification rule location",
            )
        })?
    };
    let mut request = Rxnfc {
        fs: spec(rule, queue, location),
        ..Rxnfc::new(ETHTOOL_SRXCLSRLINS)
    };
    request.flow_type = request.fs.flow_type;
    ioctl(socket, ifindex, (&mut request as *mut Rxnfc).cast())
        .map_err(|e| context(e, "ETHTOOL_SRXCLSRLINS"))?;
    Ok(request.fs.location)
}

pub(crate) fn delete(socket: &OwnedFd, ifindex: u32, location: u32) -> io::Result<()> {
    let mut request = Rxnfc::new(ETHTOOL_SRXCLSRLDEL);
    request.fs.location = location;
    ioctl(socket, ifindex, (&mut request as *mut Rxnfc).cast())
        .map_err(|e| context(e, "ETHTOOL_SRXCLSRLDEL"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    #[test]
    fn layout_matches_uapi() {
        assert_eq!(size_of::<FlowSpec>(), 168);
        assert_eq!(offset_of!(FlowSpec, h_u), 4);
        assert_eq!(offset_of!(FlowSpec, h_ext), 56);
        assert_eq!(offset_of!(FlowSpec, m_u), 76);
        assert_eq!(offset_of!(FlowSpec, m_ext), 128);
        assert_eq!(offset_of!(FlowSpec, ring_cookie), 152);
        assert_eq!(offset_of!(FlowSpec, location), 160);
        assert_eq!(size_of::<Rxnfc>(), 192);
        assert_eq!(offset_of!(Rxnfc, data), 8);
        assert_eq!(offset_of!(Rxnfc, fs), 16);
        assert_eq!(offset_of!(Rxnfc, rule_cnt), 184);
        assert_eq!(size_of::<Ifreq>(), 40);
        assert_eq!(size_of::<Rxfh>(), 24);
        assert_eq!(offset_of!(Rxfh, rss_context), 4);
        assert_eq!(offset_of!(Rxfh, indir_size), 8);
        assert_eq!(offset_of!(Rxfh, key_size), 12);
        assert_eq!(offset_of!(Rxfh, hfunc), 16);
        assert_eq!(offset_of!(Rxfh, input_xfrm), 17);
        assert_eq!(offset_of!(Rxfh, rsvd32), 20);
    }

    #[test]
    fn tcp_port_spec() {
        let rule = Match::TcpIpv4Destination {
            address: Ipv4Addr::new(10, 80, 0, 12),
            port: 0x1230,
            mask: 0xfff0,
        };
        let tcp = spec(rule, 2, 5);
        assert_eq!(tcp.flow_type, TCP_V4_FLOW);
        assert_eq!(
            tcp.h_u[..13],
            [0, 0, 0, 0, 10, 80, 0, 12, 0, 0, 0x12, 0x30, 0]
        );
        assert_eq!(
            tcp.m_u[..13],
            [0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0xff, 0xf0, 0]
        );
        assert!(tcp.h_u[13..].iter().chain(&tcp.m_u[13..]).all(|&b| b == 0));
        assert!(tcp.h_ext.iter().chain(&tcp.m_ext).all(|&b| b == 0));
        assert_eq!((tcp.ring_cookie, tcp.location), (2, 5));
    }

    #[test]
    fn rss_reply() {
        let reply = Rxfh {
            cmd: ETHTOOL_GRSSH,
            indir_size: 4,
            key_size: 6,
            hfunc: ETH_RSS_HASH_TOP,
            ..Rxfh::default()
        };
        let key = [0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b];
        let mut config = vec![0, 1, 0, 1];
        config.push(u32::from_ne_bytes(key[..4].try_into().unwrap()));
        config.push(u32::from_ne_bytes([key[4], key[5], 0, 0]));
        let rss = decode_rss(&reply, &config, 4, 6);
        assert_eq!(
            rss,
            Rss {
                key: key.to_vec(),
                table: vec![0, 1, 0, 1],
                function: RssFunction::Toeplitz,
                symmetric_xor: false,
            }
        );
        let reply = Rxfh {
            key_size: 0,
            hfunc: 0,
            input_xfrm: RXH_XFRM_SYM_XOR,
            ..reply
        };
        let rss = decode_rss(&reply, &config, 4, 6);
        assert!(rss.key.is_empty());
        assert_eq!(rss.function, RssFunction::Other(0));
        assert!(rss.symmetric_xor);
        let reply = Rxfh {
            hfunc: ETH_RSS_HASH_CRC32,
            input_xfrm: RXH_XFRM_NO_CHANGE,
            ..reply
        };
        let rss = decode_rss(&reply, &config, 4, 6);
        assert_eq!(rss.function, RssFunction::Crc32);
        assert!(!rss.symmetric_xor);
    }

    // ETHTOOL_GRSSH needs no privilege; loopback has no RSS operations.
    #[test]
    fn loopback_has_no_rss() {
        // SAFETY: socket returns a new descriptor, checked before wrapping.
        let socket =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(socket >= 0, "{}", io::Error::last_os_error());
        // SAFETY: as above.
        let socket = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(socket) };
        // SAFETY: NUL-terminated name.
        let lo = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
        assert_ne!(lo, 0, "{}", io::Error::last_os_error());
        assert_eq!(rss(&socket, lo).unwrap(), None);
    }

    #[test]
    fn specs() {
        let ip = spec(Match::Ipv4Destination(Ipv4Addr::new(10, 80, 0, 12)), 3, 7);
        assert_eq!(ip.flow_type, IP_USER_FLOW);
        assert_eq!(
            ip.h_u[..16],
            [0, 0, 0, 0, 10, 80, 0, 12, 0, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(
            ip.m_u[..16],
            [0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(ip.h_u[16..].iter().chain(&ip.m_u[16..]).all(|&b| b == 0));
        assert_eq!((ip.ring_cookie, ip.location), (3, 7));
        let arp = spec(Match::EtherType(0x0806), 0, RX_CLS_LOC_ANY);
        assert_eq!(arp.flow_type, ETHER_FLOW);
        assert_eq!(arp.h_u[12..14], [0x08, 0x06]);
        assert_eq!(arp.m_u[12..14], [0xff, 0xff]);
        let mut rest = arp.h_u.to_vec();
        rest.extend_from_slice(&arp.m_u);
        rest.drain(64..66);
        rest.drain(12..14);
        assert!(rest.iter().all(|&b| b == 0));
        assert!(arp.h_ext.iter().chain(&arp.m_ext).all(|&b| b == 0));
    }

    #[test]
    fn last_free_location() {
        assert_eq!(free_location(4, &[]), Some(3));
        assert_eq!(free_location(4, &[3, 1]), Some(2));
        assert_eq!(free_location(4, &[3, 2]), Some(1));
        assert_eq!(free_location(2, &[0, 1]), None);
        assert_eq!(free_location(0, &[]), None);
    }
}
