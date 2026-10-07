#![cfg(target_os = "linux")]

use ntcp_io::{PacketIo, TxOutcome, af_packet::AfPacket, tun::Tun};
use std::{io, net::UdpSocket, os::fd::AsRawFd, process::Command, time::Duration};

fn ip(args: &[&str]) {
    assert!(Command::new("ip").args(args).status().unwrap().success());
}

fn index(name: &str) -> u32 {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: name is a terminated C string.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

fn ready(fd: i32) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is live and writable for the single poll entry.
    assert_eq!(
        unsafe { libc::poll(&mut pfd, 1, 2000) },
        1,
        "packet readiness timed out"
    );
    assert_ne!(pfd.revents & libc::POLLIN, 0);
}

fn incompatible_tun(name: &str, flags: libc::c_short) {
    use std::{fs::OpenOptions, os::fd::AsRawFd};
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .unwrap();
    // SAFETY: zero is valid for ifreq and its name buffer.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = flags;
    // SAFETY: live TUN fd and writable ifreq; persistence takes an integer.
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) },
        0
    );
    assert_eq!(
        unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETPERSIST, 1) },
        0
    );
    drop(file);
    let details = || {
        let output = Command::new("ip")
            .args(["-details", "link", "show", "dev", name])
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    };
    let before = details();
    assert_eq!(
        Tun::open(name).err().unwrap().kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        details(),
        before,
        "failed attach changed persistent TUN flags"
    );
    ip(&["link", "del", name]);
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) | u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
#[ignore = "run via tests/namespace.py in an isolated user+net namespace"]
fn isolated_roundtrips() {
    use std::os::unix::fs::MetadataExt;
    let parent: u64 = std::env::var("NTCP_IO_PARENT_NETNS")
        .expect("namespace launcher required")
        .parse()
        .unwrap();
    assert_ne!(
        std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
        parent,
        "refusing host interface changes"
    );
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link", "add", "nio-a", "type", "veth", "peer", "name", "nio-b",
    ]);
    ip(&["link", "set", "nio-a", "up"]);
    ip(&["link", "set", "nio-b", "up"]);
    let mut a = AfPacket::bind(index("nio-a"), 0x88b5).unwrap();
    let mut b = AfPacket::bind(index("nio-b"), 0x88b5).unwrap();
    let mut frame = [0x5a; 64];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let mut out = [0; 2048];
    assert_eq!(a.transmit(&frame).unwrap(), TxOutcome::Submitted);
    ready(b.as_raw_fd());
    assert_eq!(b.receive(&mut out).unwrap(), Some(frame.len()));
    assert_eq!(&out[..frame.len()], frame);
    assert_eq!(b.transmit(&frame).unwrap(), TxOutcome::Submitted);
    ready(a.as_raw_fd());
    assert_eq!(a.receive(&mut out).unwrap(), Some(frame.len()));
    assert_eq!(&out[..frame.len()], frame);
    a.transmit(&frame).unwrap();
    ready(b.as_raw_fd());
    assert_eq!(
        b.receive(&mut [0; 8]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    // veth receive strips the 802.1Q header into skb metadata. Never expose
    // the resulting untagged bytes as if they were the caller's tagged frame.
    let mut tagged = Vec::from(&frame[..12]);
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a]);
    tagged.extend_from_slice(&frame[12..]);
    for tci in [42u16, 0] {
        tagged[14..16].copy_from_slice(&tci.to_be_bytes());
        a.transmit(&tagged).unwrap();
        ready(b.as_raw_fd());
        assert_eq!(
            b.receive(&mut out).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(b.receive(&mut out).unwrap(), None);
    }
    let mut all = AfPacket::bind(index("nio-b"), libc::ETH_P_ALL as u16).unwrap();
    a.transmit(&tagged).unwrap();
    ready(all.as_raw_fd());
    assert_eq!(
        all.receive(&mut out).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    // The protocol-specific receiver must reject this frame too.
    ready(b.as_raw_fd());
    assert_eq!(
        b.receive(&mut out).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    drop(all);
    let mut other = AfPacket::bind(index("nio-b"), 0x88b6).unwrap();
    let mut unrelated = frame;
    unrelated[12..14].copy_from_slice(&0x88b6u16.to_be_bytes());
    a.transmit(&unrelated).unwrap();
    ready(other.as_raw_fd());
    assert_eq!(other.receive(&mut out).unwrap(), Some(unrelated.len()));
    assert_eq!(&out[..unrelated.len()], unrelated);
    assert_eq!(b.receive(&mut out).unwrap(), None); // filtered in-kernel
    a.transmit(&frame).unwrap();
    ready(b.as_raw_fd());
    assert_eq!(b.receive(&mut out).unwrap(), Some(frame.len()));
    assert_eq!(&out[..frame.len()], frame);

    for (name, flags) in [
        ("nio-pi", libc::IFF_TUN),
        (
            "nio-vnet",
            libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR,
        ),
        ("nio-both", libc::IFF_TUN | libc::IFF_VNET_HDR),
        (
            "nio-mq",
            libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE,
        ),
        ("nio-tap", libc::IFF_TAP | libc::IFF_NO_PI),
    ] {
        incompatible_tun(name, flags as libc::c_short);
    }

    assert!(Tun::open("nio-missing").is_err());
    assert_eq!(index("nio-missing"), 0);
    assert!(Tun::open("nio-a").is_err()); // reject an existing non-TUN interface
    let created = Tun::create("nio-new").unwrap();
    assert_eq!(created.name(), "nio-new");
    drop(created);
    assert_eq!(index("nio-new"), 0);
    ip(&["tuntap", "add", "dev", "nio-tun", "mode", "tun"]);
    let mut tun = Tun::open("nio-tun").unwrap();
    assert_eq!(tun.name(), "nio-tun");
    assert!(Tun::open("nio-tun").is_err()); // already attached, not multiqueue
    assert!(Tun::create("nio-tun").is_err()); // exclusive; no existing interface attachment
    let ipv6 = "/proc/sys/net/ipv6/conf/nio-tun/disable_ipv6";
    if std::path::Path::new(ipv6).exists() {
        std::fs::write(ipv6, "1").unwrap();
    }
    ip(&["addr", "add", "192.0.2.1/24", "dev", "nio-tun"]);
    ip(&["link", "set", "nio-tun", "up"]);
    let udp = UdpSocket::bind("192.0.2.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    udp.send_to(b"hello", "192.0.2.2:4242").unwrap();
    ready(tun.as_raw_fd());
    let len = tun.receive(&mut out).unwrap().unwrap();
    assert_eq!(out[0], 0x45);
    assert_eq!(out[9], 17);
    assert_eq!(&out[28..len], b"hello");
    // Turn the kernel's UDP packet into a valid incoming reply.
    for i in 0..4 {
        out.swap(12 + i, 16 + i);
    }
    out.swap(20, 22);
    out.swap(21, 23);
    out[26..28].fill(0); // IPv4 UDP checksum is optional
    out[10..12].fill(0);
    let sum = checksum(&out[..20]);
    out[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(tun.transmit(&out[..len]).unwrap(), TxOutcome::Submitted);
    let mut reply = [0; 16];
    let (len, peer) = udp.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..len], b"hello");
    assert_eq!(peer.to_string(), "192.0.2.2:4242");
    udp.send_to(b"too long", "192.0.2.2:4242").unwrap();
    ready(tun.as_raw_fd());
    assert_eq!(
        tun.receive(&mut [0; 8]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(tun.receive(&mut out).unwrap(), None);
    for fd in [a.as_raw_fd(), b.as_raw_fd(), tun.as_raw_fd()] {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }
    drop(tun);
    assert_ne!(index("nio-tun"), 0); // preconfigured persistent interface stays caller-owned
    ip(&["tuntap", "del", "dev", "nio-tun", "mode", "tun"]);
    assert_eq!(index("nio-tun"), 0);
}
