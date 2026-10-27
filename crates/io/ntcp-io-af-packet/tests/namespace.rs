#![cfg(target_os = "linux")]

use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_af_packet::AfPacket;
use ntcp_io_tun::Tun;
use std::{io, net::UdpSocket, os::fd::AsRawFd, process::Command, time::Duration};

fn ip(args: &[&str]) {
    assert!(Command::new("ip").args(args).status().unwrap().success());
}

fn index(name: &str) -> u32 {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: name is a terminated C string.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

#[track_caller]
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
    assert_eq!(a.local_ip_mtu().unwrap(), Some(1500));
    assert_eq!(a.max_packet_len(), None);
    ip(&["link", "set", "nio-a", "mtu", "1400"]);
    assert_eq!(a.local_ip_mtu().unwrap(), Some(1400));
    ip(&["link", "set", "nio-a", "name", "nio-renamed"]);
    assert_eq!(a.local_ip_mtu().unwrap(), Some(1400));
    ip(&["link", "set", "nio-renamed", "name", "nio-a"]);
    ip(&["link", "set", "nio-a", "mtu", "1500"]);
    assert_eq!(a.local_ip_mtu().unwrap(), Some(1500));
    let mut frame = [0x5a; 64];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let mut out = [0; 2048];
    // Live MTU counts IP bytes; untagged frame allowance adds exactly 14.
    ip(&["link", "set", "nio-a", "mtu", "1400"]);
    let mut large = vec![0; 1415];
    large[..frame.len()].copy_from_slice(&frame);
    assert_eq!(
        a.transmit(&large).unwrap_err().raw_os_error(),
        Some(libc::EMSGSIZE)
    );
    assert_eq!(b.receive(&mut out).unwrap(), None);
    assert_eq!(a.transmit(&large[..1414]).unwrap(), TxOutcome::Submitted);
    ready(b.as_raw_fd());
    assert_eq!(b.receive(&mut out).unwrap(), Some(1414));
    ip(&["link", "set", "nio-a", "mtu", "1500"]);
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

    ip(&["link", "add", "nio-gone", "type", "dummy"]);
    let gone = AfPacket::bind(index("nio-gone"), 0x88b5).unwrap();
    assert!(gone.local_ip_mtu().unwrap().is_some());
    ip(&["link", "del", "nio-gone"]);
    assert_eq!(
        gone.local_ip_mtu().unwrap_err().raw_os_error(),
        Some(libc::ENODEV)
    );

    assert!(Tun::open("nio-missing").is_err());
    assert_eq!(index("nio-missing"), 0);
    assert!(Tun::open("nio-a").is_err()); // reject an existing non-TUN interface
    let created = Tun::create("nio-new").unwrap();
    assert_eq!(created.max_packet_len(), None);
    ip(&["link", "set", "nio-new", "mtu", "1400"]);
    assert_eq!(created.local_ip_mtu().unwrap(), Some(1400));
    ip(&["link", "set", "nio-new", "name", "nio-renamed"]);
    ip(&["link", "set", "nio-renamed", "mtu", "9000"]);
    assert_eq!(created.local_ip_mtu().unwrap(), Some(9000));
    ip(&["link", "set", "nio-renamed", "name", "nio-new"]);
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

#[test]
#[ignore = "run via tests/namespace.py in an isolated user+net namespace"]
fn isolated_software_timestamps() {
    use ntcp_io::{
        ClockDomain, TimestampPoint, TimestampSource, TimestampUnit, TxTimestampRequest,
    };
    use ntcp_io_af_packet::TimestampConfig;
    use std::{os::unix::fs::MetadataExt, time::Instant};
    let parent: u64 = std::env::var("NTCP_IO_PARENT_NETNS")
        .expect("namespace launcher required")
        .parse()
        .unwrap();
    assert_ne!(
        std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
        parent,
        "refusing host interface changes"
    );
    ip(&[
        "link", "add", "nio-ts-a", "type", "veth", "peer", "name", "nio-ts-b",
    ]);
    ip(&["link", "set", "nio-ts-a", "up"]);
    ip(&["link", "set", "nio-ts-b", "up"]);
    let mut a = AfPacket::bind(index("nio-ts-a"), 0x88b5).unwrap();
    let mut b = AfPacket::bind(index("nio-ts-b"), 0x88b5).unwrap();
    let mut frame = [0x5a; 64];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    let mut out = [0; 2048];
    let disabled = TxTimestampRequest {
        cookie: 1,
        software: true,
        hardware: false,
    };
    assert_eq!(
        a.transmit_with_timestamp(&frame, disabled)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(b.receive(&mut out).unwrap(), None); // no submission
    a.enable_timestamps(TimestampConfig {
        tx_software: true,
        tx_hardware: true,
        device_clock: Some(77),
        tx_completion_capacity: 2,
        ..Default::default()
    })
    .unwrap();
    b.enable_timestamps(TimestampConfig {
        rx_software: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(a.timestamp_capabilities().tx_completion_capacity, 2);
    assert!(b.timestamp_capabilities().rx_software);
    for (software, hardware, kind) in [
        (false, false, io::ErrorKind::InvalidInput),
        (true, false, io::ErrorKind::Unsupported),
        (true, true, io::ErrorKind::Unsupported),
    ] {
        assert_eq!(
            b.transmit_with_timestamp(
                &frame,
                TxTimestampRequest {
                    cookie: 5,
                    software,
                    hardware
                }
            )
            .unwrap_err()
            .kind(),
            kind
        );
        assert_eq!(a.receive(&mut out).unwrap(), None);
    }
    // net_enable_timestamp() schedules a work item to enable the RX static
    // key. Especially on a freshly booted VM, initial frames can have no stamp.
    // Require a real observation within a deadline, never invent a fallback.
    // Plain TX with reporting enabled must not request TX events.
    let deadline = Instant::now() + Duration::from_secs(2);
    let sw = loop {
        assert_eq!(a.transmit(&frame).unwrap(), TxOutcome::Submitted);
        ready(b.as_raw_fd());
        let received = b.receive_with_metadata(&mut out).unwrap().unwrap();
        assert_eq!(received.len, frame.len());
        assert_eq!(&out[..received.len], frame);
        assert!(received.timestamps.hardware.is_none());
        if let Some(sw) = received.timestamps.software {
            break sw;
        }
        assert!(Instant::now() < deadline, "missing SOFTWARE RX timestamp");
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(sw.value > 0);
    assert_eq!(sw.source, TimestampSource::Software);
    assert_eq!(sw.point, TimestampPoint::KernelReceive);
    assert_eq!(sw.clock.domain, ClockDomain::Realtime);
    assert_eq!(sw.clock.unit, TimestampUnit::Nanoseconds);
    assert!(a.poll_tx_timestamp().unwrap().is_none());
    assert!(b.receive_with_metadata(&mut out).unwrap().is_none());

    // A failed syscall must not retain the cookie or reserve completions.
    assert!(a.transmit_with_timestamp(&[], disabled).is_err());
    assert!(!a.cancel_tx_timestamp(disabled.cookie).unwrap());
    assert_eq!(b.receive(&mut out).unwrap(), None);

    let mut supported = true;
    for cookie in [u64::MAX, 0, 0x1234_5678_9abc_def0] {
        let request = TxTimestampRequest {
            cookie,
            software: true,
            hardware: true,
        };
        match a.transmit_with_timestamp(&frame, request) {
            Ok(TxOutcome::Submitted) => {}
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                // Pre-6.13 kernels reject unknown SCM_TS_OPT_ID in sock_cmsg_send,
                // before AF_PACKET queues the frame. No fallback ID guessing.
                assert_eq!(b.receive(&mut out).unwrap(), None);
                assert!(!a.cancel_tx_timestamp(cookie).unwrap());
                assert!(a.poll_tx_timestamp().unwrap().is_none());
                assert!(
                    std::env::var_os("NTCP_AF_PACKET_REQUIRE_TX").is_none(),
                    "explicit-ID TX required by this run: {error}"
                );
                eprintln!("SCM_TS_OPT_ID unsupported; verified rejection before packet acceptance");
                supported = false;
                break;
            }
            other => panic!("unexpected timestamp send: {other:?}"),
        }
        assert_eq!(
            a.transmit_with_timestamp(&frame, request)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            a.transmit_with_timestamp(
                &frame,
                TxTimestampRequest {
                    cookie: 13,
                    ..request
                }
            )
            .unwrap(),
            TxOutcome::WouldBlock
        );
        ready(b.as_raw_fd());
        assert_eq!(
            b.receive_with_metadata(&mut out).unwrap().unwrap().len,
            frame.len()
        );
        assert_eq!(&out[..frame.len()], frame);
        assert_eq!(b.receive(&mut out).unwrap(), None); // rejected sends have no side effects
        let deadline = Instant::now() + Duration::from_secs(2);
        let completion = loop {
            if let Some(completion) = a.poll_tx_timestamp().unwrap() {
                break completion;
            }
            assert!(
                Instant::now() < deadline,
                "missing SOFTWARE TX completion (kernel-ID mismatch?)"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(completion.cookie, cookie);
        assert_eq!(completion.timestamp.source, TimestampSource::Software);
        assert_eq!(completion.timestamp.point, TimestampPoint::KernelTransmit);
        assert_eq!(completion.timestamp.clock.domain, ClockDomain::Realtime);
        assert!(completion.timestamp.value > 0);
        assert!(a.poll_tx_timestamp().unwrap().is_none());
        // veth has no HW completion: the missing source remains reserved.
        assert_eq!(
            a.transmit_with_timestamp(
                &frame,
                TxTimestampRequest {
                    cookie: 13,
                    ..request
                }
            )
            .unwrap(),
            TxOutcome::WouldBlock
        );
        assert!(a.cancel_tx_timestamp(cookie).unwrap());
        assert!(!a.cancel_tx_timestamp(cookie).unwrap());
        assert_eq!(a.transmit(&frame).unwrap(), TxOutcome::Submitted);
        ready(b.as_raw_fd());
        assert_eq!(b.receive(&mut out).unwrap(), Some(frame.len()));
        assert!(a.poll_tx_timestamp().unwrap().is_none());
    }
    if supported {
        eprintln!(
            "SOCK_RAW SOFTWARE RX/TX: arbitrary cookies correlated through explicit kernel IDs, separate source reservations verified"
        );
    }

    // Reporting metadata must not weaken truncation or VLAN rejection.
    a.transmit(&frame).unwrap();
    ready(b.as_raw_fd());
    assert_eq!(
        b.receive_with_metadata(&mut [0; 8]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut tagged = Vec::from(&frame[..12]);
    tagged.extend_from_slice(&[0x81, 0, 0, 0]);
    tagged.extend_from_slice(&frame[12..]);
    a.transmit(&tagged).unwrap();
    ready(b.as_raw_fd());
    assert_eq!(
        b.receive_with_metadata(&mut out).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(b.receive_with_metadata(&mut out).unwrap().is_none());
    drop((a, b));
    ip(&["link", "del", "nio-ts-a"]);
}
