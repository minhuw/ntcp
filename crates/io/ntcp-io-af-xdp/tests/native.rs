#![cfg(target_os = "linux")]

use ntcp_io::{PacketIo, TxOutcome};
use ntcp_io_af_xdp::{AfXdp, Config};
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

#[repr(C)]
struct ObjectAttr {
    path: u64,
    fd: u32,
    flags: u32,
}
#[repr(C)]
struct MapAttr {
    fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

fn index(name: &str) -> u32 {
    let name = CString::new(name).unwrap();
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    assert_ne!(index, 0, "{}", io::Error::last_os_error());
    index
}
fn until(mut operation: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !operation() {
        assert!(Instant::now() < deadline, "native packet I/O timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

// Only run inside an isolated namespace with xdp-a/xdp-b veth and an attached
// redirect program. NTCP_XSKMAP must name its pinned queue-keyed XSKMAP.
#[test]
#[ignore = "requires isolated veth namespace and pinned XSKMAP redirect program"]
fn copy_mode_roundtrip() {
    let path = CString::new(std::env::var("NTCP_XSKMAP").expect("NTCP_XSKMAP")).unwrap();
    let attr = ObjectAttr {
        path: path.as_ptr() as u64,
        fd: 0,
        flags: 0,
    };
    let map = unsafe { libc::syscall(libc::SYS_bpf, 7, &attr, std::mem::size_of::<ObjectAttr>()) };
    assert!(map >= 0, "{}", io::Error::last_os_error());
    let map = unsafe { OwnedFd::from_raw_fd(map as i32) };
    let fd_count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = fd_count();
    for _ in 0..4 {
        assert!(
            AfXdp::new(Config {
                ifindex: i32::MAX as u32,
                queue_id: 0,
                frame_size: 4096,
                frame_count: 128,
                ring_size: 64,
                headroom: 32,
                mtu: 1500,
            })
            .is_err()
        );
    }
    assert_eq!(fd_count(), before, "constructor failure leaked socket fds");
    let mut xsk = AfXdp::new(Config {
        ifindex: index("xdp-a"),
        queue_id: 0,
        frame_size: 4096,
        frame_count: 128,
        ring_size: 64,
        headroom: 32,
        mtu: 1500,
    })
    .unwrap();
    let key = 0u32;
    let fd = xsk.as_raw_fd();
    let attr = MapAttr {
        fd: map.as_raw_fd() as u32,
        pad: 0,
        key: &key as *const _ as u64,
        value: &fd as *const _ as u64,
        flags: 0,
    };
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_bpf, 2, &attr, std::mem::size_of::<MapAttr>()) },
        0,
        "{}",
        io::Error::last_os_error()
    );

    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    assert!(raw >= 0, "{}", io::Error::last_os_error());
    let peer = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    address.sll_ifindex = index("xdp-b") as i32;
    assert_eq!(
        unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        },
        0
    );
    let mut packet = [0x5a; 64];
    packet[..6].fill(0xff);
    packet[6..12].fill(0x02);
    packet[12..14].copy_from_slice(&[0x88, 0xb5]);
    assert_eq!(
        unsafe { libc::send(peer.as_raw_fd(), packet.as_ptr().cast(), packet.len(), 0) },
        packet.len() as isize
    );
    let mut out = [0; 4096];
    until(|| {
        xsk.receive(&mut out)
            .unwrap()
            .is_some_and(|n| out[..n] == packet)
    });

    // More packets than TX frames: exercise real completion reclamation as well.
    for sequence in 0..200u32 {
        packet[14..18].copy_from_slice(&sequence.to_ne_bytes());
        packet[18] = 0xa5;
        until(|| xsk.transmit(&packet).unwrap() == TxOutcome::Submitted);
        until(|| {
            let n = unsafe {
                libc::recv(
                    peer.as_raw_fd(),
                    out.as_mut_ptr().cast(),
                    out.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                false
            } else {
                out[..n as usize] == packet
            }
        });
    }
}
