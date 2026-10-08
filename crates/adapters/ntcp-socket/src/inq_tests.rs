// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
unsafe extern "C" {
    #[link_name = "ioctl"]
    fn abi_ioctl(fd: i32, request: c_ulong, ...) -> i32;
}
use std::time::{Duration, Instant};

fn capture() -> Vec<u8> {
    let start = Instant::now();
    loop {
        match packet_test::try_capture(65535) {
            Ok((bytes, _)) => return bytes,
            Err(EAGAIN) if start.elapsed() < Duration::from_secs(2) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => panic!("capture: {result:?}"),
        }
    }
}
fn header(bytes: &[u8]) -> ntcp::wire::Header {
    let p = packet_profile::parse_frame(bytes).unwrap();
    ntcp::wire::parse(p.ip, p.payload).unwrap().header
}
fn inject(h: ntcp::wire::Header, options: &[u8], payload: &[u8]) {
    let ip = ntcp::IpMetadata {
        source: Ipv4Addr::new(192, 0, 2, 2).into(),
        destination: Ipv4Addr::new(192, 0, 2, 1).into(),
    };
    let mut bytes = vec![0; 20 + 60 + payload.len()];
    let len = ntcp::wire::encode(ip, h, options, payload, &mut bytes[20..]).unwrap();
    ntcp_ip::encode(
        &mut bytes,
        ntcp::Transmit {
            tx_timestamp: None,
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        0,
    )
    .unwrap();
    bytes.truncate(20 + len);
    packet_test::inject(bytes).unwrap();
}
const TS: &[u8] = &[1, 1, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0];
fn connected() -> (i32, ntcp::wire::Header) {
    unsafe {
        let fd = packet_test::packet_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        assert!(fd >= 0);
        let addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 8080u16.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes([192, 0, 2, 2]),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(connect(fd, (&addr as *const sockaddr_in).cast(), 16), -1);
        assert_eq!(errno(), EINPROGRESS);
        let enabled = 1i32;
        assert_eq!(
            setsockopt(fd, IPPROTO_TCP, TCP_INQ, (&enabled as *const i32).cast(), 4),
            0
        );
        let syn = header(&capture());
        let h = ntcp::wire::Header {
            source_port: 8080,
            destination_port: syn.source_port,
            sequence: 100,
            acknowledgment: syn.sequence.wrapping_add(1),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        inject(h, TS, &[]);
        assert_eq!(header(&capture()).acknowledgment, 101);
        (
            fd,
            ntcp::wire::Header {
                sequence: 101,
                flags: ntcp::wire::ACK,
                ..h
            },
        )
    }
}
unsafe fn message(fd: i32, data: &mut [u8], flags: i32) -> i32 {
    unsafe { message_n(fd, data, flags, data.len()) }
}
unsafe fn message_n(fd: i32, data: &mut [u8], flags: i32, received: usize) -> i32 {
    let mut peer: sockaddr_in = unsafe { std::mem::zeroed() };
    let mut control = [0xaau8; 32];
    let mut vector = iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut m: msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = (&mut peer as *mut sockaddr_in).cast();
    m.msg_namelen = 16;
    m.msg_iov = &mut vector;
    m.msg_iovlen = 1;
    m.msg_control = control.as_mut_ptr().cast();
    m.msg_controllen = 24;
    let pointers = (m.msg_name, m.msg_iov, m.msg_control);
    assert_eq!(unsafe { recvmsg(fd, &mut m, flags) }, received as isize);
    assert_eq!((m.msg_name, m.msg_iov, m.msg_control), pointers);
    assert_eq!(m.msg_iovlen, 1);
    assert_eq!(m.msg_flags, 0);
    assert_eq!(m.msg_controllen, 24);
    assert_eq!(peer.sin_family, AF_INET as u16);
    assert_eq!(control[20], 0xaa);
    assert_eq!(usize::from_ne_bytes(control[..8].try_into().unwrap()), 20);
    assert_eq!(
        i32::from_ne_bytes(control[8..12].try_into().unwrap()),
        IPPROTO_TCP
    );
    assert_eq!(
        i32::from_ne_bytes(control[12..16].try_into().unwrap()),
        TCP_INQ
    );
    i32::from_ne_bytes(control[16..20].try_into().unwrap())
}
#[test]
fn shared_abi_inq_timestamp_gate_staging_alias_fault_and_eof() {
    const CHILD: &str = "NTCP_TEST_INQ_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for scenario in ["stream", "read-reset", "soerror-reset", "inherit"] {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "inq_tests::shared_abi_inq_timestamp_gate_staging_alias_fault_and_eof",
                        "--test-threads=1"
                    ])
                    .env(CHILD, scenario)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        return;
    }
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        packet_profile::Profile::UpstreamBasic,
    ))
    .unwrap();
    let scenario = std::env::var(CHILD).unwrap();
    if scenario != "stream" {
        unsafe {
            if scenario == "inherit" {
                // INQ inherits at passive admission, not at accept; a FIN that arrived
                // before accept must survive consumption of the core half-close event.
                let listener =
                    packet_test::packet_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
                assert!(listener >= 0);
                let mut enabled = 1i32;
                assert_eq!(
                    setsockopt(
                        listener,
                        IPPROTO_TCP,
                        TCP_INQ,
                        (&enabled as *const i32).cast(),
                        4
                    ),
                    0
                );
                let addr = sockaddr_in {
                    sin_family: AF_INET as u16,
                    sin_port: 8081u16.to_be(),
                    sin_addr: in_addr {
                        s_addr: u32::from_ne_bytes([192, 0, 2, 1]),
                    },
                    sin_zero: [0; 8],
                };
                assert_eq!(bind(listener, (&addr as *const sockaddr_in).cast(), 16), 0);
                assert_eq!(listen(listener, 1), 0);
                let mut h = ntcp::wire::Header {
                    source_port: 50000,
                    destination_port: 8081,
                    sequence: 200,
                    acknowledgment: 0,
                    flags: ntcp::wire::SYN,
                    window: 65535,
                    urgent_pointer: 0,
                };
                inject(h, &[], &[]);
                let synack = header(&capture());
                enabled = 0;
                assert_eq!(
                    setsockopt(
                        listener,
                        IPPROTO_TCP,
                        TCP_INQ,
                        (&enabled as *const i32).cast(),
                        4
                    ),
                    0
                );
                h.sequence = 201;
                h.acknowledgment = synack.sequence.wrapping_add(1);
                h.flags = ntcp::wire::ACK | ntcp::wire::FIN;
                inject(h, &[], b"hi");
                assert_eq!(header(&capture()).acknowledgment, 204);
                let child = accept(listener, ptr::null_mut(), ptr::null_mut());
                assert!(child >= 0);
                let mut data = [0; 2];
                assert_eq!(message(child, &mut data, 0), 1);
                assert_eq!(&data, b"hi");
                assert_eq!(message_n(child, &mut data, 0, 0), 1);
                close(child);
                close(listener);
            } else {
                let via_so_error = scenario == "soerror-reset";
                let (fd, mut h) = connected();
                h.flags = ntcp::wire::RST | ntcp::wire::ACK;
                inject(h, &[], &[]); // RST does not require negotiated timestamps.
                let mut byte = [0];
                if via_so_error {
                    let mut error = 0i32;
                    let mut size = 4;
                    assert_eq!(
                        getsockopt(
                            fd,
                            SOL_SOCKET,
                            SO_ERROR,
                            (&mut error as *mut i32).cast(),
                            &mut size
                        ),
                        0
                    );
                    assert_eq!(error, ECONNRESET);
                } else {
                    assert_eq!(read(fd, byte.as_mut_ptr().cast(), 1), -1);
                    assert_eq!(errno(), ECONNRESET);
                }
                assert_eq!(message_n(fd, &mut byte, 0, 0), 0);
                close(fd);
            }
        }
        packet_test::stop();
        return;
    }
    unsafe {
        let (fd, mut h) = connected();
        // The unchanged upstream INQ client omits TS after negotiating it.
        // Its timeout is a missing data ACK, not a connect/setsockopt deadlock.
        inject(h, &[], b"abcdef");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(packet_test::try_capture(65535).unwrap_err(), EAGAIN);
        let mut available = -1;
        assert_eq!(abi_ioctl(fd, FIONREAD as _, &mut available as *mut i32), 0);
        assert_eq!(available, 0);
        inject(h, TS, b"abcdef");
        assert_eq!(header(&capture()).acknowledgment, 107);
        let mut peek = [0; 2];
        assert_eq!(message(fd, &mut peek, MSG_PEEK), 6);
        assert_eq!(&peek, b"ab");
        let alias = dup(fd);
        assert!(alias >= 0);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            READ_TO_BEFORE_LOCK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    entered_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                }))
            });
            let mut data = [0; 2];
            assert_eq!(read(alias, data.as_mut_ptr().cast(), 2), 2);
            assert_eq!(&data, b"ab");
            close(alias);
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let fault = mmap(
            ptr::null_mut(),
            4096,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(fault, MAP_FAILED);
        let mut vector = iovec {
            iov_base: peek.as_mut_ptr().cast(),
            iov_len: 2,
        };
        let mut m: msghdr = std::mem::zeroed();
        m.msg_iov = &mut vector;
        m.msg_iovlen = 1;
        m.msg_control = fault;
        m.msg_controllen = 24;
        assert_eq!(recvmsg(fd, &mut m, 0), -1);
        assert_eq!(errno(), EFAULT);
        resume_tx.send(()).unwrap();
        reader.join().unwrap();
        let mut rest = [0; 2];
        assert_eq!(message(fd, &mut rest, 0), 2);
        assert_eq!(&rest, b"cd"); // no replay of ab, no silent loss of cd
        assert_eq!(message(fd, &mut rest, 0), 0);
        assert_eq!(&rest, b"ef");
        h.sequence = 107;
        h.flags |= ntcp::wire::FIN;
        inject(h, TS, b"xyz");
        assert_eq!(header(&capture()).acknowledgment, 111);
        let mut last = [0; 3];
        // Address and payload faults must leave the data available for retry.
        m.msg_name = fault;
        m.msg_namelen = 16;
        assert_eq!(recvmsg(fd, &mut m, 0), -1);
        assert_eq!(errno(), EFAULT);
        m.msg_name = ptr::null_mut();
        (*m.msg_iov).iov_base = fault;
        assert_eq!(recvmsg(fd, &mut m, 0), -1);
        assert_eq!(errno(), EFAULT);
        assert_eq!(message(fd, &mut last, 0), 1);
        assert_eq!(&last, b"xyz");
        assert_eq!(message_n(fd, &mut last, 0, 0), 1);
        assert_eq!(read(fd, last.as_mut_ptr().cast(), 3), 0);
        munmap(fault, 4096);
        close(fd);
    }
    packet_test::stop();
}

#[test]
fn splice_stops_at_urgent_octet_without_consuming_it() {
    const CHILD: &str = "NTCP_TEST_SPLICE_URGENT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inq_tests::splice_stops_at_urgent_octet_without_consuming_it",
                    "--test-threads=1"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        packet_profile::Profile::UpstreamBasic,
    ))
    .unwrap();
    unsafe {
        let (fd, mut h) = connected();
        h.flags |= ntcp::wire::URG;
        h.urgent_pointer = 100;
        inject(h, TS, &[7; 100]);
        let mut pipe = [-1; 2];
        assert_eq!(
            syscall(SYS_pipe2, pipe.as_mut_ptr(), O_NONBLOCK | O_CLOEXEC),
            0
        );
        assert_eq!(
            crate::file_transfer::splice(fd, ptr::null_mut(), pipe[1], ptr::null_mut(), 100, 0),
            99
        );
        let mut bytes = [0u8; 100];
        assert_eq!(read(pipe[0], bytes.as_mut_ptr().cast(), 100), 99);
        assert_eq!(&bytes[..99], &[7; 99]);
        assert_eq!(
            crate::file_transfer::splice(fd, ptr::null_mut(), pipe[1], ptr::null_mut(), 1, 0),
            0
        );
        let mut available = 0;
        assert_eq!(abi_ioctl(fd, FIONREAD, &mut available), 0);
        assert_eq!(available, 1);
        assert_eq!(read(fd, bytes.as_mut_ptr().cast(), 1), 1);
        assert_eq!(bytes[0], 7);
        assert_eq!(
            crate::file_transfer::splice(
                fd,
                ptr::null_mut(),
                pipe[1],
                ptr::null_mut(),
                1,
                SPLICE_F_NONBLOCK
            ),
            -1
        );
        assert_eq!(errno(), EAGAIN);
        h.sequence += 100;
        h.flags = ntcp::wire::ACK | ntcp::wire::FIN;
        h.urgent_pointer = 0;
        inject(h, TS, &[]);
        assert_eq!(
            crate::file_transfer::splice(fd, ptr::null_mut(), pipe[1], ptr::null_mut(), 1, 0),
            0
        );
        close(pipe[0]);
        close(pipe[1]);
        close(fd);
    }
    packet_test::stop();
}

#[test]
fn lowat_shared_alias_partial_write() {
    const CHILD: &str = "NTCP_TEST_LOWAT_ABI_CHILD";
    if std::env::var_os(CHILD).is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inq_tests::lowat_shared_alias_partial_write",
                    "--test-threads=1"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        packet_profile::Profile::UpstreamBasic,
    ))
    .unwrap();
    unsafe {
        let (fd, mut h) = connected();
        h.window = 0;
        inject(h, TS, b"x");
        assert_eq!(header(&capture()).acknowledgment, 102);
        let alias = dup(fd);
        assert!(alias >= 0);
        let lowat = 1u32;
        assert_eq!(
            setsockopt(
                alias,
                IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&lowat as *const u32).cast(),
                4
            ),
            0
        );
        let mut observed = 0u32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&mut observed as *mut u32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!(observed, lowat);
        assert_eq!(send(fd, b"abc".as_ptr().cast(), 3, MSG_MORE), 1);
        assert_eq!(send(alias, b"x".as_ptr().cast(), 1, MSG_MORE), -1);
        assert_eq!(errno(), EAGAIN);
        let unlimited = 0u32; // Socket zero still resolves to its default, UINT_MAX.
        assert_eq!(
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&unlimited as *const u32).cast(),
                4
            ),
            0
        );
        assert_eq!(send(alias, b"bc".as_ptr().cast(), 2, MSG_MORE), 2);
        assert_eq!(close(alias), 0);
        assert_eq!(close(fd), 0);
    }
}
