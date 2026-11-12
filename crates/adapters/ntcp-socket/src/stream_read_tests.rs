// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use std::time::{Duration, Instant};

fn capture() -> ntcp::wire::Header {
    let start = Instant::now();
    loop {
        match packet_test::try_capture(65535) {
            Ok((bytes, _)) => {
                let p = packet_profile::parse_frame(&bytes).unwrap();
                return ntcp::wire::parse(p.ip, p.payload).unwrap().header;
            }
            Err(EAGAIN) if start.elapsed() < Duration::from_secs(2) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => panic!("capture: {result:?}"),
        }
    }
}
fn inject(h: ntcp::wire::Header, options: &[u8], payload: &[u8]) {
    let ip = ntcp::IpMetadata {
        source: Ipv4Addr::new(192, 0, 2, 2).into(),
        destination: Ipv4Addr::new(192, 0, 2, 1).into(),
    };
    let mut bytes = vec![0; 80 + payload.len()];
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
            mark: 0,
        },
        0,
    )
    .unwrap();
    bytes.truncate(20 + len);
    packet_test::inject(bytes).unwrap();
}

// Exercise the C shared ABI, not just the managed Rust entry points.
unsafe fn receive(fd: i32, kind: &str, p: *mut c_void, n: usize, flags: i32) -> ssize_t {
    unsafe {
        let mut vectors = [
            iovec {
                iov_base: p,
                iov_len: 3,
            },
            iovec {
                iov_base: p.wrapping_add(3),
                iov_len: n - 3,
            },
        ];
        match kind {
            "read" => read(fd, p, n),
            "recv" => recv(fd, p, n, flags),
            "readv" => readv(fd, vectors.as_ptr(), 2),
            "recvmsg" => {
                let mut m: msghdr = std::mem::zeroed();
                m.msg_iov = vectors.as_mut_ptr();
                m.msg_iovlen = 2;
                recvmsg(fd, &mut m, flags)
            }
            "recvfrom" => {
                let mut peer: sockaddr_in = std::mem::zeroed();
                let mut len = 16;
                let result = recvfrom(
                    fd,
                    p,
                    n,
                    flags,
                    (&mut peer as *mut sockaddr_in).cast(),
                    &mut len,
                );
                assert_eq!(peer.sin_family, AF_INET as u16);
                assert_eq!(peer.sin_port, 8080u16.to_be());
                result
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn shared_abi_large_stream_read_requests() {
    const CHILD: &str = "NTCP_TEST_STREAM_READ_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for kind in ["read", "recv", "readv", "recvmsg", "recvfrom"] {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "stream_read_tests::shared_abi_large_stream_read_requests",
                        "--test-threads=1"
                    ])
                    .env(CHILD, kind)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        return;
    }
    let kind = std::env::var(CHILD).unwrap();
    packet_test::start((
        Ipv4Addr::new(192, 0, 2, 1),
        upstream_stream_read_tests("immediate-ack,abort-with-ack,coalesce-read-window"),
    ))
    .unwrap();
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
        let syn = capture();
        let mut h = ntcp::wire::Header {
            source_port: 8080,
            destination_port: syn.source_port,
            sequence: 100,
            acknowledgment: syn.sequence.wrapping_add(1),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        inject(h, &[3, 3, 0, 1], &[]); // Negotiate scaling, not timestamps.
        assert_eq!(capture().acknowledgment, 101);
        h.sequence = 101;
        h.flags = ntcp::wire::ACK;
        let mut output = vec![0xa5; 150_000];
        inject(h, &[], b"abcdef");
        h.sequence += 6;
        assert_eq!(capture().acknowledgment, h.sequence);
        let fault = mmap(
            ptr::null_mut(),
            4096,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(fault, MAP_FAILED);
        assert_eq!(receive(fd, &kind, fault, output.len(), 0), -1);
        assert_eq!(errno(), EFAULT);
        munmap(fault, 4096);
        if matches!(kind.as_str(), "recv" | "recvmsg" | "recvfrom") {
            assert_eq!(
                receive(
                    fd,
                    &kind,
                    output.as_mut_ptr().cast(),
                    output.len(),
                    MSG_PEEK
                ),
                6
            );
            assert_eq!(&output[..6], b"abcdef");
        }
        assert_eq!(
            receive(fd, &kind, output.as_mut_ptr().cast(), output.len(), 0),
            6
        );
        assert_eq!(&output[..6], b"abcdef");
        assert!(output[6..].iter().all(|&b| b == 0xa5));

        // Queue more than the 64 KiB owner work bound using legal IP packets.
        let payload: Vec<u8> = (0..100_000).map(|n| (n % 251) as u8).collect();
        for chunk in payload.chunks(1400) {
            inject(h, &[], chunk);
            h.sequence += chunk.len() as u32;
            assert_eq!(capture().acknowledgment, h.sequence);
        }
        let mut received = Vec::new();
        while received.len() < payload.len() {
            output.fill(0xa5);
            let n = receive(fd, &kind, output.as_mut_ptr().cast(), output.len(), 0);
            assert!(
                n > 0 && n as usize <= runtime::BYTES,
                "{kind}: {n}, errno {}",
                errno()
            );
            if received.is_empty() {
                assert_eq!(n as usize, runtime::BYTES);
            }
            received.extend_from_slice(&output[..n as usize]);
            assert!(output[n as usize..].iter().all(|&b| b == 0xa5));
        }
        assert_eq!(received, payload);
        assert_eq!(
            receive(fd, &kind, output.as_mut_ptr().cast(), output.len(), 0),
            -1
        );
        assert_eq!(errno(), EAGAIN);
        assert_eq!(packet_test::inject(vec![0; 65536]), Err(EMSGSIZE));
        close(fd);
    }
    packet_test::stop();
}

fn upstream_stream_read_tests(options: &str) -> crate::packet_profile::Profile {
    crate::packet_profile::profile(&format!(
        "upstream,local=192.0.2.1{}{}",
        if options.is_empty() { "" } else { "," },
        options
    ))
    .unwrap()
    .1
}
