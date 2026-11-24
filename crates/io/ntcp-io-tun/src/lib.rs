#![cfg(target_os = "linux")]

use ntcp_io::linux::{attribute, received, transmitted};
use ntcp_io::{PacketIo, PacketLayer, TransmitError, TransmitRequest, TxOutcome, TxPacket};
use std::{
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
};

pub struct Tun {
    fd: OwnedFd,
    name: String,
    ifindex: u32,
}

impl Tun {
    // Creates an exclusively named, nonpersistent TUN in the caller's current
    // namespace. Never attaches to an existing interface or configures routes,
    // addresses, MTU or link state. The interface disappears with the last fd.
    pub fn create(name: &str) -> io::Result<Self> {
        Self::attach(name, true)
    }

    // Attaches a caller-preconfigured IFF_TUN | IFF_NO_PI interface. Missing
    // names are rejected. The caller must not concurrently reconfigure or
    // remove/recreate the interface: TUNSETIFF has no atomic attach-only mode.
    pub fn open(name: &str) -> io::Result<Self> {
        Self::attach(name, false)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn attach(name: &str, exclusive: bool) -> io::Result<Self> {
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || name == "."
            || name == ".."
            || name
                .bytes()
                .any(|b| b == 0 || b == b'/' || b == b':' || b == b'%' || b.is_ascii_whitespace())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        if !exclusive {
            // Name validation above excludes interior NULs.
            let c_name = std::ffi::CString::new(name).unwrap();
            // SAFETY: c_name is a terminated C string.
            let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::last_os_error());
            }
            check_existing(index)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        // SAFETY: zero initializes the name buffer and every ifreq union member.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | if exclusive { libc::IFF_TUN_EXCL } else { 0 })
                as libc::c_short;
        // SAFETY: live TUN fd and a writable, correctly sized ifreq.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let c_name = std::ffi::CString::new(name).unwrap();
        // SAFETY: validated, terminated interface name; remember identity across renames.
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ifindex,
            fd: file.into(),
            name: name.to_owned(),
        })
    }
}

fn check_format(attributes: &[u8]) -> io::Result<()> {
    // IFLA_LINKINFO -> IFLA_INFO_KIND / IFLA_INFO_DATA. TUN attributes
    // are from linux/if_link.h (not exposed by every supported libc version).
    let incompatible = || {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "existing interface is not single-queue TUN without PI/VNET_HDR",
        )
    };
    let info = attribute(attributes, 18)?.ok_or_else(incompatible)?;
    if attribute(info, 1)? != Some(b"tun\0".as_slice()) {
        return Err(incompatible());
    }
    let data = attribute(info, 2)?.ok_or_else(incompatible)?;
    for (kind, expected) in [(3, 1), (4, 0), (5, 0), (7, 0)] {
        if attribute(data, kind)? != Some([expected].as_slice()) {
            return Err(incompatible());
        }
    }
    Ok(())
}

fn check_existing(index: u32) -> io::Result<()> {
    ntcp_io::linux::with_link(index, check_format)
}

impl PacketIo for Tun {
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        ntcp_io::linux::local_ip_mtu(self.ifindex)
    }
    // No fixed adapter buffer: do not invent a raw-IP protocol limit (e.g.
    // IPv6 payload length excludes its header). The independent cap is unknown.

    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        // TUN cannot MSG_PEEK. One extra byte in the readv catches every packet
        // larger than out, including packets larger than the whole iovec. Such
        // packets are consumed, but never returned as valid truncated packets.
        let mut overflow = 0u8;
        let vectors = [
            libc::iovec {
                iov_base: out.as_mut_ptr().cast(),
                iov_len: out.len(),
            },
            libc::iovec {
                iov_base: (&mut overflow as *mut u8).cast(),
                iov_len: 1,
            },
        ];
        // SAFETY: both iovecs point to distinct writable buffers that stay live.
        let count = unsafe { libc::readv(self.as_raw_fd(), vectors.as_ptr(), 2) };
        received(count, out.len())
    }

    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        // SAFETY: packet is readable for its length; write retains no pointer.
        let count = unsafe { libc::write(self.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        transmitted(count, packet.len())
    }

    fn transmit_packet(
        &mut self,
        packet: &TxPacket<'_>,
        request: TransmitRequest,
    ) -> Result<TxOutcome, TransmitError> {
        const STACK_IOVS: usize = 16;
        // Linux UIO_MAXIOV / POSIX IOV_MAX (linux/uio.h).
        const MAX_IOVS: usize = 1024;
        let total = packet.checked_len().ok_or(TransmitError::InvalidInput)?;
        let TransmitRequest {
            tcp_checksum_offload,
            segmentation,
            timestamp,
            when,
        } = request;
        if segmentation.is_some() || tcp_checksum_offload || when.is_some() {
            return Err(TransmitError::Unsupported);
        }
        if let Some(ts) = timestamp {
            return Err(if !ts.software && !ts.hardware {
                TransmitError::InvalidInput
            } else {
                TransmitError::Unsupported
            });
        }
        if total == 0 {
            return self.transmit(&[]).map_err(TransmitError::Other);
        }

        let mut stack = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; STACK_IOVS];
        let mut len = 0usize;
        let mut heap: Vec<libc::iovec> = Vec::new();
        let mut push = |bytes: &[u8]| {
            if bytes.is_empty() {
                return;
            }
            let iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            if !heap.is_empty() {
                heap.push(iov);
            } else if len < STACK_IOVS {
                stack[len] = iov;
                len += 1;
            } else {
                heap.reserve(STACK_IOVS + 1);
                heap.extend_from_slice(&stack);
                heap.push(iov);
            }
        };
        push(packet.header);
        for part in packet.payload {
            push(part.bytes());
        }

        let iovs: &[libc::iovec] = if heap.is_empty() {
            &stack[..len]
        } else {
            &heap
        };
        if iovs.len() > MAX_IOVS {
            let mut contiguous = Vec::with_capacity(total);
            contiguous.extend_from_slice(packet.header);
            for part in packet.payload {
                contiguous.extend_from_slice(part.bytes());
            }
            return self.transmit(&contiguous).map_err(TransmitError::Other);
        }
        // SAFETY: every iovec points to readable bytes of `packet` that remain
        // live through writev; iovs.len() is within 1..=MAX_IOVS.
        let count =
            unsafe { libc::writev(self.as_raw_fd(), iovs.as_ptr(), iovs.len() as libc::c_int) };
        transmitted(count, total).map_err(TransmitError::Other)
    }
}

impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    pub(crate) fn backpressure(a: &mut impl PacketIo, b: &mut impl PacketIo) {
        let mut out = [0; 1024];
        for submitted in 0..10000 {
            let packet = [submitted as u8; 1024];
            if b.transmit(&packet).unwrap() == TxOutcome::WouldBlock {
                for sequence in 0..submitted {
                    assert_eq!(a.receive(&mut out).unwrap(), Some(1024));
                    assert_eq!(out, [sequence as u8; 1024]);
                }
                // The rejected send did not enqueue another copy.
                assert_eq!(a.receive(&mut out).unwrap(), None);
                assert_eq!(b.transmit(&packet).unwrap(), TxOutcome::Submitted);
                assert_eq!(a.receive(&mut out).unwrap(), Some(packet.len()));
                assert_eq!(out, packet);
                assert_eq!(a.receive(&mut out).unwrap(), None);
                return;
            }
        }
        panic!("queue never filled");
    }

    pub(crate) fn flags(fd: RawFd) {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    pub(crate) fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: socketpair initializes two distinct owned fds on success.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let size: libc::c_int = 4096;
        for fd in fds {
            // SAFETY: size is a correctly sized socket option integer.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&size as *const libc::c_int).cast(),
                        std::mem::size_of_val(&size) as libc::socklen_t,
                    )
                },
                0
            );
        }
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn interrupted_transmit_is_unsubmitted() {
        // SAFETY: errno is thread-local; model the failed syscall result.
        unsafe { *libc::__errno_location() = libc::EINTR };
        assert_eq!(transmitted(-1, 4).unwrap(), TxOutcome::WouldBlock);
        assert_eq!(transmitted(4, 4).unwrap(), TxOutcome::Submitted);
        assert_eq!(
            transmitted(1, 4).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn malformed_attributes_fail_closed() {
        for bytes in [
            &[0u8][..],
            &[0, 0, 1, 0],
            &[3, 0, 1, 0],
            &[8, 0, 1, 0],
            &[5, 0, 2, 0, 0],
        ] {
            assert_eq!(
                attribute(bytes, 1).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            check_format(&[]).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        // Nested attribute flag is masked off, and payload is not borrowed
        // beyond the response buffer's lifetime.
        assert_eq!(
            attribute(&[5, 0, 1, 128, 42, 0, 0, 0], 1).unwrap(),
            Some([42].as_slice())
        );
    }

    #[test]
    fn validation() {
        for name in [
            "",
            ".",
            "..",
            "abcdefghijklmnop",
            "a\0b",
            "a/b",
            "a:b",
            "a b",
            "a\nb",
            "tun%d",
        ] {
            assert_eq!(
                Tun::create(name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                Tun::open(name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn packets_and_ownership() {
        let (a, b) = pair();
        let mut a = Tun {
            fd: a,
            name: "test-a".into(),
            ifindex: 0,
        };
        let mut b = Tun {
            fd: b,
            name: "test-b".into(),
            ifindex: 0,
        };
        assert_eq!(a.name(), "test-a");
        flags(a.as_raw_fd());
        assert_eq!(a.layer(), PacketLayer::Ip);
        let mut out = [0; 8];
        assert_eq!(a.receive(&mut out).unwrap(), None);
        let mut packet = *b"12345678";
        assert_eq!(b.transmit(&packet).unwrap(), TxOutcome::Submitted);
        packet.fill(0);
        assert_eq!(a.receive(&mut out).unwrap(), Some(8));
        assert_eq!(&out, b"12345678");
        for capacity in [0, 7] {
            b.transmit(&[1; 64]).unwrap();
            assert_eq!(
                a.receive(&mut out[..capacity]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(a.receive(&mut out).unwrap(), None);
        }
        backpressure(&mut a, &mut b);
        drop(a);
        assert!(b.transmit(b"x").is_err());
    }

    #[test]
    fn transmit_packet_gathers_parts_handles_backpressure_and_enforces_i8() {
        use ntcp_io::{
            ChunkSlice, ClockDescriptor, ClockDomain, Payload, PayloadSlice,
            TcpSegmentationRequest, TimestampUnit, TransmitTime, TxChunk, TxPart,
            TxTimestampRequest,
        };

        let (a, b) = pair();
        let mut a = Tun {
            fd: a,
            name: "test-a".into(),
            ifindex: 0,
        };
        let mut b = Tun {
            fd: b,
            name: "test-b".into(),
            ifindex: 0,
        };

        // Multi-part TxPacket: header + Chunk + empty parts + Shared.
        let mut chunk = TxChunk::heap(64);
        chunk.append(b"XXchunk-bodyYY");
        let shared = Payload::from_vec(b"ZZshared-tailWW".to_vec());
        let parts = [
            TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap()),
            TxPart::Chunk(ChunkSlice::new(&chunk, 2..12).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 5..5).unwrap()),
            TxPart::Shared(PayloadSlice::new(&shared, 2..13).unwrap()),
        ];
        let packet = TxPacket {
            header: b"HDR:",
            payload: &parts,
        };
        assert_eq!(
            b.transmit_packet(&packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let mut out = [0u8; 64];
        let n = a.receive(&mut out).unwrap().unwrap();
        assert_eq!(&out[..n], b"HDR:chunk-bodyshared-tail");

        // Empty header with payload only, and zero-length packet.
        let payload_only = TxPacket {
            header: &[],
            payload: &[TxPart::Shared(PayloadSlice::new(&shared, 2..8).unwrap())],
        };
        assert_eq!(
            b.transmit_packet(&payload_only, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let n = a.receive(&mut out).unwrap().unwrap();
        assert_eq!(&out[..n], b"shared");

        let empty_packet = TxPacket {
            header: &[],
            payload: &[TxPart::Chunk(ChunkSlice::new(&chunk, 0..0).unwrap())],
        };
        assert_eq!(
            b.transmit_packet(&empty_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        assert_eq!(a.receive(&mut out).unwrap(), Some(0));

        // > 16 iovecs (heap spill path).
        let many_storage = Payload::from_vec((0..24u8).collect());
        let many_parts: Vec<TxPart<'_>> = (0..24)
            .map(|i| TxPart::Shared(PayloadSlice::new(&many_storage, i..i + 1).unwrap()))
            .collect();
        let many_packet = TxPacket {
            header: b"H",
            payload: &many_parts,
        };
        assert_eq!(
            b.transmit_packet(&many_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let n = a.receive(&mut out).unwrap().unwrap();
        let mut expected = vec![b'H'];
        expected.extend(0..24u8);
        assert_eq!(&out[..n], expected.as_slice());

        // > UIO_MAXIOV (1024) iovecs (gather fallback path).
        let huge_storage = Payload::from_vec((0..1025).map(|i| (i & 0xff) as u8).collect());
        let huge_parts: Vec<TxPart<'_>> = (0..1025)
            .map(|i| TxPart::Shared(PayloadSlice::new(&huge_storage, i..i + 1).unwrap()))
            .collect();
        let huge_packet = TxPacket {
            header: b"!",
            payload: &huge_parts,
        };
        assert_eq!(
            b.transmit_packet(&huge_packet, TransmitRequest::default())
                .unwrap(),
            TxOutcome::Submitted
        );
        let mut huge_out = vec![0u8; 1026];
        let n = a.receive(&mut huge_out).unwrap().unwrap();
        assert_eq!(n, 1026);
        assert_eq!(huge_out[0], b'!');
        assert_eq!(&huge_out[1..], huge_storage.as_slice());

        // I8 unsupported features & combinations submit nothing.
        let when = Some(TransmitTime {
            value: 100,
            clock: ClockDescriptor {
                domain: ClockDomain::Monotonic,
                unit: TimestampUnit::Nanoseconds,
            },
        });
        let segmentation = Some(TcpSegmentationRequest {
            segment_payload_len: 10,
        });
        let timestamp = Some(TxTimestampRequest {
            cookie: 7,
            software: true,
            hardware: false,
        });
        let empty_timestamp = Some(TxTimestampRequest {
            cookie: 8,
            software: false,
            hardware: false,
        });
        for unsupported in [
            TransmitRequest {
                segmentation,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                when,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                segmentation,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                when,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                tcp_checksum_offload: true,
                timestamp: empty_timestamp,
                ..Default::default()
            },
            TransmitRequest {
                when,
                ..Default::default()
            },
            TransmitRequest {
                when,
                timestamp,
                ..Default::default()
            },
            TransmitRequest {
                timestamp,
                ..Default::default()
            },
        ] {
            assert!(matches!(
                b.transmit_packet(&packet, unsupported),
                Err(TransmitError::Unsupported)
            ));
        }
        assert!(matches!(
            b.transmit_packet(
                &packet,
                TransmitRequest {
                    timestamp: empty_timestamp,
                    ..Default::default()
                }
            ),
            Err(TransmitError::InvalidInput)
        ));
        assert_eq!(a.receive(&mut out).unwrap(), None);

        // Backpressure (WouldBlock) with multi-part TxPacket.
        let mut rx_buf = [0u8; 1024];
        let mut hit_would_block = false;
        let fill_shared = Payload::from_vec(vec![0x5Au8; 768]);
        let fill_parts = [TxPart::Shared(
            PayloadSlice::new(&fill_shared, 0..768).unwrap(),
        )];
        for submitted in 0..10000usize {
            let hdr = [submitted as u8; 256];
            let pkt = TxPacket {
                header: &hdr,
                payload: &fill_parts,
            };
            if b.transmit_packet(&pkt, TransmitRequest::default()).unwrap() == TxOutcome::WouldBlock
            {
                hit_would_block = true;
                for i in 0..submitted {
                    assert_eq!(a.receive(&mut rx_buf).unwrap(), Some(1024));
                    assert_eq!(&rx_buf[..256], &[i as u8; 256]);
                    assert_eq!(&rx_buf[256..], &[0x5Au8; 768]);
                }
                assert_eq!(a.receive(&mut rx_buf).unwrap(), None);
                assert_eq!(
                    b.transmit_packet(&pkt, TransmitRequest::default()).unwrap(),
                    TxOutcome::Submitted
                );
                assert_eq!(a.receive(&mut rx_buf).unwrap(), Some(1024));
                assert_eq!(&rx_buf[..256], &[submitted as u8; 256]);
                assert_eq!(&rx_buf[256..], &[0x5Au8; 768]);
                break;
            }
        }
        assert!(hit_would_block, "queue never filled");
    }
}
