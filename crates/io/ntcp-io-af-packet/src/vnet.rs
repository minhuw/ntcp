use std::{io, num::NonZeroU16};
pub(super) const LEN: usize = 10;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid receive offload metadata",
    )
}
fn word(h: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([h[offset], h[offset + 1]])
}

// PACKET_VNET_HDR uses the legacy native-endian virtio layout. Only IPv4 TCP
// coalescing is supported here; unknown offloads fail closed. This normalizes
// CHECKSUM_PARTIAL using its existing pseudo-header seed. DATA_VALID never
// bypasses the stack's normal IP/TCP checksum validation.
pub(super) fn decode(h: &[u8; LEN], frame: &mut [u8]) -> io::Result<Option<NonZeroU16>> {
    if h[0] & !3 != 0 || h[0] == 3 {
        return Err(invalid());
    }
    let kind = h[1];
    if kind == 0 && h[0] & 1 == 0 {
        return if word(h, 4) == 0 {
            Ok(None)
        } else {
            Err(invalid())
        };
    }
    if kind != 0 && kind != 1 && kind != 0x81 {
        return Err(invalid());
    }
    if frame.len() < 14 + 20 || frame[12..14] != [8, 0] || frame[14] >> 4 != 4 {
        return Err(invalid());
    }
    let ihl = usize::from(frame[14] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if ihl < 20
        || total < ihl + 20
        || total + 14 > frame.len()
        || frame[23] != 6
        || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0
    {
        return Err(invalid());
    }
    let tcp = 14 + ihl;
    let header = usize::from(frame[tcp + 12] >> 4) * 4;
    if header < 20 || header > total - ihl {
        return Err(invalid());
    }
    let payload = total - ihl - header;
    let segmentation = if kind != 0 {
        let size = NonZeroU16::new(word(h, 4)).ok_or_else(invalid)?;
        if usize::from(size.get()) > payload
            || frame[tcp + 13] & 0x10 == 0
            || frame[tcp + 13] & 0x26 != 0
            || usize::from(word(h, 2)) < tcp + header
            || usize::from(word(h, 2)) > total + 14
        {
            return Err(invalid());
        }
        Some(size)
    } else {
        if word(h, 4) != 0 {
            return Err(invalid());
        }
        None
    };
    if h[0] & 1 != 0 {
        if usize::from(word(h, 6)) != tcp || word(h, 8) != 16 {
            return Err(invalid());
        }
        let mut sum = 0u32;
        for pair in frame[tcp..14 + total].chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        frame[tcp + 16..tcp + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }
    Ok(segmentation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AfPacket, PacketIo, TxOutcome};
    fn frame(len: usize) -> Vec<u8> {
        let ip = ntcp::IpMetadata {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
        };
        let mut packet = vec![0; 14 + 40 + len];
        packet[12..14].copy_from_slice(&[8, 0]);
        ntcp::wire::encode(
            ip,
            ntcp::wire::Header {
                source_port: 1,
                destination_port: 2,
                sequence: 1,
                acknowledgment: 1,
                flags: ntcp::wire::ACK,
                window: 32000,
                urgent_pointer: 0,
            },
            &[],
            &vec![0x68; len],
            &mut packet[34..],
        )
        .unwrap();
        ntcp_ip::encode(
            &mut packet[14..],
            ntcp::Transmit {
                connection: None,
                tx_timestamp: None,
                ip,
                len: 20 + len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            0,
        )
        .unwrap();
        packet
    }
    fn header(size: u16) -> [u8; LEN] {
        let mut h = [0; LEN];
        h[1] = 1;
        h[2..4].copy_from_slice(&54u16.to_ne_bytes());
        h[4..6].copy_from_slice(&size.to_ne_bytes());
        h
    }
    fn check(packet: &[u8]) {
        let ip = ntcp_ip::parse(&packet[14..], false).unwrap();
        ntcp::wire::parse(ip.ip, ip.payload).unwrap();
    }
    #[test]
    fn vnet_metadata_and_partial_checksum_preserve_tcp_validation() {
        for len in [10000, 10037] {
            let mut p = frame(len);
            let h = header(1000);
            assert_eq!(decode(&h, &mut p).unwrap(), NonZeroU16::new(1000));
            check(&p);
            let mut h = h;
            h[0] = 1;
            h[6..8].copy_from_slice(&34u16.to_ne_bytes());
            h[8..10].copy_from_slice(&16u16.to_ne_bytes());
            let mut pseudo = Vec::from(&p[26..34]);
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((len + 20) as u16).to_be_bytes());
            let seed = !ntcp_ip::checksum(&pseudo);
            p[50..52].copy_from_slice(&seed.to_be_bytes());
            assert_eq!(decode(&h, &mut p).unwrap(), NonZeroU16::new(1000));
            check(&p);
            p[54] ^= 1;
            let ip = ntcp_ip::parse(&p[14..], false).unwrap();
            assert!(ntcp::wire::parse(ip.ip, ip.payload).is_err());
        }
    }
    #[test]
    fn malformed_offload_lengths_flags_and_controls_fail_closed() {
        let original = frame(10000);
        let good = header(1000);
        for (offset, value) in [(0, 8), (0, 3), (1, 3), (5, 255), (2, 0)] {
            let mut h = good;
            h[offset] = value;
            let mut p = original.clone();
            assert!(decode(&h, &mut p).is_err(), "header offset {offset}");
            assert_eq!(p, original);
        }
        let mut h = good;
        h[4..6].fill(0);
        assert!(decode(&h, &mut original.clone()).is_err());
        for flags in [0x02, 0x14, 0x30] {
            let mut p = original.clone();
            p[47] = flags;
            assert!(decode(&good, &mut p).is_err());
        }
        for len in [0, 13, 33, 53, 100] {
            assert!(decode(&good, &mut original[..len].to_vec()).is_err());
        }
        let mut h = good;
        h[0] = 1;
        h[6..8].copy_from_slice(&35u16.to_ne_bytes());
        h[8..10].copy_from_slice(&16u16.to_ne_bytes());
        assert!(decode(&h, &mut original.clone()).is_err());
        assert_eq!(decode(&[0; LEN], &mut original.clone()).unwrap(), None);
    }
    #[test]
    fn native_receive_strips_header_and_tx_emits_only_plain_packet_header() {
        let (fd, peer) = crate::tests::pair();
        let mut receiver = AfPacket {
            fd,
            ifindex: 0,
            timestamps: None,
            packet_mark: 0,
            vnet_header: true,
        };
        let mut sender = AfPacket {
            fd: peer,
            ifindex: 0,
            timestamps: None,
            packet_mark: 0,
            vnet_header: false,
        };
        let capacity: libc::c_int = 65536;
        for io in [&sender, &receiver] {
            use std::os::fd::AsRawFd;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        io.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_SNDBUF,
                        (&capacity as *const libc::c_int).cast(),
                        std::mem::size_of_val(&capacity) as _,
                    )
                },
                0
            );
        }
        let p = frame(10037);
        let mut bytes = header(1000).to_vec();
        bytes.extend_from_slice(&p);
        assert_eq!(sender.transmit(&bytes).unwrap(), TxOutcome::Submitted);
        let mut out = vec![0; 20000];
        let got = receiver.receive_with_metadata(&mut out).unwrap().unwrap();
        assert_eq!(got.len, p.len());
        assert_eq!(got.tcp_segment_size, NonZeroU16::new(1000));
        assert_eq!(&out[..got.len], p);
        assert_eq!(receiver.transmit(&p).unwrap(), TxOutcome::Submitted);
        let n = sender.receive(&mut out).unwrap().unwrap();
        assert_eq!(n, p.len() + LEN);
        assert_eq!(&out[..LEN], &[0; LEN]);
        assert_eq!(&out[LEN..n], p);
        sender.transmit(&bytes).unwrap();
        assert_eq!(
            receiver.receive(&mut out[..8]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(receiver.receive(&mut out).unwrap().is_none());
    }
}
