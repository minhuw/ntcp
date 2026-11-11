use ntcp_io::{TcpSegmentationCapabilities, TcpSegmentationError as Error};

// TSO repeats l2_len + l3_len + l4_len header bytes, TCP options included, in
// every segment, as Linux hardware TSO does. The generic API does not say how
// a device spreads PSH, FIN or CWR over the segments (Linux keeps PSH/FIN on
// the last, CWR on the first), so this PMD-independent subset admits only ACK
// and reports allow_psh/allow_cwr false. Returns (l3_len, l4_len).
pub(crate) fn validate(
    p: &[u8],
    mss: usize,
    caps: TcpSegmentationCapabilities,
) -> Result<(u16, u16), Error> {
    if p.len() > caps.max_aggregate_len || p.len() < 54 || mss == 0 || mss > u16::MAX as usize {
        return Err(Error::InvalidInput);
    }
    let word = |i| u16::from_be_bytes([p[i], p[i + 1]]);
    let l3 = match word(12) {
        0x0800 => {
            if p[14] != 0x45 || p[23] != 6 || word(20) & !0x4000 != 0 || p[15] & 3 != 0 {
                return Err(Error::Unsupported);
            }
            if usize::from(word(16)) != p.len() - 14 || word(24) != 0 {
                return Err(Error::InvalidInput);
            }
            20
        }
        0x86dd => {
            if p.len() < 74 {
                return Err(Error::InvalidInput);
            }
            if p[14] >> 4 != 6 || p[20] != 6 || p[15] & 0x30 != 0 {
                return Err(Error::Unsupported);
            }
            if usize::from(word(18)) != p.len() - 54 {
                return Err(Error::InvalidInput);
            }
            40
        }
        _ => return Err(Error::Unsupported),
    };
    let tcp = 14 + l3;
    let l4 = usize::from(p[tcp + 12] >> 4) * 4;
    if l4 < 20 || tcp + l4 >= p.len() || word(tcp + 16) != 0 {
        return Err(Error::InvalidInput);
    }
    if p[tcp + 12] & 0x0f != 0 || p[tcp + 13] != 0x10 || word(tcp + 18) != 0 {
        return Err(Error::Unsupported);
    }
    options(&p[tcp + 20..tcp + l4])?;
    let headers = tcp + l4;
    let payload = p.len() - headers;
    let count = payload.div_ceil(mss);
    // Ethernet pads frames shorter than 60 bytes (excluding FCS). Account for
    // that too: especially small MSS must not evade the wire-work bound.
    let wire = count.checked_sub(1).and_then(|full| {
        full.checked_mul((headers + mss).max(60))
            .and_then(|bytes| bytes.checked_add((headers + payload - full * mss).max(60)))
    });
    if payload == 0
        || count > caps.max_segments
        || wire.is_none_or(|w| w > caps.max_wire_bytes)
        || l3 + l4 + mss.min(payload) > caps.local_ip_mtu as usize
    {
        return Err(Error::InvalidInput);
    }
    // Sequence space is modulo 2^32; the bounded payload cannot cover it twice.
    Ok((l3 as u16, l4 as u16))
}

// Copied options must stay valid in every segment: timestamps and SACK do (one
// TSval per burst, as Linux sends), but a TCP-MD5 (19) or TCP-AO (29) MAC covers
// one segment's payload, so Linux disables GSO for such sockets.
fn options(mut o: &[u8]) -> Result<(), Error> {
    while let [kind, rest @ ..] = o {
        o = match (kind, rest) {
            (0, _) => return Ok(()),
            (1, _) => rest,
            (19 | 29, _) => return Err(Error::Unsupported),
            (_, [len, ..]) if (2..=o.len()).contains(&usize::from(*len)) => &o[usize::from(*len)..],
            _ => return Err(Error::InvalidInput),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn packet(v6: bool, payload: usize) -> Vec<u8> {
        with_options(v6, &[], payload)
    }
    // Options must be a multiple of four bytes long, as ntcp pads them.
    fn with_options(v6: bool, options: &[u8], payload: usize) -> Vec<u8> {
        let l3 = if v6 { 40 } else { 20 };
        let l4 = 20 + options.len();
        let mut p = vec![0; 14 + l3 + l4 + payload];
        p[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
        if v6 {
            p[14] = 0x60;
            p[20] = 6;
            p[18..20].copy_from_slice(&((l4 + payload) as u16).to_be_bytes());
        } else {
            p[14] = 0x45;
            p[23] = 6;
            p[16..18].copy_from_slice(&((20 + l4 + payload) as u16).to_be_bytes());
        }
        p[14 + l3 + 12] = (l4 as u8 / 4) << 4;
        p[14 + l3 + 13] = 0x10;
        p[14 + l3 + 20..14 + l3 + l4].copy_from_slice(options);
        p
    }
    // NOP, NOP, timestamps: what ntcp sends on every segment by default.
    const TIMESTAMPS: [u8; 12] = [1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 9];
    const CAPS: TcpSegmentationCapabilities = TcpSegmentationCapabilities {
        max_aggregate_len: 65535,
        max_segments: 64,
        max_wire_bytes: 100000,
        local_ip_mtu: 1500,
        allow_psh: false,
        allow_cwr: false,
    };
    #[test]
    fn headers_and_bounds() {
        let caps = CAPS;
        let small = packet(false, 2);
        assert!(
            validate(
                &small,
                1,
                TcpSegmentationCapabilities {
                    max_wire_bytes: 119,
                    ..caps
                }
            )
            .is_err()
        );
        assert!(
            validate(
                &small,
                1,
                TcpSegmentationCapabilities {
                    max_wire_bytes: 120,
                    ..caps
                }
            )
            .is_ok()
        );
        assert!(validate(&packet(false, 0), 1, caps).is_err());
        let maximum = packet(false, 65535 - 54);
        assert!(validate(&maximum, 1400, caps).is_ok());
        assert!(validate(&packet(false, 65536 - 54), 1400, caps).is_err());
        let mut flags = packet(false, 3000);
        for flag in [0x01, 0x02, 0x04, 0x08, 0x20, 0x40, 0x80] {
            flags[47] = 0x10 | flag;
            assert!(matches!(
                validate(&flags, 1400, caps),
                Err(Error::Unsupported)
            ));
        }
        for (offset, value) in [(14, 0x46), (15, 3), (20, 0x20), (21, 1), (24, 1)] {
            let mut bad = packet(false, 3000);
            bad[offset] = value;
            assert!(validate(&bad, 1400, caps).is_err());
        }
        for (offset, value) in [(15, 0x30), (20, 0)] {
            let mut bad = packet(true, 3000);
            bad[offset] = value;
            assert!(matches!(
                validate(&bad, 1400, caps),
                Err(Error::Unsupported)
            ));
        }
        for v6 in [false, true] {
            let p = packet(v6, 3000);
            assert_eq!(
                validate(&p, 1400, caps).unwrap(),
                (if v6 { 40 } else { 20 }, 20)
            );
            for mss in [0, usize::MAX, 1500, 1] {
                assert!(validate(&p, mss, caps).is_err());
            }
            for c in [
                TcpSegmentationCapabilities {
                    max_segments: 2,
                    ..caps
                },
                TcpSegmentationCapabilities {
                    max_wire_bytes: 3000,
                    ..caps
                },
                TcpSegmentationCapabilities {
                    max_aggregate_len: 3000,
                    ..caps
                },
            ] {
                assert!(validate(&p, 1400, c).is_err());
            }
            for len in 0..p.len() {
                assert!(validate(&p[..len], 1400, caps).is_err());
            }
            let tcp = if v6 { 54 } else { 34 };
            for (offset, value) in [
                (tcp + 12, 0x40),
                (tcp + 12, 0x51),
                (tcp + 12, 0x58),
                (tcp + 13, 0x18),
                (tcp + 16, 1),
                (tcp + 18, 1),
                (14, 0),
            ] {
                let mut bad = p.clone();
                bad[offset] = value;
                assert!(validate(&bad, 1400, caps).is_err());
            }
            let mut wrap = p.clone();
            wrap[tcp + 4..tcp + 8].fill(255);
            assert!(validate(&wrap, 1400, caps).is_ok());
        }
    }

    #[test]
    fn tcp_options() {
        let sack = [5, 26].into_iter().chain(1..=24);
        let maximum: Vec<u8> = TIMESTAMPS.into_iter().chain([1, 1]).chain(sack).collect();
        assert_eq!(maximum.len(), 40);
        for v6 in [false, true] {
            let l3 = if v6 { 40 } else { 20 };
            let tcp = 14 + l3;
            for options in [&TIMESTAMPS[..], &maximum] {
                let l4 = 20 + options.len();
                let p = with_options(v6, options, 3000);
                assert_eq!(p[tcp + 12] >> 4, l4 as u8 / 4); // 8 and 15
                assert_eq!(validate(&p, 1400, CAPS).unwrap(), (l3 as u16, l4 as u16));
                // Every segment carries the options: they count against the MTU.
                let mss = 1500 - l3 - l4;
                assert!(validate(&p, mss, CAPS).is_ok());
                assert!(matches!(
                    validate(&p, mss + 1, CAPS),
                    Err(Error::InvalidInput)
                ));
                for flag in [0x01, 0x02, 0x04, 0x08, 0x20, 0x40, 0x80] {
                    let mut bad = p.clone();
                    bad[tcp + 13] |= flag;
                    assert!(matches!(
                        validate(&bad, 1400, CAPS),
                        Err(Error::Unsupported)
                    ));
                }
            }
            // Repeated option bytes count against the wire bound too.
            let small = with_options(v6, &TIMESTAMPS, 2);
            let wire = 2 * (small.len() - 1);
            for (max_wire_bytes, ok) in [(wire - 1, false), (wire, true)] {
                let caps = TcpSegmentationCapabilities {
                    max_wire_bytes,
                    ..CAPS
                };
                assert_eq!(validate(&small, 1, caps).is_ok(), ok);
            }
            // 32 header and 28 payload bytes: a data offset of 15 (60 bytes)
            // leaves no payload, 14 leaves four bytes after zero padding.
            let mut p = with_options(v6, &TIMESTAMPS, 28);
            for offset in [0, 1, 2, 3, 4, 15] {
                p[tcp + 12] = offset << 4;
                assert!(matches!(validate(&p, 10, CAPS), Err(Error::InvalidInput)));
            }
            p[tcp + 12] = 14 << 4;
            assert_eq!(validate(&p, 10, CAPS).unwrap(), (l3 as u16, 56));
            for (options, unsupported) in [
                ([1, 1, 2, 0], false),
                ([1, 1, 1, 8], false),
                ([1, 1, 3, 3], false),
                ([1, 2, 1, 1], false),
                ([19, 18, 0, 0], true),
                ([29, 4, 0, 0], true),
            ] {
                match validate(&with_options(v6, &options, 30), 10, CAPS) {
                    Err(Error::Unsupported) => assert!(unsupported),
                    Err(Error::InvalidInput) => assert!(!unsupported),
                    other => panic!("{options:?}: {other:?}"),
                }
            }
            // After end-of-list the rest is padding, as RFC 9293 defines it.
            for options in [[0, 19, 29, 1], [1, 4, 2, 0], [1, 1, 1, 1]] {
                assert!(validate(&with_options(v6, &options, 30), 10, CAPS).is_ok());
            }
        }
    }
}
