use ntcp_io::{TcpSegmentationCapabilities, TcpSegmentationError as Error};

// The first PMD-independent subset deliberately excludes TCP options and control
// flags whose per-segment semantics are not guaranteed by the generic TSO API.
pub(crate) fn validate(
    p: &[u8],
    mss: usize,
    caps: TcpSegmentationCapabilities,
) -> Result<u16, Error> {
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
    if p[tcp + 12] != 0x50 || p[tcp + 13] != 0x10 || word(tcp + 18) != 0 {
        return Err(Error::Unsupported);
    }
    if word(tcp + 16) != 0 {
        return Err(Error::InvalidInput);
    }
    let headers = tcp + 20;
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
        || l3 + 20 + mss.min(payload) > caps.local_ip_mtu as usize
    {
        return Err(Error::InvalidInput);
    }
    // Sequence space is modulo 2^32; the bounded payload cannot cover it twice.
    Ok(l3 as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn packet(v6: bool, payload: usize) -> Vec<u8> {
        let l3 = if v6 { 40 } else { 20 };
        let mut p = vec![0; 14 + l3 + 20 + payload];
        p[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x0800 }).to_be_bytes());
        if v6 {
            p[14] = 0x60;
            p[20] = 6;
            p[18..20].copy_from_slice(&((20 + payload) as u16).to_be_bytes());
        } else {
            p[14] = 0x45;
            p[23] = 6;
            p[16..18].copy_from_slice(&((40 + payload) as u16).to_be_bytes());
        }
        p[14 + l3 + 12] = 0x50;
        p[14 + l3 + 13] = 0x10;
        p
    }
    #[test]
    fn headers_and_bounds() {
        let caps = TcpSegmentationCapabilities {
            max_aggregate_len: 65535,
            max_segments: 64,
            max_wire_bytes: 100000,
            local_ip_mtu: 1500,
        };
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
            assert_eq!(validate(&p, 1400, caps).unwrap(), if v6 { 40 } else { 20 });
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
                (tcp + 12, 0x60),
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
}
