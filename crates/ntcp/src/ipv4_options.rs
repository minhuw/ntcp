use core::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4OptionsError {
    Malformed,
    Capacity,
    InvalidAddress,
    SourceRouteDisabled,
    IncompleteRoute,
}

fn unicast(ip: Ipv4Addr) -> bool {
    ip.octets()[0] != 0 && ip.octets()[0] < 224
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRoute {
    hops: [Ipv4Addr; 9],
    len: u8,
    pub strict: bool,
}
impl SourceRoute {
    pub fn new(hops: &[Ipv4Addr], strict: bool) -> Result<Self, Ipv4OptionsError> {
        if hops.len() > 9 {
            return Err(Ipv4OptionsError::Capacity);
        }
        if hops.iter().any(|&ip| !unicast(ip)) {
            return Err(Ipv4OptionsError::InvalidAddress);
        }
        let mut result = Self {
            hops: [Ipv4Addr::UNSPECIFIED; 9],
            len: hops.len() as u8,
            strict,
        };
        result.hops[..hops.len()].copy_from_slice(hops);
        Ok(result)
    }
    pub fn hops(&self) -> &[Ipv4Addr] {
        &self.hops[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampRequest {
    Times(u8),
    AddressTimes(u8),
    Prespecified { addresses: [Ipv4Addr; 4], len: u8 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutgoingIpv4Options {
    pub source_route: Option<SourceRoute>,
    pub record_route_slots: Option<u8>,
    pub timestamp: Option<TimestampRequest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Options {
    bytes: [u8; 40],
    len: u8,
}
impl Default for Ipv4Options {
    fn default() -> Self {
        Self {
            bytes: [0; 40],
            len: 0,
        }
    }
}
impl Ipv4Options {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn parse(bytes: &[u8], source_routes_enabled: bool) -> Result<Self, Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        if bytes.len() > 40 {
            return Err(Capacity);
        }
        let mut result = Self::default();
        let mut offset = 0;
        let mut seen = [false; 3];
        while offset < bytes.len() {
            let kind = bytes[offset];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                offset += 1;
                continue;
            }
            let len = usize::from(*bytes.get(offset + 1).ok_or(Malformed)?);
            if len < 2 || len > bytes.len() - offset {
                return Err(Malformed);
            }
            let option = &bytes[offset..offset + len];
            let index = match kind {
                131 | 137 => Some(0),
                7 => Some(1),
                68 => Some(2),
                _ => None,
            };
            if let Some(index) = index {
                if seen[index] {
                    return Err(Malformed);
                }
                seen[index] = true;
                if index == 0 && !source_routes_enabled {
                    return Err(SourceRouteDisabled);
                }
                let (base, stride) = if kind == 68 {
                    if len < 4 {
                        return Err(Malformed);
                    }
                    (
                        4,
                        match option[3] & 15 {
                            0 => 4,
                            1 | 3 => 8,
                            _ => return Err(Malformed),
                        },
                    )
                } else {
                    (3, 4)
                };
                if len < base || (len - base) % stride != 0 {
                    return Err(Malformed);
                }
                let pointer = usize::from(option[2]);
                // RFC 791: any pointer beyond the length denotes a completed/full
                // option; only a pointer into option data must address a whole slot.
                if pointer < base + 1 || (pointer <= len && (pointer - base - 1) % stride != 0) {
                    return Err(Malformed);
                }
                // Endpoints terminate, never forward an unfinished source route.
                if index == 0 && pointer <= len {
                    return Err(IncompleteRoute);
                }
                if index == 0 && option[3..].chunks_exact(4).any(|b| !unicast(address(b))) {
                    return Err(InvalidAddress);
                }
                let start = usize::from(result.len);
                result.bytes[start..start + len].copy_from_slice(option);
                result.len += len as u8;
            }
            offset += len;
        }
        Ok(result)
    }

    pub fn return_route(&self, source: Ipv4Addr) -> Option<SourceRoute> {
        let mut offset = 0;
        while offset < usize::from(self.len) {
            let option = &self.bytes[offset..offset + usize::from(self.bytes[offset + 1])];
            if matches!(option[0], 131 | 137) {
                let mut hops = [Ipv4Addr::UNSPECIFIED; 9];
                let mut count = 0;
                // RFC 1122 3.2.1.8(c): tolerate the old encoding that records S first.
                let records = if option.len() >= 7 && address(&option[3..7]) == source {
                    &option[7..]
                } else {
                    &option[3..]
                };
                for hop in records.chunks_exact(4).rev() {
                    hops[count] = address(hop);
                    count += 1;
                }
                return SourceRoute::new(&hops[..count], option[0] == 137).ok();
            }
            offset += option.len();
        }
        None
    }

    pub fn record(mut self, local: Ipv4Addr, timestamp: u32) -> Result<Self, Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        if !unicast(local) {
            return Err(InvalidAddress);
        }
        let mut offset = 0;
        while offset < usize::from(self.len) {
            let len = usize::from(self.bytes[offset + 1]);
            let o = &mut self.bytes[offset..offset + len];
            let p = usize::from(o[2]) - 1;
            match o[0] {
                7 if p < len => {
                    o[p..p + 4].copy_from_slice(&local.octets());
                    o[2] += 4;
                }
                68 => {
                    let flag = o[3] & 15;
                    if p >= len {
                        if o[3] >> 4 == 15 {
                            return Err(Malformed);
                        }
                        o[3] += 16;
                    } else if flag != 3 || address(&o[p..p + 4]) == local {
                        let time = if flag == 0 { p } else { p + 4 };
                        if flag == 1 {
                            o[p..p + 4].copy_from_slice(&local.octets());
                        }
                        o[time..time + 4].copy_from_slice(&timestamp.to_be_bytes());
                        o[2] += if flag == 0 { 4 } else { 8 };
                    }
                }
                _ => {}
            }
            offset += len;
        }
        Ok(self)
    }
}
fn address(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
//# A TCP implementation MAY support the Timestamp (MAY-10) and Record
//# Route (MAY-11) Options.
impl OutgoingIpv4Options {
    pub fn encode(
        &self,
        source: Ipv4Addr,
        final_destination: Ipv4Addr,
        timestamp: u32,
        out: &mut [u8],
    ) -> Result<(Ipv4Addr, usize), Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        if !unicast(source) || !unicast(final_destination) {
            return Err(InvalidAddress);
        }
        let mut bytes = [0u8; 40];
        let mut len = 0;
        let mut destination = final_destination;
        if let Some(route) = self.source_route
            && !route.hops().is_empty()
        {
            destination = route.hops()[0];
            len = 3 + route.hops().len() * 4;
            bytes[..3].copy_from_slice(&[if route.strict { 137 } else { 131 }, len as u8, 4]);
            for (i, hop) in route.hops()[1..]
                .iter()
                .chain(core::iter::once(&final_destination))
                .enumerate()
            {
                bytes[3 + i * 4..7 + i * 4].copy_from_slice(&hop.octets());
            }
        }
        if let Some(slots) = self.record_route_slots {
            let size = 3 + usize::from(slots) * 4;
            if slots > 9 || len + size > 40 {
                return Err(Capacity);
            }
            bytes[len..len + 3].copy_from_slice(&[7, size as u8, 4]);
            len += size;
        }
        if let Some(request) = self.timestamp {
            let (flag, slots, addresses) = match request {
                TimestampRequest::Times(n) => (0, n, None),
                TimestampRequest::AddressTimes(n) => (1, n, None),
                TimestampRequest::Prespecified { addresses, len } => {
                    if len > 4 || addresses[..usize::from(len)].iter().any(|&a| !unicast(a)) {
                        return Err(InvalidAddress);
                    }
                    (3, len, Some(addresses))
                }
            };
            if slots == 0 {
                return Err(Malformed);
            }
            let size = 4 + usize::from(slots) * if flag == 0 { 4 } else { 8 };
            if len + size > 40 {
                return Err(Capacity);
            }
            bytes[len..len + 4].copy_from_slice(&[68, size as u8, 5, flag]);
            if let Some(addresses) = addresses {
                for (i, a) in addresses[..usize::from(slots)].iter().enumerate() {
                    bytes[len + 4 + i * 8..len + 8 + i * 8].copy_from_slice(&a.octets());
                }
            }
            len += size;
        }
        // Record originating RR/TS without interpreting the unconsumed outgoing route.
        let route_len = if matches!(bytes[0], 131 | 137) {
            usize::from(bytes[1])
        } else {
            0
        };
        let recorded =
            Ipv4Options::parse(&bytes[route_len..len], false)?.record(source, timestamp)?;
        bytes[route_len..len].copy_from_slice(recorded.as_bytes());
        let padded = (len + 3) & !3;
        if out.len() < padded {
            return Err(Capacity);
        }
        out[..padded].copy_from_slice(&bytes[..padded]);
        Ok((destination, padded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    #[test]
    fn completed_option_pointers_need_not_be_slot_aligned() {
        for pointer in [8, 9, 255] {
            for kind in [131, 137, 7] {
                let bytes = [kind, 7, pointer, 192, 0, 2, 9];
                let options = Ipv4Options::parse(&bytes, true).unwrap();
                assert_eq!(options.record(ip(2), 42).unwrap(), options);
                if kind != 7 {
                    let route = options.return_route(ip(1)).unwrap();
                    assert_eq!(route.hops(), &[ip(9)]);
                    assert_eq!(route.strict, kind == 137);
                }
            }
        }
        for (flag, len) in [(0, 8), (1, 12), (3, 12)] {
            for pointer in [len + 1, len + 2, 255] {
                let mut bytes = [0; 12];
                bytes[..4].copy_from_slice(&[68, len, pointer, flag]);
                let options = Ipv4Options::parse(&bytes[..usize::from(len)], true).unwrap();
                let recorded = options.record(ip(2), 42).unwrap();
                assert_eq!(recorded.as_bytes()[2], pointer);
                assert_eq!(recorded.as_bytes()[3], 0x10 | flag);
                bytes[3] |= 0xf0;
                let full = Ipv4Options::parse(&bytes[..usize::from(len)], true).unwrap();
                assert_eq!(full.record(ip(2), 42), Err(Ipv4OptionsError::Malformed));
            }
        }
        // A pointer into data still needs to identify the beginning of a slot.
        assert_eq!(
            Ipv4Options::parse(&[7, 7, 5, 0, 0, 0, 0], true),
            Err(Ipv4OptionsError::Malformed)
        );
    }

    #[test]
    fn route_swap_reverse_strict_loose_and_nine_hops() {
        for strict in [false, true] {
            for count in 0..=9 {
                let hops = core::array::from_fn::<_, 9, _>(|i| ip(i as u8 + 10));
                let route = SourceRoute::new(&hops[..count], strict).unwrap();
                let options = OutgoingIpv4Options {
                    source_route: Some(route),
                    ..Default::default()
                };
                let mut bytes = [0; 40];
                let (dest, len) = options.encode(ip(1), ip(2), 0, &mut bytes).unwrap();
                if count == 0 {
                    assert_eq!((dest, len), (ip(2), 0));
                    continue;
                }
                assert_eq!(dest, hops[0]);
                assert_eq!(bytes[0], if strict { 137 } else { 131 });
                assert_eq!(bytes[2], 4);
                assert_eq!(address(&bytes[3 + 4 * (count - 1)..]), ip(2));
                assert_eq!(
                    Ipv4Options::parse(&bytes[..len], true),
                    Err(Ipv4OptionsError::IncompleteRoute)
                );
                // Each reached hop swaps its outgoing-interface address into the slot.
                for (i, hop) in hops[..count].iter().enumerate() {
                    bytes[3 + i * 4..7 + i * 4].copy_from_slice(&hop.octets());
                    bytes[2] += 4;
                }
                let incoming = Ipv4Options::parse(&bytes[..len], true).unwrap();
                let reverse = incoming.return_route(ip(1)).unwrap();
                assert_eq!(reverse.strict, strict);
                for (actual, expected) in reverse.hops().iter().zip(hops[..count].iter().rev()) {
                    assert_eq!(actual, expected);
                }
                assert_eq!(
                    Ipv4Options::parse(&bytes[..len], false),
                    Err(Ipv4OptionsError::SourceRouteDisabled)
                );
            }
        }
        let old = [131, 11, 12, 192, 0, 2, 1, 192, 0, 2, 9];
        assert_eq!(
            Ipv4Options::parse(&old, true)
                .unwrap()
                .return_route(ip(1))
                .unwrap()
                .hops(),
            &[ip(9)]
        );
        assert!(SourceRoute::new(&[ip(1); 10], false).is_err());
        assert!(SourceRoute::new(&[Ipv4Addr::BROADCAST], false).is_err());
        assert!(SourceRoute::new(&[Ipv4Addr::UNSPECIFIED], false).is_err());
    }

    //= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
    //= type=test
    //# A TCP implementation MAY support the Timestamp (MAY-10) and Record
    //# Route (MAY-11) Options.
    #[test]
    fn record_route_and_timestamp_slots_flags_and_overflow() {
        let mut out = [0; 40];
        let requests = OutgoingIpv4Options {
            record_route_slots: Some(2),
            timestamp: Some(TimestampRequest::AddressTimes(2)),
            ..Default::default()
        };
        let (_, len) = requests
            .encode(ip(1), ip(2), 0x8000_0001, &mut out)
            .unwrap();
        assert_eq!(len, 32);
        let received = Ipv4Options::parse(&out[..len], false)
            .unwrap()
            .record(ip(2), 0x8000_0002)
            .unwrap();
        let bytes = received.as_bytes();
        assert_eq!(bytes[2], 12);
        assert_eq!(&bytes[3..11], &[192, 0, 2, 1, 192, 0, 2, 2]);
        assert_eq!(bytes[13], 21);
        assert_eq!(
            &bytes[15..31],
            &[192, 0, 2, 1, 128, 0, 0, 1, 192, 0, 2, 2, 128, 0, 0, 2]
        );
        let full = received.record(ip(2), 0).unwrap();
        assert_eq!(full.as_bytes()[14], 0x11);
        let mut full = full;
        for _ in 1..15 {
            full = full.record(ip(2), 0).unwrap();
        }
        assert_eq!(full.record(ip(2), 0), Err(Ipv4OptionsError::Malformed));
        let requests = OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::Times(2)),
            ..Default::default()
        };
        let (_, len) = requests.encode(ip(1), ip(2), 123, &mut out).unwrap();
        let received = Ipv4Options::parse(&out[..len], false)
            .unwrap()
            .record(ip(2), 456)
            .unwrap();
        assert_eq!(
            received.as_bytes(),
            &[68, 12, 13, 0, 0, 0, 0, 123, 0, 0, 1, 200]
        );
        let requests = OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::Prespecified {
                addresses: [ip(2); 4],
                len: 1,
            }),
            ..Default::default()
        };
        let (_, len) = requests.encode(ip(1), ip(2), 123, &mut out).unwrap();
        assert_eq!(out[2], 5); // Origin does not match next prespecified address.
        let parsed = Ipv4Options::parse(&out[..len], false).unwrap();
        assert_eq!(parsed.record(ip(3), 1).unwrap(), parsed);
        let received = parsed.record(ip(2), 456).unwrap();
        assert_eq!(received.as_bytes()[2], 13);
        assert_eq!(&received.as_bytes()[8..12], &456u32.to_be_bytes());
    }

    #[test]
    fn combined_bounds_atomic_output_and_malformed_options() {
        let mut options = OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[ip(3)], false).unwrap()),
            record_route_slots: Some(2),
            timestamp: Some(TimestampRequest::Times(4)),
        };
        let mut out = [0xa5; 40];
        assert_eq!(options.encode(ip(1), ip(2), 1, &mut out).unwrap().1, 40);
        out.fill(0xa5);
        assert!(options.encode(ip(1), ip(2), 1, &mut out[..39]).is_err());
        assert_eq!(out, [0xa5; 40]);
        options.timestamp = Some(TimestampRequest::Times(0));
        assert!(options.encode(ip(1), ip(2), 1, &mut out).is_err());
        assert_eq!(out, [0xa5; 40]);
        options.timestamp = Some(TimestampRequest::Times(5));
        assert!(options.encode(ip(1), ip(2), 1, &mut out).is_err());
        assert_eq!(out, [0xa5; 40]);
        for bytes in [
            &[7][..],
            &[7, 2],
            &[7, 4, 4, 0],
            &[7, 7, 3, 0, 0, 0, 0],
            &[7, 7, 5, 0, 0, 0, 0],
            &[68, 3, 5],
            &[68, 4, 4, 0],
            &[68, 4, 5, 2],
            &[68, 8, 5, 1, 0, 0, 0, 0],
            &[131, 3, 4, 137, 3, 4],
            &[7, 3, 4, 7, 3, 4],
            &[68, 4, 5, 0, 68, 4, 5, 0],
            &[131, 7, 8, 224, 0, 0, 1],
            &[131, 7, 8, 0, 0, 0, 0],
            &[30, 1],
            &[30, 4, 0],
        ] {
            assert!(Ipv4Options::parse(bytes, true).is_err(), "{bytes:?}");
        }
        assert!(Ipv4Options::parse(&[1; 41], true).is_err());
        assert!(
            Ipv4Options::parse(&[30, 4, 99, 99, 1, 0, 255], true)
                .unwrap()
                .is_empty()
        );
        let valid = [131, 11, 12, 192, 0, 2, 3, 192, 0, 2, 4];
        for n in 1..valid.len() {
            assert!(Ipv4Options::parse(&valid[..n], true).is_err());
        }
        // Every one-byte pointer/length combination is bounds checked before recording.
        for kind in [7, 68, 131, 137] {
            for len in 0..=40 {
                for pointer in 0..=255 {
                    let mut bytes = [0; 40];
                    bytes[0] = kind;
                    bytes[1] = len;
                    bytes[2] = pointer;
                    if let Ok(parsed) = Ipv4Options::parse(&bytes, true) {
                        let _ = parsed.record(ip(1), 0);
                    }
                }
            }
        }
    }
}
