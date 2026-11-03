use core::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4OptionsError {
    Malformed,
    Capacity,
    InvalidAddress,
    InvalidTimestamp,
    SourceRouteDisabled,
    IncompleteRoute,
}

/// IPv4 option time, independent of TCP TSval and the transport timebase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Timestamp(u32);
impl Ipv4Timestamp {
    /// The caller supplies UTC milliseconds since midnight, from a clock updated
    /// at least 15 times/second and accurate within a few minutes (RFC 1122).
    /// This checks the day range, not the physical clock's accuracy or cadence:
    /// a low-level caller contract, for callers that characterize their clock.
    pub fn utc_milliseconds(value: u32) -> Result<Self, Ipv4OptionsError> {
        if value < 86_400_000 {
            Ok(Self(value))
        } else {
            Err(Ipv4OptionsError::InvalidTimestamp)
        }
    }

    /// Mark an arbitrary clock value as nonstandard; preserves all lower bits.
    pub const fn nonstandard(value: u32) -> Self {
        Self(value | 0x8000_0000)
    }

    /// Validate a legacy wire value: unmarked values assert the UTC contract.
    pub fn from_wire(value: u32) -> Result<Self, Ipv4OptionsError> {
        if value & 0x8000_0000 != 0 {
            Ok(Self(value))
        } else {
            Self::utc_milliseconds(value)
        }
    }

    pub const fn wire_value(self) -> u32 {
        self.0
    }
}

/// Embedding-supplied clock for destination Timestamp recording. Recording
/// samples it only for a slot this host may write; `None` means no time is
/// available, so that slot and its pointer stay unchanged. An embedding
/// without a characterized UTC clock returns [`Ipv4Timestamp::nonstandard`]
/// values (RFC 791 section 3.1).
pub trait Ipv4TimestampProvider {
    fn ipv4_timestamp(&mut self) -> Option<Ipv4Timestamp>;
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

/// Requested source route, Record Route and Timestamp options, in the order
/// they are encoded. This is the low-level request: its RR and TS slot counts
/// are capacities the caller asserts are large enough for the registrations it
/// expects (RFC 791 section 3.1); [`Ipv4RegistrationPlan`] checks that
/// assertion against stated expected registrations.
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

    /// Preserve opaque TLVs for adapters whose optional known-option processing
    /// is disabled. Parsing has already enforced all structural/security checks.
    pub fn unrecognized(&self) -> Self {
        let mut result = Self::default();
        let mut offset = 0;
        while offset < usize::from(self.len) {
            let len = usize::from(self.bytes[offset + 1]);
            if !matches!(self.bytes[offset], 7 | 68 | 131 | 137) {
                let start = usize::from(result.len);
                result.bytes[start..start + len].copy_from_slice(&self.bytes[offset..offset + len]);
                result.len += len as u8;
            }
            offset += len;
        }
        result
    }

    pub(crate) fn has_source_route(&self) -> bool {
        let mut offset = 0;
        while offset < usize::from(self.len) {
            if matches!(self.bytes[offset], 131 | 137) {
                return true;
            }
            offset += usize::from(self.bytes[offset + 1]);
        }
        false
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The option-length octet counts the option-type octet and the
    //# option-length octet as well as the option-data octets.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# This option indicates the end of the option list. This might not
    //# coincide with the end of the internet header according to the internet
    //# header length. This is used at the end of all options, not the end of
    //# each option, and need only be used if the end of the options would not
    //# otherwise coincide with the end of the internet header.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# This option may be used between options, for example, to align the
    //# beginning of a subsequent option on a 32 bit boundary.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The option begins with the option type code. The second octet is the
    //# option length which includes the option type code and the length
    //# octet, the pointer octet, and length-3 octets of route data. The third
    //# octet is the pointer into the route data indicating the octet which
    //# begins the next source address to be processed. The pointer is
    //# relative to this option, and the smallest legal value for the pointer
    //# is 4.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The option begins with the option type code. The second octet is the
    //# option length which includes the option type code and the length
    //# octet, the pointer octet, and length-3 octets of route data. The third
    //# octet is the pointer into the route data indicating the octet which
    //# begins the next area to store a route address. The pointer is relative
    //# to this option, and the smallest legal value for the pointer is 4.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The Option Length is the number of octets in the option counting the
    //# type, length, pointer, and overflow/flag octets (maximum length 40).

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The Pointer is the number of octets from the beginning of this option
    //# to the end of timestamps plus one (i.e., it points to the octet
    //# beginning the space for next timestamp). The smallest legal value is
    //# 5. The timestamp area is full when the pointer is greater than the
    //# length.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# The IP layer must not crash as the result of an option length that is
    //# outside the possible range. For example, erroneous option lengths
    //# have been observed to put some IP implementations into infinite loops.
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
            }
            let start = usize::from(result.len);
            result.bytes[start..start + len].copy_from_slice(option);
            result.len += len as u8;
            offset += len;
        }
        Ok(result)
    }

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# If host receives a datagram containing a completed source route (i.e.,
    //# the pointer points beyond the last field), the datagram has reached
    //# its final destination; the option as received (the recorded route)
    //# MUST be passed up to the transport layer (or to ICMP message
    //# processing). This recorded route will be reversed and used to form a
    //# return source route for reply datagrams (see discussion of IP Options
    //# in Section 4). When a return source route is built, it MUST be
    //# correctly formed even if the recorded route included the source host
    //# (see case (B) in the discussion below).
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

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The Flag (flg) [4 bits] values are
    //# 0 -- time stamps only, stored in consecutive 32-bit words,
    //# 1 -- each timestamp is preceded with internet address of the
    //# registering entity,
    //# 3 -- the internet address fields are prespecified. An IP module only
    //# registers its timestamp if it matches its own address with the next
    //# specified internet address.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# Implementation of originating and processing the Record Route option
    //# is OPTIONAL.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# Implementation of originating and processing the Timestamp option is
    //# OPTIONAL. If it is implemented, the following rules apply:
    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The Timestamp is a right-justified, 32-bit timestamp in milliseconds
    //# since midnight UT. If the time is not available in milliseconds or
    //# cannot be provided with respect to midnight UT then any time may be
    //# inserted as a timestamp provided the high order bit of the timestamp
    //# field is set to one to indicate the use of a non-standard value.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
    //# the ICMP Timestamp message.
    /// Low-level caller contract: `timestamp` is a caller-asserted
    /// [`Ipv4Timestamp`] wire value, so an unmarked value claims the RFC 1122
    /// section 3.2.2.8 UTC contract. Only a local slot write validates it;
    /// remote records and irrelevant values on no-write paths remain opaque.
    pub fn record(self, local: Ipv4Addr, timestamp: u32) -> Result<Self, Ipv4OptionsError> {
        self.record_sampled(local, || Ipv4Timestamp::from_wire(timestamp).map(Some))
    }

    /// Record `local` with time from `provider`, sampled at most once and only
    /// for a Timestamp slot this host may write. Without a sample the Timestamp
    /// option is preserved and Record Route is still processed.
    pub fn record_with<P: Ipv4TimestampProvider + ?Sized>(
        self,
        local: Ipv4Addr,
        provider: &mut P,
    ) -> Result<Self, Ipv4OptionsError> {
        self.record_sampled(local, || Ok(provider.ipv4_timestamp()))
    }

    fn record_sampled(
        mut self,
        local: Ipv4Addr,
        mut sample: impl FnMut() -> Result<Option<Ipv4Timestamp>, Ipv4OptionsError>,
    ) -> Result<Self, Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        if !unicast(local) {
            return Err(InvalidAddress);
        }
        let mut offset = 0;
        while offset < usize::from(self.len) {
            let len = usize::from(self.bytes[offset + 1]);
            let o = &mut self.bytes[offset..offset + len];
            match o[0] {
                7 => {
                    let p = usize::from(o[2]) - 1;
                    if p < len {
                        o[p..p + 4].copy_from_slice(&local.octets());
                        o[2] += 4;
                    }
                }
                68 => {
                    let p = usize::from(o[2]) - 1;
                    let flag = o[3] & 15;
                    if p >= len {
                        if o[3] >> 4 == 15 {
                            return Err(Malformed);
                        }
                        o[3] += 16;
                    } else if (flag != 3 || address(&o[p..p + 4]) == local)
                        && let Some(timestamp) = sample()?
                    {
                        let timestamp = timestamp.wire_value();
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

/// Option area of every IPv4 fragment after the first. RFC 791 section 3.2
/// keeps all options in the first fragment and copies into later fragments
/// only those whose type has the copied flag (0x80) set: both source routes
/// are copied, Record Route and Timestamp are not. End stops the scan and NOP
/// is not copied. `encoded` is a complete option area (an encoded outgoing set
/// may still hold an unconsumed source route, so it is walked structurally,
/// not through the endpoint parser). Returns the zero-padded length in `out`.
pub fn copied_fragment_options(encoded: &[u8], out: &mut [u8]) -> Result<usize, Ipv4OptionsError> {
    use Ipv4OptionsError::*;
    if encoded.len() > 40 {
        return Err(Capacity);
    }
    let mut copied = [0u8; 40];
    let mut len = 0;
    let mut offset = 0;
    while offset < encoded.len() {
        match encoded[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let size = usize::from(*encoded.get(offset + 1).ok_or(Malformed)?);
                if size < 2 || size > encoded.len() - offset {
                    return Err(Malformed);
                }
                if kind & 0x80 != 0 {
                    copied[len..len + size].copy_from_slice(&encoded[offset..offset + size]);
                    len += size;
                }
                offset += size;
            }
        }
    }
    let padded = (len + 3) & !3;
    let out = out.get_mut(..padded).ok_or(Capacity)?;
    out.copy_from_slice(&copied[..padded]);
    Ok(padded)
}

// An originating source route toward `final_destination` at the start of
// `bytes`: its first hop is the header destination and the option holds the
// remaining hops and the final destination, pointer 4 (RFC 791 section 3.1).
// Returns the header destination and the option length; an empty route
// encodes nothing.
fn encode_route(
    route: Option<&SourceRoute>,
    final_destination: Ipv4Addr,
    bytes: &mut [u8; 40],
) -> (Ipv4Addr, usize) {
    let Some(route) = route.filter(|route| !route.hops().is_empty()) else {
        return (final_destination, 0);
    };
    let len = 3 + route.hops().len() * 4;
    bytes[..3].copy_from_slice(&[if route.strict { 137 } else { 131 }, len as u8, 4]);
    for (i, hop) in route.hops()[1..]
        .iter()
        .chain(core::iter::once(&final_destination))
        .enumerate()
    {
        bytes[3 + i * 4..7 + i * 4].copy_from_slice(&hop.octets());
    }
    (route.hops()[0], len)
}

/// An already-encoded IPv4 option area that is sent as is: encoding, retries
/// and source fragmentation never record into it. It carries options a host
/// continues from a received datagram (a reply's options), distinct from
/// received options (`Ipv4Options`) and from `OutgoingIpv4Options`, which
/// originates fresh Record Route and Timestamp options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedIpv4Options {
    bytes: [u8; 40],
    len: u8,
    destination: Ipv4Addr,
    final_destination: Ipv4Addr,
}

impl EncodedIpv4Options {
    /// At most one source route toward `final_destination`, encoded as an
    /// originating host does (`OutgoingIpv4Options`), followed by `carried`:
    /// complete, validated options in the form `Ipv4Options::as_bytes`
    /// presents them, so without NOP, End or a source route (RFC 1122
    /// section 3.2.1.8 forbids sending a second one, and its first hop would
    /// not be the header's).
    /// Their contents, Record Route and Timestamp slots and pointers
    /// included, are kept octet for octet. The area is zero padded to a
    /// 32-bit boundary and must fit the 40-octet maximum (Capacity).
    pub fn new(
        route: Option<&SourceRoute>,
        final_destination: Ipv4Addr,
        carried: &[u8],
    ) -> Result<Self, Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        if !unicast(final_destination) {
            return Err(InvalidAddress);
        }
        let parsed = Ipv4Options::parse(carried, false).map_err(|error| match error {
            SourceRouteDisabled | IncompleteRoute => Malformed,
            error => error,
        })?;
        if parsed.as_bytes() != carried {
            return Err(Malformed);
        }
        let mut bytes = [0; 40];
        let (destination, route_len) = encode_route(route, final_destination, &mut bytes);
        let len = route_len + carried.len();
        if len > 40 {
            return Err(Capacity);
        }
        bytes[route_len..len].copy_from_slice(carried);
        Ok(Self {
            bytes,
            len: ((len + 3) & !3) as u8,
            destination,
            final_destination,
        })
    }
    /// The zero-padded option area.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    /// The header destination: the source route's first hop, otherwise the
    /// final destination.
    pub const fn destination(&self) -> Ipv4Addr {
        self.destination
    }
    /// The datagram's final destination, which transport checksums and
    /// Identification uniqueness use.
    pub const fn final_destination(&self) -> Ipv4Addr {
        self.final_destination
    }
}

//= https://www.rfc-editor.org/rfc/rfc9293#section-3.9.2
//# A TCP implementation MAY support the Timestamp (MAY-10) and Record
//# Route (MAY-11) Options.
impl OutgoingIpv4Options {
    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //# The internet header padding is used to ensure that the internet
    //# header ends on a 32 bit boundary. The padding is zero.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# An IP header containing more than one Source Route option MUST NOT be
    //# sent; the effect on routing of multiple Source Route options is
    //# implementation-specific.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //# The originating host MUST record a timestamp in a Timestamp option
    //# whose Internet address fields are not pre-specified or whose first
    //# pre-specified address is the host's interface address.
    /// Low-level caller contract: encodes the requested slot counts without
    /// checking them against any expected registrations, and records the
    /// origin with `timestamp`, a caller-asserted [`Ipv4Timestamp`] wire value
    /// validated only when a Timestamp slot is written. Returns the header
    /// destination and the zero-padded option length.
    pub fn encode(
        &self,
        source: Ipv4Addr,
        final_destination: Ipv4Addr,
        timestamp: u32,
        out: &mut [u8],
    ) -> Result<(Ipv4Addr, usize), Ipv4OptionsError> {
        self.encode_recorded(source, final_destination, out, |area| {
            area.record(source, timestamp)
        })
    }

    /// [`Self::encode`] recording the origin with time from `provider`,
    /// sampled at most once and only for a Timestamp slot the origin writes:
    /// one whose addresses are not prespecified, or whose first prespecified
    /// address is `source`. Without a sample that slot and its pointer stay
    /// initialized. A request checked by [`Ipv4RegistrationPlan`] from
    /// `source` toward `final_destination` yields
    /// [`Ipv4RegistrationPlan::option_octets`].
    pub fn encode_with<P: Ipv4TimestampProvider + ?Sized>(
        &self,
        source: Ipv4Addr,
        final_destination: Ipv4Addr,
        provider: &mut P,
        out: &mut [u8],
    ) -> Result<(Ipv4Addr, usize), Ipv4OptionsError> {
        self.encode_recorded(source, final_destination, out, |area| {
            area.record_with(source, provider)
        })
    }

    // The one origin recording: the initialized area, then `record` on its
    // Record Route and Timestamp options, never on the unconsumed outgoing
    // route. `out` is checked first, so nothing is sampled for an area that
    // cannot be written.
    fn encode_recorded(
        &self,
        source: Ipv4Addr,
        final_destination: Ipv4Addr,
        out: &mut [u8],
        record: impl FnOnce(Ipv4Options) -> Result<Ipv4Options, Ipv4OptionsError>,
    ) -> Result<(Ipv4Addr, usize), Ipv4OptionsError> {
        if !unicast(source) || !unicast(final_destination) {
            return Err(Ipv4OptionsError::InvalidAddress);
        }
        let mut bytes = [0u8; 40];
        let (destination, route_len, len) = self.initialize(final_destination, &mut bytes)?;
        let padded = (len + 3) & !3;
        let out = out.get_mut(..padded).ok_or(Ipv4OptionsError::Capacity)?;
        let recorded = record(Ipv4Options::parse(&bytes[route_len..len], false)?)?;
        bytes[route_len..len].copy_from_slice(recorded.as_bytes());
        out.copy_from_slice(&bytes[..padded]);
        Ok((destination, padded))
    }

    // The initialized option area before origin recording: the source route,
    // Record Route with zeroed slots and Timestamp with zeroed or
    // prespecified-address/zero slots, each pointer at its first slot
    // (RFC 791 section 3.1). Returns the header destination, the route length
    // and the unpadded length; the rest of `bytes` is zero.
    fn initialize(
        &self,
        final_destination: Ipv4Addr,
        bytes: &mut [u8; 40],
    ) -> Result<(Ipv4Addr, usize, usize), Ipv4OptionsError> {
        use Ipv4OptionsError::*;
        *bytes = [0; 40];
        let (destination, mut len) =
            encode_route(self.source_route.as_ref(), final_destination, bytes);
        let route_len = len;
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
        Ok((destination, route_len, len))
    }
}

/// The originated option an expectation or a capacity refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisteredOption {
    RecordRoute,
    Timestamp,
}

/// Timestamp registrations the owner expects, in the form the requested
/// Timestamp flag needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedTimestamps<'a> {
    /// Registrations for flags 0 and 1, counting every visit that records.
    Count(u8),
    /// For flag 3, the ordered addresses expected to register, repeated
    /// visits included. A module registers only at the next prespecified
    /// address, so these must begin the requested address list.
    Prespecified(&'a [Ipv4Addr]),
}

/// The owner's statement of the registrations a datagram is expected to
/// collect on its path, counting every visit that records, the originating
/// host and the destination included. It comes from the owner's topology
/// knowledge: the stack never infers downstream hop counts. `None` states
/// nothing about that option.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpectedRegistrations<'a> {
    pub record_route: Option<u8>,
    pub timestamp: Option<ExpectedTimestamps<'a>>,
}

/// Why requested options cannot hold the expected registrations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4RegistrationError {
    /// `option` holds `available` registrations, `expected` are expected; an
    /// option that is not requested holds none.
    InsufficientRecords {
        option: RegisteredOption,
        expected: usize,
        available: usize,
    },
    /// The zero-padded option area needs `required_octets`, beyond the
    /// `maximum` IPv4 option area of 40 octets.
    CombinedCapacity {
        required_octets: usize,
        maximum: usize,
    },
    /// The prespecified Timestamp address at `index` is not unicast, or is not
    /// the expected address at that position.
    InvalidPrespecifiedAddress { index: usize },
    /// An endpoint address is not IPv4.
    WrongFamily,
    /// `option` is requested without an expectation in the form it needs,
    /// or by a managed open without a plan.
    MissingExpectation { option: RegisteredOption },
    /// The plan was made for other endpoint addresses or another request
    /// (any source-route hop, its strictness, a slot count or a prespecified
    /// address) than the open it is supplied with.
    PlanMismatch,
    /// The request is otherwise unencodable: a non-unicast endpoint address
    /// (`InvalidAddress`) or a Timestamp option without slots (`Malformed`).
    Options(Ipv4OptionsError),
}

const MAX_OPTION_OCTETS: usize = 40;

// Unpadded octets of each requested option: a nonempty source route
// 3 + 4n (an absent or empty one is the direct route and encodes nothing),
// Record Route 3 + 4r, Timestamp 4 + 4t (flag 0) or 4 + 8t (flags 1 and 3).
fn requested_octets(options: &OutgoingIpv4Options) -> Option<usize> {
    let route = match options.source_route.map_or(0, |route| route.hops().len()) {
        0 => 0,
        hops => hops.checked_mul(4)?.checked_add(3)?,
    };
    let record_route = match options.record_route_slots {
        Some(slots) => usize::from(slots).checked_mul(4)?.checked_add(3)?,
        None => 0,
    };
    let timestamp = match options.timestamp {
        Some(TimestampRequest::Times(slots)) => usize::from(slots).checked_mul(4)?,
        Some(
            TimestampRequest::AddressTimes(slots)
            | TimestampRequest::Prespecified { len: slots, .. },
        ) => usize::from(slots).checked_mul(8)?,
        None => return route.checked_add(record_route),
    }
    .checked_add(4)?;
    route.checked_add(record_route)?.checked_add(timestamp)
}

// Each requested capacity must hold every expected registration; capacity may
// exceed the expectation, never fall short.
fn check_expectations(
    options: &OutgoingIpv4Options,
    expected: &ExpectedRegistrations<'_>,
) -> Result<(), Ipv4RegistrationError> {
    use Ipv4RegistrationError::*;
    use RegisteredOption::*;
    let insufficient = |option, expected: usize, available: usize| {
        if expected > available {
            Err(InsufficientRecords {
                option,
                expected,
                available,
            })
        } else {
            Ok(())
        }
    };
    match (options.record_route_slots, expected.record_route) {
        (Some(_), None) => {
            return Err(MissingExpectation {
                option: RecordRoute,
            });
        }
        (slots, Some(count)) => insufficient(
            RecordRoute,
            usize::from(count),
            usize::from(slots.unwrap_or(0)),
        )?,
        (None, None) => {}
    }
    match (options.timestamp, expected.timestamp) {
        (None, None) => Ok(()),
        (
            Some(TimestampRequest::Times(slots) | TimestampRequest::AddressTimes(slots)),
            Some(ExpectedTimestamps::Count(count)),
        ) => insufficient(Timestamp, usize::from(count), usize::from(slots)),
        (
            Some(TimestampRequest::Prespecified { addresses, len }),
            Some(ExpectedTimestamps::Prespecified(visits)),
        ) => {
            insufficient(Timestamp, visits.len(), usize::from(len))?;
            match visits
                .iter()
                .zip(addresses)
                .position(|(visit, address)| *visit != address)
            {
                Some(index) => Err(InvalidPrespecifiedAddress { index }),
                None => Ok(()),
            }
        }
        (None, Some(ExpectedTimestamps::Count(count))) => {
            insufficient(Timestamp, usize::from(count), 0)
        }
        (None, Some(ExpectedTimestamps::Prespecified(visits))) => {
            insufficient(Timestamp, visits.len(), 0)
        }
        (Some(_), _) => Err(MissingExpectation { option: Timestamp }),
    }
}

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# A recorded route is composed of a series of internet addresses. Each
//# internet address is 32 bits or 4 octets. If the pointer is greater than
//# the length, the recorded route data area is full. The originating host
//# must compose this option with a large enough route data area to hold all
//# the address expected. The size of the option does not change due to
//# adding addresses. The intitial contents of the route data area must be
//# zero.

//= https://www.rfc-editor.org/rfc/rfc791#section-3.1
//# The originating host must compose this option with a large enough
//# timestamp data area to hold all the timestamp information expected. The
//# size of the option does not change due to adding timestamps. The
//# intitial contents of the timestamp data area must be zero or internet
//# address/zero pairs.
/// A checked capacity plan for originating `OutgoingIpv4Options` between two
/// IPv4 endpoints, not yet bound to a connection or route.
///
/// Planning succeeds only when each requested Record Route and Timestamp
/// option holds every expected registration (RFC 791 section 3.1: the
/// originating host composes the option with a data area large enough for all
/// expected addresses and timestamps) and the zero-padded option area fits
/// the 40-octet IPv4 maximum. Nothing is truncated, shrunk or dropped. The
/// checked request's encoded area ([`OutgoingIpv4Options::encode_with`])
/// always has [`Self::option_octets`] octets, initialized (zero, or
/// address/zero pairs for prespecified addresses) before origin recording;
/// registration never changes its size. TCP options are carried in the TCP
/// header and do not consume this budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4RegistrationPlan {
    options: OutgoingIpv4Options,
    source: Ipv4Addr,
    final_destination: Ipv4Addr,
    octets: u8,
}

impl Ipv4RegistrationPlan {
    /// Plan `options` from `local` to `remote` for the `expected`
    /// registrations. Request errors (family, addresses, slots, the combined
    /// budget) are reported before expectation errors.
    pub fn new(
        local: IpAddr,
        remote: IpAddr,
        options: OutgoingIpv4Options,
        expected: &ExpectedRegistrations<'_>,
    ) -> Result<Self, Ipv4RegistrationError> {
        use Ipv4RegistrationError::*;
        let (IpAddr::V4(source), IpAddr::V4(final_destination)) = (local, remote) else {
            return Err(WrongFamily);
        };
        if !unicast(source) || !unicast(final_destination) {
            return Err(Options(Ipv4OptionsError::InvalidAddress));
        }
        if let Some(request) = options.timestamp {
            let (TimestampRequest::Times(slots)
            | TimestampRequest::AddressTimes(slots)
            | TimestampRequest::Prespecified { len: slots, .. }) = request;
            if slots == 0 {
                return Err(Options(Ipv4OptionsError::Malformed));
            }
            if let TimestampRequest::Prespecified { addresses, len } = request
                && let Some(index) = addresses
                    .iter()
                    .take(usize::from(len))
                    .position(|&address| !unicast(address))
            {
                return Err(InvalidPrespecifiedAddress { index });
            }
        }
        let required_octets = requested_octets(&options)
            .and_then(|octets| octets.checked_add(3))
            .map_or(usize::MAX, |octets| octets & !3);
        if required_octets > MAX_OPTION_OCTETS {
            return Err(CombinedCapacity {
                required_octets,
                maximum: MAX_OPTION_OCTETS,
            });
        }
        check_expectations(&options, expected)?;
        Ok(Self {
            options,
            source,
            final_destination,
            octets: required_octets as u8,
        })
    }

    /// The checked request.
    pub const fn options(&self) -> &OutgoingIpv4Options {
        &self.options
    }

    /// The fixed, zero-padded size of the option area, which IHL counts.
    pub const fn option_octets(&self) -> usize {
        self.octets as usize
    }

    // A plan states expectations for exactly one request between two
    // endpoints; any other request needs its own plan.
    pub(crate) fn check_request(
        &self,
        local: IpAddr,
        remote: IpAddr,
        options: &OutgoingIpv4Options,
    ) -> Result<(), Ipv4RegistrationError> {
        let (IpAddr::V4(source), IpAddr::V4(final_destination)) = (local, remote) else {
            return Err(Ipv4RegistrationError::WrongFamily);
        };
        if source != self.source
            || final_destination != self.final_destination
            || *options != self.options
        {
            return Err(Ipv4RegistrationError::PlanMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    #[test]
    fn opaque_tlvs_survive_all_scanners_and_mixed_recording() {
        for len in 2..=40 {
            let mut bytes = [0xff; 40];
            bytes[..2].copy_from_slice(&[158, len as u8]);
            let parsed = Ipv4Options::parse(&bytes[..len], false).unwrap();
            assert_eq!(parsed.as_bytes(), &bytes[..len]);
            assert_eq!(parsed.unrecognized(), parsed);
            assert_eq!(parsed.record(ip(2), u32::MAX).unwrap(), parsed);
            assert_eq!(parsed.return_route(ip(1)), None);
            for cut in 1..len {
                assert!(Ipv4Options::parse(&bytes[..cut], false).is_err());
            }
        }
        // Repeated unknown kinds, short TLVs and misleading pointer/flag data.
        let raw = [1, 30, 2, 30, 3, 0, 158, 4, 255, 255, 1, 0, 68];
        let parsed = Ipv4Options::parse(&raw, false).unwrap();
        assert_eq!(parsed.as_bytes(), &raw[1..10]);
        assert_eq!(parsed.record(ip(2), u32::MAX).unwrap(), parsed);
        assert_eq!(parsed.return_route(ip(1)), None);
        for len in [0, 1, 41, 255] {
            assert!(Ipv4Options::parse(&[30, len], false).is_err());
        }
        let mixed = [30, 2, 7, 7, 4, 0, 0, 0, 0, 158, 3, 0];
        let parsed = Ipv4Options::parse(&mixed, false).unwrap();
        let recorded = parsed.record(ip(2), u32::MAX).unwrap();
        assert_eq!(
            recorded.as_bytes(),
            &[30, 2, 7, 7, 8, 192, 0, 2, 2, 158, 3, 0]
        );
        assert_eq!(recorded.unrecognized().as_bytes(), &[30, 2, 158, 3, 0]);
        for kind in [131, 137] {
            let raw = [30, 2, kind, 7, 8, 192, 0, 2, 9, 158, 3, 255];
            assert_eq!(
                Ipv4Options::parse(&raw, false),
                Err(Ipv4OptionsError::SourceRouteDisabled)
            );
            let parsed = Ipv4Options::parse(&raw, true).unwrap();
            assert_eq!(parsed.record(ip(2), u32::MAX).unwrap(), parsed);
            let route = parsed.return_route(ip(1)).unwrap();
            assert_eq!(route.hops(), &[ip(9)]);
            assert_eq!(route.strict, kind == 137);
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# A timestamp value MUST follow the rules given in Section 3.2.2.8 for
    //# the ICMP Timestamp message.
    #[test]
    fn timestamp_value_contract_only_applies_to_local_writes() {
        for value in [0, 1, 86_399_999] {
            assert_eq!(
                Ipv4Timestamp::utc_milliseconds(value).unwrap().wire_value(),
                value
            );
            assert_eq!(Ipv4Timestamp::from_wire(value).unwrap().wire_value(), value);
        }
        for value in [86_400_000, 0x7fff_ffff, u32::MAX] {
            assert_eq!(
                Ipv4Timestamp::utc_milliseconds(value),
                Err(Ipv4OptionsError::InvalidTimestamp)
            );
        }
        for value in [0, 1, 86_400_000, 0x7fff_ffff, u32::MAX] {
            let wire = Ipv4Timestamp::nonstandard(value).wire_value();
            assert_eq!(wire, value | 0x8000_0000);
            assert_eq!(Ipv4Timestamp::from_wire(wire).unwrap().wire_value(), wire);
        }
        let invalid = 86_400_000;
        assert_eq!(
            Ipv4Options::default().record(ip(1), invalid).unwrap(),
            Ipv4Options::default()
        );
        for flag in [0, 1, 3] {
            let mut bytes = [0; 12];
            let len = if flag == 0 { 8 } else { 12 };
            bytes[..4].copy_from_slice(&[68, len, 5, flag]);
            if flag == 3 {
                bytes[4..8].copy_from_slice(&ip(1).octets());
                let parsed = Ipv4Options::parse(&bytes, false).unwrap();
                assert_eq!(parsed.record(ip(2), invalid).unwrap(), parsed);
            }
            let parsed = Ipv4Options::parse(&bytes[..usize::from(len)], false).unwrap();
            assert_eq!(
                parsed.record(ip(1), invalid),
                Err(Ipv4OptionsError::InvalidTimestamp)
            );
            let recorded = parsed.record(ip(1), 86_399_999).unwrap();
            assert_eq!(recorded.as_bytes()[2], len + 1);
            assert_eq!(
                &recorded.as_bytes()[usize::from(len) - 4..],
                &86_399_999u32.to_be_bytes()
            );
            let full = recorded.record(ip(1), invalid).unwrap();
            assert_eq!(full.as_bytes()[3], flag | 0x10);
            assert_eq!(full.as_bytes().len(), usize::from(len));
            bytes[2] = 255;
            bytes[3] |= 0xf0;
            let overflowed = Ipv4Options::parse(&bytes[..usize::from(len)], false).unwrap();
            assert_eq!(
                overflowed.record(ip(1), invalid),
                Err(Ipv4OptionsError::Malformed)
            );
        }
        // A remote record is opaque even when its numeric value is nonconforming.
        let remote = [68, 12, 9, 0, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        let recorded = Ipv4Options::parse(&remote, false)
            .unwrap()
            .record(ip(1), 123)
            .unwrap();
        assert_eq!(&recorded.as_bytes()[4..8], &remote[4..8]);
        assert_eq!(&recorded.as_bytes()[8..12], &123u32.to_be_bytes());
        for flag in [
            TimestampRequest::Times(2),
            TimestampRequest::AddressTimes(2),
            TimestampRequest::Prespecified {
                addresses: [ip(1); 4],
                len: 2,
            },
        ] {
            let request = OutgoingIpv4Options {
                timestamp: Some(flag),
                ..Default::default()
            };
            let mut out = [0xa5; 40];
            assert_eq!(
                request.encode(ip(1), ip(2), invalid, &mut out),
                Err(Ipv4OptionsError::InvalidTimestamp)
            );
            assert_eq!(out, [0xa5; 40]);
            request
                .encode(
                    ip(1),
                    ip(2),
                    Ipv4Timestamp::nonstandard(invalid).wire_value(),
                    &mut out,
                )
                .unwrap();
        }
        let unmatched = OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::Prespecified {
                addresses: [ip(2); 4],
                len: 1,
            }),
            ..Default::default()
        };
        let mut out = [0; 40];
        unmatched.encode(ip(1), ip(2), invalid, &mut out).unwrap();
        assert_eq!(&out[..4], &[68, 12, 5, 3]);
        assert_eq!(&out[8..12], &[0; 4]);
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The Pointer is the number of octets from the beginning of this option
    //# to the end of timestamps plus one (i.e., it points to the octet
    //# beginning the space for next timestamp). The smallest legal value is
    //# 5. The timestamp area is full when the pointer is greater than the
    //# length.
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
        for flag in [0, 1, 3] {
            for pointer in 0..5 {
                assert_eq!(
                    Ipv4Options::parse(&[68, 4, pointer, flag], true),
                    Err(Ipv4OptionsError::Malformed)
                );
            }
        }
        // A pointer into data still needs to identify the beginning of a slot.
        assert_eq!(
            Ipv4Options::parse(&[7, 7, 5, 0, 0, 0, 0], true),
            Err(Ipv4OptionsError::Malformed)
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# This option indicates the end of the option list. This might not
    //# coincide with the end of the internet header according to the internet
    //# header length. This is used at the end of all options, not the end of
    //# each option, and need only be used if the end of the options would not
    //# otherwise coincide with the end of the internet header.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# This option may be used between options, for example, to align the
    //# beginning of a subsequent option on a 32 bit boundary.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The internet header padding is used to ensure that the internet
    //# header ends on a 32 bit boundary. The padding is zero.
    #[test]
    fn end_nop_and_padding_preserve_option_boundaries() {
        let raw = [1, 7, 7, 4, 0, 0, 0, 0, 1, 68, 8, 5, 0, 0, 0, 0, 0, 0, 255];
        let options = Ipv4Options::parse(&raw, false).unwrap();
        assert_eq!(
            options.as_bytes(),
            &[7, 7, 4, 0, 0, 0, 0, 68, 8, 5, 0, 0, 0, 0, 0]
        );
        assert!(Ipv4Options::parse(&[0, 255], false).unwrap().is_empty());
        for slots in 0..=9 {
            let request = OutgoingIpv4Options {
                record_route_slots: Some(slots),
                ..Default::default()
            };
            let mut out = [0xa5; 40];
            let (_, padded) = request.encode(ip(1), ip(2), 0, &mut out).unwrap();
            let option_len = 3 + usize::from(slots) * 4;
            assert_eq!(padded % 4, 0);
            assert_eq!(padded, option_len + 1);
            assert_eq!(out[1], option_len as u8);
            assert_eq!(out[option_len], 0);
            assert!(out[padded..].iter().all(|&b| b == 0xa5));
            assert_eq!(
                Ipv4Options::parse(&out[..padded], false)
                    .unwrap()
                    .as_bytes(),
                &out[..option_len]
            );
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The option begins with the option type code. The second octet is the
    //# option length which includes the option type code and the length
    //# octet, the pointer octet, and length-3 octets of route data. The third
    //# octet is the pointer into the route data indicating the octet which
    //# begins the next source address to be processed. The pointer is
    //# relative to this option, and the smallest legal value for the pointer
    //# is 4.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The option begins with the option type code. The second octet is the
    //# option length which includes the option type code and the length
    //# octet, the pointer octet, and length-3 octets of route data. The third
    //# octet is the pointer into the route data indicating the octet which
    //# begins the next area to store a route address. The pointer is relative
    //# to this option, and the smallest legal value for the pointer is 4.
    #[test]
    fn source_route_wire_format_and_pointer_bounds() {
        for kind in [7, 131, 137] {
            for slots in 0..=9 {
                let len = 3 + slots * 4;
                let mut bytes = [0; 40];
                bytes[..3].copy_from_slice(&[kind, len as u8, 4]);
                for i in 0..slots {
                    bytes[3 + i * 4..7 + i * 4].copy_from_slice(&ip(i as u8 + 3).octets());
                }
                for pointer in 0..4 {
                    bytes[2] = pointer;
                    assert_eq!(
                        Ipv4Options::parse(&bytes[..len], true),
                        Err(Ipv4OptionsError::Malformed)
                    );
                }
                bytes[2] = 4;
                if kind == 7 {
                    let parsed = Ipv4Options::parse(&bytes[..len], true).unwrap();
                    let recorded = parsed.record(ip(1), 0).unwrap();
                    assert_eq!(recorded.as_bytes().len(), len);
                    if slots > 0 {
                        assert_eq!(recorded.as_bytes()[2], 8);
                        assert_eq!(&recorded.as_bytes()[3..7], &ip(1).octets());
                    }
                } else if slots > 0 {
                    assert_eq!(
                        Ipv4Options::parse(&bytes[..len], true),
                        Err(Ipv4OptionsError::IncompleteRoute)
                    );
                }
                bytes[2] = (len + 1) as u8;
                assert_eq!(
                    Ipv4Options::parse(&bytes[..len], true).unwrap().as_bytes(),
                    &bytes[..len]
                );
                if slots > 0 {
                    bytes[2] = 5;
                    assert_eq!(
                        Ipv4Options::parse(&bytes[..len], true),
                        Err(Ipv4OptionsError::Malformed)
                    );
                }
            }
        }
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
    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The Option Length is the number of octets in the option counting the
    //# type, length, pointer, and overflow/flag octets (maximum length 40).

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The Flag (flg) [4 bits] values are
    //# 0 -- time stamps only, stored in consecutive 32-bit words,
    //# 1 -- each timestamp is preceded with internet address of the
    //# registering entity,
    //# 3 -- the internet address fields are prespecified. An IP module only
    //# registers its timestamp if it matches its own address with the next
    //# specified internet address.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# Implementation of originating and processing the Record Route option
    //# is OPTIONAL.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# Implementation of originating and processing the Timestamp option is
    //# OPTIONAL. If it is implemented, the following rules apply:

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# The originating host MUST record a timestamp in a Timestamp option
    //# whose Internet address fields are not pre-specified or whose first
    //# pre-specified address is the host's interface address.
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
        // Matching prespecified address must also record at origination.
        let requests = OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::Prespecified {
                addresses: [ip(1); 4],
                len: 1,
            }),
            ..Default::default()
        };
        let (_, len) = requests.encode(ip(1), ip(2), 789, &mut out).unwrap();
        assert_eq!(len, 12);
        assert_eq!(&out[..4], &[68, 12, 13, 3]);
        assert_eq!(&out[4..8], &ip(1).octets());
        assert_eq!(&out[8..12], &789u32.to_be_bytes());
        for slots in 1..=9 {
            let requests = OutgoingIpv4Options {
                timestamp: Some(TimestampRequest::Times(slots)),
                ..Default::default()
            };
            let (_, len) = requests.encode(ip(1), ip(2), 123, &mut out).unwrap();
            assert_eq!(len, 4 + usize::from(slots) * 4);
            assert_eq!(out[1], len as u8);
            assert_eq!(out[2], 9);
            assert!(out[8..len].iter().all(|&b| b == 0));
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The option-length octet counts the option-type octet and the
    //# option-length octet as well as the option-data octets.

    //= https://www.rfc-editor.org/rfc/rfc1122#section-3.2.1.8
    //= type=test
    //# The IP layer must not crash as the result of an option length that is
    //# outside the possible range. For example, erroneous option lengths
    //# have been observed to put some IP implementations into infinite loops.
    #[test]
    fn fragment_copy_projection_keeps_only_copied_options() {
        // Every known kind together: LSRR (copied), RR and TS (not copied).
        for strict in [false, true] {
            let options = OutgoingIpv4Options {
                source_route: Some(SourceRoute::new(&[ip(3), ip(4)], strict).unwrap()),
                record_route_slots: Some(2),
                timestamp: Some(TimestampRequest::Times(2)),
            };
            let mut encoded = [0; 40];
            let (_, len) = options.encode(ip(1), ip(2), 7, &mut encoded).unwrap();
            let mut out = [0xa5; 40];
            let copied = copied_fragment_options(&encoded[..len], &mut out).unwrap();
            // The 11-octet route pads to 12; RR and TS vanish.
            assert_eq!(copied, 12);
            assert_eq!(&out[..11], &encoded[..11]);
            assert_eq!(out[0], if strict { 137 } else { 131 });
            assert_eq!(out[11], 0);
            assert_eq!(out[12..], [0xa5; 28]);
        }
        // RR and TS alone leave later fragments without options.
        let options = OutgoingIpv4Options {
            source_route: None,
            record_route_slots: Some(3),
            timestamp: Some(TimestampRequest::AddressTimes(1)),
        };
        let mut encoded = [0; 40];
        let (_, len) = options.encode(ip(1), ip(2), 7, &mut encoded).unwrap();
        assert_eq!(
            copied_fragment_options(&encoded[..len], &mut []).unwrap(),
            0
        );
        // Opaque kinds follow their copied flag; NOP is dropped, End stops.
        let bytes = [1, 158, 4, 9, 9, 30, 3, 0, 1, 0, 148, 2];
        let mut out = [0; 40];
        let copied = copied_fragment_options(&bytes, &mut out).unwrap();
        assert_eq!(&out[..copied], &[158, 4, 9, 9]);
        // Malformed lengths, oversize areas and short outputs are refused.
        for bytes in [&[7][..], &[131, 1], &[131, 9, 4, 0], &[1; 41]] {
            assert!(
                copied_fragment_options(bytes, &mut [0; 40]).is_err(),
                "{bytes:?}"
            );
        }
        assert_eq!(
            copied_fragment_options(&[131, 7, 4, 192, 0, 2, 3, 0], &mut [0; 7]),
            Err(Ipv4OptionsError::Capacity)
        );
    }

    struct Clock {
        sample: Option<Ipv4Timestamp>,
        calls: usize,
    }
    impl Ipv4TimestampProvider for Clock {
        fn ipv4_timestamp(&mut self) -> Option<Ipv4Timestamp> {
            self.calls += 1;
            self.sample
        }
    }
    fn provider(sample: Option<u32>) -> Clock {
        Clock {
            sample: sample.map(Ipv4Timestamp::nonstandard),
            calls: 0,
        }
    }

    #[test]
    fn provider_recording_samples_only_writable_timestamp_slots() {
        let rr = [7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        let recorded_rr = [7, 11, 8, 192, 0, 2, 2, 0, 0, 0, 0];
        // Record Route never depends on a timestamp.
        for sample in [None, Some(5)] {
            let mut clock = provider(sample);
            let parsed = Ipv4Options::parse(&rr, false).unwrap();
            let recorded = parsed.record_with(ip(2), &mut clock).unwrap();
            assert_eq!(recorded.as_bytes(), &recorded_rr);
            assert_eq!(clock.calls, 0);
        }
        for flag in [0u8, 1, 3] {
            let len = if flag == 0 { 8 } else { 12 };
            let mut ts = [0u8; 12];
            ts[..4].copy_from_slice(&[68, len, 5, flag]);
            if flag == 3 {
                ts[4..8].copy_from_slice(&ip(2).octets());
            }
            let ts = &ts[..usize::from(len)];
            let mut both = [0u8; 23];
            both[..11].copy_from_slice(&rr);
            both[11..11 + ts.len()].copy_from_slice(ts);
            let both = &both[..11 + ts.len()];
            let parsed = Ipv4Options::parse(both, false).unwrap();

            // A successful write samples once.
            let mut clock = provider(Some(7));
            let recorded = parsed.record_with(ip(2), &mut clock).unwrap();
            assert_eq!(clock.calls, 1);
            let out = recorded.as_bytes();
            assert_eq!(&out[..11], &recorded_rr);
            assert_eq!(out[13], len + 1);
            if flag != 0 {
                assert_eq!(&out[15..19], &ip(2).octets());
            }
            assert_eq!(&out[out.len() - 4..], &0x8000_0007u32.to_be_bytes());
            // The value adapter keeps the caller-asserted wire contract.
            assert_eq!(parsed.record(ip(2), 0x8000_0007).unwrap(), recorded);

            // No sample: slot and pointer preserved, RR still recorded.
            let mut clock = provider(None);
            let unsampled = parsed.record_with(ip(2), &mut clock).unwrap();
            assert_eq!(clock.calls, 1);
            assert_eq!(&unsampled.as_bytes()[..11], &recorded_rr);
            assert_eq!(&unsampled.as_bytes()[11..], ts);

            // A non-matching prespecified address is not sampled.
            if flag == 3 {
                let mut clock = provider(Some(7));
                let other = parsed.record_with(ip(3), &mut clock).unwrap();
                assert_eq!(clock.calls, 0);
                assert_eq!(&other.as_bytes()[3..7], &ip(3).octets());
                assert_eq!(&other.as_bytes()[11..], ts);
            }

            // A full area increments overflow once (14 -> 15) without sampling.
            let mut full = [0u8; 12];
            full[..usize::from(len)].copy_from_slice(ts);
            full[2] = len + 1;
            full[3] = 0xe0 | flag;
            let full = &full[..usize::from(len)];
            let mut clock = provider(Some(7));
            let advanced = Ipv4Options::parse(full, false)
                .unwrap()
                .record_with(ip(2), &mut clock)
                .unwrap();
            assert_eq!(clock.calls, 0);
            assert_eq!(advanced.as_bytes()[3], 0xf0 | flag);
            assert_eq!(&advanced.as_bytes()[4..], &full[4..]);

            // Exhausted overflow discards the datagram, again without sampling.
            let mut clock = provider(Some(7));
            assert_eq!(
                advanced.record_with(ip(2), &mut clock),
                Err(Ipv4OptionsError::Malformed)
            );
            assert_eq!(clock.calls, 0);
        }
        let mut clock = provider(Some(7));
        assert_eq!(
            Ipv4Options::parse(&rr, false)
                .unwrap()
                .record_with(Ipv4Addr::BROADCAST, &mut clock),
            Err(Ipv4OptionsError::InvalidAddress)
        );
        assert_eq!(clock.calls, 0);
    }

    #[test]
    fn every_kind_with_opaque_tlvs_is_retained_to_forty_octets() {
        // Completed LSRR, RR, TS, an opaque copied and a non-copied TLV: 40 octets.
        let mut raw = [0u8; 40];
        raw[..7].copy_from_slice(&[131, 7, 8, 192, 0, 2, 9]);
        raw[7..14].copy_from_slice(&[7, 7, 4, 0, 0, 0, 0]);
        raw[14..26].copy_from_slice(&[68, 12, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        raw[26..30].copy_from_slice(&[158, 4, 1, 2]);
        raw[30..32].copy_from_slice(&[30, 10]);
        raw[32..].fill(0xee);
        let parsed = Ipv4Options::parse(&raw, true).unwrap();
        assert_eq!(parsed.as_bytes(), &raw);
        assert_eq!(
            Ipv4Options::parse(&raw, false),
            Err(Ipv4OptionsError::SourceRouteDisabled)
        );
        let mut longer = [1u8; 41];
        longer[1..].copy_from_slice(&raw);
        assert_eq!(
            Ipv4Options::parse(&longer, true),
            Err(Ipv4OptionsError::Capacity)
        );
        let mut clock = provider(Some(1));
        let recorded = parsed.record_with(ip(2), &mut clock).unwrap();
        assert_eq!(clock.calls, 1);
        let out = recorded.as_bytes();
        assert_eq!(&out[..7], &raw[..7]);
        assert_eq!(&out[7..14], &[7, 7, 8, 192, 0, 2, 2]);
        assert_eq!(&out[14..22], &[68, 12, 9, 0, 0x80, 0, 0, 1]);
        assert_eq!(&out[22..], &raw[22..]);
        let mut copied = [0; 40];
        let n = copied_fragment_options(out, &mut copied).unwrap();
        assert_eq!(&copied[..n], &[131, 7, 8, 192, 0, 2, 9, 158, 4, 1, 2, 0]);
        // NOP and EOL are removed; every other option survives in order.
        let spaced = [
            1, 7, 3, 4, 1, 1, 68, 4, 5, 0, 1, 30, 2, 1, 158, 3, 7, 0, 158, 2,
        ];
        assert_eq!(
            Ipv4Options::parse(&spaced, false).unwrap().as_bytes(),
            &[7, 3, 4, 68, 4, 5, 0, 30, 2, 158, 3, 7]
        );
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
        assert_eq!(
            Ipv4Options::parse(&[30, 4, 99, 99, 1, 0, 255], true)
                .unwrap()
                .as_bytes(),
            &[30, 4, 99, 99]
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

    #[test]
    fn encoded_options_send_carried_options_as_is_behind_one_route() {
        // Processed RR (one recorded hop) and TS (a remote value no local
        // clock produced, beyond the UTC day): kept octet for octet.
        let carried = [
            7, 11, 8, 192, 0, 2, 7, 0, 0, 0, 0, 68, 12, 13, 1, 192, 0, 2, 8, 0x7f, 0xff, 0xff, 0xff,
        ];
        assert!(Ipv4Options::parse(&carried, false).is_ok());
        for strict in [false, true] {
            let route = SourceRoute::new(&[ip(3), ip(4)], strict).unwrap();
            let encoded = EncodedIpv4Options::new(Some(&route), ip(2), &carried).unwrap();
            assert_eq!(encoded.destination(), ip(3));
            assert_eq!(encoded.final_destination(), ip(2));
            let bytes = encoded.as_bytes();
            assert_eq!(bytes.len(), 36);
            let kind = if strict { 137 } else { 131 };
            assert_eq!(&bytes[..11], &[kind, 11, 4, 192, 0, 2, 4, 192, 0, 2, 2]);
            assert_eq!(&bytes[11..34], &carried);
            assert_eq!(&bytes[34..], &[0, 0]);
            // The same route as an originating host encodes it.
            let outgoing = OutgoingIpv4Options {
                source_route: Some(route),
                ..Default::default()
            };
            let mut out = [0; 40];
            let (first_hop, len) = outgoing.encode(ip(1), ip(2), 0, &mut out).unwrap();
            assert_eq!(first_hop, ip(3));
            assert_eq!(&out[..11], &bytes[..11]);
            assert_eq!(len, 12);
        }
        // Without a route (or with an empty one) the header names the final
        // destination; nothing at all is an empty area.
        let empty = SourceRoute::new(&[], true).unwrap();
        for route in [None, Some(&empty)] {
            let encoded = EncodedIpv4Options::new(route, ip(2), &carried).unwrap();
            assert_eq!(encoded.destination(), ip(2));
            assert_eq!(&encoded.as_bytes()[..23], &carried);
            assert_eq!(encoded.as_bytes().len(), 24);
            assert!(
                EncodedIpv4Options::new(route, ip(2), &[])
                    .unwrap()
                    .as_bytes()
                    .is_empty()
            );
        }
        // Nine hops fill 39 octets; padding makes 40, one more octet does not fit.
        let hops: [Ipv4Addr; 9] = core::array::from_fn(|i| ip(10 + i as u8));
        let nine = SourceRoute::new(&hops, false).unwrap();
        let encoded = EncodedIpv4Options::new(Some(&nine), ip(2), &[]).unwrap();
        assert_eq!(encoded.as_bytes().len(), 40);
        assert_eq!(encoded.as_bytes()[39], 0);
        assert_eq!(
            EncodedIpv4Options::new(Some(&nine), ip(2), &[68, 4, 5, 0]),
            Err(Ipv4OptionsError::Capacity)
        );
        // A one-hop completed route with a 31-octet RR, 38 admitted octets,
        // still fits after reversal.
        let mut admitted = [0u8; 38];
        admitted[..7].copy_from_slice(&[131, 7, 8, 192, 0, 2, 9]);
        admitted[7..10].copy_from_slice(&[7, 31, 32]);
        let parsed = Ipv4Options::parse(&admitted, true).unwrap();
        let reversed = parsed.return_route(ip(2)).unwrap();
        let encoded = EncodedIpv4Options::new(Some(&reversed), ip(2), &admitted[7..]).unwrap();
        assert_eq!(encoded.as_bytes().len(), 40);
        assert_eq!(encoded.destination(), ip(9));
        // Malformed carried areas: NOP, End, a source route, a cut TLV, a
        // bad pointer; oversized areas and non-unicast destinations.
        for bad in [
            &[1, 68, 4, 5, 0][..],
            &[68, 4, 5, 0, 0],
            &[131, 7, 8, 192, 0, 2, 9],
            &[137, 7, 4, 192, 0, 2, 9],
            &[7, 7, 4, 0],
            &[7, 7, 5, 0, 0, 0, 0],
        ] {
            assert_eq!(
                EncodedIpv4Options::new(None, ip(2), bad),
                Err(Ipv4OptionsError::Malformed),
                "{bad:?}"
            );
        }
        assert_eq!(
            EncodedIpv4Options::new(None, ip(2), &[30; 41]),
            Err(Ipv4OptionsError::Capacity)
        );
        assert_eq!(
            EncodedIpv4Options::new(None, Ipv4Addr::BROADCAST, &[]),
            Err(Ipv4OptionsError::InvalidAddress)
        );
    }

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(ip(n))
    }

    fn plan(
        options: OutgoingIpv4Options,
        expected: &ExpectedRegistrations<'_>,
    ) -> Result<Ipv4RegistrationPlan, Ipv4RegistrationError> {
        Ipv4RegistrationPlan::new(v4(1), v4(2), options, expected)
    }

    fn timestamp_capacity(request: TimestampRequest) -> (u8, usize) {
        match request {
            TimestampRequest::Times(n) => (n, 4),
            TimestampRequest::AddressTimes(n) | TimestampRequest::Prespecified { len: n, .. } => {
                (n, 8)
            }
        }
    }

    // Expectations equal to every requested capacity.
    fn exact<'a>(
        options: &OutgoingIpv4Options,
        prespecified: &'a [Ipv4Addr; 4],
    ) -> ExpectedRegistrations<'a> {
        ExpectedRegistrations {
            record_route: options.record_route_slots,
            timestamp: options.timestamp.map(|request| match request {
                TimestampRequest::Prespecified { len, .. } => {
                    ExpectedTimestamps::Prespecified(&prespecified[..usize::from(len).min(4)])
                }
                request => ExpectedTimestamps::Count(timestamp_capacity(request).0),
            }),
        }
    }

    #[test]
    fn plan_budget_fits_exactly_forty_padded_octets_with_every_combination() {
        let hops: [Ipv4Addr; 9] = core::array::from_fn(|i| ip(10 + i as u8));
        let addresses = [ip(1), ip(3), ip(4), ip(1)];
        let mut routes = [None; 21];
        for count in 0..=9 {
            for strict in [false, true] {
                routes[1 + count * 2 + usize::from(strict)] =
                    Some(SourceRoute::new(&hops[..count], strict).unwrap());
            }
        }
        let mut timestamps = [None; 21];
        for n in 1..=10 {
            timestamps[usize::from(n)] = Some(TimestampRequest::Times(n));
        }
        for n in 1..=5 {
            timestamps[10 + usize::from(n)] = Some(TimestampRequest::AddressTimes(n));
            timestamps[15 + usize::from(n)] =
                Some(TimestampRequest::Prespecified { addresses, len: n });
        }
        let mut smallest_over = usize::MAX;
        let mut largest_fit = 0;
        for source_route in routes {
            for record_route_slots in core::iter::once(None).chain((0..=10).map(Some)) {
                for timestamp in timestamps {
                    let options = OutgoingIpv4Options {
                        source_route,
                        record_route_slots,
                        timestamp,
                    };
                    let route = match source_route.map_or(0, |r| r.hops().len()) {
                        0 => 0,
                        n => 3 + 4 * n,
                    };
                    let rr = record_route_slots.map_or(0, |r| 3 + 4 * usize::from(r));
                    let ts = timestamp.map_or(0, |t| {
                        let (n, stride) = timestamp_capacity(t);
                        4 + stride * usize::from(n)
                    });
                    let unpadded = route + rr + ts;
                    let padded = unpadded.div_ceil(4) * 4;
                    let result = plan(options, &exact(&options, &addresses));
                    let mut raw = [0xa5; 40];
                    let raw_result = options.encode(ip(1), ip(2), 0x8000_0007, &mut raw);
                    if padded > 40 {
                        smallest_over = smallest_over.min(unpadded);
                        assert_eq!(
                            result,
                            Err(Ipv4RegistrationError::CombinedCapacity {
                                required_octets: padded,
                                maximum: 40,
                            }),
                            "{options:?}"
                        );
                        assert!(raw_result.is_err(), "{options:?}");
                        continue;
                    }
                    largest_fit = largest_fit.max(unpadded);
                    let plan = result.unwrap();
                    assert_eq!(plan.option_octets(), padded);
                    assert_eq!(plan.options(), &options);
                    let mut out = [0xa5; 40];
                    let mut clock = provider(Some(7));
                    let (destination, len) = plan
                        .options()
                        .encode_with(ip(1), ip(2), &mut clock, &mut out)
                        .unwrap();
                    assert_eq!(len, padded);
                    assert!(out[padded..].iter().all(|&b| b == 0xa5));
                    assert!(out[unpadded..padded].iter().all(|&b| b == 0));
                    // The low-level encoder agrees octet for octet.
                    assert_eq!(raw_result, Ok((destination, len)));
                    assert_eq!(raw[..len], out[..len]);
                    let first_hop = source_route.and_then(|r| r.hops().first().copied());
                    assert_eq!(destination, first_hop.unwrap_or(ip(2)));
                }
            }
        }
        // Option sizes are 3 or 0 modulo 4, so 41 unpadded octets are not
        // attainable: the smallest overflow is a nonempty route with Record
        // Route (6 + 4k = 42), one record beyond 38.
        assert_eq!((largest_fit, smallest_over), (40, 42));
    }

    #[test]
    fn plan_boundaries_one_record_over_and_padding() {
        let ok = |options: OutgoingIpv4Options| {
            plan(options, &exact(&options, &[ip(1); 4])).map(|plan| plan.option_octets())
        };
        let over = |required_octets| {
            Err(Ipv4RegistrationError::CombinedCapacity {
                required_octets,
                maximum: 40,
            })
        };
        let route = |n: usize, strict| Some(SourceRoute::new(&[ip(3); 9][..n], strict).unwrap());
        let rr = |slots| OutgoingIpv4Options {
            record_route_slots: Some(slots),
            ..Default::default()
        };
        // 39 octets pad to 40; one more record needs 43, padded 44.
        assert_eq!(ok(rr(9)), Ok(40));
        assert_eq!(ok(rr(10)), over(44));
        // Flag 0 fills exactly 40 unpadded octets; one more record is 44.
        let times = |n| OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::Times(n)),
            ..Default::default()
        };
        assert_eq!(ok(times(9)), Ok(40));
        assert_eq!(ok(times(10)), over(44));
        // Flags 1 and 3: four address/time pairs are 36 octets, five 44.
        for request in [
            TimestampRequest::AddressTimes(4),
            TimestampRequest::Prespecified {
                addresses: [ip(1); 4],
                len: 4,
            },
        ] {
            let mut options = OutgoingIpv4Options {
                timestamp: Some(request),
                ..Default::default()
            };
            assert_eq!(ok(options), Ok(36));
            options.timestamp = Some(match request {
                TimestampRequest::AddressTimes(_) => TimestampRequest::AddressTimes(5),
                _ => TimestampRequest::Prespecified {
                    addresses: [ip(1); 4],
                    len: 5,
                },
            });
            assert_eq!(ok(options), over(44));
        }
        for strict in [false, true] {
            // Route 7 + RR 11 + TS 20 = 38, padded 40; one more of either record is 42.
            let mut options = OutgoingIpv4Options {
                source_route: route(1, strict),
                record_route_slots: Some(2),
                timestamp: Some(TimestampRequest::Times(4)),
            };
            assert_eq!(ok(options), Ok(40));
            options.record_route_slots = Some(3);
            assert_eq!(ok(options), over(44));
            options.record_route_slots = Some(2);
            options.timestamp = Some(TimestampRequest::Times(5));
            assert_eq!(ok(options), over(44));
            // Route 11 + RR 27 = 38 pads to 40; one more hop or record is 42.
            let mut options = OutgoingIpv4Options {
                source_route: route(2, strict),
                record_route_slots: Some(6),
                timestamp: None,
            };
            assert_eq!(ok(options), Ok(40));
            options.source_route = route(3, strict);
            assert_eq!(ok(options), over(44));
            options.source_route = route(2, strict);
            options.record_route_slots = Some(7);
            assert_eq!(ok(options), over(44));
            // Nine hops fill 39 octets and leave no room for any record.
            options.source_route = route(9, strict);
            options.record_route_slots = None;
            assert_eq!(ok(options), Ok(40));
            options.record_route_slots = Some(0);
            assert_eq!(ok(options), over(44));
        }
        // An absent and an explicitly empty source route both take 0 octets.
        for source_route in [None, route(0, true), route(0, false)] {
            let options = OutgoingIpv4Options {
                source_route,
                record_route_slots: Some(3),
                timestamp: Some(TimestampRequest::Times(3)),
            };
            // RR 15 + TS 16 = 31, padded 32: three records each.
            assert_eq!(ok(options), Ok(32));
            // Addressed TS with three RR records needs 15 + 28 = 43, padded 44.
            let options = OutgoingIpv4Options {
                timestamp: Some(TimestampRequest::AddressTimes(3)),
                ..options
            };
            assert_eq!(ok(options), over(44));
        }
        // Without RR or TS a plan is just the route; nothing at all is empty.
        assert_eq!(ok(OutgoingIpv4Options::default()), Ok(0));
        assert_eq!(
            ok(OutgoingIpv4Options {
                source_route: route(2, false),
                ..Default::default()
            }),
            Ok(12)
        );
    }

    #[test]
    fn plan_refuses_insufficient_records_per_option() {
        use Ipv4RegistrationError::InsufficientRecords;
        use RegisteredOption::*;
        let insufficient = |option, expected, available| {
            Err(InsufficientRecords {
                option,
                expected,
                available,
            })
        };
        let route = Some(SourceRoute::new(&[ip(3)], true).unwrap());
        let options = OutgoingIpv4Options {
            source_route: route,
            record_route_slots: Some(2),
            timestamp: Some(TimestampRequest::Times(2)),
        };
        let expect = |rr, ts| ExpectedRegistrations {
            record_route: Some(rr),
            timestamp: Some(ExpectedTimestamps::Count(ts)),
        };
        // Capacity may exceed the expectation, never fall short.
        for (rr, ts) in [(0, 0), (1, 2), (2, 1), (2, 2)] {
            assert_eq!(plan(options, &expect(rr, ts)).unwrap().option_octets(), 32);
        }
        assert_eq!(
            plan(options, &expect(3, 2)),
            insufficient(RecordRoute, 3, 2)
        );
        assert_eq!(plan(options, &expect(2, 3)), insufficient(Timestamp, 3, 2));
        let addressed = OutgoingIpv4Options {
            timestamp: Some(TimestampRequest::AddressTimes(2)),
            ..options
        };
        assert_eq!(plan(addressed, &expect(2, 2)).unwrap().option_octets(), 40);
        assert_eq!(
            plan(addressed, &expect(2, 3)),
            insufficient(Timestamp, 3, 2)
        );
        // A zero-slot Record Route holds no registration.
        let empty_rr = OutgoingIpv4Options {
            record_route_slots: Some(0),
            timestamp: None,
            ..options
        };
        let rr_only = |rr| ExpectedRegistrations {
            record_route: Some(rr),
            timestamp: None,
        };
        assert_eq!(plan(empty_rr, &rr_only(0)).unwrap().option_octets(), 12);
        assert_eq!(plan(empty_rr, &rr_only(1)), insufficient(RecordRoute, 1, 0));
        // Expected registrations for an option that is not requested.
        let none = OutgoingIpv4Options {
            source_route: route,
            ..Default::default()
        };
        assert_eq!(plan(none, &rr_only(1)), insufficient(RecordRoute, 1, 0));
        fn ts_only(timestamp: ExpectedTimestamps<'_>) -> ExpectedRegistrations<'_> {
            ExpectedRegistrations {
                record_route: None,
                timestamp: Some(timestamp),
            }
        }
        assert_eq!(
            plan(none, &ts_only(ExpectedTimestamps::Count(1))),
            insufficient(Timestamp, 1, 0)
        );
        assert_eq!(
            plan(none, &ts_only(ExpectedTimestamps::Prespecified(&[ip(1)]))),
            insufficient(Timestamp, 1, 0)
        );
        // Stating zero registrations of an absent option is consistent.
        assert!(plan(none, &expect(0, 0)).is_ok());
        assert!(plan(none, &ts_only(ExpectedTimestamps::Prespecified(&[]))).is_ok());
        // Ten expected registrations exceed what any 40-octet option holds.
        let full = OutgoingIpv4Options {
            source_route: None,
            record_route_slots: Some(9),
            timestamp: None,
        };
        assert_eq!(plan(full, &rr_only(10)), insufficient(RecordRoute, 10, 9));
    }

    #[test]
    fn plan_prespecified_addresses_missing_expectations_and_family() {
        use Ipv4RegistrationError::*;
        let addresses = [ip(1), ip(3), ip(1), ip(4)];
        let options = OutgoingIpv4Options {
            source_route: Some(SourceRoute::new(&[], false).unwrap()),
            record_route_slots: None,
            timestamp: Some(TimestampRequest::Prespecified { addresses, len: 3 }),
        };
        fn visits(visits: &[Ipv4Addr]) -> ExpectedRegistrations<'_> {
            ExpectedRegistrations {
                record_route: None,
                timestamp: Some(ExpectedTimestamps::Prespecified(visits)),
            }
        }
        // The expected ordered visits, repeated ones included, begin the list.
        for n in 0..=3 {
            assert_eq!(
                plan(options, &visits(&addresses[..n]))
                    .unwrap()
                    .option_octets(),
                28
            );
        }
        assert_eq!(
            plan(options, &visits(&addresses)),
            Err(InsufficientRecords {
                option: RegisteredOption::Timestamp,
                expected: 4,
                available: 3,
            })
        );
        // A module registers only at the next prespecified address.
        assert_eq!(
            plan(options, &visits(&[ip(1), ip(1)])),
            Err(InvalidPrespecifiedAddress { index: 1 })
        );
        assert_eq!(
            plan(options, &visits(&[ip(3)])),
            Err(InvalidPrespecifiedAddress { index: 0 })
        );
        // Requested addresses must be unicast; entries beyond `len` are unused.
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let mut addresses = addresses;
            addresses[2] = bad;
            let request = |len| OutgoingIpv4Options {
                timestamp: Some(TimestampRequest::Prespecified { addresses, len }),
                ..options
            };
            assert_eq!(
                plan(request(3), &visits(&addresses[..2])),
                Err(InvalidPrespecifiedAddress { index: 2 })
            );
            assert!(plan(request(2), &visits(&addresses[..2])).is_ok());
        }
        // Requested options without an expectation in the form they need.
        let rr = OutgoingIpv4Options {
            record_route_slots: Some(1),
            timestamp: None,
            ..options
        };
        let missing = |option| Err(MissingExpectation { option });
        assert_eq!(
            plan(rr, &ExpectedRegistrations::default()),
            missing(RegisteredOption::RecordRoute)
        );
        assert_eq!(
            plan(options, &ExpectedRegistrations::default()),
            missing(RegisteredOption::Timestamp)
        );
        let count = ExpectedRegistrations {
            record_route: None,
            timestamp: Some(ExpectedTimestamps::Count(1)),
        };
        assert_eq!(plan(options, &count), missing(RegisteredOption::Timestamp));
        for request in [
            TimestampRequest::Times(2),
            TimestampRequest::AddressTimes(2),
        ] {
            let options = OutgoingIpv4Options {
                timestamp: Some(request),
                ..options
            };
            assert!(plan(options, &count).is_ok());
            assert_eq!(
                plan(options, &visits(&[ip(1)])),
                missing(RegisteredOption::Timestamp)
            );
        }
        // IPv4 options exist only between IPv4 endpoints.
        let v6 = IpAddr::V6(core::net::Ipv6Addr::LOCALHOST);
        let mapped = IpAddr::V6(ip(2).to_ipv6_mapped());
        let expected = visits(&addresses[..1]);
        for (local, remote) in [(v6, v4(2)), (v4(1), v6), (v6, v6), (v4(1), mapped)] {
            assert_eq!(
                Ipv4RegistrationPlan::new(local, remote, options, &expected),
                Err(WrongFamily)
            );
            assert_eq!(
                Ipv4RegistrationPlan::new(local, remote, OutgoingIpv4Options::default(), &expected),
                Err(WrongFamily)
            );
        }
        for (local, remote) in [
            (Ipv4Addr::BROADCAST, ip(2)),
            (ip(1), Ipv4Addr::UNSPECIFIED),
            (ip(1), Ipv4Addr::new(224, 0, 0, 1)),
        ] {
            assert_eq!(
                Ipv4RegistrationPlan::new(local.into(), remote.into(), options, &expected),
                Err(Options(Ipv4OptionsError::InvalidAddress))
            );
        }
        // A Timestamp option needs at least one slot.
        for request in [
            TimestampRequest::Times(0),
            TimestampRequest::AddressTimes(0),
            TimestampRequest::Prespecified { addresses, len: 0 },
        ] {
            let options = OutgoingIpv4Options {
                timestamp: Some(request),
                ..options
            };
            assert_eq!(
                plan(options, &visits(&[])),
                Err(Options(Ipv4OptionsError::Malformed))
            );
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# A recorded route is composed of a series of internet addresses. Each
    //# internet address is 32 bits or 4 octets. If the pointer is greater than
    //# the length, the recorded route data area is full. The originating host
    //# must compose this option with a large enough route data area to hold all
    //# the address expected. The size of the option does not change due to
    //# adding addresses. The intitial contents of the route data area must be
    //# zero.

    //= https://www.rfc-editor.org/rfc/rfc791#section-3.1
    //= type=test
    //# The originating host must compose this option with a large enough
    //# timestamp data area to hold all the timestamp information expected. The
    //# size of the option does not change due to adding timestamps. The
    //# intitial contents of the timestamp data area must be zero or internet
    //# address/zero pairs.
    #[test]
    fn plan_initializes_fixed_size_area_before_origin_recording() {
        let route = SourceRoute::new(&[ip(3)], false).unwrap();
        for (request, flag, stride) in [
            (TimestampRequest::Times(3), 0, 4),
            (TimestampRequest::AddressTimes(2), 1, 8),
            (
                TimestampRequest::Prespecified {
                    addresses: [ip(1), ip(5), ip(2), ip(6)],
                    len: 2,
                },
                3,
                8,
            ),
            (
                TimestampRequest::Prespecified {
                    addresses: [ip(5), ip(1), ip(2), ip(6)],
                    len: 2,
                },
                3,
                8,
            ),
        ] {
            let options = OutgoingIpv4Options {
                source_route: Some(route),
                record_route_slots: Some(2),
                timestamp: Some(request),
            };
            let prespecified = match request {
                TimestampRequest::Prespecified { addresses, .. } => addresses,
                _ => [ip(1); 4],
            };
            let plan = plan(options, &exact(&options, &prespecified)).unwrap();
            // Before origin recording: route, zeroed RR, zeroed or
            // address/zero TS slots, pointers at their first slot.
            let mut initialized = [0xa5; 40];
            let (_, route_len, len) = options.initialize(ip(2), &mut initialized).unwrap();
            assert_eq!(route_len, 7);
            assert_eq!(&initialized[..7], &[131, 7, 4, 192, 0, 2, 2]);
            assert_eq!(&initialized[7..18], &[7, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
            let ts_len = len - 18;
            assert_eq!(&initialized[18..22], &[68, ts_len as u8, 5, flag]);
            for (i, slot) in initialized[22..len].chunks_exact(stride).enumerate() {
                let address = if flag == 3 {
                    &prespecified[i].octets()[..]
                } else {
                    &[0; 4]
                };
                assert_eq!(&slot[..stride - 4], &address[..stride - 4]);
                assert_eq!(&slot[stride - 4..], &[0; 4]);
            }
            assert!(initialized[len..].iter().all(|&b| b == 0));
            assert_eq!(plan.option_octets(), (len + 3) & !3);

            // Origin recording writes into that area without resizing it,
            // sampling only for a slot the origin may write.
            let writes = flag != 3 || prespecified[0] == ip(1);
            for sample in [Some(9), None] {
                let mut clock = provider(sample);
                let mut out = [0xa5; 40];
                let (destination, octets) = plan
                    .options()
                    .encode_with(ip(1), ip(2), &mut clock, &mut out)
                    .unwrap();
                assert_eq!((destination, octets), (ip(3), plan.option_octets()));
                assert_eq!(clock.calls, usize::from(writes));
                assert_eq!(&out[..7], &initialized[..7]);
                assert_eq!(&out[7..18], &[7, 11, 8, 192, 0, 2, 1, 0, 0, 0, 0]);
                let mut expected = initialized;
                if writes && sample.is_some() {
                    expected[20] += stride as u8;
                    if flag == 1 {
                        expected[22..26].copy_from_slice(&ip(1).octets());
                    }
                    expected[18 + stride..22 + stride]
                        .copy_from_slice(&0x8000_0009u32.to_be_bytes());
                }
                assert_eq!(&out[18..octets], &expected[18..octets]);
                assert!(out[octets..].iter().all(|&b| b == 0xa5));
                let mut short = provider(sample);
                assert_eq!(
                    plan.options()
                        .encode_with(ip(1), ip(2), &mut short, &mut out[..octets - 1]),
                    Err(Ipv4OptionsError::Capacity)
                );
                // An area that cannot be written samples nothing.
                assert_eq!(short.calls, 0);

                // Downstream registrations fill the area, never resize it.
                let mut received = Ipv4Options::parse(&out[7..len], false).unwrap();
                for _ in 0..4 {
                    received = received.record(ip(2), 0x8000_0001).unwrap();
                    assert_eq!(received.as_bytes().len(), len - 7);
                    assert_eq!(&received.as_bytes()[..2], &[7, 11]);
                    assert_eq!(&received.as_bytes()[11..13], &[68, ts_len as u8]);
                }
                let bytes = received.as_bytes();
                // Record Route is full: its pointer is one past its length.
                assert_eq!(bytes[2], 12);
                if flag != 3 {
                    assert_eq!(bytes[13], ts_len as u8 + 1);
                    assert!(bytes[14] >> 4 > 0);
                }
            }
        }
    }

    #[test]
    fn plan_output_keeps_fragment_copy_rules() {
        for strict in [false, true] {
            let options = OutgoingIpv4Options {
                source_route: Some(SourceRoute::new(&[ip(3), ip(4)], strict).unwrap()),
                record_route_slots: Some(2),
                timestamp: Some(TimestampRequest::Times(2)),
            };
            let plan = plan(options, &exact(&options, &[ip(1); 4])).unwrap();
            let mut encoded = [0; 40];
            let (_, len) = plan
                .options()
                .encode_with(ip(1), ip(2), &mut provider(Some(7)), &mut encoded)
                .unwrap();
            let mut out = [0xa5; 40];
            // Only the copied source route reaches later fragments.
            assert_eq!(copied_fragment_options(&encoded[..len], &mut out), Ok(12));
            assert_eq!(&out[..11], &encoded[..11]);
            assert_eq!(out[11], 0);
        }
        let options = OutgoingIpv4Options {
            source_route: None,
            record_route_slots: Some(3),
            timestamp: Some(TimestampRequest::Times(3)),
        };
        let plan = plan(options, &exact(&options, &[ip(1); 4])).unwrap();
        let mut encoded = [0; 40];
        let (_, len) = plan
            .options()
            .encode_with(ip(1), ip(2), &mut provider(Some(7)), &mut encoded)
            .unwrap();
        assert_eq!(len, 32);
        assert_eq!(copied_fragment_options(&encoded[..len], &mut []), Ok(0));
    }
}
