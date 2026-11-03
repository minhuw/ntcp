//! Versioned, length-prefixed binary protocol of the local path control
//! socket. Every frame is a big-endian `u32` body length followed by the
//! body; every field has a fixed width, so each request and each response
//! has an exact encoded size and every bound below is derived from the
//! largest encoded message rather than chosen.
//!
//! Request body: `version u8, opcode u8, fields`. Response body:
//! `version u8, status u8, opcode u8, payload` (payload only for `Ok`).
//! Identifiers are opaque 64-bit tokens the server issues per process
//! instance; they are provenance, never authority (authority is the peer's
//! kernel-supplied credential, checked before dispatch).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const VERSION: u8 = 1;
/// The big-endian body length that precedes every frame.
pub const LENGTH_PREFIX: usize = 4;

pub mod opcode {
    pub const QUERY_ROUTES: u8 = 1;
    pub const QUERY_PATHS: u8 = 2;
    pub const QUERY_CLIENTS: u8 = 3;
    pub const SELECT_ROUTE: u8 = 4;
    pub const SET_ROUTE_POLICY: u8 = 5;
    pub const SET_PATH_POLICY: u8 = 6;
    pub const GET_PLATEAUS: u8 = 7;
    pub const SET_PLATEAUS: u8 = 8;
    pub const GET_AGING: u8 = 9;
    pub const SET_AGING: u8 = 10;
}

/// Response status. Every status but `Ok` means nothing changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// The body does not have the exact size or field values of its opcode.
    Malformed = 1,
    UnknownVersion = 2,
    UnknownOpcode = 3,
    /// The announced body exceeds the largest request; the connection closes.
    Oversized = 4,
    /// The peer's credentials are not on the allow-list (or unavailable).
    Unauthorized = 5,
    /// A compare-and-set named a generation or target incarnation that is no
    /// longer current.
    Stale = 6,
    NotFound = 7,
    /// A selector (or an identifier token) matched more than one object.
    Ambiguous = 8,
    /// A paginated continuation named a revision the listing no longer has.
    Inconsistent = 9,
    /// A value the Host rejects (estimate, plateau table, aging bound).
    Invalid = 10,
    /// Administrative storage, revisions or allocation are exhausted.
    Capacity = 11,
    /// Every peer slot is in use, or a reservation cannot be withdrawn
    /// now; retry later.
    Busy = 12,
    /// Another Host failure; nothing changed.
    Failed = 13,
}

impl Status {
    pub fn from_u8(value: u8) -> Option<Self> {
        use Status::*;
        Some(match value {
            0 => Ok,
            1 => Malformed,
            2 => UnknownVersion,
            3 => UnknownOpcode,
            4 => Oversized,
            5 => Unauthorized,
            6 => Stale,
            7 => NotFound,
            8 => Ambiguous,
            9 => Inconsistent,
            10 => Invalid,
            11 => Capacity,
            12 => Busy,
            13 => Failed,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        use Status::*;
        match self {
            Ok => "ok",
            Malformed => "malformed",
            UnknownVersion => "unknown-version",
            UnknownOpcode => "unknown-opcode",
            Oversized => "oversized",
            Unauthorized => "unauthorized",
            Stale => "stale",
            NotFound => "not-found",
            Ambiguous => "ambiguous",
            Inconsistent => "inconsistent",
            Invalid => "invalid",
            Capacity => "capacity",
            Busy => "busy",
            Failed => "failed",
        }
    }
}

/// Complete administrative policy of one target (compare-and-set replaces
/// all of it; the empty policy clears it).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Policy {
    pub discovery_disabled: bool,
    pub estimate: Option<u32>,
}

/// Source of an effective constraint: route, exact path or both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Source {
    Route = 1,
    Path = 2,
    RouteAndPath = 3,
}

/// Provenance of a path's accepted network estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Provenance {
    Unlearned = 1,
    Learned = 2,
    OwnerTrustedApplication = 3,
    Administrative = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    pub network: IpAddr,
    pub length: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextHop {
    OnLink,
    Gateway(IpAddr),
    Forwarder(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Aging {
    /// No owner value: each connection keeps its creation policy.
    Unset,
    Infinity,
    Seconds(u64),
}

/// IPv4 plateau table: at most `PLATEAUS` values.
pub const PLATEAUS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plateaus {
    pub values: [u32; PLATEAUS],
    pub len: u8,
}

impl Plateaus {
    pub fn new(values: &[u32]) -> Option<Self> {
        if values.is_empty() || values.len() > PLATEAUS {
            return None;
        }
        let mut table = Self {
            values: [0; PLATEAUS],
            len: values.len() as u8,
        };
        table.values[..values.len()].copy_from_slice(values);
        Some(table)
    }
    pub fn as_slice(&self) -> &[u32] {
        &self.values[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    QueryRoutes {
        cursor: u32,
        revision: u64,
    },
    QueryPaths {
        cursor: u32,
        revision: u64,
    },
    QueryClients {
        path: u64,
        cursor: u32,
        revision: u64,
    },
    SelectRoute {
        destination: Prefix,
    },
    SetRoutePolicy {
        route: u64,
        expected: u64,
        policy: Policy,
    },
    SetPathPolicy {
        path: u64,
        expected: u64,
        policy: Policy,
    },
    GetPlateaus,
    SetPlateaus(Plateaus),
    GetAging,
    SetAging(Aging),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    pub token: u64,
    /// Policy generation (compare-and-set `expected`; 0 = never set).
    pub generation: u64,
    pub destination: Prefix,
    pub source: Option<Prefix>,
    pub dscp: Option<u8>,
    pub link: u64,
    pub next_hop: NextHop,
    pub metric: u32,
    pub policy: Policy,
}

/// One resolved path: identity, generations, policy, and the three values
/// reported separately (cached administrative estimate, accepted network
/// estimate with the shared packet budget, and, per client through
/// `QueryClients`, usable sizes and transport ceilings).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEntry {
    pub token: u64,
    pub generation: u64,
    /// Path snapshot version (advances on every change clients see).
    pub version: u64,
    pub valid: bool,
    pub route: u64,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub forwarding: IpAddr,
    pub dscp: u8,
    pub pins: u32,
    pub policy: Policy,
    pub route_policy: Option<Policy>,
    pub discovery_disabled: Option<Source>,
    /// Cached administrative estimate (route and path intersected).
    pub estimate: Option<(u32, Source)>,
    /// Accepted network estimate and its provenance (None once invalidated).
    pub accepted: Option<(u32, Provenance)>,
    pub first_hop: u32,
    pub learned: Option<u32>,
    pub restriction: Option<u32>,
    /// Effective shared IP packet budget every client sizes with.
    pub budget: Option<u32>,
    pub retry_not_before: u64,
    pub negative_revision: u64,
    pub discovery_revision: u64,
    pub clients: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClientKind {
    Tcp = 1,
    Udp = 2,
    OutputLease = 3,
    Adjunct = 4,
    Echo = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transport {
    pub peer_mss: u16,
    pub user_mss: Option<u16>,
    pub local_mss: u16,
    pub allocation: u32,
    pub send_ip_payload_limit: u16,
    pub destination_mtu: Option<u32>,
    pub effective_mss: u32,
}

/// Deferred or clipped growth toward the administrative estimate. Reason
/// codes: deferral 1 hold, 2 cooldown, 3 loss recovery, 4 data or window,
/// 5 discovery disabled; clip 1 search high, 2 transport, 3 search low.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Search {
    Pending {
        target: u32,
        deferred: Option<u8>,
    },
    Attempted {
        target: u32,
        size: u32,
        clipped: Option<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientEntry {
    pub kind: ClientKind,
    /// Opaque client token; for the Echo service, its queued message count.
    pub id: u64,
    pub usable_ip_packet: Option<u32>,
    pub transport: Option<Transport>,
    pub search: Option<Search>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageHeader {
    /// Digest of the complete listing; a continuation must repeat it.
    pub revision: u64,
    pub total: u32,
    pub cursor: u32,
    pub count: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    None,
    Routes(PageHeader, Vec<RouteEntry>),
    Paths(PageHeader, Vec<PathEntry>),
    Clients(PageHeader, Vec<ClientEntry>),
    Selected { route: u64 },
    Applied { generation: u64, affected: u32 },
    Plateaus(Plateaus),
    Aging(Aging),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: Status,
    pub opcode: u8,
    pub payload: Payload,
}

// Field widths.
const ADDRESS: usize = 1 + 16;
const PREFIX: usize = ADDRESS + 1;
const POLICY: usize = 1 + 4;
const QUERY: usize = 4 + 8;

pub const ROUTE_ENTRY: usize = 8 + 8 + PREFIX + PREFIX + 1 + 8 + ADDRESS + 4 + POLICY;
pub const PATH_ENTRY: usize = 8
    + 8
    + 8
    + 1
    + 8
    + 3 * ADDRESS
    + 1
    + 4
    + POLICY
    + (1 + POLICY)
    + 1
    + (4 + 1)
    + (4 + 1)
    + 4 * 4
    + 3 * 8
    + 2;
const TRANSPORT: usize = 1 + 2 + 2 + 2 + 4 + 2 + 4 + 4;
const SEARCH: usize = 1 + 4 + 4 + 1;
pub const CLIENT_ENTRY: usize = 1 + 8 + 4 + TRANSPORT + SEARCH;
const PLATEAU_TABLE: usize = 1 + 4 * PLATEAUS;

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Largest request body: `SetPlateaus` (the full plateau table).
pub const MAX_REQUEST_BODY: usize = 2 + max(
    max(8 + QUERY, PREFIX),
    max(8 + 8 + POLICY, max(PLATEAU_TABLE, 1 + 8)),
);
pub const MAX_REQUEST_FRAME: usize = LENGTH_PREFIX + MAX_REQUEST_BODY;

/// Operational budget of one response page: 4096 octets, one page of
/// memory and one nonblocking write into a Unix stream socket's default
/// send buffer, so a reply normally leaves in a single call and a slot's
/// reply buffer stays small. Page sizes follow from the entry sizes.
pub const PAGE_BUDGET: usize = 4096;
const RESPONSE_HEADER: usize = 3;
const PAGE_HEADER: usize = 8 + 4 + 4 + 1;
const PAGE_ROOM: usize = PAGE_BUDGET - LENGTH_PREFIX - RESPONSE_HEADER - PAGE_HEADER;
pub const ROUTES_PER_PAGE: usize = PAGE_ROOM / ROUTE_ENTRY;
pub const PATHS_PER_PAGE: usize = PAGE_ROOM / PATH_ENTRY;
pub const CLIENTS_PER_PAGE: usize = PAGE_ROOM / CLIENT_ENTRY;
/// Largest response body: a full page of the largest listing (larger than
/// the plateau table and every fixed reply).
pub const MAX_RESPONSE_BODY: usize = RESPONSE_HEADER
    + max(
        PAGE_HEADER
            + max(
                ROUTES_PER_PAGE * ROUTE_ENTRY,
                max(PATHS_PER_PAGE * PATH_ENTRY, CLIENTS_PER_PAGE * CLIENT_ENTRY),
            ),
        max(PLATEAU_TABLE, 8 + 4),
    );
pub const MAX_RESPONSE_FRAME: usize = LENGTH_PREFIX + MAX_RESPONSE_BODY;

/// Why a request body could not be decoded; each maps to a status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    UnknownVersion,
    UnknownOpcode(u8),
    Malformed(u8),
}

impl DecodeError {
    pub fn status(self) -> (Status, u8) {
        match self {
            Self::UnknownVersion => (Status::UnknownVersion, 0),
            Self::UnknownOpcode(op) => (Status::UnknownOpcode, op),
            Self::Malformed(op) => (Status::Malformed, op),
        }
    }
}

pub(crate) struct Writer<'a> {
    bytes: &'a mut Vec<u8>,
}

impl Writer<'_> {
    fn u8(&mut self, v: u8) {
        self.bytes.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes.extend_from_slice(&v.to_be_bytes());
    }
    fn address(&mut self, a: Option<IpAddr>) {
        let mut field = [0u8; 16];
        match a {
            None => self.u8(0),
            Some(IpAddr::V4(v)) => {
                self.u8(4);
                field[..4].copy_from_slice(&v.octets());
            }
            Some(IpAddr::V6(v)) => {
                self.u8(6);
                field = v.octets();
            }
        }
        self.bytes.extend_from_slice(&field);
    }
    fn prefix(&mut self, p: Option<Prefix>) {
        self.address(p.map(|p| p.network));
        self.u8(p.map_or(0, |p| p.length));
    }
    fn policy(&mut self, p: Policy) {
        self.u8(u8::from(p.discovery_disabled) | (u8::from(p.estimate.is_some()) << 1));
        self.u32(p.estimate.unwrap_or(0));
    }
    fn page(&mut self, h: PageHeader) {
        self.u64(h.revision);
        self.u32(h.total);
        self.u32(h.cursor);
        self.u8(h.count);
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.bytes.split_first_chunk::<N>()?;
        self.bytes = rest;
        Some(*head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_be_bytes)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_be_bytes)
    }
    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_be_bytes)
    }
    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    fn address(&mut self) -> Option<Option<IpAddr>> {
        let family = self.u8()?;
        let field: [u8; 16] = self.take()?;
        match family {
            0 if field == [0; 16] => Some(None),
            4 if field[4..] == [0; 12] => Some(Some(IpAddr::V4(Ipv4Addr::new(
                field[0], field[1], field[2], field[3],
            )))),
            6 => Some(Some(IpAddr::V6(Ipv6Addr::from(field)))),
            _ => None,
        }
    }
    fn some_address(&mut self) -> Option<IpAddr> {
        self.address()?
    }
    fn prefix(&mut self) -> Option<Option<Prefix>> {
        let network = self.address()?;
        let length = self.u8()?;
        match network {
            None if length == 0 => Some(None),
            Some(network) => Some(Some(Prefix { network, length })),
            None => None,
        }
    }
    fn policy(&mut self) -> Option<Policy> {
        let flags = self.u8()?;
        let estimate = self.u32()?;
        if flags & !3 != 0 || (flags & 2 == 0 && estimate != 0) {
            return None;
        }
        Some(Policy {
            discovery_disabled: flags & 1 != 0,
            estimate: (flags & 2 != 0).then_some(estimate),
        })
    }
    fn nonzero(&mut self) -> Option<Option<u32>> {
        let v = self.u32()?;
        Some((v != 0).then_some(v))
    }
    fn page(&mut self) -> Option<PageHeader> {
        Some(PageHeader {
            revision: self.u64()?,
            total: self.u32()?,
            cursor: self.u32()?,
            count: self.u8()?,
        })
    }
    fn finish<T>(&self, value: T) -> Option<T> {
        self.bytes.is_empty().then_some(value)
    }
}

/// Encode a request as a complete frame.
pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_REQUEST_FRAME);
    bytes.extend_from_slice(&[0; LENGTH_PREFIX]);
    let mut w = Writer { bytes: &mut bytes };
    w.u8(VERSION);
    match *request {
        Request::QueryRoutes { cursor, revision } => {
            w.u8(opcode::QUERY_ROUTES);
            w.u32(cursor);
            w.u64(revision);
        }
        Request::QueryPaths { cursor, revision } => {
            w.u8(opcode::QUERY_PATHS);
            w.u32(cursor);
            w.u64(revision);
        }
        Request::QueryClients {
            path,
            cursor,
            revision,
        } => {
            w.u8(opcode::QUERY_CLIENTS);
            w.u64(path);
            w.u32(cursor);
            w.u64(revision);
        }
        Request::SelectRoute { destination } => {
            w.u8(opcode::SELECT_ROUTE);
            w.prefix(Some(destination));
        }
        Request::SetRoutePolicy {
            route,
            expected,
            policy,
        } => {
            w.u8(opcode::SET_ROUTE_POLICY);
            w.u64(route);
            w.u64(expected);
            w.policy(policy);
        }
        Request::SetPathPolicy {
            path,
            expected,
            policy,
        } => {
            w.u8(opcode::SET_PATH_POLICY);
            w.u64(path);
            w.u64(expected);
            w.policy(policy);
        }
        Request::GetPlateaus => w.u8(opcode::GET_PLATEAUS),
        Request::SetPlateaus(table) => {
            w.u8(opcode::SET_PLATEAUS);
            plateaus(&mut w, table);
        }
        Request::GetAging => w.u8(opcode::GET_AGING),
        Request::SetAging(aging) => {
            w.u8(opcode::SET_AGING);
            encode_aging(&mut w, aging);
        }
    }
    frame(bytes)
}

fn frame(mut bytes: Vec<u8>) -> Vec<u8> {
    let len = (bytes.len() - LENGTH_PREFIX) as u32;
    bytes[..LENGTH_PREFIX].copy_from_slice(&len.to_be_bytes());
    bytes
}

fn plateaus(w: &mut Writer, table: Plateaus) {
    w.u8(table.len);
    for v in table.values {
        w.u32(v);
    }
}

fn encode_aging(w: &mut Writer, aging: Aging) {
    match aging {
        Aging::Unset => {
            w.u8(0);
            w.u64(0);
        }
        Aging::Infinity => {
            w.u8(1);
            w.u64(0);
        }
        Aging::Seconds(s) => {
            w.u8(2);
            w.u64(s);
        }
    }
}

fn read_plateaus(r: &mut Reader) -> Option<Plateaus> {
    let len = r.u8()?;
    let mut values = [0; PLATEAUS];
    for v in &mut values {
        *v = r.u32()?;
    }
    if len == 0 || usize::from(len) > PLATEAUS || values[usize::from(len)..].iter().any(|&v| v != 0)
    {
        return None;
    }
    Some(Plateaus { values, len })
}

fn read_aging(r: &mut Reader) -> Option<Aging> {
    match (r.u8()?, r.u64()?) {
        (0, 0) => Some(Aging::Unset),
        (1, 0) => Some(Aging::Infinity),
        (2, s) => Some(Aging::Seconds(s)),
        _ => None,
    }
}

/// Decode a request body (without its length prefix).
pub fn decode_request(body: &[u8]) -> Result<Request, DecodeError> {
    let mut r = Reader { bytes: body };
    if r.u8() != Some(VERSION) {
        return Err(DecodeError::UnknownVersion);
    }
    let op = r.u8().ok_or(DecodeError::Malformed(0))?;
    let malformed = DecodeError::Malformed(op);
    let request = match op {
        opcode::QUERY_ROUTES | opcode::QUERY_PATHS => {
            let cursor = r.u32().ok_or(malformed)?;
            let revision = r.u64().ok_or(malformed)?;
            if op == opcode::QUERY_ROUTES {
                Request::QueryRoutes { cursor, revision }
            } else {
                Request::QueryPaths { cursor, revision }
            }
        }
        opcode::QUERY_CLIENTS => Request::QueryClients {
            path: r.u64().ok_or(malformed)?,
            cursor: r.u32().ok_or(malformed)?,
            revision: r.u64().ok_or(malformed)?,
        },
        opcode::SELECT_ROUTE => Request::SelectRoute {
            destination: r.prefix().flatten().ok_or(malformed)?,
        },
        opcode::SET_ROUTE_POLICY | opcode::SET_PATH_POLICY => {
            let target = r.u64().ok_or(malformed)?;
            let expected = r.u64().ok_or(malformed)?;
            let policy = r.policy().ok_or(malformed)?;
            if op == opcode::SET_ROUTE_POLICY {
                Request::SetRoutePolicy {
                    route: target,
                    expected,
                    policy,
                }
            } else {
                Request::SetPathPolicy {
                    path: target,
                    expected,
                    policy,
                }
            }
        }
        opcode::GET_PLATEAUS => Request::GetPlateaus,
        opcode::SET_PLATEAUS => Request::SetPlateaus(read_plateaus(&mut r).ok_or(malformed)?),
        opcode::GET_AGING => Request::GetAging,
        opcode::SET_AGING => match read_aging(&mut r).ok_or(malformed)? {
            Aging::Unset => return Err(malformed),
            aging => Request::SetAging(aging),
        },
        other => return Err(DecodeError::UnknownOpcode(other)),
    };
    r.finish(request).ok_or(malformed)
}

fn source(s: Option<Source>) -> u8 {
    s.map_or(0, |s| s as u8)
}

fn read_source(v: u8) -> Option<Option<Source>> {
    Some(match v {
        0 => None,
        1 => Some(Source::Route),
        2 => Some(Source::Path),
        3 => Some(Source::RouteAndPath),
        _ => return None,
    })
}

fn route_entry(w: &mut Writer, e: &RouteEntry) {
    w.u64(e.token);
    w.u64(e.generation);
    w.prefix(Some(e.destination));
    w.prefix(e.source);
    w.u8(e.dscp.unwrap_or(0xff));
    w.u64(e.link);
    match e.next_hop {
        NextHop::OnLink => w.address(None),
        NextHop::Gateway(a) => w.address(Some(a)),
        NextHop::Forwarder(id) => {
            w.u8(0xf);
            w.u64(id);
            w.u64(0);
        }
    }
    w.u32(e.metric);
    w.policy(e.policy);
}

fn read_route_entry(r: &mut Reader) -> Option<RouteEntry> {
    let token = r.u64()?;
    let generation = r.u64()?;
    let destination = r.prefix()??;
    let source = r.prefix()?;
    let dscp = match r.u8()? {
        0xff => None,
        v => Some(v),
    };
    let link = r.u64()?;
    let next_hop = if r.bytes.first() == Some(&0xf) {
        r.u8()?;
        let id = r.u64()?;
        r.u64()?;
        NextHop::Forwarder(id)
    } else {
        r.address()?.map_or(NextHop::OnLink, NextHop::Gateway)
    };
    Some(RouteEntry {
        token,
        generation,
        destination,
        source,
        dscp,
        link,
        next_hop,
        metric: r.u32()?,
        policy: r.policy()?,
    })
}

fn path_entry(w: &mut Writer, e: &PathEntry) {
    w.u64(e.token);
    w.u64(e.generation);
    w.u64(e.version);
    w.u8(u8::from(e.valid));
    w.u64(e.route);
    w.address(Some(e.source));
    w.address(Some(e.destination));
    w.address(Some(e.forwarding));
    w.u8(e.dscp);
    w.u32(e.pins);
    w.policy(e.policy);
    w.u8(u8::from(e.route_policy.is_some()));
    w.policy(e.route_policy.unwrap_or_default());
    w.u8(source(e.discovery_disabled));
    w.u32(e.estimate.map_or(0, |e| e.0));
    w.u8(source(e.estimate.map(|e| e.1)));
    w.u32(e.accepted.map_or(0, |a| a.0));
    w.u8(e.accepted.map_or(0, |a| a.1 as u8));
    w.u32(e.first_hop);
    w.u32(e.learned.unwrap_or(0));
    w.u32(e.restriction.unwrap_or(0));
    w.u32(e.budget.unwrap_or(0));
    w.u64(e.retry_not_before);
    w.u64(e.negative_revision);
    w.u64(e.discovery_revision);
    w.u16(e.clients);
}

fn read_path_entry(r: &mut Reader) -> Option<PathEntry> {
    let token = r.u64()?;
    let generation = r.u64()?;
    let version = r.u64()?;
    let valid = r.bool()?;
    let route = r.u64()?;
    let source_address = r.some_address()?;
    let destination = r.some_address()?;
    let forwarding = r.some_address()?;
    let dscp = r.u8()?;
    let pins = r.u32()?;
    let policy = r.policy()?;
    let has_route = r.bool()?;
    let route_policy = r.policy()?;
    let discovery_disabled = read_source(r.u8()?)?;
    let estimate_value = r.u32()?;
    let estimate = match read_source(r.u8()?)? {
        None if estimate_value == 0 => None,
        Some(s) => Some((estimate_value, s)),
        None => return None,
    };
    let accepted_value = r.u32()?;
    let accepted = match r.u8()? {
        0 => None,
        1 => Some((accepted_value, Provenance::Unlearned)),
        2 => Some((accepted_value, Provenance::Learned)),
        3 => Some((accepted_value, Provenance::OwnerTrustedApplication)),
        4 => Some((accepted_value, Provenance::Administrative)),
        _ => return None,
    };
    Some(PathEntry {
        token,
        generation,
        version,
        valid,
        route,
        source: source_address,
        destination,
        forwarding,
        dscp,
        pins,
        policy,
        route_policy: has_route.then_some(route_policy),
        discovery_disabled,
        estimate,
        accepted,
        first_hop: r.u32()?,
        learned: r.nonzero()?,
        restriction: r.nonzero()?,
        budget: r.nonzero()?,
        retry_not_before: r.u64()?,
        negative_revision: r.u64()?,
        discovery_revision: r.u64()?,
        clients: r.u16()?,
    })
}

fn client_entry(w: &mut Writer, e: &ClientEntry) {
    w.u8(e.kind as u8);
    w.u64(e.id);
    w.u32(e.usable_ip_packet.unwrap_or(0));
    w.u8(u8::from(e.transport.is_some()));
    let t = e.transport.unwrap_or(Transport {
        peer_mss: 0,
        user_mss: None,
        local_mss: 0,
        allocation: 0,
        send_ip_payload_limit: 0,
        destination_mtu: None,
        effective_mss: 0,
    });
    w.u16(t.peer_mss);
    w.u16(t.user_mss.unwrap_or(0));
    w.u16(t.local_mss);
    w.u32(t.allocation);
    w.u16(t.send_ip_payload_limit);
    w.u32(t.destination_mtu.unwrap_or(0));
    w.u32(t.effective_mss);
    match e.search {
        None => {
            w.u8(0);
            w.u32(0);
            w.u32(0);
            w.u8(0);
        }
        Some(Search::Pending { target, deferred }) => {
            w.u8(1);
            w.u32(target);
            w.u32(0);
            w.u8(deferred.unwrap_or(0));
        }
        Some(Search::Attempted {
            target,
            size,
            clipped,
        }) => {
            w.u8(2);
            w.u32(target);
            w.u32(size);
            w.u8(clipped.unwrap_or(0));
        }
    }
}

fn read_client_entry(r: &mut Reader) -> Option<ClientEntry> {
    let kind = match r.u8()? {
        1 => ClientKind::Tcp,
        2 => ClientKind::Udp,
        3 => ClientKind::OutputLease,
        4 => ClientKind::Adjunct,
        5 => ClientKind::Echo,
        _ => return None,
    };
    let id = r.u64()?;
    let usable_ip_packet = r.nonzero()?;
    let has_transport = r.bool()?;
    let transport = Transport {
        peer_mss: r.u16()?,
        user_mss: r.u16().map(|v| (v != 0).then_some(v))?,
        local_mss: r.u16()?,
        allocation: r.u32()?,
        send_ip_payload_limit: r.u16()?,
        destination_mtu: r.nonzero()?,
        effective_mss: r.u32()?,
    };
    let (kind_code, target, size, reason) = (r.u8()?, r.u32()?, r.u32()?, r.u8()?);
    let reason = (reason != 0).then_some(reason);
    let search = match kind_code {
        0 => None,
        1 => Some(Search::Pending {
            target,
            deferred: reason,
        }),
        2 => Some(Search::Attempted {
            target,
            size,
            clipped: reason,
        }),
        _ => return None,
    };
    Some(ClientEntry {
        kind,
        id,
        usable_ip_packet,
        transport: has_transport.then_some(transport),
        search,
    })
}

/// Encode one route entry alone (the listing revision digests these).
pub(crate) fn encode_route_entry(out: &mut Vec<u8>, e: &RouteEntry) {
    route_entry(&mut Writer { bytes: out }, e);
}
pub(crate) fn encode_path_entry(out: &mut Vec<u8>, e: &PathEntry) {
    path_entry(&mut Writer { bytes: out }, e);
}
pub(crate) fn encode_client_entry(out: &mut Vec<u8>, e: &ClientEntry) {
    client_entry(&mut Writer { bytes: out }, e);
}

/// Encode a response as a complete frame into `out` (cleared first).
pub fn encode_response(out: &mut Vec<u8>, response: &Response) {
    out.clear();
    out.extend_from_slice(&[0; LENGTH_PREFIX]);
    let mut w = Writer { bytes: out };
    w.u8(VERSION);
    w.u8(response.status as u8);
    w.u8(response.opcode);
    match &response.payload {
        Payload::None => {}
        Payload::Routes(h, entries) => {
            w.page(*h);
            entries.iter().for_each(|e| route_entry(&mut w, e));
        }
        Payload::Paths(h, entries) => {
            w.page(*h);
            entries.iter().for_each(|e| path_entry(&mut w, e));
        }
        Payload::Clients(h, entries) => {
            w.page(*h);
            entries.iter().for_each(|e| client_entry(&mut w, e));
        }
        Payload::Selected { route } => w.u64(*route),
        Payload::Applied {
            generation,
            affected,
        } => {
            w.u64(*generation);
            w.u32(*affected);
        }
        Payload::Plateaus(table) => plateaus(&mut w, *table),
        Payload::Aging(aging) => encode_aging(&mut w, *aging),
    }
    let len = (out.len() - LENGTH_PREFIX) as u32;
    out[..LENGTH_PREFIX].copy_from_slice(&len.to_be_bytes());
}

/// Decode a response body (without its length prefix).
pub fn decode_response(body: &[u8]) -> Option<Response> {
    let mut r = Reader { bytes: body };
    if r.u8()? != VERSION {
        return None;
    }
    let status = Status::from_u8(r.u8()?)?;
    let op = r.u8()?;
    if status != Status::Ok {
        return r.finish(Response {
            status,
            opcode: op,
            payload: Payload::None,
        });
    }
    fn page<T>(
        r: &mut Reader,
        limit: usize,
        entry: fn(&mut Reader) -> Option<T>,
    ) -> Option<(PageHeader, Vec<T>)> {
        let header = r.page()?;
        if usize::from(header.count) > limit {
            return None;
        }
        let entries = (0..header.count)
            .map(|_| entry(r))
            .collect::<Option<Vec<_>>>()?;
        Some((header, entries))
    }
    let payload = match op {
        opcode::QUERY_ROUTES => {
            let (h, e) = page(&mut r, ROUTES_PER_PAGE, read_route_entry)?;
            Payload::Routes(h, e)
        }
        opcode::QUERY_PATHS => {
            let (h, e) = page(&mut r, PATHS_PER_PAGE, read_path_entry)?;
            Payload::Paths(h, e)
        }
        opcode::QUERY_CLIENTS => {
            let (h, e) = page(&mut r, CLIENTS_PER_PAGE, read_client_entry)?;
            Payload::Clients(h, e)
        }
        opcode::SELECT_ROUTE => Payload::Selected { route: r.u64()? },
        opcode::SET_ROUTE_POLICY
        | opcode::SET_PATH_POLICY
        | opcode::SET_PLATEAUS
        | opcode::SET_AGING => {
            if matches!(op, opcode::SET_PLATEAUS | opcode::SET_AGING) {
                Payload::None
            } else {
                Payload::Applied {
                    generation: r.u64()?,
                    affected: r.u32()?,
                }
            }
        }
        opcode::GET_PLATEAUS => Payload::Plateaus(read_plateaus(&mut r)?),
        opcode::GET_AGING => Payload::Aging(read_aging(&mut r)?),
        _ => return None,
    };
    r.finish(Response {
        status,
        opcode: op,
        payload,
    })
}

// Every listing fits at least one entry per page.
const _: () = assert!(PATHS_PER_PAGE >= 1 && ROUTES_PER_PAGE >= 1 && CLIENTS_PER_PAGE >= 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_bounds_hold_for_the_largest_messages() {
        let table = Plateaus::new(&[65535; PLATEAUS]).unwrap();
        let frame = encode_request(&Request::SetPlateaus(table));
        assert_eq!(frame.len(), MAX_REQUEST_FRAME);
        let entry = PathEntry {
            token: 1,
            generation: 2,
            version: 3,
            valid: true,
            route: 4,
            source: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            forwarding: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dscp: 46,
            pins: 2,
            policy: Policy {
                discovery_disabled: true,
                estimate: Some(1400),
            },
            route_policy: Some(Policy::default()),
            discovery_disabled: Some(Source::Path),
            estimate: Some((1400, Source::Path)),
            accepted: Some((1500, Provenance::Learned)),
            first_hop: 1500,
            learned: Some(1500),
            restriction: None,
            budget: Some(1280),
            retry_not_before: 9,
            negative_revision: 8,
            discovery_revision: 7,
            clients: 3,
        };
        let mut one = Vec::new();
        encode_path_entry(&mut one, &entry);
        assert_eq!(one.len(), PATH_ENTRY);
        let route = RouteEntry {
            token: 1,
            generation: 0,
            destination: Prefix {
                network: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                length: 0,
            },
            source: None,
            dscp: None,
            link: 5,
            next_hop: NextHop::Forwarder(1),
            metric: 0,
            policy: Policy::default(),
        };
        one.clear();
        encode_route_entry(&mut one, &route);
        assert_eq!(one.len(), ROUTE_ENTRY);
        let client = ClientEntry {
            kind: ClientKind::Tcp,
            id: 1,
            usable_ip_packet: Some(1280),
            transport: None,
            search: Some(Search::Attempted {
                target: 1400,
                size: 1300,
                clipped: Some(2),
            }),
        };
        one.clear();
        encode_client_entry(&mut one, &client);
        assert_eq!(one.len(), CLIENT_ENTRY);
        let mut out = Vec::new();
        let header = |count: usize| PageHeader {
            revision: 1,
            total: 99,
            cursor: 0,
            count: count as u8,
        };
        for response in [
            Response {
                status: Status::Ok,
                opcode: opcode::QUERY_PATHS,
                payload: Payload::Paths(header(PATHS_PER_PAGE), vec![entry; PATHS_PER_PAGE]),
            },
            Response {
                status: Status::Ok,
                opcode: opcode::QUERY_ROUTES,
                payload: Payload::Routes(header(ROUTES_PER_PAGE), vec![route; ROUTES_PER_PAGE]),
            },
            Response {
                status: Status::Ok,
                opcode: opcode::QUERY_CLIENTS,
                payload: Payload::Clients(header(CLIENTS_PER_PAGE), vec![client; CLIENTS_PER_PAGE]),
            },
            Response {
                status: Status::Ok,
                opcode: opcode::GET_PLATEAUS,
                payload: Payload::Plateaus(table),
            },
        ] {
            encode_response(&mut out, &response);
            assert!(out.len() <= MAX_RESPONSE_FRAME && out.len() <= PAGE_BUDGET);
            assert_eq!(decode_response(&out[LENGTH_PREFIX..]), Some(response));
        }
    }

    #[test]
    fn every_request_round_trips_and_malformed_bodies_are_rejected() {
        let requests = [
            Request::QueryRoutes {
                cursor: 3,
                revision: 7,
            },
            Request::QueryPaths {
                cursor: 0,
                revision: 0,
            },
            Request::QueryClients {
                path: 9,
                cursor: 1,
                revision: 2,
            },
            Request::SelectRoute {
                destination: Prefix {
                    network: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    length: 0,
                },
            },
            Request::SetRoutePolicy {
                route: 1,
                expected: 2,
                policy: Policy {
                    discovery_disabled: true,
                    estimate: Some(1300),
                },
            },
            Request::SetPathPolicy {
                path: 1,
                expected: 0,
                policy: Policy::default(),
            },
            Request::GetPlateaus,
            Request::SetPlateaus(Plateaus::new(&[1500, 576, 68]).unwrap()),
            Request::GetAging,
            Request::SetAging(Aging::Seconds(600)),
            Request::SetAging(Aging::Infinity),
        ];
        for request in requests {
            let frame = encode_request(&request);
            let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(len, frame.len() - LENGTH_PREFIX);
            assert_eq!(decode_request(&frame[LENGTH_PREFIX..]), Ok(request));
            // Truncated or extended bodies are malformed.
            let body = &frame[LENGTH_PREFIX..];
            assert!(
                matches!(
                    decode_request(&body[..body.len() - 1]),
                    Err(DecodeError::Malformed(_))
                ) || body.len() == 2
            );
            let mut longer = body.to_vec();
            longer.push(0);
            assert!(matches!(
                decode_request(&longer),
                Err(DecodeError::Malformed(_))
            ));
        }
        assert_eq!(decode_request(&[2, 1]), Err(DecodeError::UnknownVersion));
        assert_eq!(
            decode_request(&[VERSION, 200]),
            Err(DecodeError::UnknownOpcode(200))
        );
        // Unknown policy flags, an estimate without its flag, an unset aging
        // request and plateau padding are malformed.
        let mut frame = encode_request(&Request::SetRoutePolicy {
            route: 1,
            expected: 0,
            policy: Policy::default(),
        });
        let flags = LENGTH_PREFIX + 2 + 16;
        frame[flags] = 4;
        assert!(decode_request(&frame[LENGTH_PREFIX..]).is_err());
        frame[flags] = 0;
        frame[flags + 4] = 1;
        assert!(decode_request(&frame[LENGTH_PREFIX..]).is_err());
        let mut frame = encode_request(&Request::SetPlateaus(Plateaus::new(&[576, 68]).unwrap()));
        *frame.last_mut().unwrap() = 1;
        assert!(decode_request(&frame[LENGTH_PREFIX..]).is_err());
        assert!(decode_request(&[VERSION, opcode::SET_AGING, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
