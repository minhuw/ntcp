//! The local control server, served from the Host owner's loop.
//!
//! Exposure. Opt-in: an embedding creates a server only when a socket
//! pathname is configured. The pathname must be absolute and lie in a
//! private directory: a real directory (not a symbolic link) owned by the
//! effective uid with no group or other permission bits, so nobody else can
//! reach the socket while it is created. The socket itself gets mode 0600.
//! An existing pathname is never unlinked unless it is a socket owned by the
//! effective uid that refuses connections (the stale socket of an earlier
//! instance in the same private directory); anything else is an error. On
//! drop the server unlinks its pathname only while it still names the
//! socket it bound. No IP listener exists.
//!
//! Authority. Every accepted descriptor's peer credential is read with
//! SO_PEERCRED (supplied by the kernel at connect time) and checked against
//! an explicit uid allow-list that defaults to the owner's effective uid.
//! There is no implicit root bypass; when the credential is unavailable the
//! connection is closed (fail closed). A peer not on the allow-list is
//! answered `Unauthorized` at accept and closed without taking a peer slot,
//! before it sends anything: none of its requests, queries included, is
//! read or dispatched, so reconnecting denied peers never hold a slot an
//! allowed administrator needs. They can still fill the listen backlog
//! between passes (`listen(SLOTS)`; a Linux unix stream listener holds
//! `SLOTS + 1` pending connections), which the kernel's
//! connection queue shares with allowed peers: a denied local process can
//! delay an allowed administrator's connection (a blocking connect waits,
//! a nonblocking one fails with `EAGAIN`), not exclude it from a slot.
//! Requests then act through the Host-bound `Administration` capability
//! the owner issued, never through Host access.
//!
//! Listings. Route, path and client queries are paginated. The revision of
//! a listing covers what identifies each entry and its administrative state
//! (`protocol::PageHeader::revision`), never values that change with
//! traffic or time, so a continuation fails `Inconsistent` only after an
//! administrative or membership change; each page reports the live values
//! (sizes, pins, holds, revisions, transport values) current when that page
//! is built.
//!
//! Bounds (all I/O is nonblocking; descriptors are native and every call is
//! a direct system call, so an interposition library serving this from its
//! owner thread never re-enters itself):
//! - `SLOTS` allowed peers at once: one interactive administrator plus a
//!   few concurrent scripted queries; a further connection is answered
//!   `Busy` and closed so a client never hangs on a full server. Refusals
//!   (`Busy`, `Unauthorized`) are one nonblocking best-effort send of the
//!   small reply frame before the close.
//! - Frames: a request frame is at most `MAX_REQUEST_FRAME` octets (derived
//!   from the largest request, the plateau table); a larger announced length
//!   is answered `Oversized` and the connection closes, because the stream
//!   cannot be resynchronized without reading unbounded input. A reply is at
//!   most `MAX_RESPONSE_FRAME` (derived from one response page).
//! - One outstanding request per connection: no input is read while a reply
//!   is pending, so a pipelining client is held by its own socket buffer;
//!   each accepted descriptor's send buffer is capped at one reply frame.
//! - Per pass: at most `SLOTS` accepts and one read, dispatch and write per
//!   slot, so serving never delays the owner loop by more than a bounded
//!   amount of work.
//! - Deadlines in the owner's caller clock: `FRAME_SECONDS` to complete a
//!   started request frame or to drain a reply (a trickling or non-reading
//!   client cannot hold a slot), and `IDLE_SECONDS` between requests. Both
//!   are interactive-tool budgets: a local request is one write and a reply
//!   one read, so a healthy client needs milliseconds; two seconds absorbs
//!   scheduling stalls of a loaded host, ten seconds leaves room for a
//!   person typing successive commands over one connection.

use crate::protocol::{
    self, Aging, ClientEntry, ClientKind, LENGTH_PREFIX, MAX_REQUEST_BODY, MAX_REQUEST_FRAME,
    MAX_RESPONSE_FRAME, NextHop, PageHeader, PathEntry, Payload, Plateaus, Policy, Prefix,
    Provenance, Request, Response, RouteEntry, Search, Source, Status, Transport,
};
use libc::c_long;
use ntcp::{Endpoint, Instant, SearchAging};
use ntcp_host::path::{
    self, AdminChange, AdminPolicy, AdminTarget, EstimateProvenance, PathStatus, PolicySource,
};
use ntcp_host::{AdminClient, Administration, Host};
use std::collections::hash_map::RandomState;
use std::ffi::{CString, OsStr};
use std::hash::{BuildHasher, Hash};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const SLOTS: usize = 4;
pub const FRAME_SECONDS: u64 = 2;
pub const IDLE_SECONDS: u64 = 10;
/// Largest uid allow-list: a handful of administrative accounts.
pub const MAX_ALLOWED_UIDS: usize = 16;

/// Owner configuration of the control socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlConfig {
    pub socket: PathBuf,
    /// Allowed peer uids; empty means the owner's effective uid only.
    pub allow_uids: Vec<u32>,
}

impl ControlConfig {
    /// Parse a comma-separated uid list (`control.allow_uids`,
    /// `NTCP_CONTROL_ALLOW_UIDS`).
    pub fn parse_uids(text: &str) -> io::Result<Vec<u32>> {
        let uids = text
            .split(',')
            .map(|uid| {
                uid.trim()
                    .parse::<u32>()
                    .map_err(|_| invalid("invalid uid"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if uids.is_empty() || uids.len() > MAX_ALLOWED_UIDS {
            return Err(invalid("invalid uid allow-list"));
        }
        Ok(uids)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn sys(result: c_long) -> io::Result<c_long> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

struct Fd(i32);

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::syscall(libc::SYS_close, self.0) };
    }
}

fn lstat(path: &CString) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    sys(unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            path.as_ptr(),
            &mut st as *mut libc::stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    Ok(st)
}

fn euid() -> u32 {
    unsafe { libc::syscall(libc::SYS_geteuid) as u32 }
}

fn address(path: &CString) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(invalid("control socket pathname too long"));
    }
    for (dst, &src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

fn unix_socket() -> io::Result<Fd> {
    let fd = sys(unsafe {
        libc::syscall(
            libc::SYS_socket,
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    })?;
    Ok(Fd(fd as i32))
}

/// Validate the private directory of `socket`: absolute, a real directory
/// owned by `owner` with no group or other permission bits.
pub fn validate_private_directory(socket: &Path, owner: u32) -> io::Result<()> {
    if !socket.is_absolute() || socket.file_name().is_none() {
        return Err(invalid("control socket pathname must be absolute"));
    }
    let parent = socket
        .parent()
        .ok_or_else(|| invalid("control socket has no directory"))?;
    let dir = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| invalid("control socket pathname contains NUL"))?;
    let st = lstat(&dir)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control socket directory is not a real directory",
        ));
    }
    if st.st_uid != owner || st.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control socket directory is not private to the owner",
        ));
    }
    Ok(())
}

struct Slot {
    fd: Fd,
    input: [u8; MAX_REQUEST_FRAME],
    filled: usize,
    output: Vec<u8>,
    written: usize,
    close_after: bool,
    // Caller-clock deadline of the current state (frame completion, reply
    // drain or idle).
    deadline: Instant,
}

pub struct Server {
    listener: Fd,
    path: CString,
    bound: (libc::dev_t, libc::ino_t),
    allow: Vec<u32>,
    slots: Vec<Option<Slot>>,
    capability: Administration,
    // Per-instance token key: identifiers from an earlier server process (or
    // another Host's server) never name an object here.
    key: RandomState,
    frame_units: u64,
    idle_units: u64,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Ok(st) = lstat(&self.path)
            && (st.st_dev, st.st_ino) == self.bound
        {
            unsafe { libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, self.path.as_ptr(), 0) };
        }
    }
}

fn status_of(error: ntcp_host::Error) -> Status {
    use ntcp_host::Error as E;
    use path::Error as P;
    match error {
        E::Unauthorized => Status::Unauthorized,
        E::Path(P::StaleGeneration | P::StaleHandle | P::Invalidated | P::SelectionChanged) => {
            Status::Stale
        }
        E::Path(P::NoRoute | P::ForeignContext) => Status::NotFound,
        E::Path(P::Ambiguous) => Status::Ambiguous,
        E::Path(P::InvalidArgument) => Status::Invalid,
        E::Endpoint(ntcp::EndpointError::Connection(ntcp::Error::InvalidArgument)) => {
            Status::Invalid
        }
        // A reservation the Endpoint cannot withdraw now: retry later.
        E::Endpoint(ntcp::EndpointError::OutputReserved) => Status::Busy,
        E::Path(P::Capacity | P::Allocation | P::Exhausted) | E::Capacity | E::Allocation => {
            Status::Capacity
        }
        _ => Status::Failed,
    }
}

fn prefix(p: path::IpPrefix) -> Prefix {
    Prefix {
        network: p.network(),
        length: p.length(),
    }
}

fn policy(p: AdminPolicy) -> Policy {
    Policy {
        discovery_disabled: p.discovery_disabled,
        estimate: p.estimate,
    }
}

fn source(s: PolicySource) -> Source {
    match s {
        PolicySource::Route => Source::Route,
        PolicySource::Path => Source::Path,
        PolicySource::RouteAndPath => Source::RouteAndPath,
    }
}

fn search(s: ntcp::AdministrativeSearch) -> Search {
    use ntcp::{AdministrativeClip as C, AdministrativeDeferral as D};
    match s {
        ntcp::AdministrativeSearch::Pending { target, deferred } => Search::Pending {
            target,
            deferred: deferred.map(|d| match d {
                D::Hold => 1,
                D::Cooldown => 2,
                D::LossRecovery => 3,
                D::DataOrWindow => 4,
                D::DiscoveryDisabled => 5,
            }),
        },
        ntcp::AdministrativeSearch::Attempted {
            target,
            size,
            clipped,
        } => Search::Attempted {
            target,
            size,
            clipped: clipped.map(|c| match c {
                C::SearchHigh => 1,
                C::Transport => 2,
                C::SearchLow => 3,
            }),
        },
    }
}

impl Server {
    /// Create the listening socket for `config` (see the module text) on
    /// the owner thread. `capability` is the owner's Host-bound
    /// administration capability; `timebase` is the owner's caller clock.
    pub fn bind(
        config: &ControlConfig,
        capability: Administration,
        timebase: ntcp::CallerTimebase,
    ) -> io::Result<Self> {
        let owner = euid();
        validate_private_directory(&config.socket, owner)?;
        if config.allow_uids.len() > MAX_ALLOWED_UIDS {
            return Err(invalid("invalid uid allow-list"));
        }
        let path = CString::new(config.socket.as_os_str().as_bytes())
            .map_err(|_| invalid("control socket pathname contains NUL"))?;
        let (addr, len) = address(&path)?;
        match lstat(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
            Ok(st) => {
                // Only our own stale socket is replaced.
                if st.st_mode & libc::S_IFMT != libc::S_IFSOCK || st.st_uid != owner {
                    return Err(io::Error::from(io::ErrorKind::AlreadyExists));
                }
                let probe = unix_socket()?;
                let refused = sys(unsafe {
                    libc::syscall(
                        libc::SYS_connect,
                        probe.0,
                        &addr as *const libc::sockaddr_un,
                        len,
                    )
                })
                .err()
                .is_some_and(|e| e.raw_os_error() == Some(libc::ECONNREFUSED));
                if !refused {
                    return Err(io::Error::from(io::ErrorKind::AddrInUse));
                }
                sys(unsafe {
                    libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path.as_ptr(), 0)
                })?;
            }
        }
        let listener = unix_socket()?;
        sys(unsafe {
            libc::syscall(
                libc::SYS_bind,
                listener.0,
                &addr as *const libc::sockaddr_un,
                len,
            )
        })?;
        let st = lstat(&path)?;
        let bound = (st.st_dev, st.st_ino);
        let server = Self {
            listener,
            path,
            bound,
            allow: if config.allow_uids.is_empty() {
                vec![owner]
            } else {
                config.allow_uids.clone()
            },
            slots: (0..SLOTS).map(|_| None).collect(),
            capability,
            key: RandomState::new(),
            frame_units: FRAME_SECONDS
                .checked_mul(timebase.units_per_second)
                .ok_or_else(|| invalid("caller timebase"))?,
            idle_units: IDLE_SECONDS
                .checked_mul(timebase.units_per_second)
                .ok_or_else(|| invalid("caller timebase"))?,
        };
        // From here Drop unlinks the bound socket on any failure.
        sys(unsafe {
            libc::syscall(
                libc::SYS_fchmodat,
                libc::AT_FDCWD,
                server.path.as_ptr(),
                0o600,
                0,
            )
        })?;
        sys(unsafe { libc::syscall(libc::SYS_listen, server.listener.0, SLOTS as i32) })?;
        Ok(server)
    }

    /// The pathname this server listens on.
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(self.path.as_bytes()))
    }

    /// One bounded service pass at owner caller time `now`.
    pub fn service(&mut self, host: &mut Host, endpoint: &mut Endpoint, now: Instant) {
        self.accept(now);
        for index in 0..SLOTS {
            if self.slots[index].is_some() && !self.service_slot(index, host, endpoint, now) {
                self.slots[index] = None;
            }
        }
    }

    fn accept(&mut self, now: Instant) {
        for _ in 0..SLOTS {
            let Ok(fd) = sys(unsafe {
                libc::syscall(
                    libc::SYS_accept4,
                    self.listener.0,
                    std::ptr::null_mut::<libc::sockaddr>(),
                    std::ptr::null_mut::<libc::socklen_t>(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            }) else {
                return;
            };
            let fd = Fd(fd as i32);
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let credential = sys(unsafe {
                libc::syscall(
                    libc::SYS_getsockopt,
                    fd.0,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut libc::ucred,
                    &mut len as *mut libc::socklen_t,
                )
            });
            if credential.is_err() || len as usize != std::mem::size_of::<libc::ucred>() {
                // Fail closed: no credential, no service.
                continue;
            }
            if !self.allow.contains(&cred.uid) {
                refuse(&fd, Status::Unauthorized);
                continue;
            }
            // One outstanding request per connection means a reply never
            // needs more than one frame of kernel buffering; capping the
            // send buffer bounds the kernel memory a peer that never reads
            // can pin (otherwise up to the system default) and lets the
            // reply-drain deadline find it.
            let sndbuf = MAX_RESPONSE_FRAME as libc::c_int;
            if sys(unsafe {
                libc::syscall(
                    libc::SYS_setsockopt,
                    fd.0,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &sndbuf as *const libc::c_int,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            })
            .is_err()
            {
                continue;
            }
            let Some(free) = self.slots.iter().position(Option::is_none) else {
                refuse(&fd, Status::Busy);
                continue;
            };
            self.slots[free] = Some(Slot {
                fd,
                input: [0; MAX_REQUEST_FRAME],
                filled: 0,
                output: Vec::with_capacity(MAX_RESPONSE_FRAME),
                written: 0,
                close_after: false,
                deadline: now.saturating_add(self.idle_units),
            });
        }
    }

    // Returns false when the slot must close.
    fn service_slot(
        &mut self,
        index: usize,
        host: &mut Host,
        endpoint: &mut Endpoint,
        now: Instant,
    ) -> bool {
        let frame_units = self.frame_units;
        let idle_units = self.idle_units;
        let slot = self.slots[index].as_mut().unwrap();
        if slot.written < slot.output.len() {
            match send(&slot.fd, &slot.output[slot.written..]) {
                Ok(n) => slot.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
            if slot.written < slot.output.len() {
                return now < slot.deadline;
            }
            if slot.close_after {
                return false;
            }
            slot.output.clear();
            slot.written = 0;
            slot.deadline = now.saturating_add(idle_units);
            return true;
        }
        // Read only up to the end of the current frame.
        let want = if slot.filled < LENGTH_PREFIX {
            LENGTH_PREFIX
        } else {
            let body = u32::from_be_bytes(slot.input[..LENGTH_PREFIX].try_into().unwrap()) as usize;
            LENGTH_PREFIX + body
        };
        let was_empty = slot.filled == 0;
        match sys(unsafe {
            libc::syscall(
                libc::SYS_recvfrom,
                slot.fd.0,
                slot.input[slot.filled..want].as_mut_ptr(),
                want - slot.filled,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut::<libc::sockaddr>(),
                std::ptr::null_mut::<libc::socklen_t>(),
            )
        }) {
            Ok(0) => return false,
            Ok(n) => slot.filled += n as usize,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return now < slot.deadline,
            Err(_) => return false,
        }
        if was_empty {
            slot.deadline = now.saturating_add(frame_units);
        }
        if slot.filled == LENGTH_PREFIX {
            let body = u32::from_be_bytes(slot.input[..LENGTH_PREFIX].try_into().unwrap()) as usize;
            if body > MAX_REQUEST_BODY {
                self.reply(index, now, Status::Oversized, 0, Payload::None, true);
                return true;
            }
        }
        let slot = self.slots[index].as_ref().unwrap();
        if slot.filled < LENGTH_PREFIX
            || slot.filled
                < LENGTH_PREFIX
                    + u32::from_be_bytes(slot.input[..LENGTH_PREFIX].try_into().unwrap()) as usize
        {
            return now < slot.deadline;
        }
        let mut body = [0u8; MAX_REQUEST_BODY];
        let len = slot.filled - LENGTH_PREFIX;
        body[..len].copy_from_slice(&slot.input[LENGTH_PREFIX..slot.filled]);
        self.slots[index].as_mut().unwrap().filled = 0;
        match protocol::decode_request(&body[..len]) {
            Err(error) => {
                let (status, op) = error.status();
                self.reply(index, now, status, op, Payload::None, false);
            }
            Ok(request) => {
                let op = body[1];
                let (status, payload) = match self.dispatch(host, endpoint, now, request) {
                    Ok(payload) => (Status::Ok, payload),
                    Err(status) => (status, Payload::None),
                };
                self.reply(index, now, status, op, payload, false);
            }
        }
        true
    }

    fn reply(
        &mut self,
        index: usize,
        now: Instant,
        status: Status,
        opcode: u8,
        payload: Payload,
        close_after: bool,
    ) {
        let frame_units = self.frame_units;
        let slot = self.slots[index].as_mut().unwrap();
        protocol::encode_response(
            &mut slot.output,
            &Response {
                status,
                opcode,
                payload,
            },
        );
        slot.written = 0;
        slot.close_after = close_after;
        slot.deadline = now.saturating_add(frame_units);
    }

    fn token(&self, value: impl Hash) -> u64 {
        self.key.hash_one(value)
    }

    fn route_entries(&self, host: &Host) -> Result<Vec<(path::RouteId, RouteEntry)>, Status> {
        Ok(host
            .admin_routes(&self.capability)
            .map_err(status_of)?
            .map(|r| {
                let d = r.definition;
                (
                    r.route,
                    RouteEntry {
                        token: self.token(r.route),
                        generation: r.generation,
                        destination: prefix(d.destination),
                        source: d.source.map(prefix),
                        dscp: d.dscp.map(path::Dscp::value),
                        link: self.token(d.link),
                        next_hop: match d.next_hop {
                            path::NextHop::OnLink => NextHop::OnLink,
                            path::NextHop::Gateway(a) => NextHop::Gateway(a.address()),
                            path::NextHop::Forwarder(id) => NextHop::Forwarder(id.0),
                        },
                        metric: d.metric,
                        policy: policy(r.policy),
                    },
                )
            })
            .collect())
    }

    fn path_entries(
        &self,
        host: &Host,
        endpoint: &Endpoint,
    ) -> Result<Vec<(path::PathId, PathEntry)>, Status> {
        Ok(host
            .admin_paths(&self.capability)
            .map_err(status_of)?
            .map(|a| {
                let s = a.snapshot;
                let key = s.key();
                let clients = host
                    .admin_clients(&self.capability, endpoint, s.path())
                    .map_or(0, |c| c.count());
                (
                    s.path(),
                    PathEntry {
                        token: self.token(s.path()),
                        generation: a.generation,
                        version: s.version(),
                        valid: s.status() == PathStatus::Valid,
                        route: self.token(key.route()),
                        source: key.source_address().address(),
                        destination: key.destination().address(),
                        forwarding: key.forwarding_destination().address(),
                        dscp: key.dscp().value(),
                        pins: u32::try_from(a.pins).unwrap_or(u32::MAX),
                        policy: policy(a.policy),
                        route_policy: a.route_policy.map(policy),
                        discovery_disabled: a.effective.discovery_disabled.map(source),
                        estimate: a.effective.estimate.map(|e| (e.value, source(e.source))),
                        accepted: a.accepted.map(|e| {
                            (
                                e.value,
                                match e.provenance {
                                    EstimateProvenance::Unlearned => Provenance::Unlearned,
                                    EstimateProvenance::Learned => Provenance::Learned,
                                    EstimateProvenance::OwnerTrustedApplication => {
                                        Provenance::OwnerTrustedApplication
                                    }
                                    EstimateProvenance::Administrative => {
                                        Provenance::Administrative
                                    }
                                },
                            )
                        }),
                        first_hop: s.first_hop_mtu(),
                        learned: s.learned_mtu(),
                        restriction: s.administrative_restriction(),
                        budget: s.ip_packet_budget().ok(),
                        retry_not_before: s.retry_not_before(),
                        negative_revision: s.negative_revision(),
                        discovery_revision: s.discovery_revision(),
                        clients: u16::try_from(clients).unwrap_or(u16::MAX),
                    },
                )
            })
            .collect())
    }

    fn client_entries(
        &self,
        host: &Host,
        endpoint: &Endpoint,
        path: path::PathId,
    ) -> Result<Vec<ClientEntry>, Status> {
        Ok(host
            .admin_clients(&self.capability, endpoint, path)
            .map_err(status_of)?
            .map(|report| {
                let (kind, id) = match report.client {
                    AdminClient::Tcp(c) => (ClientKind::Tcp, self.token(format!("{c:?}"))),
                    AdminClient::Udp(f) => (ClientKind::Udp, self.token(format!("{f:?}"))),
                    AdminClient::OutputLease(a) => {
                        (ClientKind::OutputLease, self.token(format!("{a:?}")))
                    }
                    AdminClient::Adjunct => (ClientKind::Adjunct, 0),
                    AdminClient::Echo { queued } => (ClientKind::Echo, queued as u64),
                };
                ClientEntry {
                    kind,
                    id,
                    usable_ip_packet: report.usable_ip_packet,
                    transport: report.transport.map(|t| Transport {
                        peer_mss: t.peer_mss,
                        user_mss: t.user_mss,
                        local_mss: t.local_mss,
                        allocation: u32::try_from(t.allocation).unwrap_or(u32::MAX),
                        send_ip_payload_limit: t.send_ip_payload_limit,
                        destination_mtu: t.destination_mtu,
                        effective_mss: u32::try_from(t.effective_mss).unwrap_or(u32::MAX),
                    }),
                    search: report.search.map(search),
                }
            })
            .collect())
    }

    // Digest of a complete listing's identities and administrative state
    // (`protocol::PageHeader::revision`): the revision a continuation
    // repeats. Live values are left out, so traffic between two page
    // requests never makes a continuation inconsistent.
    fn revision<T>(&self, entries: &[T], encode: fn(&mut Vec<u8>, &T)) -> u64 {
        let mut bytes = Vec::with_capacity(entries.len().saturating_mul(protocol::PATH_ENTRY));
        for e in entries {
            encode(&mut bytes, e);
        }
        self.token(bytes)
    }

    fn page<T: Clone>(
        &self,
        entries: &[T],
        revision_of: fn(&mut Vec<u8>, &T),
        per_page: usize,
        cursor: u32,
        revision: u64,
    ) -> Result<(PageHeader, Vec<T>), Status> {
        let digest = self.revision(entries, revision_of);
        let start = cursor as usize;
        if start > entries.len() {
            return Err(Status::Invalid);
        }
        if start != 0 && revision != digest {
            return Err(Status::Inconsistent);
        }
        let page: Vec<T> = entries[start..].iter().take(per_page).cloned().collect();
        Ok((
            PageHeader {
                revision: digest,
                total: u32::try_from(entries.len()).map_err(|_| Status::Capacity)?,
                cursor,
                count: page.len() as u8,
            },
            page,
        ))
    }

    fn find<T: Copy>(
        &self,
        candidates: impl Iterator<Item = (T, u64)>,
        token: u64,
    ) -> Result<T, Status> {
        let mut found = None;
        for (object, t) in candidates {
            if t == token {
                if found.is_some() {
                    return Err(Status::Ambiguous);
                }
                found = Some(object);
            }
        }
        // A token no live object carries is stale: the object it named was
        // replaced, removed or evicted (or it never came from this server).
        found.ok_or(Status::Stale)
    }

    fn dispatch(
        &mut self,
        host: &mut Host,
        endpoint: &mut Endpoint,
        now: Instant,
        request: Request,
    ) -> Result<Payload, Status> {
        let cap = self.capability.clone();
        match request {
            Request::QueryRoutes { cursor, revision } => {
                let entries: Vec<RouteEntry> =
                    self.route_entries(host)?.into_iter().map(|e| e.1).collect();
                let (h, page) = self.page(
                    &entries,
                    protocol::route_revision,
                    protocol::ROUTES_PER_PAGE,
                    cursor,
                    revision,
                )?;
                Ok(Payload::Routes(h, page))
            }
            Request::QueryPaths { cursor, revision } => {
                let entries: Vec<PathEntry> = self
                    .path_entries(host, endpoint)?
                    .into_iter()
                    .map(|e| e.1)
                    .collect();
                let (h, page) = self.page(
                    &entries,
                    protocol::path_revision,
                    protocol::PATHS_PER_PAGE,
                    cursor,
                    revision,
                )?;
                Ok(Payload::Paths(h, page))
            }
            Request::QueryClients {
                path,
                cursor,
                revision,
            } => {
                let paths = self.path_entries(host, endpoint)?;
                let id = self.find(paths.iter().map(|(id, e)| (*id, e.token)), path)?;
                let entries = self.client_entries(host, endpoint, id)?;
                let (h, page) = self.page(
                    &entries,
                    protocol::client_revision,
                    protocol::CLIENTS_PER_PAGE,
                    cursor,
                    revision,
                )?;
                Ok(Payload::Clients(h, page))
            }
            Request::SelectRoute { destination } => {
                let prefix = path::IpPrefix::new(destination.network, destination.length)
                    .map_err(|_| Status::Invalid)?;
                let route = host.admin_select_route(&cap, prefix).map_err(status_of)?;
                Ok(Payload::Selected {
                    route: self.token(route),
                })
            }
            Request::SetRoutePolicy {
                route,
                expected,
                policy,
            } => {
                let routes = self.route_entries(host)?;
                let id = self.find(routes.iter().map(|(id, e)| (*id, e.token)), route)?;
                self.apply(
                    host,
                    endpoint,
                    now,
                    AdminTarget::Route(id),
                    expected,
                    policy,
                )
            }
            Request::SetPathPolicy {
                path,
                expected,
                policy,
            } => {
                let paths = self.path_entries(host, endpoint)?;
                let id = self.find(paths.iter().map(|(id, e)| (*id, e.token)), path)?;
                self.apply(host, endpoint, now, AdminTarget::Path(id), expected, policy)
            }
            Request::GetPlateaus => {
                let table = host.admin_ipv4_plateaus(&cap).map_err(status_of)?;
                Ok(Payload::Plateaus(
                    Plateaus::new(table.as_slice()).ok_or(Status::Failed)?,
                ))
            }
            Request::SetPlateaus(table) => {
                let table =
                    path::Ipv4Plateaus::new(table.as_slice()).map_err(|_| Status::Invalid)?;
                host.admin_set_ipv4_plateaus(&cap, endpoint, table)
                    .map_err(status_of)?;
                Ok(Payload::None)
            }
            Request::GetAging => Ok(Payload::Aging(
                match host.admin_search_aging(&cap).map_err(status_of)? {
                    None => Aging::Unset,
                    Some(SearchAging::Infinity) => Aging::Infinity,
                    Some(SearchAging::Seconds(s)) => Aging::Seconds(s),
                },
            )),
            Request::SetAging(aging) => {
                let aging = match aging {
                    Aging::Seconds(s) => SearchAging::Seconds(s),
                    Aging::Infinity => SearchAging::Infinity,
                    Aging::Unset => return Err(Status::Invalid),
                };
                host.admin_set_search_aging(&cap, endpoint, now, aging)
                    .map_err(status_of)?;
                Ok(Payload::None)
            }
        }
    }

    // One administration transaction (validate read-only, then apply).
    fn apply(
        &self,
        host: &mut Host,
        endpoint: &mut Endpoint,
        now: Instant,
        target: AdminTarget,
        expected: u64,
        requested: Policy,
    ) -> Result<Payload, Status> {
        let change = AdminChange {
            target,
            expected,
            policy: AdminPolicy {
                discovery_disabled: requested.discovery_disabled,
                estimate: requested.estimate,
            },
        };
        let candidate = host
            .admin_validate(&self.capability, now, change)
            .map_err(status_of)?;
        let affected = host
            .admin_affected(&self.capability, &candidate)
            .map_err(status_of)?
            .count();
        let generation = host
            .admin_apply(&self.capability, endpoint, candidate)
            .map_err(status_of)?;
        Ok(Payload::Applied {
            generation,
            affected: u32::try_from(affected).unwrap_or(u32::MAX),
        })
    }
}

// Answer a connection refused at accept with `status` (one nonblocking,
// best-effort send of the small reply frame); the caller then closes it.
fn refuse(fd: &Fd, status: Status) {
    let mut reply = Vec::with_capacity(MAX_RESPONSE_FRAME);
    protocol::encode_response(
        &mut reply,
        &Response {
            status,
            opcode: 0,
            payload: Payload::None,
        },
    );
    let _ = send(fd, &reply);
}

fn send(fd: &Fd, bytes: &[u8]) -> io::Result<usize> {
    // MSG_NOSIGNAL: a vanished client must not raise SIGPIPE in the owner.
    sys(unsafe {
        libc::syscall(
            libc::SYS_sendto,
            fd.0,
            bytes.as_ptr(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            std::ptr::null::<libc::sockaddr>(),
            0,
        )
    })
    .map(|n| n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;

    // D24: SLOTS + 1 peers outside the allow-list that connect and send
    // nothing are each answered Unauthorized at accept and closed; none of
    // them occupies a slot.
    #[test]
    fn denied_peers_are_refused_at_accept_without_a_slot() {
        let cfg = ntcp::EndpointConfig::default();
        let (paths, limits) = ntcp_host::managed_limits(&cfg, 1, 1, 1, 1, 0).unwrap();
        let mut host = Host::new(
            path::ContextId::new(5),
            paths,
            limits,
            cfg.connection.timebase,
        )
        .unwrap();
        let mut endpoint = Endpoint::new(cfg.clone(), [3; 32], 0, |_| true).unwrap();
        host.attach(&mut endpoint).unwrap();
        let dir = std::env::temp_dir().join(format!("ntcp-control-denied-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let socket = dir.join("control");
        let mut server = Server::bind(
            &ControlConfig {
                socket: socket.clone(),
                allow_uids: vec![euid().wrapping_add(1)],
            },
            host.administration(),
            endpoint.caller_timebase(),
        )
        .unwrap();
        let mut peers: Vec<UnixStream> = (0..=SLOTS)
            .map(|_| {
                let peer = UnixStream::connect(&socket).unwrap();
                peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                peer
            })
            .collect();
        // The per-pass accept bound: SLOTS per pass, the rest at the next.
        server.service(&mut host, &mut endpoint, 0);
        assert!(server.slots.iter().all(Option::is_none));
        server.service(&mut host, &mut endpoint, 0);
        assert!(server.slots.iter().all(Option::is_none));
        for peer in &mut peers {
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).unwrap();
            let len = u32::from_be_bytes(reply[..LENGTH_PREFIX].try_into().unwrap()) as usize;
            assert_eq!(
                reply.len(),
                LENGTH_PREFIX + len,
                "one frame, then end of stream"
            );
            let response = protocol::decode_response(&reply[LENGTH_PREFIX..]).unwrap();
            assert_eq!(response.status, Status::Unauthorized);
        }
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
