// SPDX-License-Identifier: GPL-2.0-or-later
// Legacy packet assertions retargeted to the real socket Owner. Numeric request
// translation is test-only; no Endpoint or socket semantics live in this harness.
use super::{Owner as SocketOwner, *};
use crate::packet_profile::{Profile, parse_frame as parse_ip, profile};
use crate::transport::transport_option;
use ntcp::{EndpointConfig, IpMetadata};
use std::{
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
    slice,
    time::Duration,
};
const LIMIT: usize = crate::packet_profile::LIMIT;
const BYTES: usize = crate::packet_profile::BYTES;
const TCP_INFO_SIZE: usize = 280;
struct Owner {
    inner: SocketOwner,
}
impl Deref for Owner {
    type Target = SocketOwner;
    fn deref(&self) -> &SocketOwner {
        &self.inner
    }
}
impl DerefMut for Owner {
    fn deref_mut(&mut self) -> &mut SocketOwner {
        &mut self.inner
    }
}
struct Request {
    reply: SyncSender<Result<Response>>,
    op: i32,
    fd: u64,
    a: i32,
    b: i32,
    bytes: Vec<u8>,
    capacity: usize,
    destinations: Vec<(usize, usize)>,
    started: bool,
    deadline: Option<Instant>,
}
#[derive(Default)]
struct Response {
    value: i64,
    bytes: Vec<u8>,
    stamp: i64,
}
fn request(
    op: i32,
    fd: u64,
    a: i32,
    bytes: Vec<u8>,
    capacity: usize,
) -> (Request, Receiver<Result<Response>>) {
    let (reply, rx) = mpsc::sync_channel(1);
    (
        Request {
            reply,
            op,
            fd,
            a,
            b: 0,
            bytes,
            capacity,
            destinations: Vec::new(),
            started: false,
            deadline: None,
        },
        rx,
    )
}
struct Adapter {
    runtime: std::sync::Arc<Runtime>,
    tx: Submission,
}
struct Submission(std::sync::Arc<Runtime>);
impl Submission {
    fn send(&self, r: Request) -> Result<()> {
        self.try_send(r)
    }
    fn try_send(&self, r: Request) -> Result<()> {
        let timeout = r
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()));
        let op = match r.op {
            1 => Op::New(r.a),
            2 => Op::Bind(decode_addr(&r.bytes)?),
            3 => Op::Listen(r.a),
            4 => Op::Wait(Box::new(Op::Accept(0)), timeout),
            5 => {
                if self.0.call(r.fd, Op::Flags(F_GETFL, 0))?.value & O_NONBLOCK != 0 {
                    Op::Connect(decode_addr(&r.bytes)?)
                } else {
                    Op::Wait(
                        Box::new(Op::BlockingConnect(decode_addr(&r.bytes)?)),
                        timeout,
                    )
                }
            }
            6 => Op::Wait(Box::new(Op::Read(r.capacity)), timeout),
            7 => Op::Wait(Box::new(Op::WriteFlags(r.bytes, r.a)), timeout),
            8 => Op::Close,
            9 => Op::Shutdown(r.a),
            10 => Op::Flags(r.a, r.b),
            11 => {
                let (level, name) = option(r.a);
                Op::Set(level, name, r.b)
            }
            12 => {
                let (level, name) = option(r.a);
                Op::Get(level, name)
            }
            14 => Op::Inject(r.bytes),
            15 => Op::Wait(Box::new(Op::Capture(r.capacity)), timeout),
            17 => Op::Available,
            18 => Op::Transport(r.a),
            _ => panic!("unported threaded op {}", r.op),
        };
        let (reply, rx) = mpsc::sync_channel(1);
        self.0
            .tx
            .try_send(super::Request {
                id: r.fd,
                op,
                reply,
                deadline: r.deadline,
            })
            .map_err(|_| EAGAIN)?;
        std::thread::spawn(move || {
            let result = rx.recv().unwrap_or(Err(EIO)).map(|p| Response {
                value: p.value as i64,
                bytes: p.bytes,
                stamp: p.stamp,
            });
            let _ = r.reply.send(result);
        });
        Ok(())
    }
}
impl Adapter {
    fn start(settings: (Ipv4Addr, Profile)) -> Result<Self> {
        let runtime = std::sync::Arc::new(Runtime::packet(settings)?);
        Ok(Self {
            tx: Submission(runtime.clone()),
            runtime,
        })
    }
    fn call(&self, r: Request) -> Result<Response> {
        let (reply, rx) = mpsc::sync_channel(1);
        let r = Request { reply, ..r };
        self.tx.try_send(r)?;
        rx.recv_timeout(Duration::from_secs(3))
            .expect("shared owner did not respond")
    }
}
impl Drop for Adapter {
    fn drop(&mut self) {
        self.runtime.stop();
    }
}
fn call(
    adapter: &Adapter,
    op: i32,
    fd: u64,
    a: i32,
    bytes: Vec<u8>,
    capacity: usize,
) -> Result<Response> {
    adapter.call(request(op, fd, a, bytes, capacity).0)
}
fn option(key: i32) -> (i32, i32) {
    match key {
        1 => (SOL_SOCKET, SO_REUSEADDR),
        2 => (IPPROTO_TCP, TCP_NODELAY),
        3 => (SOL_SOCKET, SO_ERROR),
        4 => (SOL_SOCKET, SO_TYPE),
        5 => (IPPROTO_TCP, TCP_USER_TIMEOUT),
        6 => (IPPROTO_IP, IP_TOS),
        7 => (IPPROTO_IP, IP_MTU_DISCOVER),
        8 => (SOL_SOCKET, SO_ZEROCOPY),
        _ => (-1, key),
    }
}
impl Owner {
    fn gc_ip_options(&mut self) {
        self.inner
            .connection_options
            .retain(|p| self.inner.endpoint.connection_exists(p.0));
    }
    fn retry(&mut self, r: &mut Request) -> bool {
        match self.execute(r) {
            Ok(None) => false,
            other => {
                let _ = r.reply.send(other.map(|p| p.unwrap()));
                true
            }
        }
    }
    fn new(settings: (Ipv4Addr, Profile)) -> Result<Self> {
        Ok(Self {
            inner: SocketOwner::packet(settings)?,
        })
    }
    fn new_with_prr_pacing(settings: (Ipv4Addr, Profile), pacing: bool) -> Result<Self> {
        let mut owner = Self::new(settings)?;
        let mut config = crate::packet_profile::config(settings.1);
        config.connection.prr_pacing = pacing;
        owner.inner.endpoint = Endpoint::new(config, [42; 32], 0, |_| true).map_err(engine)?;
        Ok(owner)
    }
    fn alloc(&mut self, mut socket: Socket) -> Result<u64> {
        let defaults = self.inner.fresh_socket(socket.flags);
        socket.send_capacity = defaults.send_capacity;
        socket.receive_capacity = defaults.receive_capacity;
        self.inner.alloc(socket).map(|id| id as u64)
    }
    fn connection(&self, fd: u64) -> Result<ConnectionId> {
        match self.sockets.get(&fd).ok_or(EBADF)?.handle {
            Handle::Connection(id) => Ok(id),
            _ => Err(ENOTCONN),
        }
    }
    fn execute(&mut self, r: &mut Request) -> Result<Option<Response>> {
        let op = match r.op {
            2 => Op::Bind(decode_addr(&r.bytes)?),
            3 => Op::Listen(r.a),
            4 => Op::Accept(0),
            5 => {
                if r.started {
                    self.inner.events();
                    return if self.sockets[&r.fd].connected {
                        Ok(Some(Response::default()))
                    } else {
                        Ok(None)
                    };
                }
                let result = self
                    .inner
                    .dispatch(r.fd, Op::Connect(decode_addr(&r.bytes)?));
                if matches!(result, Err(EINPROGRESS)) {
                    r.started = true;
                    if self.sockets[&r.fd].flags & SOCK_NONBLOCK == 0 {
                        return Ok(None);
                    }
                }
                return result.map(|p| {
                    Some(Response {
                        value: p.value as i64,
                        bytes: p.bytes,
                        stamp: p.stamp,
                    })
                });
            }
            6 => {
                if r.destinations.is_empty() {
                    Op::Read(r.capacity)
                } else {
                    Op::ReadTo(r.capacity, r.a, r.destinations.clone(), Vec::new())
                }
            }
            7 => {
                if r.destinations.is_empty() {
                    Op::Send(vec![(r.bytes.as_ptr() as usize, r.bytes.len())], r.a)
                } else {
                    Op::Send(r.destinations.clone(), r.a)
                }
            }
            8 => Op::Close,
            9 => Op::Shutdown(r.a),
            10 => Op::Flags(r.a, r.b),
            11 => {
                let (level, name) = option(r.a);
                Op::Set(level, name, r.b)
            }
            12 => {
                let (level, name) = option(r.a);
                Op::Get(level, name)
            }
            13 => {
                let mut bytes = r.bytes.clone();
                let mut ready = 0;
                for chunk in bytes.chunks_exact_mut(std::mem::size_of::<pollfd>()) {
                    let mut p = unsafe { ptr::read_unaligned(chunk.as_ptr().cast::<pollfd>()) };
                    p.revents = if p.fd < 0 {
                        0
                    } else {
                        match self.inner.dispatch(p.fd as u64, Op::Ready) {
                            Ok(reply) => crate::readiness::poll_events(reply.value, p.events),
                            Err(EBADF) => POLLNVAL,
                            Err(e) => return Err(e),
                        }
                    };
                    ready += i64::from(p.revents != 0);
                    unsafe {
                        ptr::write_unaligned(chunk.as_mut_ptr().cast::<pollfd>(), p);
                    }
                }
                return Ok(Some(Response {
                    value: ready,
                    bytes,
                    stamp: 0,
                }));
            }
            22 => Op::ErrorQueueTo(r.destinations[0].0),
            14 => Op::Inject(r.bytes.clone()),
            17 => Op::Available,
            18 => Op::Transport(r.a),
            _ => panic!("unported test operation {}", r.op),
        };
        match self.inner.dispatch(r.fd, op) {
            Ok(mut p) => {
                if r.op == 18 {
                    p.bytes.truncate(r.capacity);
                    p.value = p.bytes.len() as i32;
                }
                Ok(Some(Response {
                    value: p.value as i64,
                    bytes: p.bytes,
                    stamp: p.stamp,
                }))
            }
            Err(EAGAIN)
                if matches!(r.op, 4 | 6 | 7)
                    && self.sockets[&r.fd].flags & SOCK_NONBLOCK == 0
                    && r.a & MSG_DONTWAIT == 0 =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}
fn parse_frame(bytes: &[u8]) -> Result<(IpMetadata, &[u8])> {
    let p = parse_ip(bytes)?;
    Ok((p.ip, p.payload))
}
fn ip_checksum(bytes: &[u8]) -> u16 {
    ntcp_ip::checksum(bytes)
}
fn frame(tx: ntcp::Transmit, tcp: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0; 20 + tcp.len()];
    packet[20..].copy_from_slice(tcp);
    ntcp_ip::encode(&mut packet, tx, 0).map_err(|_| EINVAL)?;
    Ok(packet)
}
fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let IpAddr::V4(ip) = addr.ip() else { panic!() };
    let raw = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        slice::from_raw_parts(
            (&raw as *const sockaddr_in).cast(),
            std::mem::size_of::<sockaddr_in>(),
        )
        .to_vec()
    }
}
fn decode_addr(bytes: &[u8]) -> Result<SocketAddr> {
    if bytes.len() != std::mem::size_of::<sockaddr_in>() {
        return Err(EINVAL);
    }
    let raw = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<sockaddr_in>()) };
    if raw.sin_family != AF_INET as u16 {
        return Err(EAFNOSUPPORT);
    }
    Ok(SocketAddr::new(
        Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()).into(),
        u16::from_be(raw.sin_port),
    ))
}
fn local() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}

fn syn(sequence: u32, destination_port: u16) -> Vec<u8> {
    syn_with_options(sequence, destination_port, &[])
}

fn syn_with_options(sequence: u32, destination_port: u16, options: &[u8]) -> Vec<u8> {
    let ip = IpMetadata {
        source: Ipv4Addr::new(192, 0, 2, 2).into(),
        destination: local().into(),
    };
    let header = ntcp::wire::Header {
        source_port: 50000,
        destination_port,
        sequence,
        acknowledgment: 0,
        flags: ntcp::wire::SYN,
        window: 65535,
        urgent_pointer: 0,
    };
    let mut tcp = [0; 64];
    let n = ntcp::wire::encode(ip, header, options, &[], &mut tcp).unwrap();
    frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len: n,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..n],
    )
    .unwrap()
}

fn execute_value(owner: &mut Owner, op: i32, fd: u64, key: i32, value: i32) -> Result<i64> {
    let (mut r, _) = request(op, fd, key, vec![], 0);
    r.b = value;
    owner.execute(&mut r).map(|r| r.unwrap().value)
}

fn input_packet(owner: &mut Owner, ip: IpMetadata, header: ntcp::wire::Header, options: &[u8]) {
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(ip, header, options, &[], &mut tcp).unwrap();
    let packet = frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..len],
    )
    .unwrap();
    let (mut r, _) = request(14, 0, 0, packet, 0);
    owner.execute(&mut r).unwrap();
}

fn poll_frame(owner: &mut Owner) -> Option<(ntcp::Transmit, Vec<u8>)> {
    let mut tcp = vec![0; BYTES - 20];
    let tx = owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet?;
    Some((tx, owner.frame(tx, &tcp[..tx.len]).unwrap()))
}

fn packet_header(bytes: &[u8]) -> ntcp::wire::Header {
    let (ip, tcp) = parse_frame(bytes).unwrap();
    ntcp::wire::parse(ip, tcp).unwrap().header
}

fn check_ip(bytes: &[u8], tos: u8, df: bool) {
    assert_eq!(bytes[1], tos);
    assert_eq!(
        u16::from_be_bytes([bytes[6], bytes[7]]),
        if df { 0x4000 } else { 0 }
    );
    assert_eq!(ip_checksum(&bytes[..20]), 0);
    parse_frame(bytes).unwrap();
}

fn reverse_ack(
    tx: ntcp::Transmit,
    sent: ntcp::wire::Header,
    ack: u32,
) -> (IpMetadata, ntcp::wire::Header) {
    (
        IpMetadata {
            source: tx.ip.destination,
            destination: tx.ip.source,
        },
        ntcp::wire::Header {
            source_port: sent.destination_port,
            destination_port: sent.source_port,
            sequence: 101,
            acknowledgment: ack,
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        },
    )
}

fn active_ip_connection(
    owner: &mut Owner,
    tos: i32,
    mode: i32,
) -> (u64, ConnectionId, ntcp::Transmit, ntcp::wire::Header) {
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    execute_value(owner, 11, fd, 6, tos).unwrap();
    execute_value(owner, 11, fd, 7, mode).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    let id = owner.connection(fd).unwrap();
    let (tx, bytes) = poll_frame(owner).unwrap();
    check_ip(&bytes, tos as u8 & !3, mode != IP_PMTUDISC_DONT);
    let sent = packet_header(&bytes);
    let (ip, mut reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    reply.sequence = 100;
    reply.flags |= ntcp::wire::SYN;
    input_packet(owner, ip, reply, &[2, 4, 5, 180, 1, 1, 4, 2]);
    assert_eq!(owner.inner.endpoint.state(id), Ok(State::Established));
    let (_, bytes) = poll_frame(owner).unwrap();
    check_ip(&bytes, tos as u8 & !3, mode != IP_PMTUDISC_DONT);
    (fd, id, tx, sent)
}

fn shutdown_data(owner: &mut Owner, tx: ntcp::Transmit, syn: ntcp::wire::Header, seq: u32) {
    let (ip, mut header) = reverse_ack(tx, syn, syn.sequence.wrapping_add(1));
    header.sequence = seq;
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(ip, header, &[], b"data", &mut tcp).unwrap();
    owner
        .inner
        .endpoint
        .input(owner.inner.now(), ip, &tcp[..len])
        .unwrap();
    owner.events();
}

fn shutdown_poll(fd: u64) -> Request {
    let p = pollfd {
        fd: fd as i32,
        events: POLLIN | POLLOUT,
        revents: 0,
    };
    let bytes = unsafe {
        slice::from_raw_parts((&p as *const pollfd).cast(), std::mem::size_of::<pollfd>())
    }
    .to_vec();
    request(13, 0, 0, bytes, std::mem::size_of::<pollfd>()).0
}

#[test]
fn ipv4_validation_and_address_roundtrip() {
    let packet = syn(7, 8080);
    let (ip, tcp) = parse_frame(&packet).unwrap();
    assert_eq!(ntcp::wire::parse(ip, tcp).unwrap().header.sequence, 7);
    assert_eq!(parse_frame(&packet[..19]).unwrap_err(), EINVAL);
    for index in [2, 10, 24, 36] {
        let mut malformed = packet.clone();
        malformed[index] ^= 1;
        assert_eq!(parse_frame(&malformed).unwrap_err(), EINVAL);
    }
    let mut malformed = packet.clone();
    malformed[6] |= 0x20;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    malformed = packet.clone();
    malformed[0] = 0x46;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    malformed[0] = 0x60;
    assert_eq!(parse_frame(&malformed).unwrap_err(), ENOSYS);
    let address = SocketAddr::new(local().into(), 8080);
    assert_eq!(decode_addr(&encode_addr(address)).unwrap(), address);
    assert!(profile("").is_err());
    assert_eq!(
        profile("baseline,local=192.0.2.1").unwrap(),
        (local(), Profile::Baseline)
    );
    assert!(profile("baseline,local=192.0.2.1,sack").is_err());
}

#[test]
fn reuseaddr_allows_rebinding_connected_socket_but_not_listener() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let address = SocketAddr::new(local().into(), 40000);
    let id = owner
        .inner
        .endpoint
        .connect(
            0,
            address,
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
        )
        .unwrap();
    let mut first = Socket::new(0);
    first.handle = Handle::Connection(id);
    first.local = Some(address);
    first.reuse = true;
    owner.alloc(first).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    let (mut bind, _) = request(2, fd, 0, encode_addr(address), 0);
    assert_eq!(owner.execute(&mut bind).err(), Some(EADDRINUSE));
    owner.sockets.get_mut(&fd).unwrap().reuse = true;
    assert!(owner.execute(&mut bind).unwrap().is_some());
    let (mut listen, _) = request(3, fd, 1, vec![], 0);
    assert!(owner.execute(&mut listen).unwrap().is_some());
    let mut third = Socket::new(0);
    third.reuse = true;
    bind.fd = owner.alloc(third).unwrap();
    assert_eq!(owner.execute(&mut bind).err(), Some(EADDRINUSE));
}

#[test]
fn socket_sends_wait_for_handshake_without_core_buffering() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
    let (mut connect, _) = request(5, fd, 0, encode_addr(remote), 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    let id = owner.connection(fd).unwrap();
    let (mut send, _) = request(7, fd, 0, vec![1, 2, 3, 4], 0);
    assert_eq!(owner.execute(&mut send).err(), Some(EAGAIN));
    owner.sockets.get_mut(&fd).unwrap().flags &= !SOCK_NONBLOCK;
    send.a = MSG_DONTWAIT;
    assert_eq!(owner.execute(&mut send).err(), Some(EAGAIN));
    send.a = 0;
    assert!(owner.execute(&mut send).unwrap().is_none());
    assert_eq!(
        owner
            .inner
            .endpoint
            .transport_info(owner.connection(fd).unwrap())
            .unwrap()
            .send_used as u64,
        0
    );
    assert_eq!(owner.inner.endpoint.state(id).unwrap(), State::SynSent);

    let mut tcp = [0; 1500];
    let tx = owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
    let ip = IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let header = ntcp::wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 100,
        acknowledgment: syn.sequence.wrapping_add(1),
        flags: ntcp::wire::SYN | ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    let n = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
    owner
        .inner
        .endpoint
        .input(owner.inner.now(), ip, &tcp[..n])
        .unwrap();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 4);
    assert_eq!(
        owner
            .inner
            .endpoint
            .transport_info(owner.connection(fd).unwrap())
            .unwrap()
            .send_used as u64,
        4
    );
    // Failed/pending sends must not have queued extra data in the core.
    let tx = owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    assert_eq!(
        ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().payload,
        &[1, 2, 3, 4]
    );
}

#[test]
fn profiles_require_one_selection_and_one_ipv4_address() {
    assert_eq!(
        profile("local=192.0.2.1,upstream-window8").unwrap(),
        (local(), Profile::UpstreamWindow8)
    );
    assert_eq!(
        profile("sack,local=192.0.2.1").unwrap(),
        (local(), Profile::Sack)
    );
    assert_eq!(
        profile("upstream-sack,local=192.0.2.1").unwrap(),
        (local(), Profile::UpstreamSack)
    );
    assert_eq!(
        profile("upstream-cubic,local=192.0.2.1").unwrap(),
        (local(), Profile::UpstreamCubic)
    );
    for flags in [
        "upstream-cubic",
        "upstream-cubic,upstream-sack,local=192.0.2.1",
        "upstream-cubic,upstream-cubic,local=192.0.2.1",
        "",
        "upstream-sack",
        "upstream-sack,sack,local=192.0.2.1",
        "upstream-sack,upstream-sack,local=192.0.2.1",
        "sack",
        "sack,sack,local=192.0.2.1",
        "baseline",
        "upstream-window8",
        "local=192.0.2.1",
        "baseline,baseline,local=192.0.2.1",
        "upstream-window8,upstream-window8,local=192.0.2.1",
        "baseline,upstream-window8,local=192.0.2.1",
        "upstream-window8,baseline,local=192.0.2.1",
        "baseline,local=192.0.2.1,local=192.0.2.1",
        "upstream-window8,local=192.0.2.1,local=192.0.2.2",
        "upstream-window8,local=::1",
        "baseline,local=invalid",
        "upstream-window8,local=192.0.2.1,sack",
        "upstream-window8,local=192.0.2.1,",
    ] {
        assert_eq!(profile(flags), Err(ENOSYS), "{flags}");
    }
}

#[test]
fn window8_acks_third_2000_byte_packet_before_application_read() {
    for selected in [
        Profile::Baseline,
        Profile::Sack,
        Profile::UpstreamSack,
        Profile::UpstreamWindow8,
    ] {
        let mut owner = Owner::new((local(), selected)).unwrap();
        let listener = owner.alloc(Socket::new(0)).unwrap();
        let (mut bind, _) = request(
            2,
            listener,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        );
        owner.execute(&mut bind).unwrap();
        execute_value(&mut owner, 3, listener, 1, 0).unwrap();
        let incoming_syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 7]);
        let ip = parse_frame(&incoming_syn).unwrap().0;
        let (mut incoming, _) = request(14, 0, 0, incoming_syn, 0);
        owner.execute(&mut incoming).unwrap();
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        let ack = packet_header(&bytes).sequence.wrapping_add(1);
        let mut header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: 8080,
            sequence: 101,
            acknowledgment: ack,
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        input_packet(&mut owner, ip, header, &[]);
        let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as u64;
        for i in 0..3 {
            header.sequence = 101 + i * 2000;
            let mut tcp = vec![0; 2020];
            let len = ntcp::wire::encode(ip, header, &[], &vec![0; 2000], &mut tcp).unwrap();
            let bytes = frame(
                ntcp::Transmit {
                    connection: None,
                    ip,
                    len,
                    hop_limit: 64,
                    dscp: 0,
                    ecn: 0,
                    ipv4_options: Default::default(),
                },
                &tcp[..len],
            )
            .unwrap();
            let (mut data, _) = request(14, 0, 0, bytes, 0);
            owner.execute(&mut data).unwrap();
            // Same owner iteration: process timers and poll real wire output,
            // without sleeping or advancing to the delayed-ACK deadline.
            owner
                .inner
                .endpoint
                .on_timeout(owner.inner.now(), BUDGET)
                .unwrap();
            let output = poll_frame(&mut owner);
            if selected == Profile::UpstreamWindow8 {
                let (_, bytes) = output.expect("immediate ACK before read");
                let sent = packet_header(&bytes);
                assert_eq!(sent.flags, ntcp::wire::ACK);
                assert_eq!(sent.acknowledgment, 101 + (i + 1) * 2000);
            } else {
                assert!(output.is_none(), "{selected:?} retains delayed ACK");
            }
            if i < 2 {
                let (mut read, _) = request(6, fd, 0, vec![], 2000);
                assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 2000);
                while poll_frame(&mut owner).is_some() {}
            }
        }
    }
}

#[test]
fn upstream_sack_rto_uses_linux_floor_while_baseline_keeps_core_floor() {
    for (profile, initial_rto, floor) in [
        (Profile::Baseline, 1_000_000, 1_000_000),
        (Profile::UpstreamSack, 300_000, 200_000),
    ] {
        let mut owner = Owner::new((local(), profile)).unwrap();
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0,
        );
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        let id = owner.connection(fd).unwrap();
        let mut tcp = vec![0; BYTES];
        let mut now = owner.inner.now();
        let tx = owner
            .inner
            .endpoint
            .poll_transmit(now, &mut tcp, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
        let (ip, mut reply) = reverse_ack(tx, syn, syn.sequence.wrapping_add(1));
        reply.sequence = 100;
        reply.flags |= ntcp::wire::SYN;
        let len =
            ntcp::wire::encode(ip, reply, &[2, 4, 5, 180, 1, 1, 4, 2], &[], &mut tcp).unwrap();
        now += 100_000;
        owner.inner.endpoint.input(now, ip, &tcp[..len]).unwrap();
        let info = owner.inner.endpoint.transport_info(id).unwrap();
        assert_eq!(info.state, State::Established);
        assert_eq!(info.rtt_us, Some(100_000));
        assert_eq!(info.rto_us, initial_rto, "{profile:?}");
        // Drain the handshake ACK, then reduce RTTVAR with three 100 ms samples.
        owner
            .inner
            .endpoint
            .poll_transmit(now, &mut tcp, BUDGET)
            .unwrap();
        for _ in 0..3 {
            owner.inner.endpoint.write(id, b"data").unwrap();
            let tx = owner
                .endpoint
                .poll_transmit(now, &mut tcp, BUDGET)
                .unwrap()
                .packet
                .unwrap();
            let sent = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap();
            let (ip, reply) = reverse_ack(
                tx,
                sent.header,
                sent.header.sequence.wrapping_add(sent.payload.len() as u32),
            );
            let len = ntcp::wire::encode(ip, reply, &[], &[], &mut tcp).unwrap();
            now += 100_000;
            owner.inner.endpoint.input(now, ip, &tcp[..len]).unwrap();
        }
        let info = owner.inner.endpoint.transport_info(id).unwrap();
        assert_eq!(info.rtt_us, Some(100_000));
        assert_eq!(info.rto_us, floor, "{profile:?}");
        // Query the real owner snapshot after ACK-driven cwnd growth. Never
        // substitute the upstream CUBIC script's expected seven segments.
        let (mut query, _) = request(18, fd, 1, vec![], TCP_INFO_SIZE);
        let data = owner.execute(&mut query).unwrap().unwrap().bytes;
        for (offset, actual) in [(76, info.ssthresh), (80, info.cwnd)] {
            assert_eq!(
                u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()),
                actual / info.mss,
                "{profile:?} TCP_INFO offset {offset}"
            );
        }
    }
}

#[test]
fn profiles_charge_actual_receive_capacity_and_enforce_aggregate_cap() {
    for (name, receive_capacity) in [
        ("baseline", 65535),
        ("upstream-window8", 8 * 1024 * 1024),
        ("upstream-sack", 8 * 1024 * 1024),
    ] {
        let mut owner = Owner::new(profile(&format!("{name},local=192.0.2.1")).unwrap()).unwrap();
        // Learn the core's private metadata charge from the first connection;
        // verify it covers buffers and at least one timestamp per send octet.
        let first = owner
            .inner
            .endpoint
            .connect(
                0,
                SocketAddr::new(local().into(), 40000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
            )
            .unwrap();
        assert_eq!(
            owner
                .endpoint
                .transport_info(first)
                .unwrap()
                .receive_capacity,
            receive_capacity
        );
        let per_connection = owner.inner.endpoint.buffer_bytes();
        assert!(
            per_connection
                >= 3 * receive_capacity + 2 * 65536 + 1460 + 8 * (65536 + 2) + (65536 / 2 + 4) * 8
        );
        let max_bytes = 32 * 1024 * 1024;
        let count = LIMIT.min(max_bytes / per_connection);
        for i in 1..count {
            owner
                .endpoint
                .connect(
                    0,
                    SocketAddr::new(local().into(), 40000 + i as u16),
                    SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
                )
                .unwrap();
            assert_eq!(
                owner.inner.endpoint.buffer_bytes(),
                (i + 1) * per_connection
            );
            assert!(owner.inner.endpoint.buffer_bytes() <= max_bytes);
        }
        assert_eq!(
            owner.inner.endpoint.connect(
                0,
                SocketAddr::new(local().into(), 50000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080),
            ),
            Err(EndpointError::LimitReached)
        );
        assert_eq!(owner.inner.endpoint.buffer_bytes(), count * per_connection);
    }
}

#[test]
fn user_timeout_preconnect_updates_reset_and_deadlines() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert_eq!(execute_value(&mut owner, 11, fd, 5, -1), Err(EINVAL));
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert_eq!(user_timeout_us(0), Ok(None));
    execute_value(&mut owner, 11, fd, 5, i32::MAX).unwrap();
    assert_eq!(user_timeout_us(i32::MAX), Ok(Some(2_147_483_647_000)));
    execute_value(&mut owner, 11, fd, 5, 1234).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    let mut tcp = [0; 1500];
    let sent_at = owner.inner.now();
    let tx = owner
        .inner
        .endpoint
        .poll_transmit(sent_at, &mut tcp, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
    let ip = IpMetadata {
        source: tx.ip.destination,
        destination: tx.ip.source,
    };
    let header = ntcp::wire::Header {
        source_port: syn.destination_port,
        destination_port: syn.source_port,
        sequence: 100,
        acknowledgment: syn.sequence.wrapping_add(1),
        flags: ntcp::wire::SYN | ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    let n = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
    let established_at = owner.inner.now();
    owner
        .inner
        .endpoint
        .input(established_at, ip, &tcp[..n])
        .unwrap();
    let id = owner.connection(fd).unwrap();
    owner.inner.endpoint.write(id, b"data").unwrap();
    owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
        .unwrap();
    execute_value(&mut owner, 11, fd, 5, 1).unwrap();
    assert_eq!(
        owner.inner.endpoint.next_deadline(),
        Some(established_at + 1000)
    );
    execute_value(&mut owner, 11, fd, 5, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(0));
    assert!(owner.inner.endpoint.next_deadline().unwrap() > established_at + 1000);
    assert_eq!(execute_value(&mut owner, 11, fd, 99, 1), Err(ENOSYS));
    assert_eq!(execute_value(&mut owner, 17, u64::MAX, 0, 0), Err(EBADF));
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    execute_value(&mut owner, 11, fd, 5, 1).unwrap();
    owner
        .inner
        .endpoint
        .on_timeout(established_at + 1000, BUDGET)
        .unwrap();
    owner.events();
    assert_eq!(
        execute_value(&mut owner, 12, fd, 3, 0),
        Ok(ETIMEDOUT as i64)
    );
}

#[test]
fn listener_timeout_inheritance_and_queued_payload_gap_urgent_fin() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 5, 1234).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 1, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 17, listener, 0, 0), Err(EINVAL));
    let ip = parse_frame(&syn(100, 8080)).unwrap().0;
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let mut out = [0; 1500];
    let tx = owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut out, BUDGET)
        .unwrap()
        .packet
        .unwrap();
    let ack = ntcp::wire::parse(tx.ip, &out[..tx.len])
        .unwrap()
        .header
        .sequence
        .wrapping_add(1);
    let mut inject = |owner: &mut Owner, seq, flags, urgent, payload: &[u8]| {
        let header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: 8080,
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 65535,
            urgent_pointer: urgent,
        };
        let n = ntcp::wire::encode(ip, header, &[], payload, &mut out).unwrap();
        let packet = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len: n,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &out[..n],
        )
        .unwrap();
        let (mut incoming, _) = request(14, 0, 0, packet, 0);
        owner.execute(&mut incoming).unwrap();
    };
    inject(&mut owner, 101, ntcp::wire::ACK, 0, &[]);
    execute_value(&mut owner, 11, listener, 5, 3456).unwrap();
    let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as u64;
    let id = owner.connection(fd).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    execute_value(&mut owner, 11, listener, 5, 3456).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(1234));
    owner.inner.endpoint.write(id, b"x").unwrap();
    let mut outgoing = [0; 1500];
    owner
        .inner
        .endpoint
        .poll_transmit(owner.inner.now(), &mut outgoing, BUDGET)
        .unwrap();
    assert_eq!(
        owner.inner.endpoint.application_timeout(id),
        Ok(Some(1_234_000))
    );
    assert!(owner.inner.endpoint.next_deadline().unwrap() <= 1_234_000);
    assert_eq!(owner.inner.endpoint.readable_bytes(id), Ok(0));
    inject(
        &mut owner,
        104,
        ntcp::wire::ACK | ntcp::wire::FIN | ntcp::wire::URG,
        3,
        b"def",
    );
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    inject(&mut owner, 101, ntcp::wire::ACK, 0, b"abc");
    for _ in 0..2 {
        assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(6));
    }
    assert_eq!(owner.inner.endpoint.urgent_remaining(id), Ok(6));
    let (mut read, _) = request(6, fd, 0, vec![], 2);
    let response = owner.execute(&mut read).unwrap().unwrap();
    assert_eq!(response.bytes, b"ab");
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(4));
    execute_value(&mut owner, 11, fd, 5, 4567).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 5, 0), Ok(4567));
    read.capacity = 8;
    assert_eq!(owner.execute(&mut read).unwrap().unwrap().bytes, b"cdef");
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
    assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 0);
    assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
}

#[test]
fn logical_ephemeral_ports_do_not_follow_reused_os_descriptors() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let remote = encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080));
    for port in 40000..40004 {
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(5, fd, 0, remote.clone(), 0);
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        assert_eq!(owner.sockets[&fd].local.unwrap().port(), port);
        execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    }
    owner.next_port = 60000;
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let (mut connect, _) = request(5, fd, 0, remote, 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(EADDRNOTAVAIL));
}

#[test]
fn upstream_profiles_use_iw10() {
    for (profile, expected) in [
        (Profile::Baseline, 4380),
        (Profile::UpstreamWindow8, 4380),
        (Profile::Sack, 4380),
        (Profile::UpstreamSack, 14600),
        (Profile::UpstreamCubic, 14600),
        (Profile::UpstreamEcn, 14600),
        (Profile::UpstreamBasic, 14600),
    ] {
        let mut owner = Owner::new((local(), profile)).unwrap();
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0,
        );
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        let mut tcp = vec![0; BYTES];
        let tx = owner
            .inner
            .endpoint
            .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
        assert_eq!(
            syn.flags & (ntcp::wire::ECE | ntcp::wire::CWR),
            if profile == Profile::UpstreamEcn {
                ntcp::wire::ECE | ntcp::wire::CWR
            } else {
                0
            }
        );
        let ip = IpMetadata {
            source: tx.ip.destination,
            destination: tx.ip.source,
        };
        let header = ntcp::wire::Header {
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            sequence: 100,
            acknowledgment: syn.sequence.wrapping_add(1),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        let n = ntcp::wire::encode(ip, header, &[2, 4, 5, 180], &[], &mut tcp).unwrap();
        owner
            .inner
            .endpoint
            .input(owner.inner.now(), ip, &tcp[..n])
            .unwrap();
        let id = owner.connection(fd).unwrap();
        owner.inner.endpoint.write(id, &vec![0; 20000]).unwrap();
        let mut flight = 0;
        while let Some(tx) = owner
            .inner
            .endpoint
            .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
            .unwrap()
            .packet
        {
            flight += ntcp::wire::parse(tx.ip, &tcp[..tx.len])
                .unwrap()
                .payload
                .len();
        }
        assert_eq!(flight, expected, "{profile:?}");
        owner.inner.endpoint.abort(id).unwrap();
        let tx = owner
            .inner
            .endpoint
            .poll_transmit(owner.inner.now(), &mut tcp, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        let reset = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap();
        assert_eq!(
            reset.header.flags,
            ntcp::wire::RST
                | if profile == Profile::UpstreamBasic {
                    ntcp::wire::ACK
                } else {
                    0
                },
            "{profile:?}"
        );
        assert_eq!(reset.header.acknowledgment, 101);
        // A different port is an unmatched tuple, not a local abort.
        input_packet(
            &mut owner,
            ip,
            ntcp::wire::Header {
                destination_port: header.destination_port.wrapping_add(1),
                acknowledgment: 123,
                flags: ntcp::wire::ACK,
                ..header
            },
            &[],
        );
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        let reset = packet_header(&bytes);
        assert_eq!(reset.flags, ntcp::wire::RST, "{profile:?}");
        assert_eq!(reset.sequence, 123);
    }
}

#[test]
fn ip_options_pending_connect_updates_and_engine_owned_ecn() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(0));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_WANT as i64)
    );
    execute_value(&mut owner, 11, fd, 6, 7).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DONT).unwrap();
    let (mut connect, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert!(owner.execute(&mut connect).unwrap().is_none());
    assert!(connect.started);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 4, false);
    let sent = packet_header(&bytes);
    for bad in [-1, 3, 4, 5, 6] {
        assert_eq!(
            execute_value(&mut owner, 11, fd, 7, bad),
            Err(if (3..=5).contains(&bad) {
                ENOSYS
            } else {
                EINVAL
            })
        );
        assert_eq!(
            execute_value(&mut owner, 12, fd, 7, 0),
            Ok(IP_PMTUDISC_DONT as i64)
        );
    }
    execute_value(&mut owner, 11, fd, 6, 255).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DO).unwrap();
    let (ip, mut reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    reply.flags |= ntcp::wire::SYN;
    reply.sequence = 100;
    input_packet(&mut owner, ip, reply, &[2, 4, 5, 180]);
    assert!(owner.execute(&mut connect).unwrap().is_some());
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 252, true);
    // Framing must preserve an engine-produced ECN codepoint, not socket ECN bits.
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(tx.ip, sent, &[], &[], &mut tcp).unwrap();
    let engine_tx = ntcp::Transmit {
        len,
        dscp: 63,
        ecn: 2,
        ..tx
    };
    check_ip(&owner.frame(engine_tx, &tcp[..len]).unwrap(), 254, true);
    let id = owner.connection(fd).unwrap();
    for mode in [IP_PMTUDISC_WANT, IP_PMTUDISC_DONT, IP_PMTUDISC_DO] {
        execute_value(&mut owner, 11, fd, 7, mode).unwrap();
        execute_value(&mut owner, 11, fd, 6, 4).unwrap();
        let before = owner.inner.endpoint.buffer_bytes();
        let (mut write, _) = request(7, fd, 0, b"data".to_vec(), 0);
        assert_eq!(owner.execute(&mut write).unwrap().unwrap().value, 4);
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        check_ip(&bytes, 4, mode != IP_PMTUDISC_DONT);
        let header = packet_header(&bytes);
        let acknowledged = owner.inner.endpoint.acknowledged(id).unwrap();
        let deadline = owner.inner.endpoint.next_deadline();
        execute_value(&mut owner, 11, fd, 6, 0).unwrap();
        assert_eq!(owner.inner.endpoint.buffer_bytes(), before);
        assert_eq!(owner.inner.endpoint.next_deadline(), deadline);
        assert_eq!(owner.inner.endpoint.acknowledged(id).unwrap(), acknowledged);
        let (ip, reply) = reverse_ack(tx, header, header.sequence.wrapping_add(4));
        input_packet(&mut owner, ip, reply, &[]);
        assert_eq!(
            owner.inner.endpoint.acknowledged(id).unwrap(),
            acknowledged + 4
        );
    }
    // A failed core update must not partially change either socket or IP policy.
    let (ip, mut reset) = reverse_ack(tx, sent, sent.sequence.wrapping_add(13));
    reset.flags = ntcp::wire::RST;
    input_packet(&mut owner, ip, reset, &[]);
    assert_eq!(owner.inner.endpoint.state(id), Ok(State::Closed));
    owner.inner.endpoint.release(id).unwrap();
    let previous = (owner.sockets[&fd].tos, owner.sockets[&fd].discover);
    assert_eq!(execute_value(&mut owner, 11, fd, 6, 40), Err(EBADF));
    assert_eq!(
        execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DONT),
        Err(EBADF)
    );
    assert_eq!(
        (owner.sockets[&fd].tos, owner.sockets[&fd].discover),
        previous
    );
    assert_eq!(
        owner
            .connection_options
            .iter()
            .find(|p| p.0 == id)
            .map(|p| (p.1, p.2))
            .unwrap(),
        previous
    );
}

#[test]
fn passive_ack_fin_snapshots_zerocopy_before_accept_and_returns_eof() {
    for enabled in [0, 1] {
        let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
        let listener = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        execute_value(&mut owner, 11, listener, 8, enabled).unwrap();
        let (mut bind, _) = request(
            2,
            listener,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        );
        owner.execute(&mut bind).unwrap();
        execute_value(&mut owner, 3, listener, 1, 0).unwrap();
        let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
        owner.execute(&mut incoming).unwrap();
        let (tx, bytes) = poll_frame(&mut owner).unwrap();
        let sent = packet_header(&bytes);
        let (ip, mut reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
        reply.flags |= ntcp::wire::FIN;
        input_packet(&mut owner, ip, reply, &[]);
        execute_value(&mut owner, 11, listener, 8, 1 - enabled).unwrap();
        let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as u64;
        let id = owner.connection(fd).unwrap();
        assert_eq!(owner.inner.endpoint.state(id), Ok(State::CloseWait));
        assert_eq!(execute_value(&mut owner, 12, fd, 8, 0), Ok(enabled as i64));
        let (mut read, _) = request(6, fd, MSG_DONTWAIT, vec![], 1);
        assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 0);
        assert_eq!(execute_value(&mut owner, 4, listener, 0, 0), Err(EAGAIN));
    }
}

#[test]
fn ip_options_changes_preserve_sack_holes_and_data_ack() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let (fd, id, handshake_tx, _) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_DONT);
    let data: Vec<u8> = (0..4380).map(|i| (i % 251) as u8).collect();
    let (mut write, _) = request(7, fd, 0, data.clone(), 0);
    owner.execute(&mut write).unwrap();
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    let first = packet_header(&bytes);
    let base = first.sequence;
    let (original_ip, original_tcp) = parse_frame(&bytes).unwrap();
    let mut original_bytes = ntcp::wire::parse(original_ip, original_tcp)
        .unwrap()
        .payload
        .len();
    while let Some((_, bytes)) = poll_frame(&mut owner) {
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        original_bytes += ntcp::wire::parse(ip, tcp).unwrap().payload.len();
    }
    assert_eq!(original_bytes, data.len());
    let (ip, reply) = reverse_ack(handshake_tx, first, base);
    let mut sack = vec![1, 1, 5, 10];
    sack.extend_from_slice(&base.wrapping_add(1460).to_be_bytes());
    sack.extend_from_slice(&base.wrapping_add(1940).to_be_bytes());
    input_packet(&mut owner, ip, reply, &sack);
    let bytes_reserved = owner.inner.endpoint.buffer_bytes();
    let deadline = owner.inner.endpoint.next_deadline();
    execute_value(&mut owner, 11, fd, 6, 4).unwrap();
    execute_value(&mut owner, 11, fd, 6, 0).unwrap();
    assert_eq!(execute_value(&mut owner, 11, fd, 7, 3), Err(ENOSYS));
    assert_eq!(owner.inner.endpoint.buffer_bytes(), bytes_reserved);
    assert_eq!(owner.inner.endpoint.next_deadline(), deadline);
    assert_eq!(owner.inner.endpoint.acknowledged(id), Ok(0));
    for edge in [2420, 2920] {
        sack[8..12].copy_from_slice(&base.wrapping_add(edge).to_be_bytes());
        input_packet(&mut owner, ip, reply, &sack);
    }
    let mut retransmitted = 0;
    while let Some((_, bytes)) = poll_frame(&mut owner) {
        check_ip(&bytes, 0, false);
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        if !segment.payload.is_empty() {
            let start = segment.header.sequence.wrapping_sub(base) as usize;
            let end = start + segment.payload.len();
            assert!(end <= 1460 || start >= 2920, "retransmitted SACKed bytes");
            assert_eq!(segment.payload, &data[start..end]);
            retransmitted += segment.payload.len();
        }
    }
    assert!(retransmitted >= 1460);
    let (_, final_ack) = reverse_ack(handshake_tx, first, base.wrapping_add(data.len() as u32));
    input_packet(&mut owner, ip, final_ack, &[]);
    assert_eq!(owner.inner.endpoint.acknowledged(id), Ok(data.len() as u64));
}

#[test]
fn transport_encoding_counts_recovery_and_invalid_ledger() {
    let mut owner = Owner::new((local(), Profile::UpstreamSack)).unwrap();
    let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let (mut req, _) = request(
        5,
        fd,
        0,
        encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
        0,
    );
    assert_eq!(owner.execute(&mut req).err(), Some(EINPROGRESS));
    let mut info = owner
        .inner
        .endpoint
        .transport_info(owner.connection(fd).unwrap())
        .unwrap();
    let data = transport_option(info, 1).unwrap();
    assert_eq!(data.len(), 280);
    for (offset, actual) in [(76, info.ssthresh), (80, info.cwnd)] {
        assert_eq!(
            u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()),
            actual / info.mss
        );
    }
    // Distinct non-MSS-multiple byte values verify truncating segment units,
    // including during recovery, rather than a hard-coded CUBIC expectation.
    info.mss = 1000;
    info.cwnd = 5999;
    info.ssthresh = 8999;
    // Exercise each ABI category independently of packet sequence fixtures.
    info.unacked = 10;
    info.sacked = 3;
    info.lost = 2;
    info.retransmitted = 1;
    info.reordering = 7;
    let data = transport_option(info, 1).unwrap();
    for (offset, count) in [(24, 10), (28, 3), (32, 2), (36, 1), (88, 7)] {
        assert_eq!(
            u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()),
            count
        );
    }
    assert_eq!(data[1], 1);
    info.recovery = true;
    let data = transport_option(info, 1).unwrap();
    assert_eq!(data[1], 3);
    assert_eq!(u32::from_ne_bytes(data[76..80].try_into().unwrap()), 8);
    assert_eq!(u32::from_ne_bytes(data[80..84].try_into().unwrap()), 5);
    info.loss = true;
    assert_eq!(transport_option(info, 1).unwrap()[1], 4);
    info.ledger_valid = false;
    assert_eq!(transport_option(info, 1).err(), Some(ENOSYS));
    assert!(transport_option(info, 2).unwrap().is_empty());
    assert_eq!(transport_option(info, 3).unwrap().len(), 36);
}

#[test]
fn shutdown_modes_drain_queue_repeat_and_preserve_single_fin() {
    for how in [SHUT_RD, SHUT_WR, SHUT_RDWR] {
        let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
        let (fd, id, tx, syn) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_WANT);
        for invalid in [-1, 3, i32::MAX] {
            assert_eq!(execute_value(&mut owner, 9, fd, invalid, 0), Err(EINVAL));
            assert!(!owner.sockets[&fd].read_shutdown);
            assert!(!owner.sockets[&fd].write_shutdown);
            assert!(poll_frame(&mut owner).is_none());
        }
        shutdown_data(&mut owner, tx, syn, 101);
        for _ in 0..3 {
            assert_eq!(execute_value(&mut owner, 9, fd, how, 0), Ok(0));
        }
        assert_eq!(owner.sockets[&fd].read_shutdown, how != SHUT_WR);
        assert_eq!(owner.sockets[&fd].write_shutdown, how != SHUT_RD);
        assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(4));
        let (mut read, _) = request(6, fd, 0, vec![], 10);
        assert_eq!(owner.execute(&mut read).unwrap().unwrap().bytes, b"data");
        assert_eq!(execute_value(&mut owner, 17, fd, 0, 0), Ok(0));
        if how == SHUT_WR {
            assert_eq!(owner.execute(&mut read).err(), Some(EAGAIN));
        } else {
            assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 0);
        }
        let mut poll = shutdown_poll(fd);
        let response = owner.execute(&mut poll).unwrap().unwrap();
        let p = unsafe { ptr::read_unaligned(response.bytes.as_ptr().cast::<pollfd>()) };
        assert_eq!(p.revents & POLLIN != 0, how != SHUT_WR);
        assert_eq!(p.revents & POLLHUP != 0, how == SHUT_RDWR);
        assert_ne!(p.revents & POLLOUT, 0);
        let (mut write, _) = request(7, fd, 0, b"send".to_vec(), 0);
        if how == SHUT_RD {
            assert_eq!(owner.execute(&mut write).unwrap().unwrap().value, 4);
            shutdown_data(&mut owner, tx, syn, 105);
            assert_eq!(owner.execute(&mut read).unwrap().unwrap().bytes, b"data");
            assert_eq!(owner.execute(&mut read).unwrap().unwrap().value, 0);
            // Upgrade RD to RDWR; the write half shuts down exactly once.
            assert_eq!(execute_value(&mut owner, 9, fd, SHUT_RDWR, 0), Ok(0));
        } else {
            assert_eq!(owner.execute(&mut write).err(), Some(EPIPE));
        }
        assert_eq!(execute_value(&mut owner, 9, fd, SHUT_RDWR, 0), Ok(0));
        assert_eq!(execute_value(&mut owner, 8, fd, 0, 0), Ok(0));
        let mut fins = 0;
        while let Some((_, bytes)) = poll_frame(&mut owner) {
            let h = packet_header(&bytes);
            assert_eq!(h.flags & ntcp::wire::RST, 0);
            fins += usize::from(h.flags & ntcp::wire::FIN != 0);
        }
        assert_eq!(
            fins, 1,
            "{how}: shutdown/repeat/close must queue only one FIN"
        );
        assert_eq!(owner.inner.endpoint.state(id), Ok(State::FinWait1));
    }
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    assert_eq!(
        execute_value(&mut owner, 9, u64::MAX, SHUT_RD, 0),
        Err(EBADF)
    );
    let fd = owner.alloc(Socket::new(0)).unwrap();
    assert_eq!(execute_value(&mut owner, 9, fd, SHUT_RD, 0), Err(ENOTCONN));
}

#[test]
fn shutdown_close_resets_unread_data_in_all_modes() {
    for how in [SHUT_RD, SHUT_WR, SHUT_RDWR] {
        let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
        let (fd, id, tx, syn) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_WANT);
        shutdown_data(&mut owner, tx, syn, 101);
        execute_value(&mut owner, 9, fd, how, 0).unwrap();
        execute_value(&mut owner, 8, fd, 0, 0).unwrap();
        assert_eq!(
            owner.inner.endpoint.close_reason(id),
            Ok(Some(CloseReason::Aborted))
        );
        let (_, bytes) = poll_frame(&mut owner).unwrap();
        assert_ne!(packet_header(&bytes).flags & ntcp::wire::RST, 0);
        assert!(poll_frame(&mut owner).is_none());
    }
}

#[test]
fn native_tcp_shutdown_precedes_inaccessible_send_payload() {
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    unsafe {
        let payload = mmap(
            ptr::null_mut(),
            4096,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(payload, MAP_FAILED);
        assert_eq!(send(stream.as_raw_fd(), payload, 6, MSG_NOSIGNAL), -1);
        assert_eq!(*__errno_location(), EPIPE);
        let mut vector = iovec {
            iov_base: payload,
            iov_len: 6,
        };
        let mut msg: msghdr = std::mem::zeroed();
        msg.msg_iov = &mut vector;
        msg.msg_iovlen = 1;
        assert_eq!(sendmsg(stream.as_raw_fd(), &msg, MSG_NOSIGNAL), -1);
        assert_eq!(*__errno_location(), EPIPE);
        assert_eq!(send(stream.as_raw_fd(), ptr::null(), 6, MSG_NOSIGNAL), -1);
        assert_eq!(*__errno_location(), EPIPE);
        vector.iov_base = ptr::null_mut();
        msg.msg_iov = &mut vector;
        assert_eq!(sendmsg(stream.as_raw_fd(), &msg, MSG_NOSIGNAL), -1);
        assert_eq!(*__errno_location(), EPIPE);
        assert_eq!(munmap(payload, 4096), 0);
    }
}

#[test]
fn cubic_real_loss_snapshot_and_upstream_reno_independence() {
    for (profile, pacing, threshold) in [
        (Profile::UpstreamCubic, Some(true), 7),
        (Profile::UpstreamCubic, Some(false), 7),
        (Profile::UpstreamCubic, None, 7),
        (Profile::UpstreamSack, Some(true), 5),
        (Profile::UpstreamSack, Some(false), 5),
        (Profile::UpstreamSack, None, 5),
    ] {
        let mut owner = match pacing {
            Some(pacing) => Owner::new_with_prr_pacing((local(), profile), pacing),
            None => Owner::new((local(), profile)),
        }
        .unwrap();
        // Default CUBIC matches explicit false; legacy Reno ignores pacing.
        let pacing = pacing.unwrap_or(profile != Profile::UpstreamCubic);
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        let (mut connect, _) = request(
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0,
        );
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        let id = owner.connection(fd).unwrap();
        let mut tcp = vec![0; BYTES];
        let now = owner.inner.now();
        let tx = owner
            .inner
            .endpoint
            .poll_transmit(now, &mut tcp, BUDGET)
            .unwrap()
            .packet
            .unwrap();
        let syn = ntcp::wire::parse(tx.ip, &tcp[..tx.len]).unwrap().header;
        let (ip, mut ack) = reverse_ack(tx, syn, syn.sequence.wrapping_add(1));
        ack.sequence = 100;
        ack.flags |= ntcp::wire::SYN;
        let n = ntcp::wire::encode(ip, ack, &[2, 4, 3, 232, 1, 1, 4, 2], &[], &mut tcp).unwrap();
        owner
            .inner
            .endpoint
            .input(now + 10_000, ip, &tcp[..n])
            .unwrap();
        owner
            .inner
            .endpoint
            .poll_transmit(now + 10_000, &mut tcp, BUDGET)
            .unwrap();
        owner.inner.endpoint.write(id, &[0; 10_000]).unwrap();
        let mut emitted = 0;
        while let Some(tx) = owner
            .inner
            .endpoint
            .poll_transmit(now + 10_000, &mut tcp, BUDGET)
            .unwrap()
            .packet
        {
            emitted += ntcp::wire::parse(tx.ip, &tcp[..tx.len])
                .unwrap()
                .payload
                .len();
        }
        assert_eq!(
            emitted,
            if profile == Profile::UpstreamCubic && pacing {
                1000
            } else {
                10_000
            }
        );
        for tick in 11..=19 {
            owner
                .endpoint
                .on_timeout(now + tick * 1000, BUDGET)
                .unwrap();
            while let Some(tx) = owner
                .endpoint
                .poll_transmit(now + tick * 1000, &mut tcp, BUDGET)
                .unwrap()
                .packet
            {
                emitted += ntcp::wire::parse(tx.ip, &tcp[..tx.len])
                    .unwrap()
                    .payload
                    .len();
            }
        }
        assert_eq!(emitted, 10_000);
        assert_eq!(
            owner.inner.endpoint.transport_info(id).unwrap().cwnd,
            10_000
        );
        ack.sequence = 101;
        ack.flags = ntcp::wire::ACK;
        for i in 0..3 {
            let mut sack = vec![5, 10];
            sack.extend_from_slice(&ack.acknowledgment.wrapping_add(1000).to_be_bytes());
            sack.extend_from_slice(
                &ack.acknowledgment
                    .wrapping_add(2000 + i * 1000)
                    .to_be_bytes(),
            );
            sack.extend_from_slice(&[1, 1]);
            let n = ntcp::wire::encode(ip, ack, &sack, &[], &mut tcp).unwrap();
            owner
                .endpoint
                .input(now + 40_000 + u64::from(i) * 2000, ip, &tcp[..n])
                .unwrap();
        }
        assert_eq!(
            owner.inner.endpoint.transport_info(id).unwrap().ssthresh,
            threshold * 1000
        );
        ack.acknowledgment = ack.acknowledgment.wrapping_add(10_000);
        let n = ntcp::wire::encode(ip, ack, &[], &[], &mut tcp).unwrap();
        owner
            .inner
            .endpoint
            .input(now + 50_000, ip, &tcp[..n])
            .unwrap();
        let info = owner.inner.endpoint.transport_info(id).unwrap();
        assert_eq!(
            info.cwnd,
            if profile == Profile::UpstreamCubic {
                7000
            } else {
                2000
            }
        );
        let (mut query, _) = request(18, fd, 1, vec![], TCP_INFO_SIZE);
        let bytes = owner.execute(&mut query).unwrap().unwrap().bytes;
        for (offset, value) in [(76, info.ssthresh), (80, info.cwnd)] {
            assert_eq!(
                u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                value / 1000
            );
        }
    }
}

#[test]
fn copied_completions_wrap_coalesce_and_reserve_before_accepting_bytes() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let (fd, id, _, _) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_WANT);
    execute_value(&mut owner, 11, fd, 8, 1).unwrap();
    owner.sockets.get_mut(&fd).unwrap().zc_next = u32::MAX - 1;
    for _ in 0..3 {
        let (mut send, _) = request(7, fd, MSG_ZEROCOPY, b"x".to_vec(), 0);
        assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 1);
    }
    assert_eq!(owner.sockets[&fd].zc_next, 1);
    assert_eq!(owner.sockets[&fd].completions, [(u32::MAX - 1, 0)]);
    let mut control = [0u8; 64];
    let mut header: msghdr = unsafe { std::mem::zeroed() };
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len();
    let bytes = unsafe {
        slice::from_raw_parts(
            (&header as *const msghdr).cast(),
            std::mem::size_of::<msghdr>(),
        )
        .to_vec()
    };
    let (mut receive, _) = request(22, fd, MSG_ERRQUEUE, bytes, std::mem::size_of::<msghdr>());
    receive.destinations = vec![(
        (&mut header as *mut msghdr) as usize,
        std::mem::size_of::<msghdr>(),
    )];
    assert_eq!(owner.execute(&mut receive).unwrap().unwrap().value, 0);
    let offset = std::mem::size_of::<cmsghdr>();
    assert_eq!(
        u32::from_ne_bytes(control[offset + 8..offset + 12].try_into().unwrap()),
        u32::MAX - 1
    );
    assert_eq!(
        u32::from_ne_bytes(control[offset + 12..offset + 16].try_into().unwrap()),
        0
    );
    assert_eq!(header.msg_flags, MSG_ERRQUEUE);
    assert_eq!(owner.execute(&mut receive).err(), Some(EAGAIN));
    // Seed unreachable-in-a-short-test ranges to exercise the real capacity gate.
    owner.sockets.get_mut(&fd).unwrap().completions =
        (0..LIMIT as u32).map(|n| (n + 10, n + 10)).collect();
    let written = owner
        .inner
        .endpoint
        .transport_info(owner.connection(fd).unwrap())
        .unwrap()
        .send_used as u64;
    let used = owner.inner.endpoint.transport_info(id).unwrap().send_used;
    let (mut send, _) = request(7, fd, MSG_ZEROCOPY, vec![], 0);
    send.destinations = vec![(1, 1)];
    assert_eq!(owner.execute(&mut send).err(), Some(ENOBUFS));
    assert_eq!(
        owner
            .inner
            .endpoint
            .transport_info(owner.connection(fd).unwrap())
            .unwrap()
            .send_used as u64,
        written
    );
    assert_eq!(
        owner.inner.endpoint.transport_info(id).unwrap().send_used,
        used
    );
    assert_eq!(owner.sockets[&fd].zc_next, 1);
    assert_eq!(send.destinations, [(1, 1)]); // Capacity failure precedes payload faults.
    send.destinations.clear();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 0);
    let next = owner.sockets[&fd].completions.back().unwrap().1 + 1;
    owner.sockets.get_mut(&fd).unwrap().zc_next = next;
    send.bytes = b"x".to_vec();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 1);
    assert_eq!(owner.sockets[&fd].completions.len(), LIMIT);
    assert_eq!(owner.sockets[&fd].completions.back().unwrap().1, next);
    // A range covering almost a full counter turn cannot grow to 2^32 IDs.
    let socket = owner.sockets.get_mut(&fd).unwrap();
    socket.completions = [(1, u32::MAX)].into();
    socket.zc_next = 0;
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 1);
    assert_eq!(owner.sockets[&fd].completions, [(1, u32::MAX), (0, 0)]);
    execute_value(&mut owner, 11, fd, 8, 0).unwrap();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 1);
    assert_eq!(owner.sockets[&fd].zc_next, 1);
    execute_value(&mut owner, 11, fd, 8, 1).unwrap();
    assert_eq!(owner.execute(&mut send).unwrap().unwrap().value, 1);
    assert_eq!(owner.sockets[&fd].completions, [(1, u32::MAX), (0, 1)]);
}

#[test]
fn owner_constructs_endpoint_and_preserves_output_under_backpressure() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    for i in 0..LIMIT + 4 {
        // Respect Endpoint's separate 128-control-replies/second rate limit.
        if i == LIMIT {
            std::thread::sleep(Duration::from_millis(1010));
        }
        call(&adapter, 14, 0, 0, syn(i as u32, 8080), 0).unwrap();
    }
    // A small caller buffer must not consume the queued packet.
    assert_eq!(call(&adapter, 15, 0, 0, vec![], 1).err(), Some(EMSGSIZE));
    for i in 0..LIMIT + 4 {
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.header.flags, ntcp::wire::RST | ntcp::wire::ACK);
        assert_eq!(segment.header.acknowledgment, i as u32 + 1);
        assert!(response.stamp > 1_700_000_000_000_000);
    }
}

#[test]
fn owner_loop_emits_pure_handshake_ack_before_pending_send_data() {
    for selected in [Profile::Baseline, Profile::UpstreamWindow8] {
        let adapter = Adapter::start((local(), selected)).unwrap();
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as u64;
        let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
        assert_eq!(
            call(&adapter, 5, fd, 0, encode_addr(remote), 0).err(),
            Some(EINPROGRESS)
        );
        let syn = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (outgoing_ip, tcp) = parse_frame(&syn.bytes).unwrap();
        let sent = ntcp::wire::parse(outgoing_ip, tcp).unwrap().header;
        let (mut blocking, _) = request(10, fd, F_SETFL, vec![], 0);
        blocking.b = 0;
        adapter.call(blocking).unwrap();
        let (send, sent_reply) = request(7, fd, 0, b"data".to_vec(), 0);
        adapter.tx.send(send).unwrap();
        // FIFO barrier proves SEND is pending before the SYNACK arrives.
        call(&adapter, 17, fd, 0, vec![], 0).unwrap();
        assert!(matches!(
            sent_reply.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        // Also queue a packet read: it must observe this iteration's pure ACK.
        let (read, packet_reply) = request(15, 0, 0, vec![], BYTES);
        adapter.tx.send(read).unwrap();
        call(&adapter, 17, fd, 0, vec![], 0).unwrap();
        assert!(matches!(
            packet_reply.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let ip = IpMetadata {
            source: outgoing_ip.destination,
            destination: outgoing_ip.source,
        };
        let header = ntcp::wire::Header {
            source_port: sent.destination_port,
            destination_port: sent.source_port,
            sequence: 100,
            acknowledgment: sent.sequence.wrapping_add(1),
            flags: ntcp::wire::SYN | ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        let mut tcp = [0; 64];
        let len = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
        let bytes = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        call(&adapter, 14, 0, 0, bytes, 0).unwrap();
        assert_eq!(
            sent_reply
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .unwrap()
                .value,
            4
        );
        let ack = packet_reply
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        let (ip, tcp) = parse_frame(&ack.bytes).unwrap();
        let ack = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(ack.header.flags, ntcp::wire::ACK);
        assert_eq!(ack.header.acknowledgment, 101);
        assert_eq!(ack.header.sequence, sent.sequence.wrapping_add(1));
        assert!(
            ack.payload.is_empty(),
            "{selected:?}: handshake ACK carried SEND data"
        );
        let data = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&data.bytes).unwrap();
        let data = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(data.header.sequence, ack.header.sequence);
        assert_eq!(data.header.acknowledgment, 101);
        assert_eq!(data.payload, b"data");
    }
}

#[test]
fn profiles_emit_real_synack_scale_through_owner_thread() {
    for (name, scale) in [
        ("baseline", 0),
        ("upstream-window8", 8),
        ("upstream-sack", 8),
    ] {
        let adapter = Adapter::start(profile(&format!("{name},local=192.0.2.1")).unwrap()).unwrap();
        let fd = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as u64;
        call(
            &adapter,
            2,
            fd,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        )
        .unwrap();
        call(&adapter, 3, fd, 1, vec![], 0).unwrap();
        // MSS and WS only, matching the upstream tests' lack of SACK/TS negotiation.
        let syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 7]);
        call(&adapter, 14, 0, 0, syn, 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.header.flags, ntcp::wire::SYN | ntcp::wire::ACK);
        assert_eq!(segment.header.window, 65535);
        assert_eq!(segment.options.window_scale, Some(scale));
        assert_eq!(segment.options.mss, Some(1460));
        assert_eq!(segment.options.timestamps, None);
        assert_eq!(segment.raw_options, &[2, 4, 5, 180, 1, 3, 3, scale]);
    }
}

#[test]
fn owner_loop_coalesces_queued_reads_with_immediate_ack_window_credit() {
    let adapter = Adapter::start((local(), Profile::UpstreamWindow8)).unwrap();
    let listener = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as u64;
    call(
        &adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, listener, 1, vec![], 0).unwrap();
    let incoming_syn = syn_with_options(100, 8080, &[2, 4, 3, 232, 1, 3, 3, 7]);
    let ip = parse_frame(&incoming_syn).unwrap().0;
    call(&adapter, 14, 0, 0, incoming_syn, 0).unwrap();
    let synack = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
    let mut header = ntcp::wire::Header {
        source_port: 50000,
        destination_port: 8080,
        sequence: 101,
        acknowledgment: packet_header(&synack.bytes).sequence.wrapping_add(1),
        flags: ntcp::wire::ACK,
        window: 257,
        urgent_pointer: 0,
    };
    let send = |header, payload: &[u8]| {
        let mut tcp = vec![0; 20 + payload.len()];
        let len = ntcp::wire::encode(ip, header, &[], payload, &mut tcp).unwrap();
        let bytes = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        call(&adapter, 14, 0, 0, bytes, 0).unwrap();
    };
    send(header, &[]);
    let fd = call(&adapter, 4, listener, 0, vec![], 0).unwrap().value as u64;
    for i in 0..3 {
        let read = if i < 2 {
            let (request, rx) = request(6, fd, 0, vec![], 2000);
            adapter
                .tx
                .try_send(request)
                .unwrap_or_else(|_| panic!("request channel full"));
            // FIFO barrier: the read has been attempted and queued before data.
            call(&adapter, 17, fd, 0, vec![], 0).unwrap();
            assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            Some(rx)
        } else {
            None
        };
        header.sequence = 101 + i * 2000;
        header.flags = ntcp::wire::ACK | ntcp::wire::PSH;
        send(header, &vec![0; 2000]);
        if let Some(rx) = read {
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(3))
                    .unwrap()
                    .unwrap()
                    .value,
                2000
            );
        }
        let output = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let sent = packet_header(&output.bytes);
        // An extra ACK from an earlier read would fail the cumulative ACK check.
        assert_eq!(sent.acknowledgment, 101 + (i + 1) * 2000);
        assert_eq!(sent.flags, ntcp::wire::ACK);
        assert_eq!(sent.window, if i < 2 { 32768 } else { 32760 });
        assert!(output.stamp > 0);
    }
    // No application read follows the third data: its ACK must already be out,
    // and no redundant ACK from the two queued reads may remain in the queue.
    let (request, rx) = request(15, 0, 0, vec![], BYTES);
    adapter
        .tx
        .try_send(request)
        .unwrap_or_else(|_| panic!("request channel full"));
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(adapter);
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).unwrap().err(),
        Some(ECANCELED)
    );
}

#[test]
fn sack_profile_negotiation_reaches_owner_thread() {
    for selected in [Profile::Baseline, Profile::Sack] {
        let adapter = Adapter::start((local(), selected)).unwrap();
        let fd = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as u64;
        call(
            &adapter,
            2,
            fd,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        )
        .unwrap();
        call(&adapter, 3, fd, 1, vec![], 0).unwrap();
        let syn = syn_with_options(100, 8080, &[2, 4, 5, 180, 1, 3, 3, 0, 1, 1, 4, 2]);
        call(&adapter, 14, 0, 0, syn, 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.options.sack_permitted, selected == Profile::Sack);
        assert_eq!(segment.options.timestamps, None);
        assert_eq!(segment.options.window_scale, Some(0));
    }
}

#[test]
fn upstream_sack_profile_negotiates_combined_options_and_peer_fallback() {
    for (sack, timestamps, options) in [
        (
            true,
            true,
            &[
                2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0, 1, 3, 3, 7,
            ][..],
        ),
        (
            false,
            true,
            &[
                2, 4, 5, 180, 1, 1, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0, 1, 3, 3, 7,
            ][..],
        ),
        (true, false, &[2, 4, 5, 180, 1, 1, 4, 2, 1, 3, 3, 7][..]),
        (false, false, &[2, 4, 5, 180, 1, 3, 3, 7][..]),
    ] {
        let adapter = Adapter::start((local(), Profile::UpstreamSack)).unwrap();
        let fd = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as u64;
        call(
            &adapter,
            2,
            fd,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        )
        .unwrap();
        call(&adapter, 3, fd, 1, vec![], 0).unwrap();
        call(&adapter, 14, 0, 0, syn_with_options(100, 8080, options), 0).unwrap();
        let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let (ip, tcp) = parse_frame(&response.bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(segment.options.sack_permitted, sack);
        assert_eq!(segment.options.window_scale, Some(8));
        assert_eq!(segment.options.mss, Some(1460));
        assert_eq!(segment.header.window, 65535);
        assert_eq!(
            segment.options.timestamps.map(|pair| pair.1),
            timestamps.then_some(100)
        );
        let mut expected = options.to_vec();
        *expected.last_mut().unwrap() = 8;
        if let Some((value, _)) = segment.options.timestamps {
            expected[8..12].copy_from_slice(&value.to_be_bytes());
            expected[12..16].copy_from_slice(&100u32.to_be_bytes());
        }
        assert_eq!(segment.raw_options, expected);
    }
}

#[test]
fn owner_loop_cubic_initial_push_pairs_and_other_profiles_legacy_push() {
    for selected in [
        Profile::UpstreamCubic,
        Profile::Baseline,
        Profile::Sack,
        Profile::UpstreamWindow8,
        Profile::UpstreamSack,
        Profile::UpstreamEcn,
        Profile::UpstreamBasic,
    ] {
        let adapter = Adapter::start((local(), selected)).unwrap();
        let listener = call(&adapter, 1, 0, SOCK_STREAM, vec![], 0).unwrap().value as u64;
        call(
            &adapter,
            2,
            listener,
            0,
            encode_addr(SocketAddr::new(local().into(), 8080)),
            0,
        )
        .unwrap();
        call(&adapter, 3, listener, 1, vec![], 0).unwrap();
        let incoming_syn = syn_with_options(100, 8080, &[2, 4, 5, 180]);
        let ip = parse_frame(&incoming_syn).unwrap().0;
        call(&adapter, 14, 0, 0, incoming_syn, 0).unwrap();
        let synack = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
        let base = packet_header(&synack.bytes).sequence.wrapping_add(1);
        let header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: 8080,
            sequence: 101,
            acknowledgment: base,
            flags: ntcp::wire::ACK,
            window: 65535,
            urgent_pointer: 0,
        };
        let mut tcp = [0; 64];
        let len = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
        let ack = frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap();
        call(&adapter, 14, 0, 0, ack, 0).unwrap();
        let fd = call(&adapter, 4, listener, 0, vec![], 0).unwrap().value as u64;
        // A single SEND gives CUBIC two pairs in one owner output turn and
        // an explicit final PUSH on an unpaired segment. Legacy profiles use
        // three MSS so the whole write fits their smaller initial window.
        let segments = if selected == Profile::UpstreamCubic {
            5
        } else {
            3
        };
        let payload = vec![0x55; segments * 1460];
        assert_eq!(
            call(&adapter, 7, fd, 0, payload.clone(), 0).unwrap().value,
            payload.len() as i64
        );
        for i in 0..segments {
            let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
            let (ip, tcp) = parse_frame(&packet.bytes).unwrap();
            let sent = ntcp::wire::parse(ip, tcp).unwrap();
            assert_eq!(sent.header.sequence, base.wrapping_add((i * 1460) as u32));
            assert_eq!(sent.header.acknowledgment, 101);
            assert_eq!(sent.payload, &payload[i * 1460..(i + 1) * 1460]);
            let push = i == segments - 1 || (selected == Profile::UpstreamCubic && i % 2 == 1);
            assert_eq!(
                sent.header.flags,
                ntcp::wire::ACK | if push { ntcp::wire::PSH } else { 0 },
                "{selected:?} initial segment {i}"
            );
        }
    }
}

#[test]
fn ip_options_passive_expiry_gc_final_reset_and_unmatched_control() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 6, 40).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DONT).unwrap();
    execute_value(&mut owner, 11, listener, 5, 1).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 2, 0).unwrap();
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 40, false);
    let old = tx.connection.unwrap();
    let deadline = owner.inner.now() + 2000;
    owner.inner.endpoint.on_timeout(deadline, BUDGET).unwrap();
    // Avoid wall-clock regression in following application operations.
    owner.epoch = Instant::now() - Duration::from_micros(deadline);
    assert!(poll_frame(&mut owner).is_none());
    assert!(owner.inner.endpoint.state(old).is_err());
    owner.gc_ip_options();
    assert!(owner.connection_options.is_empty());
    execute_value(&mut owner, 11, listener, 5, 0).unwrap();
    execute_value(&mut owner, 11, listener, 6, 80).unwrap();
    owner.execute(&mut incoming).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_ne!(tx.connection, Some(old));
    check_ip(&bytes, 80, false);
    let child = tx.connection.unwrap();
    let tuple = owner.inner.endpoint.tuple(child).unwrap();
    owner.inner.endpoint.abort(child).unwrap();
    assert!(owner.inner.endpoint.state(child).is_err());
    assert!(owner.inner.endpoint.connection_exists(child));
    execute_value(&mut owner, 11, listener, 6, 120).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DO).unwrap();
    owner.execute(&mut incoming).unwrap();
    assert_eq!(owner.inner.endpoint.connection_id(tuple), Some(child));
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(child));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::RST, 0);
    check_ip(&bytes, 80, false);
    // The terminal reset retains its original policy and tuple through 2MSL.
    owner.execute(&mut incoming).unwrap();
    assert!(poll_frame(&mut owner).is_none());
    assert_eq!(owner.inner.endpoint.connection_id(tuple), Some(child));
    owner.gc_ip_options();
    assert_eq!(owner.connection_options.len(), 1);
    let expiry = owner
        .inner
        .endpoint
        .next_deadline()
        .unwrap()
        .max(owner.inner.now());
    owner.inner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(!owner.inner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert!(owner.connection_options.is_empty());
    owner.execute(&mut incoming).unwrap();
    let replacement = owner.inner.endpoint.connection_id(tuple).unwrap();
    assert_ne!(replacement, child);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(replacement));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::SYN, 0);
    check_ip(&bytes, 120, true);
    let child = replacement;
    execute_value(&mut owner, 8, listener, 0, 0).unwrap();
    owner
        .inner
        .endpoint
        .on_timeout(owner.inner.now(), BUDGET)
        .unwrap();
    // Closed children must retain policy until their last RST is framed.
    owner.gc_ip_options();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(child));
    assert_ne!(packet_header(&bytes).flags & ntcp::wire::RST, 0);
    check_ip(&bytes, 120, true);
    assert!(owner.inner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert_eq!(owner.connection_options.len(), 1);
    let expiry = owner
        .inner
        .endpoint
        .next_deadline()
        .unwrap()
        .max(owner.inner.now());
    owner.inner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(!owner.inner.endpoint.connection_exists(child));
    owner.gc_ip_options();
    assert!(owner.connection_options.is_empty());
    let (mut unmatched, _) = request(14, 0, 0, syn(200, 9090), 0);
    owner.execute(&mut unmatched).unwrap();
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, None);
    check_ip(&bytes, 0, true);
}

#[test]
fn ip_metadata_limit_is_reserved_before_connect_and_reused_after_gc() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    // Small real buffers let this test reach all 128 slots, not the profile's
    // separate aggregate byte cap. Production profile settings remain untouched.
    let mut config = EndpointConfig {
        max_connections: LIMIT,
        ..EndpointConfig::default()
    };
    config.connection.receive_capacity = 128;
    config.connection.send_capacity = 128;
    config.connection.mss = 128;
    owner.inner.endpoint = Endpoint::new(config, [42; 32], 0, |_| true).unwrap();
    let remote = encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080));
    let mut first = None;
    for _ in 0..LIMIT {
        let fd = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
        owner.sockets.get_mut(&fd).unwrap().send_capacity = 128;
        owner.sockets.get_mut(&fd).unwrap().receive_capacity = 128;
        let (mut connect, _) = request(5, fd, 0, remote.clone(), 0);
        assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
        first.get_or_insert((fd, owner.connection(fd).unwrap()));
        assert!(owner.connection_options.len() <= LIMIT);
    }
    let (fd, old) = first.unwrap();
    execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    let replacement = owner.alloc(Socket::new(SOCK_NONBLOCK)).unwrap();
    let port = owner.next_port;
    let (mut connect, _) = request(5, replacement, 0, remote, 0);
    assert_eq!(owner.execute(&mut connect).err(), Some(ENOBUFS));
    assert_eq!(owner.next_port, port);
    assert!(matches!(owner.sockets[&replacement].handle, Handle::Fresh));
    owner.inner.endpoint.release(old).unwrap();
    while poll_frame(&mut owner).is_some() {}
    owner.gc_ip_options();
    assert_eq!(owner.connection_options.len(), LIMIT - 1);
    assert_eq!(owner.execute(&mut connect).err(), Some(EINPROGRESS));
    assert_eq!(owner.connection_options.len(), LIMIT);
}

#[test]
fn receive_retry_fault_preserves_stream_and_short_copyout() {
    let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
    let (fd, id, tx, sent) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_WANT);
    execute_value(&mut owner, 10, fd, F_SETFL, O_RDWR).unwrap();
    let (mut r, rx) = request(6, fd, 0, vec![], 6);
    r.destinations = vec![(1, 6)];
    assert!(!owner.retry(&mut r)); // No data: fault checking must survive retries.
    assert!(rx.try_recv().is_err());
    let (ip, header) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    let mut tcp = [0; 128];
    let len = ntcp::wire::encode(ip, header, &[], b"abcdef", &mut tcp).unwrap();
    owner
        .inner
        .endpoint
        .input(owner.inner.now(), ip, &tcp[..len])
        .unwrap();
    assert!(owner.retry(&mut r));
    assert_eq!(rx.recv().unwrap().err(), Some(EFAULT));
    assert_eq!(owner.inner.endpoint.readable_bytes(id), Ok(6));
    let mut output = [0; 8];
    r.capacity = 8;
    // A bad unused tail must not fault a short successful receive.
    r.destinations = vec![(0, 0), (output.as_mut_ptr() as usize, 6), (1, 2)];
    assert_eq!(owner.execute(&mut r).unwrap().unwrap().value, 6);
    assert_eq!(&output[..6], b"abcdef");
    assert_eq!(owner.inner.endpoint.readable_bytes(id), Ok(0));
    let mut fin = header;
    fin.sequence += 6;
    fin.flags |= ntcp::wire::FIN;
    let len = ntcp::wire::encode(ip, fin, &[], &[], &mut tcp).unwrap();
    owner
        .inner
        .endpoint
        .input(owner.inner.now(), ip, &tcp[..len])
        .unwrap();
    r.destinations = vec![(1, 8)];
    assert_eq!(owner.execute(&mut r).unwrap().unwrap().value, 0);
}

#[test]
fn send_payload_faults_follow_owner_errors_and_shutdown() {
    // Both scalar and vector bridge requests converge on these source descriptors.
    for sources in [
        vec![(1, 6)],
        vec![(0, 6)],
        vec![(0, 0), (1, 3), (1, 3)],
        vec![(0, 0), (0, 3), (0, 3)],
    ] {
        let mut owner = Owner::new((local(), Profile::Baseline)).unwrap();
        let (fd, id, tx, syn) = active_ip_connection(&mut owner, 0, IP_PMTUDISC_WANT);
        let (mut send, _) = request(7, fd, 0, vec![], 0);
        send.destinations = sources.clone();
        let written = owner
            .inner
            .endpoint
            .transport_info(owner.connection(fd).unwrap())
            .unwrap()
            .send_used as u64;
        assert_eq!(owner.execute(&mut send).err(), Some(EFAULT));
        assert_eq!(
            owner
                .inner
                .endpoint
                .transport_info(owner.connection(fd).unwrap())
                .unwrap()
                .send_used as u64,
            written
        );
        for pending in [ECONNRESET, ETIMEDOUT] {
            owner.sockets.get_mut(&fd).unwrap().error = pending;
            assert_eq!(owner.execute(&mut send).err(), Some(pending));
            assert_eq!(owner.execute(&mut send).err(), Some(EFAULT));
        }
        execute_value(&mut owner, 9, fd, SHUT_WR, 0).unwrap();
        assert_eq!(owner.execute(&mut send).err(), Some(EPIPE));
        owner.sockets.get_mut(&fd).unwrap().error = ETIMEDOUT;
        assert_eq!(owner.execute(&mut send).err(), Some(ETIMEDOUT));
        assert_eq!(owner.execute(&mut send).err(), Some(EPIPE));
        let (ip, mut reset) = reverse_ack(tx, syn, syn.sequence.wrapping_add(1));
        reset.flags = ntcp::wire::RST;
        input_packet(&mut owner, ip, reset, &[]);
        owner.events();
        assert_eq!(owner.inner.endpoint.state(id), Ok(State::Closed));
        for how in [SHUT_RD, SHUT_WR, SHUT_RDWR] {
            assert_eq!(execute_value(&mut owner, 9, fd, how, 0), Err(ENOTCONN));
            assert!(!owner.sockets[&fd].read_shutdown);
            assert!(owner.sockets[&fd].write_shutdown);
        }
        assert_eq!(owner.execute(&mut send).err(), Some(ECONNRESET));
        assert_eq!(owner.execute(&mut send).err(), Some(EPIPE));
        assert_eq!(send.destinations, sources); // No state/error path touched payload.
        assert!(send.bytes.is_empty());
        assert_eq!(
            owner
                .inner
                .endpoint
                .transport_info(owner.connection(fd).unwrap())
                .unwrap()
                .send_used as u64,
            written
        );
    }
}

#[test]
fn ip_options_listener_snapshot_accept_detached_fin_and_fd_reuse() {
    let mut owner = Owner::new((local(), Profile::Sack)).unwrap();
    let listener = owner.alloc(Socket::new(0)).unwrap();
    execute_value(&mut owner, 11, listener, 8, 1).unwrap();
    execute_value(&mut owner, 11, listener, 6, 187).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DONT).unwrap();
    let (mut bind, _) = request(
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    );
    owner.execute(&mut bind).unwrap();
    execute_value(&mut owner, 3, listener, 1, 0).unwrap();
    let (mut incoming, _) = request(14, 0, 0, syn(100, 8080), 0);
    owner.execute(&mut incoming).unwrap();
    let tuple = ntcp::Tuple {
        local: SocketAddr::new(local().into(), 8080),
        remote: SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 50000),
    };
    let id = owner.inner.endpoint.connection_id(tuple).unwrap();
    execute_value(&mut owner, 11, listener, 6, 4).unwrap();
    execute_value(&mut owner, 11, listener, 7, IP_PMTUDISC_DO).unwrap();
    // A duplicate SYN must not overwrite the original listener snapshot.
    owner.execute(&mut incoming).unwrap();
    assert_eq!(owner.connection_options.len(), 1);
    let (tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    let sent = packet_header(&bytes);
    let (ip, reply) = reverse_ack(tx, sent, sent.sequence.wrapping_add(1));
    input_packet(&mut owner, ip, reply, &[]);
    execute_value(&mut owner, 11, listener, 8, 0).unwrap();
    let fd = execute_value(&mut owner, 4, listener, 0, 0).unwrap() as u64;
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(184));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_DONT as i64)
    );
    assert_eq!(owner.connection(fd), Ok(id));
    assert!(owner.sockets[&fd].zerocopy);
    assert_eq!(owner.sockets[&fd].zc_next, 0);
    assert!(owner.sockets[&fd].completions.is_empty());
    // Descriptor replacement is covered at the shared ABI. Here a new logical
    // owner ID must not replace the detached connection generation's IP policy.
    execute_value(&mut owner, 8, fd, 0, 0).unwrap();
    let fd = owner.alloc(Socket::new(0)).unwrap();
    assert!(!owner.sockets[&fd].zerocopy);
    execute_value(&mut owner, 11, fd, 6, 4).unwrap();
    execute_value(&mut owner, 11, fd, 7, IP_PMTUDISC_DO).unwrap();
    let (fin_tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(fin_tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    let fin = packet_header(&bytes);
    assert_ne!(fin.flags & ntcp::wire::FIN, 0);
    let (ip, mut reply) = reverse_ack(fin_tx, fin, fin.sequence.wrapping_add(1));
    reply.flags |= ntcp::wire::FIN;
    input_packet(&mut owner, ip, reply, &[]);
    assert_eq!(owner.inner.endpoint.state(id), Ok(State::TimeWait));
    let retained_bytes = owner.inner.endpoint.buffer_bytes();
    owner.inner.endpoint.release(id).unwrap();
    assert!(owner.inner.endpoint.state(id).is_err());
    assert!(owner.inner.endpoint.connection_exists(id));
    owner.gc_ip_options();
    assert_eq!(owner.connection_options.len(), 1);
    let (_, bytes) = poll_frame(&mut owner).unwrap();
    check_ip(&bytes, 184, false);
    // Even after its last ACK, a released TIME-WAIT record still owns policy
    // and buffers. A repeated FIN must get the original policy, not the new fd's.
    owner.gc_ip_options();
    assert_eq!(owner.connection_options.len(), 1);
    assert_eq!(owner.inner.endpoint.buffer_bytes(), retained_bytes);
    input_packet(&mut owner, ip, reply, &[]);
    let (ack_tx, bytes) = poll_frame(&mut owner).unwrap();
    assert_eq!(ack_tx.connection, Some(id));
    check_ip(&bytes, 184, false);
    assert_eq!(owner.inner.endpoint.buffer_bytes(), retained_bytes);
    let expiry = owner
        .inner
        .endpoint
        .next_deadline()
        .unwrap()
        .max(owner.inner.now());
    owner.inner.endpoint.on_timeout(expiry, BUDGET).unwrap();
    owner.epoch = Instant::now() - Duration::from_micros(expiry);
    assert!(poll_frame(&mut owner).is_none());
    assert!(!owner.inner.endpoint.connection_exists(id));
    owner.gc_ip_options();
    assert!(owner.connection_options.is_empty());
    assert_eq!(owner.inner.endpoint.buffer_bytes(), 0);
    assert_eq!(execute_value(&mut owner, 12, fd, 6, 0), Ok(4));
    assert_eq!(
        execute_value(&mut owner, 12, fd, 7, 0),
        Ok(IP_PMTUDISC_DO as i64)
    );
}

#[test]
fn pending_accept_does_not_block_packets_and_stop_joins() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as u64;
    call(
        &adapter,
        2,
        fd,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, fd, 1, vec![], 0).unwrap();
    let (r, waiting) = request(4, fd, 0, vec![], 0);
    adapter.tx.send(r).unwrap();
    assert!(waiting.recv_timeout(Duration::from_millis(5)).is_err());
    call(&adapter, 14, 0, 0, syn(100, 8080), 0).unwrap();
    let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
    assert_eq!(
        packet_header(&response.bytes).flags,
        ntcp::wire::SYN | ntcp::wire::ACK
    );
    let before = Instant::now();
    drop(adapter);
    assert!(before.elapsed() < Duration::from_secs(1));
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(1)).unwrap().err(),
        Some(ECANCELED)
    );
}

#[test]
fn explicit_close_cancels_pending_accept_before_descriptor_reuse() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as u64;
    call(
        &adapter,
        2,
        fd,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, fd, 1, vec![], 0).unwrap();
    let (r, waiting) = request(4, fd, 0, vec![], 0);
    adapter.tx.send(r).unwrap();
    call(&adapter, 17, fd, 0, vec![], 0).err(); // Listener SIOCINQ barrier.
    assert!(waiting.try_recv().is_err());
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(1)).unwrap().err(),
        Some(EBADF)
    );
    let replacement = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as u64;
    assert_ne!(replacement, fd);
}

#[test]
fn descriptor_and_request_limits_fail_without_hanging() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fds: Vec<_> = (0..LIMIT)
        .map(|_| call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as u64)
        .collect();
    assert_eq!(call(&adapter, 1, 0, 0, vec![], 0).err(), Some(EMFILE));
    call(&adapter, 8, fds[0], 0, vec![], 0).unwrap();
    assert!(call(&adapter, 1, 0, 0, vec![], 0).is_ok());
    assert_eq!(
        call(&adapter, 6, u64::MAX, 0, vec![], 10).err(),
        Some(EBADF)
    );
    let (tx, _rx) = mpsc::sync_channel(1);
    let (reply, _) = mpsc::sync_channel(1);
    tx.send(super::Request {
        id: 0,
        op: Op::New(0),
        reply,
        deadline: None,
    })
    .unwrap();
    let runtime = Runtime {
        tx,
        wake: -1,
        family: AF_INET,
        io_limit: BYTES,
        stop: Default::default(),
        worker: Mutex::new(None),
    };
    assert_eq!(runtime.call(0, Op::New(0)).unwrap_err(), EAGAIN);
}

#[test]
fn pending_limit_and_poll_timeout() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let mut replies = Vec::new();
    for _ in 0..LIMIT {
        let (r, rx) = request(15, 0, 0, vec![], BYTES);
        adapter.tx.send(r).unwrap();
        replies.push(rx);
    }
    assert_eq!(call(&adapter, 1, 0, 0, vec![], 0).err(), Some(EAGAIN));
    drop(adapter);
    for rx in replies {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap().err(),
            Some(ECANCELED)
        );
    }
    // Real libc-facing poll's finite timeout is checked in the ABI test.
}

#[test]
fn owner_loop_preserves_pending_send_read_fifo_on_refused_handshake() {
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as u64;
    let remote = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080);
    assert_eq!(
        call(&adapter, 5, fd, 0, encode_addr(remote), 0).err(),
        Some(EINPROGRESS)
    );
    let syn = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap();
    let (outgoing, tcp) = parse_frame(&syn.bytes).unwrap();
    let sent = ntcp::wire::parse(outgoing, tcp).unwrap().header;
    let (mut flags, _) = request(10, fd, F_SETFL, vec![], 0);
    flags.b = 0;
    adapter.call(flags).unwrap();
    let (send, sent_reply) = request(7, fd, 0, b"data".to_vec(), 0);
    adapter.tx.send(send).unwrap();
    let (read, read_reply) = request(6, fd, 0, vec![], 4);
    adapter.tx.send(read).unwrap();
    for _ in 0..3 {
        assert_eq!(call(&adapter, 17, fd, 0, vec![], 0).unwrap().value, 0);
        assert!(sent_reply.try_recv().is_err());
        assert!(read_reply.try_recv().is_err());
    }
    let ip = IpMetadata {
        source: outgoing.destination,
        destination: outgoing.source,
    };
    let header = ntcp::wire::Header {
        source_port: sent.destination_port,
        destination_port: sent.source_port,
        sequence: 0,
        acknowledgment: sent.sequence.wrapping_add(1),
        flags: ntcp::wire::RST | ntcp::wire::ACK,
        window: 0,
        urgent_pointer: 0,
    };
    let mut tcp = [0; 64];
    let len = ntcp::wire::encode(ip, header, &[], &[], &mut tcp).unwrap();
    call(
        &adapter,
        14,
        0,
        0,
        frame(
            ntcp::Transmit {
                connection: None,
                ip,
                len,
                hop_limit: 64,
                dscp: 0,
                ecn: 0,
                ipv4_options: Default::default(),
            },
            &tcp[..len],
        )
        .unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(
        sent_reply
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .err(),
        Some(ECONNREFUSED)
    );
    assert_eq!(
        read_reply
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .err(),
        Some(ENOTCONN)
    );
}
