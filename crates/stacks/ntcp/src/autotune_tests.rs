// Buffer autotuning: limits and window scale, send limit expansion, receive
// buffer growth (DRS) and the per-direction locks.
use super::*;
use crate::{BufferMemory, BufferSizes, Buffers};
use alloc::{format, vec::Vec};

const REMOTE: &str = "192.0.2.2:8080";

fn config() -> EndpointConfig {
    EndpointConfig {
        max_connections: 4,
        connection: ConnectionConfig {
            nagle: false,
            delayed_ack_us: 0,
            ..ConnectionConfig::default()
        },
        ..EndpointConfig::default()
    }
}

// Moves `from`'s packets to `to`, each also into `sent`; whether there were
// any.
fn flush(from: &mut Endpoint, to: &mut Endpoint, now: u64, sent: &mut Vec<Vec<u8>>) -> bool {
    let mut moved = false;
    loop {
        let mut bytes = [0; 2048];
        let output = from.poll_transmit(now, &mut bytes, 16).unwrap();
        if let Some(packet) = output.packet {
            sent.push(bytes[..packet.len].to_vec());
            to.input(now, packet.ip, &bytes[..packet.len]).unwrap();
            moved = true;
        }
        if !output.more_work {
            return moved;
        }
    }
}

// Exchanges packets until both sides are quiet, recording `a`'s and `b`'s.
fn exchange(a: &mut Endpoint, b: &mut Endpoint, now: u64, trace: &mut [Vec<Vec<u8>>; 2]) {
    for _ in 0..256 {
        let [to_b, to_a] = trace;
        if !(flush(a, b, now, to_b) | flush(b, a, now, to_a)) {
            return;
        }
    }
    panic!("the endpoints did not settle");
}

// A client of `a` connected to `b`'s listener on `REMOTE`, and its peer.
fn connect(
    a: &mut Endpoint,
    b: &mut Endpoint,
    port: u16,
    trace: &mut [Vec<Vec<u8>>; 2],
) -> (ConnectionId, ConnectionId) {
    let listener = match b.listen(REMOTE.parse().unwrap(), 4) {
        Ok(listener) => listener,
        Err(EndpointError::AddressInUse) => b
            .listeners
            .iter()
            .enumerate()
            .find_map(|(slot, l)| {
                l.as_ref().map(|_| ListenerId {
                    slot,
                    generation: b.listener_generations[slot],
                })
            })
            .unwrap(),
        Err(error) => panic!("{error:?}"),
    };
    let local = SocketAddr::new("192.0.2.1".parse().unwrap(), port);
    let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
    exchange(a, b, 0, trace);
    (client, b.accept(listener).unwrap())
}

// The window field of a TCP segment `packet`.
fn window_field(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[14], packet[15]])
}

// The Window Scale option's shift in TCP segment `packet`, if any.
fn window_scale_option(packet: &[u8]) -> Option<u8> {
    let end = usize::from(packet[12] >> 4) * 4;
    let mut at = 20;
    while at < end {
        match packet[at] {
            0 => return None,
            1 => at += 1,
            3 => return Some(packet[at + 2]),
            _ => at += usize::from(packet[at + 1]),
        }
    }
    None
}

// As Linux's tcp_wmem/tcp_rmem sysctls, which check no order: a min above
// the initial size acts as it, and a max below it leaves the direction
// fixed there. The setters require the order.
#[test]
fn buffer_sizes_resolve_as_the_sysctls_and_the_setters_require_their_order() {
    let mut connection = ConnectionConfig {
        send_capacity: 128,
        receive_capacity: 1 << 20,
        ..ConnectionConfig::default()
    };
    // The default min (4096) above a small initial size, the default max
    // (0) below any.
    assert_eq!(
        connection.send_buffer(),
        BufferSizes {
            min: 128,
            initial: 128,
            max: 128
        }
    );
    assert_eq!(
        ConnectionConfig::default().send_buffer(),
        BufferSizes {
            min: 4096,
            initial: 65536,
            max: 65536
        }
    );
    assert_eq!(
        connection.receive_buffer(),
        BufferSizes {
            min: 4096,
            initial: 1 << 20,
            max: 1 << 20
        }
    );
    assert!(connection.validate(true).is_ok());
    let sizes = |min, initial, max| BufferSizes { min, initial, max };
    for invalid in [sizes(0, 1, 1), sizes(2, 1, 1), sizes(1, 2, 1)] {
        assert_eq!(
            connection.set_send_buffer(invalid),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            connection.set_receive_buffer(invalid),
            Err(Error::InvalidArgument)
        );
    }
    assert_eq!(
        connection.set_send_buffer(sizes(1, 1, 1 << 30)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        connection.set_receive_buffer(sizes(1, 1, (65535 << 14) + 1)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(connection.send_buffer().initial, 128);
    connection
        .set_send_buffer(sizes(4096, 65536, (1 << 30) - 1))
        .unwrap();
    connection
        .set_receive_buffer(sizes(4096, 65536, 65535 << 14))
        .unwrap();
    assert_eq!(connection.send_buffer(), sizes(4096, 65536, (1 << 30) - 1));
    assert_eq!(connection.receive_buffer(), sizes(4096, 65536, 65535 << 14));
    let mut endpoint = EndpointConfig {
        connection,
        max_buffer_bytes: 3000,
        ..EndpointConfig::default()
    };
    assert_eq!(
        endpoint.buffers(),
        Buffers {
            send: sizes(4096, 65536, (1 << 30) - 1),
            receive: sizes(4096, 65536, 65535 << 14),
            memory: BufferMemory {
                low: 1500,
                pressure: 2000,
                high: 3000
            },
        }
    );
    assert_eq!(
        format!("{}", endpoint.buffers()),
        "wmem=4096 65536 1073741823 rmem=4096 65536 1073725440 mem=1500 2000 3000"
    );
    // A min of zero or a max past the limit is invalid in the fields too.
    assert!(endpoint.validate().is_ok());
    for field in 0..4 {
        let mut invalid = endpoint.clone();
        match field {
            0 => invalid.connection.send_capacity_min = 0,
            1 => invalid.connection.receive_capacity_min = 0,
            2 => invalid.connection.send_capacity_max = 1 << 30,
            _ => invalid.connection.receive_capacity_max = (65535 << 14) + 1,
        }
        assert_eq!(invalid.validate(), Err(Error::InvalidArgument.into()));
        assert_eq!(
            invalid.connection.validate(true),
            Err(Error::InvalidArgument)
        );
    }
    endpoint.connection.receive_capacity_min = 0;
    assert!(Endpoint::new(endpoint, [1; 32], 0, |_| true).is_err());
}

// RFC 7323 section 2.3: the scale is the shift the receive maximum needs
// (Linux's tcp_rmem[2] in tcp_select_initial_window); the SYN's window is
// the initial size, at most 65535.
#[test]
fn the_window_scale_follows_the_receive_maximum() {
    for (initial, max, scale, syn_window) in [
        (65536, 65536, 1, 65535),
        (65536, 32 << 20, 10, 65535),
        (16384, 6 << 20, 7, 16384),
        (65535, 65535, 0, 65535),
        (65535, 65536, 1, 65535),
        // A max below the initial size leaves it fixed there.
        (1 << 20, 65536, 5, 65535),
        (4000, 0, 0, 4000),
    ] {
        let mut config = config();
        config.connection.receive_capacity = initial;
        config.connection.receive_capacity_max = max;
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let mut trace = [Vec::new(), Vec::new()];
        let (client, server) = connect(&mut a, &mut b, 40000, &mut trace);
        let [to_b, to_a] = &trace;
        for syn in [&to_b[0], &to_a[0]] {
            assert_eq!(window_scale_option(syn), Some(scale), "{initial} {max}");
            assert_eq!(window_field(syn), syn_window, "{initial} {max}");
        }
        for (endpoint, id) in [(&a, client), (&b, server)] {
            let info = endpoint.transport_info(id).unwrap();
            assert_eq!(info.receive_window_scale, scale);
            assert_eq!(info.receive_capacity, initial);
        }
    }
}

// Linux's tcp_init_buffer_space starts the first DRS measure at
// min3(rcv_ssthresh, rcv_wnd, TCP_INIT_CWND * advmss), advmss being the
// MSS offered less the timestamp option once timestamps were negotiated:
// 10 * 1448 with them, 10 * 1460 without, and the window when smaller.
#[test]
fn the_first_drs_measure_is_ten_full_segments_of_payload() {
    for (timestamps, initial, space) in [
        (true, 65536, 14_480),
        (false, 65536, 14_600),
        (true, 8192, 8192),
    ] {
        let mut config = config();
        config.connection.timestamps = timestamps;
        config.connection.receive_capacity = initial;
        config.connection.receive_capacity_min = 4096;
        config.connection.receive_capacity_max = 32 << 20;
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let mut trace = [Vec::new(), Vec::new()];
        let (client, server) = connect(&mut a, &mut b, 40000, &mut trace);
        for (endpoint, id) in [(&a, client), (&b, server)] {
            assert_eq!(endpoint.transport_info(id).unwrap().advertised_mss, 1460);
            let connection = &endpoint.slot(id).unwrap().connection;
            assert_eq!(connection.receive_space(), space, "{timestamps} {initial}");
        }
    }
}

// The packets of a short bulk transfer from a client of `config`.
fn transfer(config: &EndpointConfig) -> [Vec<Vec<u8>>; 2] {
    let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(config.clone(), [2; 32], 0, |_| true).unwrap();
    let mut trace = [Vec::new(), Vec::new()];
    let (client, server) = connect(&mut a, &mut b, 40000, &mut trace);
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let (mut sent, mut read) = (0, 0);
    let mut out = [0; 4096];
    for now in 1..2000 {
        if sent < data.len() {
            sent += a.write(client, &data[sent..]).unwrap_or(0);
        }
        exchange(&mut a, &mut b, now, &mut trace);
        read += b.read(server, &mut out).unwrap_or(0);
        if read == data.len() {
            return trace;
        }
    }
    panic!("the transfer did not finish");
}

// A fixed configuration, max at the initial size, whatever its min, sends
// what the default sends: limits change nothing until a direction is tuned.
#[test]
fn fixed_sizes_leave_the_trace_as_it_was() {
    let default = transfer(&config());
    let mut fixed = config();
    fixed.connection.send_capacity_min = 1;
    fixed.connection.receive_capacity_min = 1 << 20;
    fixed.connection.send_capacity_max = 1;
    assert_eq!(transfer(&fixed), default);
    // A tuned receive direction scales its window from its maximum.
    let mut tuned = config();
    tuned.connection.receive_capacity_max = 1 << 20;
    assert_ne!(transfer(&tuned), default);
}

// A client of `a` with a tuned send direction ({4096, 4096, 256 KiB}), to a
// peer whose fixed 1 MiB receive window never limits it.
fn sender_config() -> EndpointConfig {
    let mut config = config();
    config.connection.send_capacity = 4096;
    config.connection.send_capacity_max = 256 << 10;
    config.connection.receive_capacity = 1 << 20;
    config
}

// The client's send limit and congestion window after each round of a bulk
// transfer in which it keeps its send buffer full and the peer reads
// everything: the send limit after the handshake, then one entry a round.
fn send_limits(a_config: EndpointConfig, open: Option<usize>) -> Vec<(usize, u32, u32)> {
    let mut a = Endpoint::new(a_config, [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(sender_config(), [2; 32], 0, |_| true).unwrap();
    let mut trace = [Vec::new(), Vec::new()];
    let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
    let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
    let client = match open {
        None => a.connect(0, local, REMOTE.parse().unwrap()),
        Some(send) => {
            a.connect_with_buffer_capacities(0, local, REMOTE.parse().unwrap(), send, 1 << 20)
        }
    }
    .unwrap();
    exchange(&mut a, &mut b, 0, &mut trace);
    let server = b.accept(listener).unwrap();
    let mut limits = Vec::new();
    let record = |a: &Endpoint, limits: &mut Vec<_>| {
        let info = a.transport_info(client).unwrap();
        limits.push((info.send_capacity, info.cwnd, info.mss));
    };
    record(&a, &mut limits);
    let data = [7; 65536];
    let mut out = [0; 65536];
    for now in 1..80 {
        while a.write(client, &data).is_ok_and(|count| count != 0) {}
        exchange(&mut a, &mut b, now, &mut trace);
        while b.read(server, &mut out).is_ok() {}
        record(&a, &mut limits);
        trace = [Vec::new(), Vec::new()];
    }
    limits
}

// Linux's tcp_sndbuf_expand: the limit is twice the congestion window, at
// least ten segments, up to send_capacity_max. It rises at establishment
// (tcp_init_buffer_space) and after ACKs that free room for the blocked
// writer (tcp_new_space), and never falls without pressure.
#[test]
fn the_send_limit_follows_the_congestion_window() {
    let limits = send_limits(sender_config(), None);
    let max = 256 << 10;
    let (established, _, mss) = limits[0];
    let mss = mss as usize;
    assert_eq!(established, 20 * mss);
    for pair in limits.windows(2) {
        let ((before, _, _), (after, cwnd, _)) = (pair[0], pair[1]);
        assert!(after >= before, "{limits:?}");
        let ceiling = (2 * (cwnd as usize / mss).max(10) * mss).min(max);
        assert!(after <= ceiling, "{limits:?}");
        assert!(after == max || after % (2 * mss) == 0, "{limits:?}");
    }
    assert!(
        limits
            .iter()
            .any(|&(limit, _, _)| limit > established && limit < max)
    );
    assert_eq!(limits.last().unwrap().0, max, "{limits:?}");
}

// A fixed direction, or one whose size the open locked (SOCK_SNDBUF_LOCK),
// keeps its limit.
#[test]
fn a_fixed_or_locked_send_limit_does_not_expand() {
    let mut fixed = sender_config();
    fixed.connection.send_capacity_max = 0;
    for (config, open, limit) in [(fixed, None, 4096), (sender_config(), Some(8192), 8192)] {
        let limits = send_limits(config, open);
        assert!(limits.iter().all(|&(l, _, _)| l == limit), "{limits:?}");
        assert!(limits.last().unwrap().1 > 20 * 1460);
    }
}

// Under memory pressure, or once the charge reaches tcp_mem[0], ACKs do not
// expand the limit (tcp_should_expand_sndbuf); establishment does, as
// tcp_init_buffer_space checks only the lock.
#[test]
fn memory_pressure_or_the_low_threshold_stops_send_expansion() {
    for (pressure, low) in [(2, 1), (usize::MAX / 2, 1)] {
        let mut config = sender_config();
        config.buffer_pressure_bytes = Some(pressure.min(config.max_buffer_bytes));
        config.buffer_low_bytes = Some(low);
        let limits = send_limits(config, None);
        let established = 20 * limits[0].2 as usize;
        assert!(
            limits.iter().all(|&(l, _, _)| l == established),
            "{limits:?}"
        );
        // The flight left cwnd room that would have expanded the limit.
        assert!(
            limits.last().unwrap().1 as usize > established,
            "{limits:?}"
        );
    }
}

// Two endpoints joined by a link in virtual time (microsecond ticks):
// `bytes_per_ms` each way, `delay` microseconds one way.
struct Link {
    a: Endpoint,
    b: Endpoint,
    queues: [alloc::collections::VecDeque<(u64, IpMetadata, Vec<u8>)>; 2],
    free_at: [u64; 2],
    now: u64,
    bytes_per_ms: u64,
    delay: u64,
    // Every packet `b` sent, after the handshake's.
    from_b: Vec<Vec<u8>>,
}

impl Link {
    fn new(a: Endpoint, b: Endpoint, bytes_per_ms: u64, delay: u64) -> Self {
        Self {
            a,
            b,
            queues: Default::default(),
            free_at: [0; 2],
            now: 0,
            bytes_per_ms,
            delay,
            from_b: Vec::new(),
        }
    }

    // Sends what both sides have to send and delivers what has arrived,
    // until neither has anything more now.
    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for side in 0..2 {
                let endpoint = if side == 0 { &mut self.a } else { &mut self.b };
                loop {
                    let mut bytes = [0; 2048];
                    let output = endpoint.poll_transmit(self.now, &mut bytes, 16).unwrap();
                    if let Some(packet) = output.packet {
                        let departure = self.now.max(self.free_at[side]);
                        self.free_at[side] =
                            departure + (packet.len as u64 * 1000).div_ceil(self.bytes_per_ms);
                        let frame = bytes[..packet.len].to_vec();
                        if side == 1 {
                            self.from_b.push(frame.clone());
                        }
                        self.queues[side].push_back((
                            self.free_at[side] + self.delay,
                            packet.ip,
                            frame,
                        ));
                    }
                    if !output.more_work {
                        break;
                    }
                }
            }
            for side in 0..2 {
                while self.queues[side]
                    .front()
                    .is_some_and(|&(at, _, _)| at <= self.now)
                {
                    let (_, ip, frame) = self.queues[side].pop_front().unwrap();
                    let to = if side == 0 { &mut self.b } else { &mut self.a };
                    to.input(self.now, ip, &frame).unwrap();
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
    }

    // Moves time to the next arrival or deadline and services timers.
    fn advance(&mut self) {
        let next = [
            self.queues[0].front().map(|q| q.0),
            self.queues[1].front().map(|q| q.0),
            self.a.next_deadline(),
            self.b.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
        .expect("something to wait for");
        self.now = self.now.max(next);
        for endpoint in [&mut self.a, &mut self.b] {
            if endpoint.next_deadline().is_some_and(|at| at <= self.now) {
                endpoint.on_timeout(self.now, 64).unwrap();
            }
        }
    }
}

// A bulk transfer from a client of `a_config` to a server of `b_config`
// over 100 Mb/s with a 10 ms RTT (a 125 kB BDP). The client keeps its send
// buffer full; the server reads everything as it arrives. Calls `observe`
// after each read; returns the link once `total` bytes were read.
fn bulk(
    a_config: EndpointConfig,
    b_config: EndpointConfig,
    total: usize,
    mut observe: impl FnMut(&mut Link, ConnectionId),
) -> Link {
    let mut a = Endpoint::new(a_config, [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(b_config, [2; 32], 0, |_| true).unwrap();
    let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
    let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
    let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
    let mut link = Link::new(a, b, 12_500, 5_000);
    let server = loop {
        link.pump();
        if let Ok(server) = link.b.accept(listener) {
            break server;
        }
        link.advance();
    };
    link.from_b.clear();
    let data = [7; 65536];
    let mut out = [0; 65536];
    let mut read = 0;
    while read < total {
        while link.a.write(client, &data).is_ok_and(|count| count != 0) {}
        link.pump();
        while let Ok(count) = link.b.read(server, &mut out) {
            read += count;
            observe(&mut link, server);
        }
        link.pump();
        link.advance();
    }
    link
}

// The client side of a bulk transfer: a fixed 512 KiB send buffer and
// budget for its ledgers.
fn bulk_sender(timestamps: bool) -> EndpointConfig {
    let mut config = config();
    config.connection.send_capacity = 512 << 10;
    config.connection.timestamps = timestamps;
    config.max_buffer_bytes = 1 << 30;
    config
}

// The server side: receive {4096, 65536, 1 MiB}.
fn bulk_receiver(timestamps: bool) -> EndpointConfig {
    let mut config = config();
    config.connection.receive_capacity_max = 1 << 20;
    config.connection.timestamps = timestamps;
    config
}

// The right edges of the windows `packets` (b's) advertised to the bulk
// client (port 40000), after the handshake, with scale `scale`.
fn right_edges(packets: &[Vec<u8>], scale: u8) -> Vec<Seq> {
    packets
        .iter()
        .filter(|p| u16::from_be_bytes([p[2], p[3]]) == 40000)
        .map(|p| {
            let ack = u32::from_be_bytes(p[8..12].try_into().unwrap());
            Seq(ack).wrapping_add(u32::from(window_field(p)) << scale)
        })
        .collect()
}

// Dynamic right-sizing (tcp_rcv_space_adjust, tcp_rcvbuf_grow): a bulk
// receiver's ring grows over a few RTTs from its 64 KiB initial size, never
// shrinks, and the window it advertises never retracts (RFC 9293 section
// 3.8.6, SHLD-14) by a scale unit or more; the transfer then takes about half the time a fixed 64
// KiB window, which carries 52 Mb/s at this RTT, needs. With timestamps the
// receiver's RTT comes from TSecr (tcp_rcv_rtt_measure_ts), without them
// from the time to receive a window (tcp_rcv_rtt_measure).
#[test]
fn drs_grows_the_receive_window_for_a_bulk_transfer() {
    for timestamps in [true, false] {
        let mut sizes = Vec::new();
        let mut rings = Vec::new();
        let tuned = bulk(
            bulk_sender(timestamps),
            bulk_receiver(timestamps),
            4 << 20,
            |link, server| {
                let info = link.b.transport_info(server).unwrap();
                if sizes.last() != Some(&info.receive_capacity) {
                    sizes.push(info.receive_capacity);
                }
                // window_clamp bounds rcv_ssthresh and the ring that backs
                // it, which grows by doubling.
                let (ring, ssthresh, clamp) = receive_state(&link.b, server);
                assert!(
                    ssthresh as usize <= clamp && ring <= clamp.next_multiple_of(8),
                    "{ring} {ssthresh} {clamp}"
                );
                if rings.last() != Some(&ring) {
                    rings.push(ring);
                }
            },
        );
        let mut fixed = bulk_receiver(timestamps);
        fixed.connection.receive_capacity_max = 0;
        let fixed = bulk(bulk_sender(timestamps), fixed, 4 << 20, |_, _| ());
        assert_eq!(sizes[0], 65536);
        assert!(sizes.windows(2).all(|pair| pair[0] < pair[1]), "{sizes:?}");
        // At least twice the BDP, a few doublings, within max.
        assert!(*sizes.last().unwrap() >= 250_000, "{sizes:?}");
        assert!(*sizes.last().unwrap() <= 1 << 20, "{sizes:?}");
        // With timestamps a sample is one RTT, so the ring grows by steps;
        // without them the first sample spans the slow start that filled the
        // first window, and its measure (several times the initial ten
        // segments read) asks for max at once, as Linux's does.
        assert!(!timestamps || sizes.len() >= 3, "{sizes:?}");
        // The ring follows the window offered: it grows from 64 KiB, at
        // least doubling each time but at window_clamp.
        assert_eq!(rings[0], 65536);
        assert!(rings.len() >= 3, "{rings:?}");
        assert!(
            rings.windows(2).all(|pair| pair[1] >= 2 * pair[0]
                || sizes
                    .iter()
                    .any(|&clamp| pair[1] == clamp.next_multiple_of(8))),
            "{rings:?} {sizes:?}"
        );
        let edges = right_edges(&tuned.from_b, 5);
        let worst = edges
            .windows(2)
            .filter(|e| e[0].after(e[1]))
            .map(|e| e[0].distance_from(e[1]))
            .max();
        // Only RFC 7323 section 2.4's rounding, less than one scale unit,
        // moves the encoded edge back (`advertised_window` keeps the old
        // promise internally).
        assert!(worst.is_none_or(|w| w < 1 << 5), "{timestamps} {worst:?}");
        assert!(
            tuned.now * 10 < fixed.now * 6,
            "{timestamps} {} {}",
            tuned.now,
            fixed.now
        );
        // The estimate is an RTT: 10 ms, plus the queue the grown window
        // builds at the link, at most 1 MiB / 12.5 kB/ms.
        let connection = &tuned.b.slots.iter().flatten().next().unwrap().connection;
        let rtt = connection.receive_rtt_us();
        assert!((10_000..95_000).contains(&rtt), "{timestamps} {rtt}");
    }
}

// Requests of 18 to 89 bytes, one at a time over a 2 ms RTT, as a
// key-value store's (n0bb fc_rr's masstree mix). Their only receiver RTT
// sample times a whole 64 KiB window, and the first read after it finds
// several times rcvq_space read: DRS raises window_clamp to about 1 MB, as
// Linux's tcp_rcv_space_adjust does on the same flow. Segments below 128
// bytes never raise rcv_ssthresh (tcp_event_data_recv), so the window
// stays the initial one and the ring is never grown.
#[test]
fn small_requests_keep_the_initial_ring_after_drs_raises_the_clamp() {
    let mut a = Endpoint::new(bulk_receiver(true), [1; 32], 0, |_| true).unwrap();
    let b = Endpoint::new(bulk_receiver(true), [2; 32], 0, |_| true).unwrap();
    let listener = {
        let mut b = b;
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
        (Link::new(a, b, 12_500, 1_000), listener, client)
    };
    let (mut link, listener, client) = listener;
    let server = loop {
        link.pump();
        if let Ok(server) = link.b.accept(listener) {
            break server;
        }
        link.advance();
    };
    link.from_b.clear();
    let mut out = [0; 4096];
    let mut raised = 0;
    for round in 0..4000 {
        let request = [b'q'; 89];
        let len = if round % 20 == 0 { 89 } else { 18 };
        assert_eq!(link.a.write(client, &request[..len]).unwrap(), len);
        let mut got = 0;
        while got < len {
            link.pump();
            got += link.b.read(server, &mut out).unwrap_or(0);
            if got < len {
                link.advance();
            }
        }
        link.b.write(server, &[b'r'; 71]).unwrap();
        let mut got = 0;
        while got < 71 {
            link.pump();
            got += link.a.read(client, &mut out).unwrap_or(0);
            if got < 71 {
                link.advance();
            }
        }
        let (ring, ssthresh, clamp) = receive_state(&link.b, server);
        assert_eq!((ring, ssthresh), (65536, 65536), "round {round}");
        if clamp > 65536 {
            raised += 1;
        }
    }
    // The clamp rose well before the end; the ring stayed as it was.
    assert!(raised > 500, "{raised}");
    assert!(receive_state(&link.b, server).2 > 500_000);
    assert_eq!(link.b.memory_refused_growths, 0);
    let edges = right_edges(&link.from_b, 5);
    assert!(
        edges
            .windows(2)
            .all(|e| e[1].at_or_after(e[0]) || e[0].distance_from(e[1]) < 1 << 5)
    );
}

// The receive sizes the server reported, each change once, and its count
// of refused growths, for a bulk transfer of `total` bytes in which
// `adjust` may change the server endpoint once its ring first grew.
fn receive_sizes(
    b_config: EndpointConfig,
    total: usize,
    mut adjust: impl FnMut(&mut Endpoint, ConnectionId, usize),
) -> (Vec<usize>, Link) {
    let mut sizes: Vec<usize> = Vec::new();
    let link = bulk(bulk_sender(true), b_config, total, |link, server| {
        let size = link.b.transport_info(server).unwrap().receive_capacity;
        adjust(&mut link.b, server, size);
        if sizes.last() != Some(&size) {
            sizes.push(size);
        }
    });
    (sizes, link)
}

// SO_RCVBUF (SOCK_RCVBUF_LOCK) stops DRS: tcp_rcvbuf_grow returns at once.
#[test]
fn a_locked_receive_size_does_not_grow() {
    let (sizes, _) = receive_sizes(bulk_receiver(true), 2 << 20, |b, server, size| {
        if size == 65536 {
            b.set_receive_buffer(server, 65536).unwrap();
        }
    });
    assert_eq!(sizes, [65536]);
}

// The server connection's receive ring, rcv_ssthresh and window_clamp.
fn receive_state(b: &Endpoint, server: ConnectionId) -> (usize, u32, usize) {
    let connection = &b.slot(server).unwrap().connection;
    (
        connection.receive_allocation_capacity(),
        connection.receive_ssthresh(),
        b.transport_info(server).unwrap().receive_capacity,
    )
}

// Linux's tcp_grow_window check #1: under memory pressure rcv_ssthresh does
// not rise, so the window and the ring stay as they are while window_clamp
// (a limit, which DRS raises without memory) may grow; once pressure ends
// rcv_ssthresh rises again and the ring with it.
#[test]
fn memory_pressure_stops_the_window_growth() {
    let mut phase = 0;
    let mut held = (0, 0);
    let mut reads = 0;
    let (_, link) = receive_sizes(bulk_receiver(true), 6 << 20, |b, server, _| {
        let (ring, ssthresh, _) = receive_state(b, server);
        if phase == 0 && ring > 65536 {
            phase = 1;
            b.config.buffer_pressure_bytes = Some(1);
            b.config.buffer_low_bytes = Some(0);
            b.charge(1);
            b.uncharge(1);
            assert!(b.memory_pressure());
            held = (ring, ssthresh);
        } else if phase == 1 {
            assert_eq!(ssthresh, held.1);
            // At most a growth asked for before pressure began.
            assert!(ring <= 2 * held.0, "{ring} {held:?}");
            reads += 1;
            if reads == 200 {
                phase = 2;
                b.config.buffer_pressure_bytes = None;
                b.config.buffer_low_bytes = None;
                b.charge(1);
                b.uncharge(1);
                assert!(!b.memory_pressure());
            }
        } else if phase == 2 && ssthresh > held.1 && ring > 2 * held.0 {
            phase = 3;
        }
    });
    assert_eq!(phase, 3);
    let edges = right_edges(&link.from_b, 5);
    assert!(
        edges
            .windows(2)
            .all(|e| e[1].at_or_after(e[0]) || e[0].distance_from(e[1]) < 1 << 5)
    );
}

// As Linux's __sk_mem_raise_allocated for SK_MEM_RECV: a ring growth past
// the hard cap is refused and counted, the window stays what the ring
// backs, and the growth is asked for again at the next DRS measure, so a
// larger cap lets the ring grow.
#[test]
fn a_receive_ring_growth_past_the_cap_waits_for_the_next_measure() {
    let mut phase = 0;
    let mut held = 0;
    let (_, link) = receive_sizes(bulk_receiver(true), 6 << 20, |b, server, _| {
        let (ring, _, _) = receive_state(b, server);
        if phase == 0 && ring > 65536 {
            phase = 1;
            held = ring;
            b.config.max_buffer_bytes = b.buffer_bytes();
            assert_eq!(b.memory_refused_growths, 0);
        } else if phase == 1 {
            assert_eq!(ring, held);
            if b.memory_refused_growths >= 3 {
                phase = 2;
                b.config.max_buffer_bytes = 1 << 30;
            }
        } else if phase == 2 && ring > held {
            phase = 3;
        }
    });
    assert_eq!(phase, 3);
    let edges = right_edges(&link.from_b, 5);
    assert!(
        edges
            .windows(2)
            .all(|e| e[1].at_or_after(e[0]) || e[0].distance_from(e[1]) < 1 << 5)
    );
}

// SO_RCVBUF before connect() (SOCK_RCVBUF_LOCK) sets the window scale from
// the locked size, as Linux clamps window_clamp to it before
// tcp_select_initial_window (RFC 7323 section 2.1); once the SYN has left,
// a lock keeps the scale it sent.
#[test]
fn a_receive_lock_before_the_syn_fixes_the_window_scale() {
    let mut config = config();
    config.connection.receive_capacity_max = 32 << 20;
    for (before_syn, bytes, scale) in [(true, 65536, 1), (true, 1 << 20, 5), (false, 65536, 10)] {
        let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config.clone(), [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
        let mut trace = [Vec::new(), Vec::new()];
        if before_syn {
            a.set_receive_buffer(client, bytes).unwrap();
        }
        exchange(&mut a, &mut b, 0, &mut trace);
        b.accept(listener).unwrap();
        if !before_syn {
            a.set_receive_buffer(client, bytes).unwrap();
        }
        assert_eq!(window_scale_option(&trace[0][0]), Some(scale));
        let info = a.transport_info(client).unwrap();
        assert_eq!(
            (info.receive_window_scale, info.receive_capacity),
            (scale, bytes)
        );
        // The server, unlocked, scales from its maximum.
        assert_eq!(window_scale_option(&trace[1][0]), Some(10));
    }
}

// A child takes its listener's locked sizes, locked, one direction at a
// time (a child socket inherits sk_userlocks): its locked receive size sets
// its scale and never grows; its unlocked direction stays tuned.
#[test]
fn children_inherit_their_listeners_locks() {
    for (send_lock, receive_lock) in [(true, true), (false, true), (true, false)] {
        let mut config = bulk_receiver(true);
        config.connection.send_capacity_max = 1 << 20;
        // The client's window does not limit the server's echo.
        let mut client_config = bulk_sender(true);
        client_config.connection.receive_capacity = 1 << 20;
        let mut a = Endpoint::new(client_config, [1; 32], 0, |_| true).unwrap();
        let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
        let listener = b.listen(REMOTE.parse().unwrap(), 4).unwrap();
        if send_lock {
            b.set_listener_send_buffer(listener, 8192).unwrap();
        }
        if receive_lock {
            b.set_listener_receive_buffer(listener, 32768).unwrap();
        }
        assert_eq!(
            b.listener_buffer_capacities(listener),
            Ok((
                if send_lock { 8192 } else { 65536 },
                if receive_lock { 32768 } else { 65536 }
            ))
        );
        let local = SocketAddr::new("192.0.2.1".parse().unwrap(), 40000);
        let client = a.connect(0, local, REMOTE.parse().unwrap()).unwrap();
        let mut link = Link::new(a, b, 12_500, 5_000);
        let server = loop {
            link.pump();
            if let Ok(server) = link.b.accept(listener) {
                break server;
            }
            link.advance();
        };
        let info = link.b.transport_info(server).unwrap();
        assert_eq!(info.receive_window_scale, if receive_lock { 0 } else { 5 });
        let data = [7; 65536];
        let mut out = [0; 65536];
        let mut read = 0;
        // Both sides send in bulk and read everything.
        while read < 256 << 10 {
            while link.a.write(client, &data).is_ok_and(|count| count != 0) {}
            while link.b.write(server, &data).is_ok_and(|count| count != 0) {}
            link.pump();
            while let Ok(count) = link.b.read(server, &mut out) {
                read += count;
            }
            while link.a.read(client, &mut out).is_ok() {}
            link.pump();
            link.advance();
        }
        let info = link.b.transport_info(server).unwrap();
        if send_lock {
            assert_eq!(info.send_capacity, 8192);
        } else {
            assert!(info.send_capacity > 65536, "{}", info.send_capacity);
        }
        if receive_lock {
            assert_eq!(info.receive_capacity, 32768);
        } else {
            assert!(info.receive_capacity > 65536, "{}", info.receive_capacity);
        }
    }
}

// set_send_buffer locks the send direction (SOCK_SNDBUF_LOCK): no later
// ACK expands it, and it allocates nothing.
#[test]
fn a_send_lock_stops_expansion() {
    let mut a = Endpoint::new(sender_config(), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(sender_config(), [2; 32], 0, |_| true).unwrap();
    let mut trace = [Vec::new(), Vec::new()];
    let (client, server) = connect(&mut a, &mut b, 40000, &mut trace);
    let charge = a.buffer_bytes();
    a.set_send_buffer(client, 6000).unwrap();
    assert_eq!(a.buffer_bytes(), charge);
    assert_eq!(
        a.set_send_buffer(client, 0),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(
        a.set_send_buffer(client, 1 << 30),
        Err(Error::InvalidArgument.into())
    );
    assert_eq!(
        a.set_receive_buffer(client, 0),
        Err(Error::InvalidArgument.into())
    );
    let data = [7; 65536];
    let mut out = [0; 65536];
    for now in 1..40 {
        while a.write(client, &data).is_ok_and(|count| count != 0) {}
        exchange(&mut a, &mut b, now, &mut trace);
        while b.read(server, &mut out).is_ok() {}
    }
    let info = a.transport_info(client).unwrap();
    assert_eq!(info.send_capacity, 6000);
    assert!(info.cwnd > 3 * 6000);
}
