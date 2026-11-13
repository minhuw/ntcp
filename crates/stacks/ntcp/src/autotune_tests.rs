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
