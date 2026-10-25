// SPDX-License-Identifier: MIT
use super::*;
use core::net::SocketAddr;

struct Passive {
    endpoint: Endpoint,
    listener: ListenerId,
    local: SocketAddr,
    remote: SocketAddr,
}
impl Passive {
    fn new(v6: bool, backlog: usize, tfo: bool) -> Self {
        let (local, remote) = if v6 {
            (
                "[2001:db8::2]:8080".parse().unwrap(),
                "[2001:db8::1]:40000".parse().unwrap(),
            )
        } else {
            (
                "192.0.2.2:8080".parse().unwrap(),
                "192.0.2.1:40000".parse().unwrap(),
            )
        };
        let mut config = config();
        config.connection.timestamps = false;
        config.connection.delayed_ack_us = 0;
        let mut endpoint = Endpoint::new(config, [2; 32], 0, test_policy).unwrap();
        if tfo {
            endpoint.enable_fast_open().unwrap();
        }
        let listener = endpoint.listen(local, backlog).unwrap();
        if tfo {
            endpoint.set_listener_fast_open(listener, 1).unwrap();
        }
        Self {
            endpoint,
            listener,
            local,
            remote,
        }
    }
    fn tuple(&self, port: u16) -> Tuple {
        Tuple {
            local: self.local,
            remote: SocketAddr::new(self.remote.ip(), port),
        }
    }
    fn header(&self, port: u16, sequence: u32, acknowledgment: u32, flags: u8) -> wire::Header {
        wire::Header {
            source_port: port,
            destination_port: self.local.port(),
            sequence,
            acknowledgment,
            flags,
            window: 8192,
            urgent_pointer: 0,
        }
    }
    fn input(
        &mut self,
        now: u64,
        header: wire::Header,
        options: &[u8],
        data: &[u8],
    ) -> Result<InputDisposition, EndpointError> {
        let ip = IpMetadata {
            source: self.remote.ip(),
            destination: self.local.ip(),
        };
        let mut bytes = [0; 256];
        let n = wire::encode(ip, header, options, data, &mut bytes).unwrap();
        self.endpoint.input(now, ip, &bytes[..n])
    }
    fn connect(
        &mut self,
        port: u16,
        now: u64,
        complete: bool,
        tfo: bool,
        data: &[u8],
    ) -> ConnectionId {
        let options = if tfo {
            &[34, 10, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 1, 1][..]
        } else {
            &[]
        };
        self.input(now, self.header(port, 100, 0, wire::SYN), options, &[])
            .unwrap();
        let child = self.endpoint.connection_id(self.tuple(port)).unwrap();
        let replies = packets(&mut self.endpoint, now);
        let (reply_ip, reply) = replies
            .iter()
            .find(|(ip, bytes)| {
                let segment = wire::parse(*ip, bytes).unwrap();
                segment.header.destination_port == port && segment.header.flags & wire::SYN != 0
            })
            .unwrap();
        let reply = wire::parse(*reply_ip, reply).unwrap();
        assert_eq!(reply.header.acknowledgment, 101);
        assert_eq!(self.endpoint.state(child).unwrap(), State::SynReceived);
        if complete {
            self.input(
                now,
                self.header(port, 101, reply.header.sequence.wrapping_add(1), wire::ACK),
                &[],
                data,
            )
            .unwrap();
            assert_eq!(self.endpoint.state(child).unwrap(), State::Established);
        }
        child
    }
    fn reset(&mut self, port: u16, now: u64, size: usize) {
        self.input(
            now,
            self.header(port, 101 + size as u32, 0, wire::RST),
            &[],
            &[],
        )
        .unwrap();
    }
}

#[test]
fn established_reset_before_or_after_accept_preserves_terminal_data_and_status() {
    for v6 in [false, true] {
        for tfo in [false, true] {
            for size in [0, 10] {
                for accept_first in [false, true] {
                    let mut p = Passive::new(v6, 2, tfo);
                    let baseline = p.endpoint.buffer_bytes();
                    let child = p.connect(40000, 0, true, tfo, &vec![7; size]);
                    assert_eq!(p.endpoint.listener_queue_info(p.listener).unwrap().0, 1);
                    assert_eq!(p.endpoint.next_event(), Some(Event::Acceptable(p.listener)));
                    if accept_first {
                        assert_eq!(p.endpoint.accept(p.listener).unwrap(), child);
                    }
                    p.reset(40000, 1, size);
                    assert_eq!(p.endpoint.state(child).unwrap(), State::Closed);
                    assert_eq!(
                        p.endpoint.close_reason(child).unwrap(),
                        Some(CloseReason::Reset)
                    );
                    assert_eq!(
                        p.endpoint.listener_queue_info(p.listener).unwrap().0,
                        usize::from(!accept_first)
                    );
                    if !accept_first {
                        assert_eq!(p.endpoint.accept(p.listener).unwrap(), child);
                    }
                    let info = p.endpoint.transport_info(child).unwrap();
                    assert!(!info.syn_data_acked && !info.syn_data_fully_acked);
                    assert_eq!(p.endpoint.terminal_readable_bytes(child).unwrap(), size);
                    let mut bytes = [0; 32];
                    assert_eq!(
                        p.endpoint.read(child, &mut bytes),
                        Err(Error::InvalidState.into())
                    );
                    assert_eq!(p.endpoint.read_terminal(child, &mut bytes).unwrap(), size);
                    assert_eq!(&bytes[..size], &vec![7; size]);
                    assert_eq!(p.endpoint.read_terminal(child, &mut bytes).unwrap(), 0);
                    p.endpoint.release(child).unwrap();
                    packets(&mut p.endpoint, 2);
                    assert!(!p.endpoint.connection_exists(child));
                    assert_eq!(p.endpoint.buffer_bytes(), baseline);
                }
            }
        }
    }
}

#[test]
fn terminal_pending_children_preserve_fifo_backlog_and_same_tuple_ownership() {
    for v6 in [false, true] {
        let mut p = Passive::new(v6, 2, false);
        let first = p.connect(40000, 0, true, false, &[7; 10]);
        p.reset(40000, 1, 10);
        let second = p.connect(40001, 2, true, false, &[]);
        p.reset(40001, 3, 0);
        assert_eq!(p.endpoint.listener_queue_info(p.listener).unwrap(), (2, 2));
        let retained = p.endpoint.buffer_bytes();
        p.input(4, p.header(40002, 100, 0, wire::SYN), &[], &[])
            .unwrap();
        assert!(p.endpoint.connection_id(p.tuple(40002)).is_none());
        assert_eq!(p.endpoint.buffer_bytes(), retained);
        assert_eq!(p.endpoint.listener_queue_info(p.listener).unwrap().0, 2);
        assert_eq!(p.endpoint.accept(p.listener).unwrap(), first);
        // The old closed handle owns its receive data, while a new connection
        // may reuse its now-unmapped wire tuple after queue capacity is freed.
        let replacement = p.connect(40000, 5, true, false, &[]);
        assert_ne!(replacement, first);
        assert_eq!(p.endpoint.connection_id(p.tuple(40000)), Some(replacement));
        assert_eq!(p.endpoint.state(first).unwrap(), State::Closed);
        assert_eq!(p.endpoint.terminal_readable_bytes(first).unwrap(), 10);
        assert_eq!(p.endpoint.accept(p.listener).unwrap(), second);
        assert_eq!(p.endpoint.accept(p.listener).unwrap(), replacement);
        assert_eq!(p.endpoint.accept(p.listener), Err(Error::WouldBlock.into()));
        for id in [first, second] {
            p.endpoint.release(id).unwrap();
        }
        packets(&mut p.endpoint, 6);
        assert!(!p.endpoint.connection_exists(first));
        assert!(!p.endpoint.connection_exists(second));
        assert_eq!(p.endpoint.state(replacement).unwrap(), State::Established);
    }
}

#[test]
fn listener_close_reclaims_terminal_pending_children_and_invalidates_generation() {
    for v6 in [false, true] {
        let mut p = Passive::new(v6, 2, false);
        let baseline = p.endpoint.buffer_bytes();
        let first = p.connect(40000, 0, true, false, &[7; 10]);
        p.reset(40000, 1, 10);
        let second = p.connect(40001, 2, true, false, &[]);
        p.reset(40001, 3, 0);
        let old = p.listener;
        p.endpoint.close_listener(old).unwrap();
        packets(&mut p.endpoint, 4);
        assert!(!p.endpoint.connection_exists(first));
        assert!(!p.endpoint.connection_exists(second));
        assert_eq!(p.endpoint.buffer_bytes(), baseline);
        assert_eq!(p.endpoint.accept(old), Err(EndpointError::InvalidHandle));
        p.listener = p.endpoint.listen(p.local, 2).unwrap();
        assert_ne!(p.listener, old);
        let child = p.connect(40000, 5, true, false, &[]);
        assert_eq!(p.endpoint.next_event(), Some(Event::Acceptable(p.listener)));
        assert_eq!(p.endpoint.accept(p.listener).unwrap(), child);
    }
}

#[test]
fn incomplete_ordinary_handshake_failure_does_not_enter_accept_queue() {
    for v6 in [false, true] {
        for timeout in [false, true] {
            let mut p = Passive::new(v6, 2, false);
            let baseline = p.endpoint.buffer_bytes();
            let child = p.connect(40000, 0, false, false, &[]);
            assert_eq!(p.endpoint.listener_queue_info(p.listener).unwrap().0, 0);
            let now = if timeout {
                p.endpoint.on_timeout(400_000_000, 64).unwrap();
                400_000_000
            } else {
                p.reset(40000, 1, 0);
                1
            };
            packets(&mut p.endpoint, now);
            assert!(!p.endpoint.connection_exists(child));
            assert_eq!(p.endpoint.accept(p.listener), Err(Error::WouldBlock.into()));
            assert_eq!(p.endpoint.next_event(), None);
            assert_eq!(p.endpoint.buffer_bytes(), baseline);
        }
    }
}

#[test]
fn output_reservation_preserves_accept_and_reset_ordering() {
    for v6 in [false, true] {
        let mut p = Passive::new(v6, 2, false);
        p.endpoint.enable_output_reservations().unwrap();
        let child = p.connect(40000, 0, true, false, &[7; 10]);
        let mut bytes = [0; 2048];
        let (output, attempt) = p
            .endpoint
            .poll_reserved_transmit(1, &mut bytes, 32)
            .unwrap();
        assert_eq!(output.packet.unwrap().connection, Some(child));
        let attempt = attempt.unwrap();
        assert_eq!(
            p.endpoint.accept(p.listener),
            Err(EndpointError::OutputReserved)
        );
        assert_eq!(
            p.endpoint.close_listener(p.listener),
            Err(EndpointError::OutputReserved)
        );
        assert_eq!(
            p.input(2, p.header(40000, 111, 0, wire::RST), &[], &[]),
            Err(EndpointError::OutputReserved)
        );
        assert_eq!(p.endpoint.state(child).unwrap(), State::Established);
        assert!(p.endpoint.reject_unsubmitted(attempt).unwrap());
        let (_, retry) = p
            .endpoint
            .poll_reserved_transmit_for(3, child, &mut bytes, 32)
            .unwrap();
        assert!(!p.endpoint.accept_transmit(4, attempt).unwrap());
        assert!(p.endpoint.accept_transmit(4, retry.unwrap()).unwrap());
        p.reset(40000, 5, 10);
        assert_eq!(p.endpoint.accept(p.listener).unwrap(), child);
        assert_eq!(p.endpoint.state(child).unwrap(), State::Closed);
        assert_eq!(p.endpoint.read_terminal(child, &mut bytes).unwrap(), 10);
    }
}
