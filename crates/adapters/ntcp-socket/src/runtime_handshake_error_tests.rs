// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Compare completion stages, retaining each API's distinct admission result.
use super::fast_open_tests::{tfo_capture, tfo_deliver, tfo_no_output};
use super::memory::tests::{cid, exchange};
use super::tests::new;
use super::*;
use crate::packet_profile::Profile;

#[path = "runtime_handshake_startup_tests.rs"]
mod startup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Open {
    Connect,
    MsgCold,
    MsgWarm,
    DeferredCold,
    DeferredWarm,
}
const OPENS: [Open; 5] = [
    Open::Connect,
    Open::MsgCold,
    Open::MsgWarm,
    Open::DeferredCold,
    Open::DeferredWarm,
];
impl Open {
    fn warm(self) -> bool {
        matches!(self, Self::MsgWarm | Self::DeferredWarm)
    }
    fn connect(self) -> bool {
        matches!(self, Self::Connect | Self::DeferredCold)
    }
    fn deferred(self) -> bool {
        matches!(self, Self::DeferredCold | Self::DeferredWarm)
    }
    fn op(self, remote: SocketAddr) -> Op {
        if self.connect() {
            Op::Connect(remote)
        } else {
            Op::SendTo(
                vec![(b"hello".as_ptr() as usize, 5)],
                if self.deferred() { 0 } else { MSG_FASTOPEN },
                Some(remote),
                None,
            )
        }
    }
}
fn segment(packet: &[u8]) -> ntcp::wire::Segment<'_> {
    let p = crate::ip::parse(packet).unwrap();
    ntcp::wire::parse(p.ip, p.payload).unwrap()
}
fn setup(v6: bool, warm: bool) -> (Owner, Owner, u64, SocketAddr) {
    setup_bounded(v6, warm, crate::packet_profile::LIMIT)
}
fn setup_bounded(v6: bool, warm: bool, capacity: usize) -> (Owner, Owner, u64, SocketAddr) {
    let addresses: [IpAddr; 2] = if v6 {
        [
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ]
    } else {
        ["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()]
    };
    let mut owners = addresses.map(|local| {
        let mut o = Owner::packet_with_options(
            (local, Profile::Pipeline),
            crate::packet_test::Options {
                queue_capacity: 8,
                egress_capacity: 2,
            },
        )
        .unwrap();
        o.test_now = Some(1000);
        o
    });
    let [a, b] = &mut owners;
    let mut config = crate::packet_profile::config(Profile::Pipeline);
    config.max_connections = capacity;
    a.endpoint = Endpoint::new(config.clone(), [42; 32], 0, |_| true).unwrap();
    a.defaults = config;
    a.endpoint.enable_fast_open().unwrap();
    a.enable_egress(2, None).unwrap();
    let remote = SocketAddr::new(b.local, 8080);
    let listener = new(b, SOCK_NONBLOCK);
    b.execute(listener, Op::Set(IPPROTO_TCP, TCP_FASTOPEN, 4))
        .unwrap();
    b.execute(listener, Op::Bind(remote)).unwrap();
    b.execute(listener, Op::Listen(8)).unwrap();
    if warm {
        let client = new(a, SOCK_NONBLOCK);
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        assert_eq!(
            a.execute(client, Op::Connect(remote)).unwrap_err(),
            EINPROGRESS
        );
        exchange(a, b);
        let server = b
            .execute(listener, Op::Accept(SOCK_NONBLOCK))
            .unwrap()
            .value as u64;
        // A remote reset releases the learning slot without creating a local
        // reset's intentional 2MSL tuple reservation.
        let learning = cid(a, client);
        b.endpoint.abort(cid(b, server)).unwrap();
        exchange(a, b);
        assert_eq!(
            a.execute(client, Op::FinishConnect).unwrap_err(),
            ECONNRESET
        );
        a.execute(client, Op::Close).unwrap();
        b.execute(server, Op::Close).unwrap();
        exchange(a, b);
        assert!(!a.endpoint.connection_exists(learning));
        assert!(
            a.endpoint
                .can_defer_fast_open(a.now(), a.local, remote)
                .unwrap()
        );
    }
    a.connection_options
        .retain(|p| a.endpoint.connection_exists(p.0));
    let [a, b] = owners;
    (a, b, listener, remote)
}
fn socket(a: &mut Owner, mode: Open, remote: SocketAddr, blocking: bool) -> u64 {
    let id = new(a, if blocking { 0 } else { SOCK_NONBLOCK });
    a.execute(id, Op::Set(IPPROTO_TCP, TCP_NODELAY, 1)).unwrap();
    if mode.deferred() {
        a.execute(id, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1))
            .unwrap();
        if mode.warm() {
            assert_eq!(a.execute(id, Op::Connect(remote)).unwrap().value, 0);
            assert!(matches!(a.sockets[&id].handle, Handle::Fresh));
            tfo_no_output(a);
        }
    }
    id
}
fn wait(id: u64, op: Op) -> (Request, Receiver<Result<Reply>>) {
    let (reply, rx) = mpsc::sync_channel(1);
    (
        Request {
            id,
            op: Op::Wait(Box::new(op), None),
            reply,
            deadline: None,
            send: None,
            closing: None,
        },
        rx,
    )
}
// Build a complete checksummed feedback frame around an actual emitted packet.
// IPv4 and IPv6 have distinct, independently decoded error code spaces.
pub(super) fn feedback(packet: &[u8], kind: u8, code: u8) -> Vec<u8> {
    let p = crate::ip::parse(packet).unwrap();
    if p.ip.source.is_ipv4() {
        let mut f = super::memory::tests::ptb_frame(packet);
        f[20] = kind;
        f[21] = code;
        f[24..28].fill(0);
        super::memory::tests::ptb_checksums(&mut f);
        f
    } else {
        let mut f = vec![0; 48 + packet.len()];
        f[0] = 0x60;
        let n = (f.len() - 40) as u16;
        f[4..6].copy_from_slice(&n.to_be_bytes());
        f[6] = 58;
        f[7] = 64;
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.ip.destination, p.ip.source) else {
            panic!()
        };
        f[8..24].copy_from_slice(&src.octets());
        f[24..40].copy_from_slice(&dst.octets());
        f[40] = kind;
        f[41] = code;
        f[48..].copy_from_slice(packet);
        let sum = ntcp_icmp::icmpv6_checksum(
            ntcp::IpMetadata {
                source: p.ip.destination,
                destination: p.ip.source,
            },
            &f[40..],
        )
        .unwrap();
        f[42..44].copy_from_slice(&sum.to_be_bytes());
        f
    }
}
#[derive(Clone, Copy, Debug)]
enum Failure {
    Refused,
    R2,
    Application,
    ApplicationHeld,
    SynBudget,
    Abort,
    Cancel,
    Abandon,
    Hard(u8),
}
impl Failure {
    fn errno(self) -> i32 {
        match self {
            Self::Refused => ECONNREFUSED,
            Self::R2 | Self::Application | Self::ApplicationHeld | Self::SynBudget => ETIMEDOUT,
            Self::Abort | Self::Cancel | Self::Abandon => ECONNABORTED,
            Self::Hard(_) => EHOSTUNREACH,
        }
    }
    fn reason(self) -> CloseReason {
        match self {
            Self::Refused => CloseReason::Reset,
            Self::R2 | Self::Application | Self::ApplicationHeld | Self::SynBudget => {
                CloseReason::TimedOut
            }
            Self::Abort | Self::Abandon => CloseReason::Aborted,
            Self::Cancel => CloseReason::Normal,
            Self::Hard(_) => CloseReason::NetworkError,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    completion: i32,
    so_error: i32,
    ready: i32,
    after_consume: i32,
    after_complete: i32,
}
fn fatal_case(v6: bool, mode: Open, failure: Failure, blocking: bool, consume: bool) -> Trace {
    let (mut a, mut b, listener, remote) = setup(v6, mode.warm());
    let client = socket(&mut a, mode, remote, blocking);
    if matches!(failure, Failure::Application | Failure::ApplicationHeld) {
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_USER_TIMEOUT, 100))
            .unwrap();
    }
    if matches!(failure, Failure::SynBudget) {
        a.execute(client, Op::Set(IPPROTO_TCP, TCP_SYNCNT, 1))
            .unwrap();
    }
    if matches!(failure, Failure::ApplicationHeld) {
        // A second real connection fills the bounded backend. The candidate
        // owns an unsubmitted WouldBlock reservation, not local RTO evidence.
        a.packets = Some(PacketBackend::new(Profile::Pipeline, 1).unwrap());
        let holder = new(&mut a, SOCK_NONBLOCK);
        assert_eq!(
            a.execute(holder, Op::Connect(SocketAddr::new(remote.ip(), 8090)))
                .unwrap_err(),
            EINPROGRESS
        );
        a.service_egress().unwrap();
    }
    // A real backend refusal holds an unsubmitted reservation until Owner expiry.
    if matches!(failure, Failure::Abandon) {
        a.execute(0, Op::LocalResourceReject(true)).unwrap();
    }
    let initial = if blocking && mode.connect() {
        Op::BlockingConnect(remote)
    } else {
        mode.op(remote)
    };
    let (mut request, rx) = wait(client, initial);
    if blocking {
        assert!(!a.service(&mut request));
        if !mode.connect() {
            assert_eq!(
                request.send.as_ref().unwrap().accepted,
                if mode.warm() { 5 } else { 0 }
            );
        }
    } else {
        let result = a.execute(client, mode.op(remote));
        if mode.warm() {
            assert_eq!(result.unwrap().value, 5);
        } else {
            assert_eq!(result.unwrap_err(), EINPROGRESS);
        }
    }
    let failed = cid(&a, client);
    let started = a.now();
    assert_eq!(a.endpoint.state(failed).unwrap(), State::SynSent);
    assert_eq!(a.execute(client, Op::FinishConnect).unwrap_err(), EAGAIN);
    let before = a.execute(client, Op::Ready).unwrap();
    assert_eq!(before.value & (EPOLLOUT | EPOLLERR | EPOLLHUP), 0);
    let syn = if matches!(failure, Failure::Abandon | Failure::ApplicationHeld) {
        a.service_egress().unwrap();
        assert!(a.endpoint.is_output_reserved(failed));
        if matches!(failure, Failure::ApplicationHeld) {
            let holder = a.execute(0, Op::Capture(65535)).unwrap().bytes;
            assert_ne!(
                segment(&holder).header.source_port,
                a.endpoint.tuple(failed).unwrap().local.port()
            );
            assert_eq!(a.endpoint.transport_info(failed).unwrap().rto_backoff, 0);
        }
        assert_eq!(a.execute(0, Op::Capture(65535)).unwrap_err(), EAGAIN);
        None
    } else {
        let syn = tfo_capture(&mut a);
        assert_ne!(segment(&syn).header.flags & ntcp::wire::SYN, 0);
        assert_eq!(
            segment(&syn).payload,
            if mode.warm() { &b"hello"[..] } else { &[][..] }
        );
        Some(syn)
    };
    match failure {
        Failure::Refused => {
            b.execute(listener, Op::Close).unwrap();
            tfo_deliver(&mut b, syn.unwrap());
            let reset = tfo_capture(&mut b);
            assert_ne!(segment(&reset).header.flags & ntcp::wire::RST, 0);
            tfo_deliver(&mut a, reset);
        }
        Failure::Hard(code) => {
            let f = feedback(&syn.unwrap(), if v6 { 1 } else { 3 }, code);
            let decoded = ntcp_icmp::decode_icmp(&f).unwrap();
            assert_eq!(
                if v6 {
                    decoded.ipv6_network_error()
                } else {
                    decoded.ipv4_network_error()
                },
                Some(ntcp::NetworkError::HardUnreachable)
            );
            tfo_deliver(&mut a, f);
        }
        Failure::Abort => {
            a.endpoint.abort(failed).unwrap();
        }
        Failure::Cancel => {
            a.endpoint.shutdown(failed).unwrap();
        }
        Failure::Abandon => {
            a.test_now = Some(started + a.reservation_timeout_us);
            a.expire_egress(a.now()).unwrap();
            a.execute(0, Op::LocalResourceReject(false)).unwrap();
        }
        Failure::ApplicationHeld => {
            a.test_now = Some(started + 100_000);
            // Exercise Owner's application-before-I/O-deadline branch directly.
            a.expire_egress(a.now()).unwrap();
            assert!(!a.endpoint.is_output_reserved(failed));
        }
        Failure::Application | Failure::R2 | Failure::SynBudget => {
            let mut retries = 0;
            for _ in 0..32 {
                let now = a.endpoint.next_deadline().unwrap();
                a.test_now = Some(now - 1);
                a.endpoint.on_timeout(now - 1, BUDGET).unwrap();
                assert_eq!(a.endpoint.state(failed).unwrap(), State::SynSent);
                a.test_now = Some(now);
                a.endpoint.on_timeout(now, BUDGET).unwrap();
                a.events();
                if a.endpoint.state(failed).unwrap() == State::Closed {
                    break;
                }
                a.service_egress().unwrap();
                while let Ok(retry) = a.execute(0, Op::Capture(65535)) {
                    assert_ne!(segment(&retry.bytes).header.flags & ntcp::wire::SYN, 0);
                    retries += 1;
                }
            }
            match failure {
                Failure::Application => {
                    assert_eq!(a.now() - started, 100_000);
                    assert_eq!(retries, 0);
                }
                Failure::SynBudget => {
                    assert_eq!(a.now() - started, 3_000_000);
                    assert_eq!(retries, 1);
                }
                Failure::R2 => {
                    assert!(a.now() - started >= 180_000_000);
                    assert!(retries > 1);
                }
                _ => unreachable!(),
            }
        }
    }
    a.events();
    assert_eq!(a.endpoint.state(failed).unwrap(), State::Closed);
    assert_eq!(
        a.endpoint.close_reason(failed).unwrap(),
        Some(failure.reason())
    );
    let terminal = a.execute(client, Op::Transport(1)).unwrap().bytes;
    assert_eq!(terminal.len(), 280);
    assert_eq!(terminal[0], 7);
    assert_eq!(terminal[5] & 32, 0); // Never claim established SYN data.
    let ready = a.execute(client, Op::Ready).unwrap();
    let fatal = !matches!(failure, Failure::Cancel);
    assert_eq!(ready.value & EPOLLERR != 0, fatal);
    assert_eq!(
        ready.value & (EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP),
        EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP
    );
    let level = a.execute(client, Op::Ready).unwrap();
    assert_eq!(level.value, ready.value);
    assert_eq!(level.readiness_generations, ready.readiness_generations);
    assert_ne!(ready.readiness_generations, before.readiness_generations);
    let expected_so = if fatal { failure.errno() } else { 0 };
    let so_error = if consume {
        let error = a
            .execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value;
        assert_eq!(error, expected_so);
        assert_eq!(
            a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                .unwrap()
                .value,
            0
        );
        error
    } else {
        0
    };
    let after_consume = a.execute(client, Op::Ready).unwrap().value;
    let completion = if blocking {
        assert!(a.service(&mut request));
        assert!(request.send.is_none());
        rx.try_recv().unwrap().unwrap_err()
    } else {
        // Retry the same operation: connect/check_connect and implicit send
        // completion must both consume exactly the existing attempt.
        let completion = if mode == Open::DeferredWarm {
            Op::Connect(remote)
        } else {
            mode.op(remote)
        };
        a.execute(client, completion).unwrap_err()
    };
    assert_eq!(
        completion,
        if consume {
            ECONNABORTED
        } else {
            failure.errno()
        }
    );
    assert!(!a.sockets[&client].connect_pending);
    assert!(!a.sockets[&client].connected);
    assert!(matches!(a.sockets[&client].handle, Handle::Fresh));
    assert_eq!(
        a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
            .unwrap()
            .value,
        0
    );
    assert_eq!(a.execute(client, Op::FinishConnect).unwrap_err(), ENOTCONN);
    assert_eq!(a.execute(client, Op::Read(1)).unwrap_err(), ENOTCONN);
    assert_eq!(a.execute(client, Op::Peek(1)).unwrap_err(), ENOTCONN);
    let after_complete = a.execute(client, Op::Ready).unwrap().value;
    assert_eq!(after_complete, 0);
    a.service_egress().unwrap();
    while a.execute(0, Op::Capture(65535)).is_ok() {}
    assert!(!a.endpoint.connection_exists(failed));
    assert_eq!(a.sockets[&client].zc_reserved, 0);
    assert!(a.sockets[&client].completions.is_empty());
    assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
    for n in [0, 1, 7, 24, 148, 192, 193, 280, 512] {
        assert_eq!(
            a.execute(client, Op::TransportPrefix(1, n)).unwrap().bytes,
            terminal[..n.min(280)]
        );
    }
    // Failed startup must preserve the old terminal snapshot. A real next open
    // clears it only after admission; use another port to avoid closed listeners.
    assert_eq!(
        a.execute(client, Op::Connect(SocketAddr::new(remote.ip(), 0)))
            .unwrap_err(),
        EINVAL
    );
    assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes, terminal);
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 0))
        .unwrap();
    let retry = SocketAddr::new(remote.ip(), 8081);
    assert_eq!(
        a.execute(client, Op::Connect(retry)).unwrap_err(),
        EINPROGRESS
    );
    assert_ne!(cid(&a, client), failed);
    assert!(a.connection_options.iter().all(|p| p.0 != failed));
    assert_eq!(a.execute(client, Op::Transport(1)).unwrap().bytes[0], 2);
    if matches!(
        failure,
        Failure::Abandon
            | Failure::Abort
            | Failure::Cancel
            | Failure::Application
            | Failure::ApplicationHeld
    ) && mode.warm()
    {
        assert!(
            a.endpoint
                .can_defer_fast_open(a.now(), a.local, remote)
                .unwrap()
        );
    }
    let trace = Trace {
        completion,
        so_error,
        ready: ready.value,
        after_consume,
        after_complete,
    };
    eprintln!(
        "T5_ERROR_FATAL {{\"v6\":{v6},\"open\":\"{mode:?}\",\"cause\":\"{failure:?}\",\"blocking\":{blocking},\"consumed\":{consume},\"errno\":{completion},\"so_error\":{expected_so},\"ready\":{},\"terminal_bytes\":{},\"reclaimed\":true}}",
        ready.value,
        terminal.len()
    );
    trace
}

//= https://www.rfc-editor.org/rfc/rfc7413#appendix-A.1
//= type=test
//= reason=Shared active startup and consumable completion preserve ordinary connect errno semantics for MSG_FASTOPEN and deferred first writes. Paired IPv4/IPv6 packet and Owner tests cover validated refusal, R2/application/SYN-budget timeout, local abort, unsubmitted reservation abandonment, normal cancellation and every supported hard ICMP code; all soft/time/parameter/quench codes remain notifications through successful completion and stream delivery. Blocking/nonblocking completion, consumed SO_ERROR fallback, readiness generations, public descriptor aliases/poll/epoll, retry, terminal TCP_INFO prefixes and authorized receive drain retain their distinct channels. Initial admission returns and pre-start address/copy/resource/allocation/entropy rejections are separate stages, not universal send-buffer errno claims or Linux-kernel equivalence.
//# On errors, it returns the same errno as connect() if the handshake fails.
#[test]
fn paired_handshake_failure_completion_matrix() {
    for v6 in [false, true] {
        let failures = [
            Failure::Refused,
            Failure::R2,
            Failure::Application,
            Failure::ApplicationHeld,
            Failure::SynBudget,
            Failure::Abort,
            Failure::Cancel,
            Failure::Abandon,
            Failure::Hard(2),
            Failure::Hard(if v6 { 4 } else { 3 }),
        ];
        for failure in failures {
            for blocking in [false, true] {
                for consume in [false, true] {
                    let baseline = fatal_case(v6, Open::Connect, failure, blocking, consume);
                    for mode in OPENS.into_iter().skip(1) {
                        assert_eq!(
                            fatal_case(v6, mode, failure, blocking, consume),
                            baseline,
                            "{v6} {mode:?} {failure:?} blocking={blocking} consumed={consume}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn paired_handshake_soft_feedback_keeps_completion_and_stream_live() {
    for v6 in [false, true] {
        let mut codes: Vec<(u8, u8, i32)> = if v6 {
            [0, 1, 3, 5, 6, 7]
                .into_iter()
                .map(|code| (1, code, EHOSTUNREACH))
                .collect()
        } else {
            [0, 1, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
                .into_iter()
                .map(|code| (3, code, EHOSTUNREACH))
                .collect()
        };
        codes.extend((0..=1).map(|code| (if v6 { 3 } else { 11 }, code, ETIMEDOUT)));
        codes.extend((0..=2).map(|code| (if v6 { 4 } else { 12 }, code, EPROTO)));
        if !v6 {
            codes.push((4, 0, 0));
        }
        for (kind, code, error) in codes {
            for mode in OPENS {
                for blocking in [false, true] {
                    for consume in [false, true] {
                        let (mut a, mut b, listener, remote) = setup(v6, mode.warm());
                        let client = socket(&mut a, mode, remote, blocking);
                        let initial = if blocking && mode.connect() {
                            Op::BlockingConnect(remote)
                        } else {
                            mode.op(remote)
                        };
                        let (mut request, rx) = wait(client, initial);
                        if blocking {
                            assert!(!a.service(&mut request));
                        } else if mode.warm() {
                            assert_eq!(a.execute(client, mode.op(remote)).unwrap().value, 5);
                        } else {
                            assert_eq!(
                                a.execute(client, mode.op(remote)).unwrap_err(),
                                EINPROGRESS
                            );
                        }
                        let id = cid(&a, client);
                        let syn = tfo_capture(&mut a);
                        let before = a.endpoint.transport_info(id).unwrap();
                        tfo_deliver(&mut a, feedback(&syn, kind, code));
                        assert_eq!(a.endpoint.state(id).unwrap(), State::SynSent);
                        assert_eq!(a.endpoint.transport_info(id).unwrap(), before);
                        assert_eq!(a.sockets[&client].error, 0);
                        assert_eq!(
                            a.execute(client, Op::Ready).unwrap().value & EPOLLERR != 0,
                            error != 0
                        );
                        assert_eq!(a.execute(client, Op::FinishConnect).unwrap_err(), EAGAIN);
                        if blocking {
                            assert!(!a.service(&mut request));
                        }
                        if consume {
                            assert_eq!(
                                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                                    .unwrap()
                                    .value,
                                error
                            );
                            assert_eq!(
                                a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                                    .unwrap()
                                    .value,
                                0
                            );
                            assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLERR, 0);
                        }
                        tfo_deliver(&mut b, syn.clone());
                        exchange(&mut a, &mut b);
                        if blocking {
                            assert!(a.service(&mut request));
                            assert_eq!(
                                rx.try_recv().unwrap().unwrap().value,
                                if mode.connect() { 0 } else { 5 }
                            );
                        } else {
                            a.execute(client, Op::FinishConnect).unwrap();
                        }
                        exchange(&mut a, &mut b);
                        assert_eq!(a.endpoint.state(id).unwrap(), State::Established);
                        assert!(!a.sockets[&client].connect_pending);
                        // Feedback quoting a retired SYN cannot become a new hard
                        // error after ACK progress, even though the tuple is live.
                        tfo_deliver(
                            &mut a,
                            feedback(&syn, if v6 { 1 } else { 3 }, if v6 { 4 } else { 3 }),
                        );
                        assert_eq!(a.endpoint.state(id).unwrap(), State::Established);
                        let server = b
                            .execute(listener, Op::Accept(SOCK_NONBLOCK))
                            .unwrap()
                            .value as u64;
                        if blocking && !mode.connect() || mode.warm() {
                            assert_eq!(b.execute(server, Op::Read(20)).unwrap().bytes, b"hello");
                        }
                        a.execute(client, Op::Send(vec![(b"next".as_ptr() as usize, 4)], 0))
                            .unwrap();
                        exchange(&mut a, &mut b);
                        assert_eq!(b.execute(server, Op::Read(20)).unwrap().bytes, b"next");
                        assert_eq!(
                            a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                                .unwrap()
                                .value,
                            if consume { 0 } else { error }
                        );
                        assert_eq!(
                            a.execute(client, Op::Get(SOL_SOCKET, SO_ERROR))
                                .unwrap()
                                .value,
                            0
                        );
                        assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLERR, 0);
                        eprintln!(
                            "T5_ERROR_SOFT {{\"v6\":{v6},\"open\":\"{mode:?}\",\"kind\":{kind},\"code\":{code},\"blocking\":{blocking},\"consumed\":{consume},\"notification\":{error},\"completion\":0,\"stream\":true}}"
                        );
                    }
                }
            }
        }
    }
}
