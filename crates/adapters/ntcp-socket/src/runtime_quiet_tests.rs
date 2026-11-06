// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Quiet time through the socket layer on the packet-test port, with a stated
// lifecycle and simulated time: the logic of the slow handshake, not evidence
// about a physical clock.
use super::fast_open_tests::{tfo_capture, tfo_deliver, tfo_no_output};
use super::memory::tests::exchange;
use super::tests::new;
use super::*;
use crate::packet_profile::Profile;

const QUIET: u64 = 240_000_000;
const REMOTE: &str = "192.0.2.2:8080";

fn packet_owner(local: &str) -> Owner {
    let mut owner = Owner::packet_with_options(
        (local.parse::<IpAddr>().unwrap(), Profile::Pipeline),
        crate::packet_test::Options {
            queue_capacity: 16,
            egress_capacity: 4,
        },
    )
    .unwrap();
    owner.test_now = Some(0);
    owner
}
// Nothing stated: this lifecycle waits the full interval from zero.
fn quiet_owner() -> Owner {
    let mut owner = packet_owner("192.0.2.1");
    let config = owner.defaults.clone();
    owner
        .replace_packet_lifecycle(config, ntcp::Lifecycle::default())
        .unwrap();
    owner
        .enable_egress(4, crate::packet_profile::gso(Profile::Pipeline))
        .unwrap();
    owner
}
fn at_deadline(a: &mut Owner) {
    a.test_now = Some(QUIET - 1);
    a.release_quiet_opens(QUIET - 1);
    tfo_no_output(a);
    a.test_now = Some(QUIET);
    a.release_quiet_opens(QUIET);
}
fn listener(b: &mut Owner) -> u64 {
    let id = new(b, SOCK_NONBLOCK);
    b.execute(id, Op::Bind(REMOTE.parse().unwrap())).unwrap();
    b.execute(id, Op::Listen(4)).unwrap();
    id
}
fn segment(packet: &[u8]) -> ntcp::wire::Segment<'_> {
    let p = crate::ip::parse(packet).unwrap();
    ntcp::wire::parse(p.ip, p.payload).unwrap()
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
fn so_error(a: &mut Owner, id: u64) -> i32 {
    a.execute(id, Op::Get(SOL_SOCKET, SO_ERROR)).unwrap().value
}
fn send(flags: i32, bytes: &[u8], remote: Option<SocketAddr>) -> Op {
    Op::SendTo(vec![(bytes.as_ptr() as usize, bytes.len())], flags, remote, None)
}

//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn nonblocking_connect_is_in_progress_and_writable_only_on_completion() {
    let mut a = quiet_owner();
    let mut b = packet_owner("192.0.2.2");
    let accept = listener(&mut b);
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = REMOTE.parse().unwrap();
    assert_eq!(a.execute(client, Op::Connect(remote)).unwrap_err(), EINPROGRESS);
    assert_eq!(a.execute(client, Op::Connect(remote)).unwrap_err(), EALREADY);
    assert_eq!(a.execute(client, Op::FinishConnect).unwrap_err(), EAGAIN);
    assert_eq!(a.execute(client, send(0, b"x", None)).unwrap_err(), EAGAIN);
    assert_eq!(a.execute(client, Op::Read(8)).unwrap_err(), EAGAIN);
    assert_eq!(a.execute(client, Op::Name(true)).unwrap_err(), ENOTCONN);
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    tfo_no_output(&mut a);

    at_deadline(&mut a);
    // The deadline starts the handshake; only its completion is writable.
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    let syn = tfo_capture(&mut a);
    assert_eq!(segment(&syn).header.flags, ntcp::wire::SYN);
    tfo_deliver(&mut b, syn);
    assert_eq!(a.execute(client, Op::FinishConnect).unwrap_err(), EAGAIN);
    exchange(&mut a, &mut b);
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    a.execute(client, Op::FinishConnect).unwrap();
    assert_eq!(so_error(&mut a, client), 0);
    b.execute(accept, Op::Accept(SOCK_NONBLOCK)).unwrap();
}

#[test]
fn a_refused_handshake_reports_through_so_error_not_at_the_deadline() {
    let mut a = quiet_owner();
    let mut b = packet_owner("192.0.2.2");
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(
        a.execute(client, Op::Connect(REMOTE.parse().unwrap())).unwrap_err(),
        EINPROGRESS
    );
    at_deadline(&mut a);
    assert_eq!(so_error(&mut a, client), 0);
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    exchange(&mut a, &mut b);
    a.events();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(so_error(&mut a, client), ECONNREFUSED);
}

#[test]
fn a_held_open_that_cannot_start_fails_like_a_handshake() {
    let mut a = packet_owner("192.0.2.1");
    let mut config = a.defaults.clone();
    config.max_connections = 1;
    a.replace_packet_lifecycle(config, ntcp::Lifecycle::default()).unwrap();
    a.enable_egress(1, crate::packet_profile::gso(Profile::Pipeline)).unwrap();
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let ids = [new(&mut a, SOCK_NONBLOCK), new(&mut a, SOCK_NONBLOCK)];
    for id in ids {
        assert_eq!(a.execute(id, Op::Connect(remote)).unwrap_err(), EINPROGRESS);
    }
    at_deadline(&mut a);
    assert!(matches!(a.sockets[&ids[0]].handle, Handle::Connection(_)));
    let ready = a.execute(ids[1], Op::Ready).unwrap().value;
    assert_ne!(ready & EPOLLOUT, 0);
    assert_ne!(ready & EPOLLERR, 0);
    assert_eq!(a.execute(ids[1], Op::FinishConnect).unwrap_err(), ENOBUFS);
    assert_eq!(so_error(&mut a, ids[1]), 0);
    // The failed attempt left an ordinary unconnected socket.
    assert_eq!(a.execute(ids[1], Op::FinishConnect).unwrap_err(), ENOTCONN);
}

#[test]
fn blocking_connect_waits_and_completes() {
    let mut a = quiet_owner();
    let mut b = packet_owner("192.0.2.2");
    listener(&mut b);
    let client = new(&mut a, 0);
    let (mut request, rx) = wait(client, Op::BlockingConnect(REMOTE.parse().unwrap()));
    assert!(!a.service(&mut request));
    assert!(!a.service(&mut request));
    tfo_no_output(&mut a);
    at_deadline(&mut a);
    assert!(!a.service(&mut request));
    exchange(&mut a, &mut b);
    assert!(a.service(&mut request));
    rx.try_recv().unwrap().unwrap();
}

#[test]
fn blocking_connect_is_interrupted_by_its_timeout_and_by_close() {
    let mut a = quiet_owner();
    let client = new(&mut a, 0);
    let storage = a.endpoint.buffer_bytes();
    let (mut request, rx) = wait(client, Op::BlockingConnect(REMOTE.parse().unwrap()));
    assert!(!a.service(&mut request));
    request.deadline = Some(Instant::now());
    assert!(a.service(&mut request));
    assert_eq!(rx.try_recv().unwrap().unwrap_err(), EAGAIN);

    // The open stays held for its socket until close abandons it.
    let (mut request, rx) = wait(client, Op::FinishConnect);
    assert!(!a.service(&mut request));
    a.pending.push_back(request);
    a.execute(client, Op::Close).unwrap();
    assert_eq!(rx.try_recv().unwrap().unwrap_err(), EBADF);
    at_deadline(&mut a);
    tfo_no_output(&mut a);
    assert_eq!(a.endpoint.buffer_bytes(), storage);
}

#[test]
fn a_blocking_fast_open_send_owns_nothing_until_the_deadline() {
    let mut a = quiet_owner();
    let client = new(&mut a, 0);
    let remote = REMOTE.parse().unwrap();
    a.execute(
        client,
        Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
    )
    .unwrap();
    let (mut request, _rx) = wait(client, send(MSG_FASTOPEN, b"hello", Some(remote)));
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 0);
    assert!(a.sockets[&client].quiet_open.is_none());
    tfo_no_output(&mut a);
    at_deadline(&mut a);
    assert!(!a.service(&mut request));
    assert_eq!(request.send.as_ref().unwrap().accepted, 5);
    assert_eq!(segment(&tfo_capture(&mut a)).payload, b"hello");
}

#[test]
fn msg_fastopen_data_is_held_and_sent_with_the_syn() {
    let mut a = quiet_owner();
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = REMOTE.parse().unwrap();
    a.execute(
        client,
        Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
    )
    .unwrap();
    let reply = a.execute(client, send(MSG_FASTOPEN, b"hello", Some(remote)));
    assert_eq!(reply.unwrap().value, 5);
    assert_eq!(
        a.execute(client, send(MSG_FASTOPEN, b"more", Some(remote))).unwrap_err(),
        EALREADY
    );
    assert_eq!(a.execute(client, send(0, b"more", None)).unwrap_err(), EAGAIN);
    tfo_no_output(&mut a);
    at_deadline(&mut a);
    let syn = tfo_capture(&mut a);
    assert_eq!(segment(&syn).payload, b"hello");
    assert_eq!(segment(&syn).header.flags & ntcp::wire::SYN, ntcp::wire::SYN);
}

#[test]
fn deferred_fast_open_data_is_held_and_sent_with_the_syn() {
    let mut a = quiet_owner();
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = REMOTE.parse().unwrap();
    a.execute(client, Op::Set(IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)).unwrap();
    a.execute(
        client,
        Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
    )
    .unwrap();
    a.execute(client, Op::Connect(remote)).unwrap();
    assert_ne!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    assert_eq!(a.execute(client, send(0, b"hello", None)).unwrap().value, 5);
    // The first write made it a connection attempt.
    assert_eq!(a.execute(client, Op::Ready).unwrap().value & EPOLLOUT, 0);
    tfo_no_output(&mut a);
    at_deadline(&mut a);
    assert_eq!(segment(&tfo_capture(&mut a)).payload, b"hello");
}

#[test]
fn a_cold_client_requests_a_cookie_at_the_deadline_and_keeps_no_data() {
    let mut a = quiet_owner();
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = REMOTE.parse().unwrap();
    assert_eq!(
        a.execute(client, send(MSG_FASTOPEN, b"hello", Some(remote))).unwrap_err(),
        EINPROGRESS
    );
    at_deadline(&mut a);
    let syn = tfo_capture(&mut a);
    assert!(segment(&syn).payload.is_empty());
    assert_eq!(
        segment(&syn).options.fast_open,
        Some(FastOpenCookie::request())
    );
}

#[test]
fn data_beyond_the_syn_follows_it_under_send_admission() {
    let mut a = quiet_owner();
    let client = new(&mut a, SOCK_NONBLOCK);
    let remote = REMOTE.parse().unwrap();
    a.execute(
        client,
        Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
    )
    .unwrap();
    let bytes = vec![7; 4000];
    let reply = a.execute(client, send(MSG_FASTOPEN, &bytes, Some(remote)));
    assert_eq!(reply.unwrap().value, 4000);
    at_deadline(&mut a);
    let Handle::Connection(cid) = a.sockets[&client].handle else {
        panic!()
    };
    assert_eq!(a.endpoint.send_progress(cid).unwrap().queued_end, 4000);
    assert!(segment(&tfo_capture(&mut a)).payload.len() < 4000);
}

#[test]
fn closing_a_pending_socket_sends_nothing() {
    let mut a = quiet_owner();
    let remote = REMOTE.parse().unwrap();
    let client = new(&mut a, SOCK_NONBLOCK);
    assert_eq!(a.execute(client, Op::Connect(remote)).unwrap_err(), EINPROGRESS);
    let fast = new(&mut a, SOCK_NONBLOCK);
    a.execute(
        fast,
        Op::SetFastOpenServerCookie(Some((remote, FastOpenCookie::request()))),
    )
    .unwrap();
    a.execute(fast, send(MSG_FASTOPEN, b"hello", Some(remote))).unwrap();
    // Output runs before the close, so an open already started would show.
    tfo_no_output(&mut a);
    a.execute(client, Op::Close).unwrap();
    a.execute(fast, Op::Close).unwrap();
    at_deadline(&mut a);
    tfo_no_output(&mut a);
}

//= https://www.rfc-editor.org/rfc/rfc6191#appendix-A.1
//= type=test
//= reason=Each Endpoint lifecycle has one TCP admission deadline from the configured MSL: the later of host boot + 2*MSL, from the provider's CLOCK_BOOTTIME boot age without the time namespace offset (unknown counts as a boot at the start), and the restart floor from the embedding's source continuity fact. Before it no active, passive, Fast Open or TIME-WAIT reuse factory creates a connection, no ISN, timestamp offset or cookie is assigned and no TCP segment, RST included, is emitted; host uptime alone never removes the restart floor. Core and native socket tests check refusal before and admission at the deadline; the rfc_host quiet.py namespace cases capture the wire.
//# Firstly, as specified in [RFC0793], hosts must not establish new
//# connections for a period of 2*MSL (Maximum Segment Lifetime) after they
//# boot (this is the "quiet time" concept). As a result, in terms of
//# specifications, this scenario should never occur.
#[test]
fn listeners_work_and_premature_syns_draw_nothing() {
    let mut a = quiet_owner();
    let mut peer = packet_owner("192.0.2.2");
    let id = new(&mut a, SOCK_NONBLOCK);
    a.execute(id, Op::Bind("192.0.2.1:8080".parse().unwrap())).unwrap();
    a.execute(id, Op::Set(SOL_SOCKET, SO_KEEPALIVE, 1)).unwrap();
    a.execute(id, Op::Listen(4)).unwrap();
    assert_eq!(a.execute(id, Op::Accept(SOCK_NONBLOCK)).unwrap_err(), EAGAIN);
    assert_eq!(a.execute(id, Op::Get(SOL_SOCKET, SO_KEEPALIVE)).unwrap().value, 1);
    let client = new(&mut peer, SOCK_NONBLOCK);
    assert_eq!(
        peer.execute(client, Op::Connect("192.0.2.1:8080".parse().unwrap())).unwrap_err(),
        EINPROGRESS
    );
    let syn = tfo_capture(&mut peer);
    tfo_deliver(&mut a, syn.clone());
    tfo_no_output(&mut a);
    a.test_now = Some(QUIET);
    tfo_deliver(&mut a, syn);
    let reply = segment(&tfo_capture(&mut a)).header.flags;
    assert_eq!(reply, ntcp::wire::SYN | ntcp::wire::ACK);
}
