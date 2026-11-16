// Network::try_write_vectored: one send of several slices, PUSH only at the
// end of the bytes taken, and what a transmit-only (flush) drive or a push
// sends of pushed writes. Two IPv4 Networks over an in-memory IP wire whose sender
// side segments TCP aggregates (TSO), PSH and FIN on the last segment.
use ntcp_io::{
    PacketIo, PacketLayer, TcpSegmentationCapabilities, TcpSegmentationError,
    TcpSegmentationRequest, TxOutcome,
};
use ntcp_native::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{self, IoSlice},
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

// One submission to the backend: a scalar segment or an aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Sent {
    // Payload octets, PSH.
    Scalar(usize, bool),
    // Segments, payload octets, PSH on the last.
    Aggregate(usize, usize, bool),
}

struct Wire {
    incoming: Queue,
    outgoing: Queue,
    tso: Option<TcpSegmentationCapabilities>,
    sent: Rc<RefCell<Vec<Sent>>>,
    // (payload octets, PSH) of every data segment the peer gets.
    segments: Rc<RefCell<Vec<(usize, bool)>>>,
}
// The offsets of the TCP header and the payload of an IPv4 packet.
fn layout(packet: &[u8]) -> (usize, usize) {
    let tcp = usize::from(packet[0] & 15) * 4;
    (tcp, tcp + usize::from(packet[tcp + 12] >> 4) * 4)
}
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
// The segments a device cuts from an aggregate, as Linux tcp_gso_segment:
// PSH and FIN on the last only, lengths and checksums filled.
fn cut(packet: &[u8], mss: usize) -> Vec<Vec<u8>> {
    let (tcp, payload) = layout(packet);
    let data = &packet[payload..];
    let count = data.len().div_ceil(mss);
    let sequence = u32::from_be_bytes(packet[tcp + 4..tcp + 8].try_into().unwrap());
    let ip = ntcp::IpMetadata {
        source: IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
        destination: IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
    };
    (0..count)
        .map(|n| {
            let mut s = packet[..payload].to_vec();
            s.extend_from_slice(&data[n * mss..((n + 1) * mss).min(data.len())]);
            let len = s.len() as u16;
            s[2..4].copy_from_slice(&len.to_be_bytes());
            s[10..12].fill(0);
            let sum = ip_checksum(&s[..tcp]);
            s[10..12].copy_from_slice(&sum.to_be_bytes());
            s[tcp + 4..tcp + 8]
                .copy_from_slice(&sequence.wrapping_add((n * mss) as u32).to_be_bytes());
            if n + 1 != count {
                s[tcp + 13] &= !0x09;
            }
            s[tcp + 16..tcp + 18].fill(0);
            let sum = ntcp::wire::checksum(ip, &s[tcp..]).unwrap();
            s[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
            s
        })
        .collect()
}
impl Wire {
    fn deliver(&self, packet: Vec<u8>) {
        let (tcp, payload) = layout(&packet);
        if packet.len() > payload {
            self.segments
                .borrow_mut()
                .push((packet.len() - payload, packet[tcp + 13] & 0x08 != 0));
        }
        self.outgoing.borrow_mut().push_back(packet);
    }
}
impl PacketIo for Wire {
    fn layer(&self) -> PacketLayer {
        PacketLayer::Ip
    }
    fn max_packet_len(&self) -> Option<usize> {
        Some(65535)
    }
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(packet) = self.incoming.borrow_mut().pop_front() else {
            return Ok(None);
        };
        out[..packet.len()].copy_from_slice(&packet);
        Ok(Some(packet.len()))
    }
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome> {
        let (tcp, payload) = layout(packet);
        if packet.len() > payload {
            self.sent.borrow_mut().push(Sent::Scalar(
                packet.len() - payload,
                packet[tcp + 13] & 0x08 != 0,
            ));
        }
        self.deliver(packet.to_vec());
        Ok(TxOutcome::Submitted)
    }
    fn tcp_segmentation_capabilities(&self) -> Option<TcpSegmentationCapabilities> {
        self.tso
    }
    fn transmit_segmented(
        &mut self,
        packet: &[u8],
        request: TcpSegmentationRequest,
    ) -> std::result::Result<TxOutcome, TcpSegmentationError> {
        let (tcp, payload) = layout(packet);
        let segments = cut(packet, request.segment_payload_len);
        self.sent.borrow_mut().push(Sent::Aggregate(
            segments.len(),
            packet.len() - payload,
            packet[tcp + 13] & 0x08 != 0,
        ));
        for segment in segments {
            self.deliver(segment);
        }
        Ok(TxOutcome::Submitted)
    }
}

// An mlx5 port's: 64 KiB aggregates, PSH on the last segment.
fn tso() -> TcpSegmentationCapabilities {
    TcpSegmentationCapabilities {
        max_aggregate_len: 65535,
        max_segments: 64,
        max_wire_bytes: 65535 + 63 * 114,
        local_ip_mtu: 1500,
        allow_psh: true,
        allow_cwr: false,
    }
}

const BUDGET: WorkBudget = WorkBudget::new(64, 64, 64, 64);
// A write's flush, as Stackbench's shim drives one: transmit only.
const FLUSH: WorkBudget = WorkBudget::new(0, 64, 0, 0);
const PORT: u16 = 9000;

struct Pair {
    server: Network<Wire>,
    client: Network<Wire>,
    id: ConnId,
    peer: ConnId,
    sent: Rc<RefCell<Vec<Sent>>>,
    segments: Rc<RefCell<Vec<(usize, bool)>>>,
    now: u64,
}
impl Pair {
    fn new() -> Self {
        let (a, b) = (Queue::default(), Queue::default());
        let sent = Rc::new(RefCell::new(Vec::new()));
        let segments = Rc::new(RefCell::new(Vec::new()));
        let network = |side: u8, incoming: &Queue, outgoing: &Queue, tso| {
            let mut config = NetworkConfig::new(IpAddr::from([10, 77, 0, side]), 1500);
            config.tcp.max_connections = 4;
            config.tcp.max_listeners = 1;
            let wire = Wire {
                incoming: incoming.clone(),
                outgoing: outgoing.clone(),
                tso,
                sent: if side == 2 {
                    sent.clone()
                } else {
                    Rc::default()
                },
                segments: if side == 2 {
                    segments.clone()
                } else {
                    Rc::default()
                },
            };
            Network::new(config, wire, [side; 32], 0).unwrap()
        };
        let mut client = network(1, &a, &b, None);
        let mut server = network(2, &b, &a, Some(tso()));
        let listener = server.listen(PORT, 4).unwrap();
        let peer = client
            .connect(SocketAddr::new(IpAddr::from([10, 77, 0, 2]), PORT))
            .unwrap();
        for step in 1..100u64 {
            client.drive(step * 1000, BUDGET).unwrap();
            server.drive(step * 1000, BUDGET).unwrap();
            if let Ok(id) = server.accept(listener) {
                client.drive(step * 1000, BUDGET).unwrap();
                // SPDK's target sets TCP_NODELAY.
                server.set_nodelay(id, true).unwrap();
                sent.borrow_mut().clear();
                segments.borrow_mut().clear();
                return Self {
                    server,
                    client,
                    id,
                    peer,
                    sent,
                    segments,
                    now: step * 1000,
                };
            }
        }
        panic!("no connection");
    }
    // One flush drive of the server; what it submitted.
    fn flush(&mut self) -> Vec<Sent> {
        self.now += 10;
        self.server.drive(self.now, FLUSH).unwrap();
        self.sent.borrow_mut().drain(..).collect()
    }
    // One push of the server's connection; what it submitted.
    fn push(&mut self) -> Vec<Sent> {
        self.now += 10;
        let report = self.server.push(self.id, self.now).unwrap();
        assert!(!report.more && !report.tx_blocked);
        self.sent.borrow_mut().drain(..).collect()
    }
    // The client takes what reached it; its bytes.
    fn read(&mut self) -> Vec<u8> {
        self.now += 10;
        self.client.drive(self.now, BUDGET).unwrap();
        let mut out = Vec::new();
        let mut buf = [0; 65536];
        while let Ok(ReadOutcome::Data { len, .. }) = self.client.try_read(self.peer, &mut buf) {
            out.extend_from_slice(&buf[..len]);
        }
        out
    }
}

#[test]
fn pushed_writes_leave_whole_in_their_flush_drive() {
    // An NVMe/TCP C2H data PDU written as two writes, header and data,
    // each pushed: everything goes in the write's transmit-only drive, the
    // header's segment alone (it holds the first PUSH), the rest as one
    // aggregate (1448 + 1224), as Linux's tcp_push sends all that cwnd and
    // the window allow.
    let mut pair = Pair::new();
    let id = pair.id;
    for len in [24, 4096] {
        let written = pair
            .server
            .try_write(id, &vec![9; len], WriteOptions::default());
        assert_eq!(written.unwrap().accepted, len);
    }
    assert_eq!(
        pair.flush(),
        [Sent::Scalar(1448, true), Sent::Aggregate(2, 2672, true)]
    );
    assert_eq!(pair.server.transport_info(id).unwrap().notsent_bytes, 0);
    assert_eq!(pair.read().len(), 4120);
}

#[test]
fn pushed_writes_leave_whole_in_their_push() {
    // The same PDU sent by a push after its writes (Linux's tcp_push at
    // the end of sendmsg): the same frames as the flush drive's, and a
    // second push finds nothing.
    let mut pair = Pair::new();
    let id = pair.id;
    for len in [24, 4096] {
        let written = pair
            .server
            .try_write(id, &vec![9; len], WriteOptions::default());
        assert_eq!(written.unwrap().accepted, len);
    }
    assert_eq!(
        pair.push(),
        [Sent::Scalar(1448, true), Sent::Aggregate(2, 2672, true)]
    );
    assert_eq!(pair.push(), []);
    assert_eq!(pair.server.transport_info(id).unwrap().notsent_bytes, 0);
    assert_eq!(pair.read().len(), 4120);
}

#[test]
fn a_vectored_write_pushes_only_its_end() {
    let mut pair = Pair::new();
    let (header, data) = (vec![1; 24], vec![2; 4096]);
    let start = pair.server.send_progress(pair.id).unwrap().queued_end;
    let receipt = pair
        .server
        .try_write_vectored(pair.id, &[IoSlice::new(&header), IoSlice::new(&data)])
        .unwrap();
    assert_eq!(receipt.accepted, 4120);
    assert_eq!(
        (receipt.range.start, receipt.range.end),
        (start, start + 4120)
    );
    // One aggregate in the write's flush drive, PSH on its last segment only.
    assert_eq!(pair.flush(), [Sent::Aggregate(3, 4120, true)]);
    assert_eq!(
        *pair.segments.borrow(),
        [(1448, false), (1448, false), (1224, true)]
    );
    assert_eq!(pair.read(), [header, data].concat());
}

#[test]
fn a_vectored_write_takes_a_prefix_and_pushes_its_last_byte() {
    let mut pair = Pair::new();
    let id = pair.id;
    pair.server.set_send_buffer(id, 4096).unwrap();
    let slices: Vec<Vec<u8>> = (1..=6).map(|n| vec![n; 1000]).collect();
    let bufs: Vec<IoSlice<'_>> = slices.iter().map(|s| IoSlice::new(s)).collect();
    let receipt = pair.server.try_write_vectored(id, &bufs).unwrap();
    // Whole slices and a part of the next (the 4096-byte limit is two
    // segments of room): the write ends there.
    let taken = receipt.accepted;
    assert!(
        taken > 1000 && taken < 6000 && !taken.is_multiple_of(1000),
        "{taken}"
    );
    assert_eq!(receipt.range.end - receipt.range.start, taken as u64);
    pair.flush();
    let segments = pair.segments.borrow().clone();
    assert_eq!(segments.iter().map(|s| s.0).sum::<usize>(), taken);
    // PUSH on the last byte taken, nowhere before it.
    assert!(segments.last().unwrap().1);
    assert!(segments[..segments.len() - 1].iter().all(|s| !s.1));
    assert_eq!(pair.read(), slices.concat()[..taken]);
    // Nothing more fits until the peer acknowledges: refused, nothing taken.
    assert!(matches!(
        pair.server.try_write_vectored(id, &bufs),
        Err(Error::WouldBlock(BlockReason::SendBuffer))
    ));
}

#[test]
fn an_empty_vectored_write_takes_nothing() {
    let mut pair = Pair::new();
    let start = pair.server.send_progress(pair.id).unwrap().queued_end;
    for bufs in [&[][..], &[IoSlice::new(&[]), IoSlice::new(&[])][..]] {
        let receipt = pair.server.try_write_vectored(pair.id, bufs).unwrap();
        assert_eq!(receipt.accepted, 0);
        assert_eq!((receipt.range.start, receipt.range.end), (start, start));
    }
    assert_eq!(pair.flush(), []);
    // Empty slices around data are skipped: one push at the data's end.
    let receipt = pair
        .server
        .try_write_vectored(
            pair.id,
            &[
                IoSlice::new(&[]),
                IoSlice::new(&[5; 100]),
                IoSlice::new(&[]),
            ],
        )
        .unwrap();
    assert_eq!(receipt.accepted, 100);
    assert_eq!(pair.flush(), [Sent::Scalar(100, true)]);
}
