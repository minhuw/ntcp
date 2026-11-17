// Host::input_datagram_frame against input_datagram: a TCP segment
// received in place is taken in by reference and its frame held while
// unread, with the same wire either way; a datagram that does not lie in
// the frame (reassembled into the caller's buffer), and anything not TCP,
// is dispatched from its bytes and gives the frame back untouched.
use super::ingress::{fragments, reassembly};
use super::*;
use ntcp::RxFrame;

type Side = (Host, Endpoint, IngressContext);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Bytes,
    Frame,
}

// One physical packet into `side`, as the native driver takes it: receive,
// destination processing, then dispatch, by its bytes or with the frame it
// arrived in. Some(length) when a frame came back.
fn deliver(side: &mut Side, mode: Mode, now: u64, packet: &[u8]) -> Option<usize> {
    let frame = RxFrame::copy_from_slice(packet);
    // SAFETY (test, as the driver's slice): the frame's bytes stay valid
    // until it is dropped, which happens below or when its connection lets
    // it go, after the last use of `bytes` here.
    let bytes = unsafe { core::slice::from_raw_parts(frame.as_ptr(), frame.len()) };
    let mut out = vec![0; 8192];
    let received = side.0.receive(side.2, now, bytes, false, &mut out).unwrap();
    let Received::Datagram(datagram) = received else {
        return Some(frame.len());
    };
    let processed = side.0.process(datagram, None).unwrap();
    match mode {
        Mode::Bytes => {
            side.0
                .input_datagram(&mut side.1, now, processed, RxPacketMetadata::default(), 0)
                .unwrap();
            Some(frame.len())
        }
        Mode::Frame => {
            let (result, back) = side.0.input_datagram_frame(
                &mut side.1,
                now,
                processed,
                frame,
                RxPacketMetadata::default(),
                0,
            );
            result.unwrap();
            back.map(|frame| frame.len())
        }
    }
}

// The client's and server's frames, exchanged until quiet; the server
// takes its input in `mode`. Every frame either way is in the trace.
fn exchange(
    a: &mut Side,
    b: &mut Side,
    mode: Mode,
    now: &mut u64,
    trace: &mut Vec<Vec<u8>>,
) -> usize {
    let mut held = 0;
    for _ in 0..256 {
        *now += 10;
        let mut work = false;
        while let Some(frame) = emit(&mut a.0, &mut a.1, *now) {
            if deliver(b, mode, *now + 1, &frame).is_none() {
                held += 1;
            }
            trace.push(frame);
            work = true;
        }
        while let Some(frame) = emit(&mut b.0, &mut b.1, *now + 2) {
            deliver(a, Mode::Bytes, *now + 3, &frame);
            trace.push(frame);
            work = true;
        }
        if !work {
            return held;
        }
    }
    panic!("wire exchange did not quiesce");
}

#[test]
fn frame_input_is_byte_input_and_holds_the_segments_frames() {
    let run = |mode| {
        let (local, remote) = addresses(false);
        let cfg = config(4);
        let mut a = managed(local, 1, cfg.clone());
        let mut b = managed(remote, 2, cfg.clone());
        let listener = b.1.listen(remote, 4).unwrap();
        let client =
            a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
                .unwrap();
        let (mut now, mut trace) = (0, Vec::new());
        exchange(&mut a, &mut b, mode, &mut now, &mut trace);
        let server = b.1.accept(listener).unwrap();
        let data: Vec<u8> = (0..40_000).map(|i| (i % 251) as u8).collect();
        let mut written = 0;
        let mut read = Vec::new();
        let mut held = 0;
        while read.len() < data.len() {
            written += a.1.write(client, &data[written..]).unwrap_or(0);
            held += exchange(&mut a, &mut b, mode, &mut now, &mut trace);
            let mut out = [0; 7000];
            while let Ok(n) = b.1.read(server, &mut out) {
                if n == 0 {
                    break;
                }
                read.extend_from_slice(&out[..n]);
            }
        }
        assert_eq!(read, data);
        b.1.write(server, b"done").unwrap();
        exchange(&mut a, &mut b, mode, &mut now, &mut trace);
        let mut done = [0; 4];
        assert_eq!(a.1.read(client, &mut done).unwrap(), 4);
        a.1.close(client).unwrap();
        exchange(&mut a, &mut b, mode, &mut now, &mut trace);
        b.1.close(server).unwrap();
        exchange(&mut a, &mut b, mode, &mut now, &mut trace);
        let segments = data.len().div_ceil(1448);
        match mode {
            // Every data segment's frame was held, none copied.
            Mode::Frame => assert!(held >= segments, "{held} {segments}"),
            Mode::Bytes => assert_eq!(held, 0),
        }
        trace
    };
    assert_eq!(run(Mode::Bytes), run(Mode::Frame));
}

// A segment reassembled from fragments lies in the Host's completion
// buffer, not the last fragment's frame: it is taken in from its bytes and
// the frame comes back whole. So does an ICMP Echo Request's.
#[test]
fn a_datagram_outside_the_frame_gives_the_frame_back_whole() {
    let (local, remote) = addresses(false);
    let cfg = config(4);
    let mut a = managed(local, 1, cfg.clone());
    let mut b = managed_limited(remote, 2, cfg.clone(), false, None, None, |p, mut l| {
        l.reassembly = reassembly();
        (p, l, 1)
    });
    let listener = b.1.listen(remote, 4).unwrap();
    let client =
        a.1.connect_with_path_provider(0, local, remote, options(&cfg, 0), &mut a.0)
            .unwrap();
    let (mut now, mut trace) = (0, Vec::new());
    exchange(&mut a, &mut b, Mode::Frame, &mut now, &mut trace);
    let server = b.1.accept(listener).unwrap();
    a.1.write(client, &[9; 1000]).unwrap();
    let segment = emit(&mut a.0, &mut a.1, now + 10).unwrap();
    let pieces = fragments(&segment, 7, 512);
    assert!(pieces.len() > 1);
    // Held for reassembly, then completed into the Host's buffer.
    for (i, piece) in pieces.iter().enumerate() {
        assert_eq!(
            deliver(&mut b, Mode::Frame, now + 11 + i as u64, piece),
            Some(piece.len())
        );
    }
    assert_eq!(b.0.reassembly_counters().completed, 1);
    let mut out = [0; 2000];
    assert_eq!(b.1.read(server, &mut out).unwrap(), 1000);
    assert_eq!(&out[..1000], &[9; 1000]);

    // An Echo Request to the server's address.
    let mut echo = vec![0; 28 + 8];
    echo[0] = 0x45;
    let len = echo.len() as u16;
    echo[2..4].copy_from_slice(&len.to_be_bytes());
    echo[8] = 64;
    echo[9] = 1;
    echo[12..16].copy_from_slice(&[192, 0, 2, 1]);
    echo[16..20].copy_from_slice(&[192, 0, 2, 2]);
    super::dispatch::seal_ipv4(&mut echo);
    echo[20] = 8;
    let sum = ntcp_icmp::checksum(&echo[20..]);
    echo[22..24].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(
        deliver(&mut b, Mode::Frame, now + 13, &echo),
        Some(echo.len())
    );
}
