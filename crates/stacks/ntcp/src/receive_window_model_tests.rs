//! The receive window against a model written from Linux's formulas
//! (n0bw stage 1 C5): tcp_space through the scaling ratio, the ratio as
//! tcp_measure_rcv_mss sets it, rcv_ssthresh as tcp_grow_window and
//! __tcp_grow_window raise it, and __tcp_select_window's free space capped
//! by rcv_ssthresh, then ntcp's no-shrink edge, wscale rounding and SWS
//! threshold. The model reads only the inputs of those formulas from the
//! connection (held frames, clamp, receive MSS estimate, edge), never a
//! window it computed, and checks the window of every segment the receiver
//! sends through randomized transfers with loss, reordering, duplication,
//! small and full-size segments, copied input and 2304 B and 2368 B frames.
extern crate std;

use super::*;
use crate::{connection::ReceiveModelView, rx_queue::RX_ENTRY_TRUESIZE};
use ntcp_buffer::RxFrame;
use std::vec::Vec;

// The model's state: what Linux keeps besides the inputs it reads.
struct Model {
    // scaling_ratio, exact: (payload, truesize).
    ratio: (u64, u64),
    rcv_ssthresh: u32,
}

impl Model {
    fn win(&self, space: usize) -> usize {
        (space as u64 * self.ratio.0 / self.ratio.1) as usize
    }

    // tcp_space: window_clamp less the window the held frames take.
    fn free(&self, view: &ReceiveModelView) -> usize {
        let rmem: usize = view
            .held
            .iter()
            .map(|&(_, _, truesize)| truesize + RX_ENTRY_TRUESIZE)
            .sum();
        view.clamp.saturating_sub(self.win(rmem))
    }

    // The window field of the next ACK.
    fn window(&self, view: &ReceiveModelView) -> u16 {
        let unit = 1u32 << view.shift;
        let quota = (self.free(view).min(u32::MAX as usize) as u32).min(self.rcv_ssthresh);
        let old = view.window;
        let available = quota.max(old);
        let candidate = (available / unit).min(u32::from(u16::MAX));
        let old_field = old.div_ceil(unit).min(candidate);
        if candidate * unit >= old + view.threshold {
            candidate as u16
        } else {
            old_field as u16
        }
    }

    // An arrival of `len` payload bytes at `seq`, between the views before
    // and after its input.
    fn arrival(
        &mut self,
        before: &ReceiveModelView,
        after: &ReceiveModelView,
        seq: Seq,
        len: usize,
    ) {
        let new_bytes = after.occupied - before.occupied;
        if new_bytes == 0 {
            return;
        }
        let next = before.next;
        let skip = if next.after(seq) {
            (next.distance_from(seq) as usize).min(len)
        } else {
            0
        };
        let offset = seq.wrapping_add(skip as u32).distance_from(next);
        let count = if offset < before.window {
            (len - skip).min((before.window - offset) as usize)
        } else {
            0
        };
        let in_order = offset == 0 && after.next != next;
        // The frame the arrival added: held now, not before.
        let truesize = after
            .held
            .iter()
            .find(|frame| !before.held.contains(frame))
            .map_or(0, |&(_, _, truesize)| truesize);
        // tcp_measure_rcv_mss, before tcp_grow_window.
        if in_order && count != 0 && len >= before.rcv_mss && len != before.rcv_mss {
            self.ratio = (new_bytes as u64, (truesize + RX_ENTRY_TRUESIZE) as u64);
        }
        let grows = if in_order { count >= 128 } else { after.sack };
        if !after.tuned || !grows {
            return;
        }
        // tcp_grow_window.
        let room =
            (self.free(after).min(u32::MAX as usize) as u32).saturating_sub(self.rcv_ssthresh);
        if room == 0 || after.pressure {
            return;
        }
        let truesize = truesize + RX_ENTRY_TRUESIZE;
        let increment = if self.win(truesize) <= count {
            2 * after.advmss
        } else {
            // __tcp_grow_window.
            let mut truesize = self.win(truesize) >> 1;
            let mut window = (after.receive_max.min(u32::MAX as usize) as u32) >> 1;
            let mut increment = 0;
            while self.rcv_ssthresh <= window {
                if truesize <= count {
                    increment = 2 * before.rcv_mss as u32;
                    break;
                }
                truesize >>= 1;
                window >>= 1;
            }
            increment
        };
        if increment != 0 {
            self.rcv_ssthresh += room.min(increment.max(2 * count as u32));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Input {
    Copy,
    // Frames of this truesize (or their length, if longer).
    Frame(usize),
}

fn view(endpoint: &Endpoint, id: ConnectionId) -> ReceiveModelView {
    endpoint.slot(id).unwrap().connection.receive_model_view()
}

fn deliver(endpoint: &mut Endpoint, input: Input, now: u64, ip: IpMetadata, bytes: &[u8]) {
    match input {
        Input::Copy => {
            endpoint.input(now, ip, bytes).unwrap();
        }
        Input::Frame(truesize) => {
            let mut vec = Vec::with_capacity(truesize.max(bytes.len()));
            vec.extend_from_slice(bytes);
            endpoint
                .input_frame(
                    now,
                    ip,
                    0,
                    Ipv4Options::default(),
                    RxFrame::from_vec(vec),
                    crate::RxPacketMetadata::default(),
                )
                .unwrap();
        }
    }
}

fn poll_one(endpoint: &mut Endpoint, now: u64) -> Option<(IpMetadata, Vec<u8>)> {
    let mut bytes = [0; 2048];
    let output = endpoint.poll_transmit(now, &mut bytes, 1).unwrap();
    output
        .packet
        .map(|packet| (packet.ip, bytes[..packet.len].to_vec()))
}

struct Stats {
    checked: usize,
    ratio_set: usize,
    partial_reads: usize,
    ofo_held_acks: usize,
    grown: usize,
}

// One transfer: `a` writes a mix of 18 B requests and bulk data to `b`,
// which also answers a little; `b` reads at random in random sizes; the
// network loses, delays (reorders) and duplicates segments to `b`.
fn transfer(trial: u64, input: Input, stats: &mut Stats) {
    fn random(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *seed >> 17
    }
    let mut config = EndpointConfig {
        max_connections: 4,
        max_listeners: 1,
        ..EndpointConfig::default()
    };
    config.connection.nagle = false;
    config.connection.mss = 1460;
    config.connection.send_capacity = 1 << 20;
    config.connection.receive_capacity = 65536;
    config.connection.receive_capacity_max = 4 << 20;
    config.connection.timestamps = trial.is_multiple_of(2);
    let local: core::net::SocketAddr = "192.0.2.1:40000".parse().unwrap();
    let remote: core::net::SocketAddr = "192.0.2.2:8080".parse().unwrap();
    let mut a = Endpoint::new(config.clone(), [1; 32], 0, |_| true).unwrap();
    let mut b = Endpoint::new(config, [2; 32], 0, |_| true).unwrap();
    let listener = b.listen(remote, 4).unwrap();
    let client = a.connect(0, local, remote).unwrap();
    // Handshake, no faults.
    for _ in 0..8 {
        while let Some((ip, bytes)) = poll_one(&mut a, 0) {
            deliver(&mut b, input, 0, ip, &bytes);
        }
        while let Some((ip, bytes)) = poll_one(&mut b, 0) {
            a.input(0, ip, &bytes).unwrap();
        }
    }
    let server = b.accept(listener).unwrap();
    let start = view(&b, server);
    let mut model = Model {
        ratio: (1, 1),
        rcv_ssthresh: start.rcv_ssthresh,
    };
    let mut seed = trial * 7919 + 1;
    let total = 600_000;
    let (mut sent, mut read) = (0usize, 0usize);
    let mut network: Vec<(u64, IpMetadata, Vec<u8>)> = Vec::new();
    let mut out = std::vec![0; 1 << 16];
    for step in 1..=200_000u64 {
        let now = step * 200;
        a.on_timeout(now, 64).unwrap();
        b.on_timeout(now, 64).unwrap();
        if sent < total && !random(&mut seed).is_multiple_of(4) {
            let size = if random(&mut seed).is_multiple_of(3) {
                18
            } else {
                1 + (random(&mut seed) % 20_000) as usize
            };
            let chunk: Vec<u8> = (sent..(sent + size).min(total))
                .map(|i| (i % 251) as u8)
                .collect();
            if let Ok(n) = a.write(client, &chunk) {
                sent += n;
            }
        }
        if random(&mut seed).is_multiple_of(64) {
            let _ = b.write(server, b"ok");
        }
        while let Some((ip, bytes)) = poll_one(&mut a, now) {
            let choice = random(&mut seed) % 100;
            if choice < 2 {
                continue;
            }
            let at = now
                + if choice < 8 {
                    200 * (1 + random(&mut seed) % 20)
                } else {
                    0
                };
            if choice >= 98 {
                network.push((at + 600, ip, bytes.clone()));
            }
            network.push((at, ip, bytes));
        }
        let mut index = 0;
        while index < network.len() {
            if network[index].0 <= now {
                let (_, ip, bytes) = network.swap_remove(index);
                let segment = wire::parse(ip, &bytes).unwrap();
                let (seq, len) = (Seq(segment.header.sequence), segment.payload.len());
                let before = view(&b, server);
                deliver(&mut b, input, now, ip, &bytes);
                let after = view(&b, server);
                let ratio = model.ratio;
                let ssthresh = model.rcv_ssthresh;
                model.arrival(&before, &after, seq, len);
                stats.ratio_set += usize::from(model.ratio != ratio);
                stats.grown += usize::from(model.rcv_ssthresh != ssthresh);
                assert_eq!(
                    model.rcv_ssthresh, after.rcv_ssthresh,
                    "trial {trial} {input:?} step {step}: rcv_ssthresh"
                );
            } else {
                index += 1;
            }
        }
        if random(&mut seed).is_multiple_of(3) {
            // Small reads leave frames partly read, which stay charged whole.
            let most = if random(&mut seed).is_multiple_of(2) {
                3000
            } else {
                out.len()
            };
            let want = 1 + (random(&mut seed) as usize % most);
            let before = view(&b, server);
            if let Ok(n) = b.read(server, &mut out[..want]) {
                read += n;
                let after = view(&b, server);
                stats.partial_reads += usize::from(after.held.len() == before.held.len() && n != 0);
            }
        }
        loop {
            let before = view(&b, server);
            let expected = model.window(&before);
            let Some((ip, bytes)) = poll_one(&mut b, now) else {
                break;
            };
            let segment = wire::parse(ip, &bytes).unwrap();
            if segment.header.flags & wire::SYN == 0
                && matches!(before.state, State::Established | State::CloseWait)
            {
                assert_eq!(
                    segment.header.window, expected,
                    "trial {trial} {input:?} step {step}: window, view {before:?}"
                );
                stats.checked += 1;
                stats.ofo_held_acks += usize::from(before.ofo_held);
            }
            a.input(now, ip, &bytes).unwrap();
        }
        if read == total {
            break;
        }
    }
    assert_eq!(read, total, "trial {trial} {input:?}: transfer incomplete");
}

#[test]
fn the_receive_window_follows_the_linux_model() {
    let mut stats = Stats {
        checked: 0,
        ratio_set: 0,
        partial_reads: 0,
        ofo_held_acks: 0,
        grown: 0,
    };
    for trial in 0..10 {
        // A DPDK mbuf's truesize at the default geometry (n0bw 1b, Q2),
        // and report §Q1's 2304.
        for input in [Input::Copy, Input::Frame(2304), Input::Frame(2368)] {
            transfer(trial, input, &mut stats);
        }
    }
    std::eprintln!(
        "checked {} ratio_set {} grown {} partial_reads {} ofo_held_acks {}",
        stats.checked,
        stats.ratio_set,
        stats.grown,
        stats.partial_reads,
        stats.ofo_held_acks
    );
    assert!(stats.checked > 5_000, "{}", stats.checked);
    assert!(stats.ratio_set > 8 && stats.grown > 8 && stats.partial_reads > 100);
    assert!(stats.ofo_held_acks > 100, "{}", stats.ofo_held_acks);
}
