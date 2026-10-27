// Helpers shared by the core test modules. Mounted inside connection so they
// can read Connection's private fields.
use super::*;
use alloc::vec;

// Manually audited against packet_profile::config(Upstream(default)). Tests
// start from it and override every field whose value differs.
pub(crate) fn upstream_config() -> ConnectionConfig {
    ConnectionConfig {
        receive_capacity: 8 * 1024 * 1024,
        receive_ip_payload_limit: 65515,
        send_ip_payload_limit: 65515,
        mss: 1460,
        initial_window: InitialWindow::Iw10,
        congestion_algorithm: CongestionAlgorithm::Cubic,
        cubic_hystart: true,
        cubic_fast_convergence: true,
        timestamps: true,
        sack: true,
        rack: true,
        tlp: true,
        prr: true,
        prr_pacing: false,
        pacing: None,
        rto_min_us: 200_000,
        adaptive_ack: true,
        delayed_ack_us: 200_000,
        coalesce_read_window_updates: true,
        ..ConnectionConfig::default()
    }
}

// Accepts the whole payload of the last reserved selection at `now`.
pub(crate) fn commit_reserved(a: &mut Connection, now: Instant) {
    let mut d = a.last_departure.unwrap();
    let count = d.payload;
    a.accept_reserved_output(now, &mut d, 0, count, true)
        .unwrap();
}

// Selects one packet into `out` and, when reserved, commits all of it at `now`.
pub(crate) fn select_and_commit(
    a: &mut Connection,
    now: Instant,
    out: &mut [u8],
    reserved: bool,
) -> Option<usize> {
    let n = a.transmit_selected(now, out, reserved).unwrap()?;
    if reserved {
        commit_reserved(a, now);
    }
    Some(n)
}

// Transmits at `now` until nothing is ready and returns (sequence, payload
// length, PSH) for every packet, pure ACKs included; panics after `limit`
// packets. The buffer size cannot change the wire: a packet that does not fit
// fails with OutputTooSmall rather than being shortened.
pub(crate) fn drain_wire(
    a: &mut Connection,
    now: Instant,
    limit: usize,
) -> Vec<(u32, usize, bool)> {
    let tuple = a.tuple();
    let metadata = IpMetadata {
        source: tuple.local.ip(),
        destination: tuple.remote.ip(),
    };
    let mut out = vec![0; 65535];
    let mut sent = Vec::new();
    for _ in 0..limit {
        let Some(n) = a.transmit(now, &mut out).unwrap() else {
            return sent;
        };
        let segment = wire::parse(metadata, &out[..n]).unwrap();
        sent.push((
            segment.header.sequence,
            segment.payload.len(),
            segment.header.flags & PSH != 0,
        ));
    }
    panic!("output did not quiesce");
}
