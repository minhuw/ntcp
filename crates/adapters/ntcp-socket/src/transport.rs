// SPDX-License-Identifier: GPL-2.0-or-later
use crate::runtime::unsupported_option as unsupported;
use crate::*;
use ntcp::State;
// Pinned stock _tcp_info is 280 bytes. Only the fields explicitly written
// below are supported; every other field is reserved zero, NOT a metric.
// Embedded-code assertions require the runner's field capability allowlist.
const TCP_INFO_SIZE: usize = 280;
pub(crate) fn transport_option(info: ntcp::TransportInfo, option: i32) -> Result<Vec<u8>> {
    if option == 2 {
        return Ok(Vec::new());
    } // Reno/NewReno have no CC-specific data.
    let mut bytes = vec![0; if option == 3 { 9 * 4 } else { TCP_INFO_SIZE }];
    let mut put = |offset: usize, value: u64| {
        let value = value.min(u32::MAX as u64) as u32;
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    };
    if option == 3 {
        // Fixed core storage, not Linux skb accounting: RMEM_ALLOC
        // is occupied receive bytes; RCVBUF/SNDBUF are allocated capacities;
        // WMEM_QUEUED is retained send bytes. No skb/option/backlog/drop buckets.
        put(0, info.receive_used as u64);
        put(4, info.receive_capacity as u64);
        put(12, info.send_capacity as u64);
        put(20, info.send_used as u64);
        return Ok(bytes);
    }
    if !info.ledger_valid {
        return Err(unsupported(
            "TCP_INFO segment counts: bounded transport ledger invalid",
        ));
    }
    if info.mss == 0 {
        return Err(EIO);
    }
    put(8, info.rto_us);
    put(16, info.mss as u64);
    put(24, info.unacked as u64);
    put(28, info.sacked as u64);
    put(32, info.lost as u64);
    put(36, info.retransmitted as u64);
    put(68, info.rtt_us.unwrap_or(0));
    put(72, info.rttvar_us);
    put(76, (info.ssthresh / info.mss) as u64);
    put(80, (info.cwnd / info.mss) as u64);
    put(88, info.reordering as u64);
    bytes[0] = match info.state {
        State::Established => 1,
        State::SynSent => 2,
        State::SynReceived => 3,
        State::FinWait1 => 4,
        State::FinWait2 => 5,
        State::TimeWait => 6,
        State::Closed => 7,
        State::CloseWait => 8,
        State::LastAck => 9,
        State::Closing => 11,
    };
    bytes[1] = if info.loss {
        4
    } else if info.recovery {
        3
    } else if info.sacked > 0 {
        1
    } else {
        0
    };
    Ok(bytes)
}
