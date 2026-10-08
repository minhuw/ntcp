// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;
use ntcp_io::{
    ClockDomain, PacketTimestamp, PacketTimestamps, ReceivedPacket, TimestampPoint,
    TimestampSource, TimestampUnit,
};
use ntcp_io_af_packet::{AfPacket, TimestampConfig};
use std::{
    ffi::CString,
    os::fd::{AsFd, AsRawFd},
};

pub(super) struct EthernetBackend {
    io: AfPacket,
    local: [u8; 6],
    next_hop: [u8; 6],
    next_cookie: u64,
    pending: Vec<(u64, ntcp::TxTimestampToken, bool, bool)>,
}
impl Drop for EthernetBackend {
    fn drop(&mut self) {
        for (cookie, _, _, _) in self.pending.drain(..) {
            let _ = self.io.cancel_tx_timestamp(cookie);
        }
    }
}
fn core_stamp(stamp: PacketTimestamp) -> Option<ntcp::RxTimestamp> {
    let clock = match (stamp.clock.domain, stamp.clock.unit) {
        (ClockDomain::Realtime, TimestampUnit::Nanoseconds) => {
            ntcp::TimestampClock::RealtimeNanoseconds
        }
        (ClockDomain::Device(identity), TimestampUnit::Nanoseconds) => {
            ntcp::TimestampClock::DeviceTicks {
                identity,
                units_per_second: Some(1_000_000_000),
            }
        }
        (ClockDomain::Device(identity), TimestampUnit::RawTicks { .. }) => {
            ntcp::TimestampClock::DeviceTicks {
                identity,
                units_per_second: None,
            }
        }
        _ => return None,
    };
    Some(ntcp::RxTimestamp {
        value: stamp.value,
        clock,
    })
}
pub(super) fn core_stamps(stamps: PacketTimestamps) -> ntcp::RxPacketTimestamps {
    ntcp::RxPacketTimestamps {
        software: stamps.software.and_then(core_stamp),
        hardware: stamps.hardware.and_then(core_stamp),
    }
}
fn mac(value: &str) -> Result<[u8; 6]> {
    let mut bytes = [0; 6];
    let mut fields = value.split(':');
    for byte in &mut bytes {
        *byte = u8::from_str_radix(fields.next().ok_or(EINVAL)?, 16).map_err(|_| EINVAL)?;
    }
    if fields.next().is_some() || bytes == [0; 6] || bytes[0] & 1 != 0 {
        return Err(EINVAL);
    }
    Ok(bytes)
}
impl Owner {
    pub(super) fn af_packet(name: &str, local: Ipv4Addr) -> Result<Self> {
        let subnet = context(name, local)?; // Identical address ownership and prefix policy to TUN.
        let name = CString::new(name).map_err(|_| EINVAL)?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(errno());
        }
        let next_hop = mac(&env("NTCP_SOCKET_NEXT_HOP_MAC").ok_or(EINVAL)?)?;
        let mut io = AfPacket::bind(index, ntcp_ip::ETHERTYPE_IPV4)
            .map_err(|e| e.raw_os_error().unwrap_or(EIO))?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        if name.as_bytes_with_nul().len() > request.ifr_name.len() {
            return Err(EINVAL);
        }
        for (out, &byte) in request.ifr_name.iter_mut().zip(name.as_bytes_with_nul()) {
            *out = byte as _;
        }
        // Query only: never SIOCSHWTSTAMP, ethtool or host-interface mutation.
        if unsafe {
            libc::ioctl(
                io.as_fd().as_raw_fd(),
                libc::SIOCGIFHWADDR as _,
                &mut request,
            )
        } < 0
        {
            return Err(errno());
        }
        let mut hardware = [0; 6];
        for (byte, value) in hardware
            .iter_mut()
            .zip(unsafe { request.ifr_ifru.ifru_hwaddr.sa_data })
        {
            *byte = value as u8;
        }
        io.enable_timestamps(TimestampConfig {
            rx_software: true,
            rx_hardware: true,
            tx_software: true,
            tx_hardware: true,
            device_clock: Some(u64::from(index)),
            tx_completion_capacity: timestamps::PHASES,
        })
        .map_err(|e| e.raw_os_error().unwrap_or(EOPNOTSUPP))?;
        let mut secret = [0u8; 32];
        let mut at = 0;
        while at < secret.len() {
            let n = unsafe {
                syscall(
                    SYS_getrandom,
                    secret[at..].as_mut_ptr(),
                    secret.len() - at,
                    0,
                )
            };
            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                return Err(errno());
            }
            if n == 0 {
                return Err(EIO);
            }
            at += n as usize;
        }
        let mut owner = Self::with_endpoint(local, subnet, secret, None)?;
        owner.ethernet = Some(EthernetBackend {
            io,
            local: hardware,
            next_hop,
            next_cookie: 1,
            pending: Vec::with_capacity(timestamps::PHASES),
        });
        Ok(owner)
    }
    pub(super) fn receive_backend(
        &mut self,
        out: &mut [u8],
    ) -> std::io::Result<Option<ReceivedPacket>> {
        if let Some(backend) = &mut self.ethernet {
            return backend.io.receive_with_metadata(out);
        }
        let software = self.software_rx_enabled();
        let Some(tun) = &mut self.tun else {
            return Ok(None);
        };
        let Some(len) = tun.receive(out)? else {
            return Ok(None);
        };
        Ok(Some(ReceivedPacket {
            len,
            timestamps: PacketTimestamps {
                software: software.then(|| PacketTimestamp {
                    value: timestamps::realtime(),
                    source: TimestampSource::Software,
                    point: TimestampPoint::UserReceive,
                    clock: ntcp_io::ClockDescriptor {
                        domain: ClockDomain::Realtime,
                        unit: TimestampUnit::Nanoseconds,
                    },
                }),
                hardware: None,
            },
        }))
    }
    pub(super) fn transmit_ethernet(&mut self) -> std::io::Result<TxOutcome> {
        let sources = self
            .pending_token
            .map(|token| self.backend_sources(token))
            .unwrap_or_default();
        let backend = self.ethernet.as_mut().unwrap();
        if (sources.0 || sources.1) && backend.pending.len() >= timestamps::PHASES {
            return Ok(TxOutcome::WouldBlock);
        }
        let packet = self.pending_packet.as_ref().unwrap();
        let mut frame = vec![0; (packet.len() + 14).max(60)];
        let n = ntcp_ip::encode_ethernet(
            &mut frame,
            backend.local,
            backend.next_hop,
            ntcp_ip::ETHERTYPE_IPV4,
            packet,
        )
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        if !(sources.0 || sources.1) {
            return backend.io.transmit(&frame[..n]);
        }
        if backend.next_cookie == u64::MAX {
            return Err(std::io::Error::other("timestamp cookie exhausted"));
        }
        let cookie = backend.next_cookie;
        let outcome = backend.io.transmit_with_timestamp(
            &frame[..n],
            ntcp_io::TxTimestampRequest {
                cookie,
                software: sources.0,
                hardware: sources.1,
            },
        )?;
        if outcome == TxOutcome::Submitted {
            backend
                .pending
                .push((cookie, self.pending_token.unwrap(), sources.0, sources.1));
            backend.next_cookie += 1;
        }
        Ok(outcome)
    }
    pub(super) fn poll_backend_timestamps(&mut self) {
        if let Some(backend) = &mut self.ethernet {
            for _ in 0..BUDGET {
                let completion = match backend.io.poll_tx_timestamp() {
                    Ok(Some(completion)) => completion,
                    Ok(None) => break,
                    Err(_) => {
                        // Explicitly free every backend reservation on failure.
                        for (cookie, token, _, _) in backend.pending.drain(..) {
                            let _ = backend.io.cancel_tx_timestamp(cookie);
                            let _ = self.endpoint.cancel_tx_timestamps(token.connection());
                        }
                        break;
                    }
                };
                let Some(index) = backend
                    .pending
                    .iter()
                    .position(|p| p.0 == completion.cookie)
                else {
                    continue;
                };
                let entry = &mut backend.pending[index];
                let source = match completion.timestamp.source {
                    TimestampSource::Software => {
                        entry.2 = false;
                        ntcp::TxTimestampSource::Software
                    }
                    TimestampSource::Hardware => {
                        entry.3 = false;
                        ntcp::TxTimestampSource::Hardware
                    }
                };
                if let Some(stamp) = core_stamp(completion.timestamp) {
                    let _ = self.endpoint.report_tx_timestamp(
                        entry.1,
                        source,
                        stamp.value,
                        stamp.clock,
                    );
                }
                if !entry.2 && !entry.3 {
                    backend.pending.swap_remove(index);
                }
            }
        }
        self.drain_timestamps(ClockPair::sample(self));
        self.cancel_unused_backend_timestamps();
    }
    pub(super) fn cancel_unused_backend_timestamps(&mut self) {
        let Some(mut backend) = self.ethernet.take() else {
            return;
        };
        backend.pending.retain(|&(cookie, token, sw, hw)| {
            let needed = self.backend_sources(token);
            if (needed.0 && sw) || (needed.1 && hw) {
                true
            } else {
                let _ = backend.io.cancel_tx_timestamp(cookie);
                false
            }
        });
        self.ethernet = Some(backend);
    }
}
