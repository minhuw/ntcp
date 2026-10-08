use ntcp_io::{
    ClockDescriptor, ClockDomain, PacketTimestamp, PacketTimestamps, TimestampCapabilities,
    TimestampPoint, TimestampSource, TimestampUnit, TxTimestampCompletion, TxTimestampRequest,
};
use std::{collections::VecDeque, io, mem::size_of};

// Linux v6.13 include/uapi/asm-generic/socket.h (also the arch-specific UAPI):
// https://github.com/torvalds/linux/blob/v6.13/include/uapi/asm-generic/socket.h#L144
// libc and older installed headers may not yet expose this constant.
#[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
const SCM_TS_OPT_ID: libc::c_int = 81;
// https://github.com/torvalds/linux/blob/v6.13/arch/sparc/include/uapi/asm/socket.h
#[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
const SCM_TS_OPT_ID: libc::c_int = 0x005a;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimestampConfig {
    pub rx_software: bool,
    pub rx_hardware: bool,
    pub tx_software: bool,
    pub tx_hardware: bool,
    // Host-assigned identity for the NIC's raw hardware nanosecond clock.
    // The host, not this adapter, configures SIOCSHWTSTAMP and calibrates clocks.
    pub device_clock: Option<u64>,
    // Total reserved source completions, including events not yet consumed.
    pub tx_completion_capacity: usize,
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(crate) fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "timestamp path unavailable")
}

impl TimestampConfig {
    pub(crate) fn flags(self) -> io::Result<libc::c_int> {
        if ((self.rx_hardware || self.tx_hardware) && self.device_clock.is_none())
            || ((self.tx_software || self.tx_hardware) && self.tx_completion_capacity == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing device clock or TX capacity",
            ));
        }
        let mut flags = 0;
        if self.rx_software || self.tx_software {
            flags |= libc::SOF_TIMESTAMPING_SOFTWARE;
        }
        if self.rx_hardware || self.tx_hardware {
            flags |= libc::SOF_TIMESTAMPING_RAW_HARDWARE;
        }
        if self.rx_software {
            flags |= libc::SOF_TIMESTAMPING_RX_SOFTWARE;
        }
        if self.rx_hardware {
            flags |= libc::SOF_TIMESTAMPING_RX_HARDWARE;
        }
        if self.tx_software || self.tx_hardware {
            flags |= libc::SOF_TIMESTAMPING_OPT_ID
                | libc::SOF_TIMESTAMPING_OPT_TSONLY
                | libc::SOF_TIMESTAMPING_OPT_TX_SWHW;
        }
        // TX generation is per-send, never enabled for ordinary transmit().
        Ok(flags as libc::c_int)
    }

    pub(crate) fn capabilities(self) -> TimestampCapabilities {
        TimestampCapabilities {
            rx_software: self.rx_software,
            rx_hardware: self.rx_hardware,
            tx_software: self.tx_software,
            tx_hardware: self.tx_hardware,
            tx_completion_capacity: if self.tx_software || self.tx_hardware {
                self.tx_completion_capacity
            } else {
                0
            },
        }
    }
}

// Aligned fixed storage covers AUXDATA, three timespecs and sock_extended_err.
// No allocation is performed by send/receive/poll.
pub(crate) struct Control(pub(crate) [usize; 64]);
impl Control {
    pub(crate) fn new() -> Self {
        Self([0; 64])
    }
    pub(crate) fn attach(&mut self, message: &mut libc::msghdr) {
        message.msg_control = self.0.as_mut_ptr().cast();
        message.msg_controllen = size_of::<Self>() as _;
    }

    pub(crate) fn append<T: Copy>(&mut self, used: &mut usize, level: i32, kind: i32, value: T) {
        // SAFETY: fixed storage is aligned, used advances by CMSG_SPACE, and
        // all callers append bounded, plain C structs fitting this buffer.
        unsafe {
            let space = libc::CMSG_SPACE(size_of::<T>() as u32) as usize;
            assert!(
                used.checked_add(space)
                    .is_some_and(|end| end <= size_of::<Self>())
            );
            assert!(used.is_multiple_of(std::mem::align_of::<libc::cmsghdr>()));
            let header = self
                .0
                .as_mut_ptr()
                .cast::<u8>()
                .add(*used)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<T>() as u32) as _;
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            libc::CMSG_DATA(header).cast::<T>().write_unaligned(value);
            *used += space;
        }
    }

    pub(crate) fn tx(request: TxTimestampRequest, id: u32) -> (Self, usize) {
        let mut control = Self::new();
        let mut used = 0;
        let flags = if request.software {
            libc::SOF_TIMESTAMPING_TX_SOFTWARE
        } else {
            0
        } | if request.hardware {
            libc::SOF_TIMESTAMPING_TX_HARDWARE
        } else {
            0
        };
        control.append(&mut used, libc::SOL_SOCKET, libc::SO_TIMESTAMPING, flags);
        control.append(&mut used, libc::SOL_SOCKET, SCM_TS_OPT_ID, id);
        (control, used)
    }

    pub(crate) fn parse(
        &self,
        len: usize,
        flags: i32,
        device: Option<u64>,
        tx: bool,
    ) -> io::Result<Metadata> {
        if len > size_of::<Self>() || flags & libc::MSG_CTRUNC != 0 {
            return Err(invalid("truncated ancillary data"));
        }
        let mut result = Metadata::default();
        let mut offset = 0;
        let mut has_timestamp = false;
        // SAFETY: reads below are unaligned and bounded by validated cmsg_len
        // and the actual size of this initialized control storage.
        unsafe {
            let base = libc::CMSG_LEN(0) as usize;
            while offset < len {
                if len - offset < base {
                    return Err(invalid("short ancillary header"));
                }
                let ptr = self.0.as_ptr().cast::<u8>().add(offset);
                let header = ptr.cast::<libc::cmsghdr>().read_unaligned();
                #[allow(clippy::unnecessary_cast)] // musl uses socklen_t, glibc size_t
                let length = header.cmsg_len as usize;
                if length < base || length > len - offset {
                    return Err(invalid("invalid ancillary length"));
                }
                let data = ptr.add(base);
                let payload = length - base;
                match (header.cmsg_level, header.cmsg_type) {
                    (libc::SOL_PACKET, libc::PACKET_AUXDATA) => {
                        if payload < size_of::<libc::tpacket_auxdata>() {
                            return Err(invalid("short PACKET_AUXDATA"));
                        }
                        let aux = data.cast::<libc::tpacket_auxdata>().read_unaligned();
                        if aux.tp_status & libc::TP_STATUS_VLAN_VALID != 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::Unsupported,
                                "VLAN-stripped packet discarded",
                            ));
                        }
                    }
                    (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => {
                        if has_timestamp || payload != size_of::<[libc::timespec; 3]>() {
                            return Err(invalid("invalid SCM_TIMESTAMPING"));
                        }
                        has_timestamp = true;
                        let times = data.cast::<[libc::timespec; 3]>().read_unaligned();
                        result.timestamps.software =
                            stamp(times[0], TimestampSource::Software, device, tx)?;
                        result.timestamps.hardware =
                            stamp(times[2], TimestampSource::Hardware, device, tx)?;
                    }
                    (libc::SOL_PACKET, libc::PACKET_TX_TIMESTAMP) => {
                        if result.error.is_some() || payload < size_of::<libc::sock_extended_err>()
                        {
                            return Err(invalid("invalid PACKET_TX_TIMESTAMP"));
                        }
                        result.error =
                            Some(data.cast::<libc::sock_extended_err>().read_unaligned());
                    }
                    _ => {}
                }
                if length == len - offset {
                    break;
                } // last cmsg need not include padding
                let aligned = libc::CMSG_SPACE(payload as u32) as usize;
                if aligned > len - offset {
                    return Err(invalid("truncated ancillary padding"));
                }
                offset += aligned;
            }
        }
        Ok(result)
    }
}

#[derive(Default)]
pub(crate) struct Metadata {
    pub(crate) timestamps: PacketTimestamps,
    pub(crate) error: Option<libc::sock_extended_err>,
}

fn stamp(
    time: libc::timespec,
    source: TimestampSource,
    device: Option<u64>,
    tx: bool,
) -> io::Result<Option<PacketTimestamp>> {
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(invalid("invalid timestamp timespec"));
    }
    let value = (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| invalid("timestamp overflow"))?;
    if value == 0 {
        return Ok(None);
    }
    let (point, domain) = match source {
        TimestampSource::Software => (
            if tx {
                TimestampPoint::KernelTransmit
            } else {
                TimestampPoint::KernelReceive
            },
            ClockDomain::Realtime,
        ),
        TimestampSource::Hardware => {
            let Some(device) = device else {
                return Ok(None);
            };
            (
                if tx {
                    TimestampPoint::DeviceTransmit
                } else {
                    TimestampPoint::DeviceReceive
                },
                ClockDomain::Device(device),
            )
        }
    };
    Ok(Some(PacketTimestamp {
        value,
        source,
        point,
        clock: ClockDescriptor {
            domain,
            unit: TimestampUnit::Nanoseconds,
        },
    }))
}

struct Pending {
    id: u32,
    request: TxTimestampRequest,
}
pub(crate) struct State {
    pub(crate) config: TimestampConfig,
    next_id: u64,
    pending: Vec<Pending>,
    events: VecDeque<TxTimestampCompletion>,
}
impl State {
    pub(crate) fn new(config: TimestampConfig) -> io::Result<Self> {
        config.flags()?;
        let mut pending = Vec::new();
        let mut events = VecDeque::new();
        pending
            .try_reserve_exact(config.tx_completion_capacity)
            .map_err(io::Error::other)?;
        events
            .try_reserve_exact(config.tx_completion_capacity)
            .map_err(io::Error::other)?;
        Ok(Self {
            config,
            next_id: 1,
            pending,
            events,
        })
    }
    // ponytail: linear scans bounded by configured completion capacity; index
    // only if measured large-capacity workloads justify the extra allocation.
    pub(crate) fn prepare(&self, request: TxTimestampRequest) -> io::Result<Option<u32>> {
        if !request.software && !request.hardware {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty timestamp request",
            ));
        }
        if (request.software && !self.config.tx_software)
            || (request.hardware && !self.config.tx_hardware)
        {
            return Err(unsupported());
        }
        if self
            .pending
            .iter()
            .any(|p| p.request.cookie == request.cookie)
            || self.events.iter().any(|e| e.cookie == request.cookie)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "duplicate timestamp cookie",
            ));
        }
        if self.next_id > u32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "timestamp IDs exhausted; reopen socket",
            ));
        }
        let reserved = self.events.len()
            + self
                .pending
                .iter()
                .map(|p| usize::from(p.request.software) + usize::from(p.request.hardware))
                .sum::<usize>();
        if usize::from(request.software) + usize::from(request.hardware)
            > self.config.tx_completion_capacity - reserved
        {
            return Ok(None);
        }
        Ok(Some(self.next_id as u32))
    }
    pub(crate) fn submitted(&mut self, id: u32, request: TxTimestampRequest) {
        self.pending.push(Pending { id, request });
        self.next_id += 1; // u32 namespace never wraps, including cancelled IDs
    }
    pub(crate) fn complete(&mut self, metadata: Metadata) {
        let Some(error) = metadata.error else {
            return;
        };
        // Other errors and scheduling/ACK observations are not send timestamps.
        if error.ee_errno != libc::ENOMSG as u32
            || error.ee_origin != libc::SO_EE_ORIGIN_TIMESTAMPING
            || error.ee_info != 0
        {
            return;
        }
        let Some(index) = self.pending.iter().position(|p| p.id == error.ee_data) else {
            return;
        };
        let pending = &mut self.pending[index];
        for (wanted, stamp) in [
            (&mut pending.request.software, metadata.timestamps.software),
            (&mut pending.request.hardware, metadata.timestamps.hardware),
        ] {
            if *wanted && let Some(timestamp) = stamp {
                self.events.push_back(TxTimestampCompletion {
                    cookie: pending.request.cookie,
                    timestamp,
                });
                *wanted = false;
            }
        }
        if !pending.request.software && !pending.request.hardware {
            self.pending.swap_remove(index);
        }
    }
    pub(crate) fn pop(&mut self) -> Option<TxTimestampCompletion> {
        self.events.pop_front()
    }
    pub(crate) fn cancel(&mut self, cookie: u64) -> bool {
        let before = self.pending.len() + self.events.len();
        self.pending.retain(|p| p.request.cookie != cookie);
        self.events.retain(|e| e.cookie != cookie);
        before != self.pending.len() + self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn times() -> [libc::timespec; 3] {
        [
            libc::timespec {
                tv_sec: 2,
                tv_nsec: 3,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 4,
                tv_nsec: 5,
            },
        ]
    }
    fn error(id: u32) -> libc::sock_extended_err {
        libc::sock_extended_err {
            ee_errno: libc::ENOMSG as u32,
            ee_origin: libc::SO_EE_ORIGIN_TIMESTAMPING,
            ee_type: 0,
            ee_code: 0,
            ee_pad: 0,
            ee_info: 0,
            ee_data: id,
        }
    }
    fn event(id: u32, sw: bool, hw: bool) -> Metadata {
        // Exercise the actual SOL_PACKET error + SOL_SOCKET timestamp parser.
        let mut control = Control::new();
        let mut used = 0;
        control.append(
            &mut used,
            libc::SOL_PACKET,
            libc::PACKET_TX_TIMESTAMP,
            error(id),
        );
        let mut ts = times();
        if !sw {
            ts[0] = ts[1];
        }
        if !hw {
            ts[2] = ts[1];
        }
        control.append(&mut used, libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, ts);
        control.parse(used, 0, Some(99), true).unwrap()
    }
    fn config(capacity: usize) -> TimestampConfig {
        TimestampConfig {
            rx_software: true,
            rx_hardware: true,
            tx_software: true,
            tx_hardware: true,
            device_clock: Some(99),
            tx_completion_capacity: capacity,
        }
    }
    fn request(cookie: u64, sw: bool, hw: bool) -> TxTimestampRequest {
        TxTimestampRequest {
            cookie,
            software: sw,
            hardware: hw,
        }
    }

    #[test]
    fn mixed_ancillary_validation() {
        let mut control = Control::new();
        assert_eq!(
            control.parse(0, 0, None, false).unwrap().timestamps,
            PacketTimestamps::default()
        );
        assert!(control.parse(0, libc::MSG_CTRUNC, None, false).is_err());
        assert!(
            control
                .parse(size_of::<Control>() + 1, 0, None, false)
                .is_err()
        );
        let mut used = 0;
        control.append(&mut used, libc::SOL_SOCKET, -1, [123u8; 3]); // alignment/padding
        let aux_offset = used;
        let mut aux: libc::tpacket_auxdata = unsafe { std::mem::zeroed() };
        control.append(&mut used, libc::SOL_PACKET, libc::PACKET_AUXDATA, aux);
        control.append(&mut used, libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, times());
        let parsed = control.parse(used, 0, Some(99), false).unwrap();
        let sw = parsed.timestamps.software.unwrap();
        assert_eq!(sw.value, 2_000_000_003);
        assert_eq!(sw.source, TimestampSource::Software);
        assert_eq!(sw.point, TimestampPoint::KernelReceive);
        assert_eq!(sw.clock.domain, ClockDomain::Realtime);
        let hw = parsed.timestamps.hardware.unwrap();
        assert_eq!(hw.value, 4_000_000_005);
        assert_eq!(hw.point, TimestampPoint::DeviceReceive);
        assert_eq!(hw.clock.domain, ClockDomain::Device(99));
        assert_eq!(hw.clock.unit, TimestampUnit::Nanoseconds);
        for len in [1, used - 1, used + 1] {
            assert!(control.parse(len, 0, Some(99), false).is_err());
        }
        // Priority-only VLAN metadata remains fatal, even with timestamps.
        aux.tp_status = libc::TP_STATUS_VLAN_VALID;
        control.append(
            &mut { aux_offset },
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            aux,
        );
        assert_eq!(
            control
                .parse(used, 0, Some(99), false)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Unsupported
        );
        // Corrupt a header's bounds; no unbounded CMSG_NXTHDR traversal.
        for length in [0, size_of::<Control>() + 1] {
            unsafe {
                (*control.0.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_len = length;
            }
            assert!(control.parse(used, 0, None, false).is_err());
        }
        let mut control = Control::new();
        let mut used = 0;
        control.append(&mut used, libc::SOL_PACKET, libc::PACKET_AUXDATA, 0u8);
        assert!(control.parse(used, 0, None, false).is_err());
        let mut used = 0;
        control.append(&mut used, libc::SOL_PACKET, libc::PACKET_TX_TIMESTAMP, 0u8);
        assert!(control.parse(used, 0, None, true).is_err());
        let mut used = 0;
        control.append(&mut used, libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, times());
        control.append(&mut used, libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, times());
        assert!(control.parse(used, 0, None, false).is_err());
    }

    #[test]
    fn timespec_validation_and_absence() {
        let mut control = Control::new();
        for time in [
            libc::timespec {
                tv_sec: -1,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 1,
                tv_nsec: -1,
            },
            libc::timespec {
                tv_sec: 1,
                tv_nsec: 1_000_000_000,
            },
        ] {
            for index in [0, 2] {
                let mut ts = times();
                ts[index] = time;
                let mut used = 0;
                control.append(&mut used, libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, ts);
                assert!(control.parse(used, 0, Some(1), false).is_err());
            }
        }
        #[cfg(target_pointer_width = "64")]
        assert!(
            stamp(
                libc::timespec {
                    tv_sec: i64::MAX,
                    tv_nsec: 0
                },
                TimestampSource::Software,
                None,
                false
            )
            .is_err()
        );
        let mut used = 0;
        control.append(
            &mut used,
            libc::SOL_SOCKET,
            libc::SCM_TIMESTAMPING,
            [times()[1]; 3],
        );
        assert_eq!(
            control.parse(used, 0, Some(1), false).unwrap().timestamps,
            PacketTimestamps::default()
        );
        assert!(
            stamp(times()[2], TimestampSource::Hardware, None, true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bounded_correlation_sources_cancel_and_exhaustion() {
        let mut state = State::new(config(2)).unwrap();
        let req = request(u64::MAX, true, true);
        let id = state.prepare(req).unwrap().unwrap();
        state.submitted(id, req);
        assert!(state.prepare(req).is_err());
        assert_eq!(state.prepare(request(8, true, false)).unwrap(), None);
        for field in 0..4 {
            let mut event = event(id, true, true);
            match field {
                0 => event.error = None,
                1 => event.error.as_mut().unwrap().ee_errno = libc::EIO as u32,
                2 => event.error.as_mut().unwrap().ee_origin = libc::SO_EE_ORIGIN_LOCAL,
                _ => event.error.as_mut().unwrap().ee_info = 1, // SCM_TSTAMP_SCHED
            }
            state.complete(event);
            assert!(state.pop().is_none());
        }
        state.complete(event(id + 1, true, true));
        assert!(state.pop().is_none());
        state.complete(event(id, true, false));
        state.complete(event(id, true, false)); // same source only once
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.prepare(request(8, true, false)).unwrap(), None); // queued event reserved
        let sw = state.pop().unwrap();
        assert_eq!(sw.cookie, u64::MAX);
        assert_eq!(sw.timestamp.point, TimestampPoint::KernelTransmit);
        assert!(state.pop().is_none()); // hardware absence does NOT expire request
        let req2 = request(8, true, false);
        let id2 = state.prepare(req2).unwrap().unwrap();
        state.submitted(id2, req2);
        state.complete(event(id2, false, true)); // unrequested source ignored
        assert!(state.pop().is_none());
        state.complete(event(id, false, true));
        let hw = state.pop().unwrap();
        assert_eq!(hw.cookie, u64::MAX);
        assert_eq!(hw.timestamp.point, TimestampPoint::DeviceTransmit);
        state.complete(event(id, true, true));
        assert!(state.pop().is_none());
        assert!(state.cancel(8));
        assert!(!state.cancel(8));
        let id3 = state.prepare(req2).unwrap().unwrap();
        assert_ne!(id2, id3);
        state.submitted(id3, req2);
        state.complete(event(id2, true, false)); // late ID, reused caller cookie
        assert!(state.pop().is_none());
        state.complete(event(id3, true, false));
        assert!(state.cancel(8)); // queued observation is also cancelled
        assert!(state.pop().is_none());
        state.next_id = u32::MAX as u64;
        let id = state.prepare(req2).unwrap().unwrap();
        state.submitted(id, req2);
        state.cancel(8);
        assert_eq!(
            state.prepare(req2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn combined_and_hardware_first_completions() {
        for combined in [false, true] {
            let mut state = State::new(config(2)).unwrap();
            let req = request(19, true, true);
            let id = state.prepare(req).unwrap().unwrap();
            state.submitted(id, req);
            state.complete(event(id, combined, true));
            if !combined {
                state.complete(event(id, false, true)); // duplicate hardware
                state.complete(event(id, true, false));
            }
            assert_eq!(state.events.len(), 2);
            assert!(state.pending.is_empty());
            let a = state.pop().unwrap();
            let b = state.pop().unwrap();
            assert_eq!((a.cookie, b.cookie), (19, 19));
            assert_ne!(a.timestamp.source, b.timestamp.source);
            assert!(state.pop().is_none());
        }
    }

    #[test]
    fn unsupported_and_transactional_prepare() {
        assert!(
            State::new(TimestampConfig {
                tx_software: true,
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            State::new(TimestampConfig {
                rx_hardware: true,
                ..Default::default()
            })
            .is_err()
        );
        let state = State::new(TimestampConfig {
            tx_software: true,
            tx_completion_capacity: 1,
            ..Default::default()
        })
        .unwrap();
        for (sw, hw, kind) in [
            (false, false, io::ErrorKind::InvalidInput),
            (false, true, io::ErrorKind::Unsupported),
            (true, true, io::ErrorKind::Unsupported),
        ] {
            assert_eq!(state.prepare(request(1, sw, hw)).unwrap_err().kind(), kind);
        }
        let req = request(4, true, false);
        // Preparation reserves capacity logically but never consumes an ID or
        // slot: send errors/WouldBlock simply omit submitted().
        assert_eq!(state.prepare(req).unwrap(), state.prepare(req).unwrap());
        assert_eq!(state.pending.len(), 0);
        assert_eq!(state.next_id, 1);
        let mut state = State::new(config(1)).unwrap();
        assert_eq!(state.prepare(request(1, true, true)).unwrap(), None);
        let id = state.prepare(req).unwrap().unwrap();
        state.submitted(id, req);
        assert_eq!(state.prepare(request(1, true, false)).unwrap(), None);
        assert!(state.cancel(4));
        assert!(state.prepare(req).unwrap().is_some());
    }
}
