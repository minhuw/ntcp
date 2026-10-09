use std::io;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketLayer {
    Ip,
    Ethernet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOutcome {
    Submitted,
    WouldBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampSource {
    Software,
    Hardware,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampPoint {
    UserReceive,
    UserTransmit,
    KernelReceive,
    KernelTransmit,
    DeviceReceive,
    DeviceTransmit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockDomain {
    Realtime,
    Monotonic,
    Device(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampUnit {
    Nanoseconds,
    // Host-assigned calibration identity. No implicit conversion to nanoseconds.
    RawTicks { identity: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockDescriptor {
    pub domain: ClockDomain,
    pub unit: TimestampUnit,
}

// Absolute value in an explicit clock; no implicit clock conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitTime {
    pub value: u64,
    pub clock: ClockDescriptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSchedulingCapabilities {
    pub clock: ClockDescriptor,
    pub hardware: bool,
}

// Best-effort negative observation, not a delivery completion. Requested time
// is identity, not a unique cookie. errno/code are native backend diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSchedulingError {
    pub when: TransmitTime,
    pub errno: u32,
    pub code: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketTimestamp {
    pub value: u64,
    pub source: TimestampSource,
    pub point: TimestampPoint,
    pub clock: ClockDescriptor,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketTimestamps {
    pub software: Option<PacketTimestamp>,
    pub hardware: Option<PacketTimestamp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedPacket {
    pub len: usize,
    pub timestamps: PacketTimestamps,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampRequest {
    pub cookie: u64,
    pub software: bool,
    pub hardware: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTimestampCompletion {
    pub cookie: u64,
    pub timestamp: PacketTimestamp,
}

// Enabled adapter paths, not a guarantee that every packet has metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimestampCapabilities {
    pub rx_software: bool,
    pub rx_hardware: bool,
    pub tx_software: bool,
    pub tx_hardware: bool,
    pub tx_completion_capacity: usize,
}

// Packet operations do bounded, nonblocking work on one complete packet. The caller
// owns its buffers: receive copies into out, transmit retains no borrow.
// Submitted transfers a copy to the backend; it implies neither wire delivery
// nor a TCP acknowledgement. Backend DMA buffers are reclaimed internally.
// None/WouldBlock leaves the caller free to retry. Errors never report a
// truncated packet as valid. Drivers, threads and scheduling belong to callers.
pub trait PacketIo {
    fn layer(&self) -> PacketLayer;

    // Current interface IP MTU, including IP header, excluding L2/FCS.
    // Read-only, bounded query; unknown is distinct from a failed query.
    // Linux queries may wait up to 100ms and use the caller's network namespace.
    fn local_ip_mtu(&self) -> io::Result<Option<u32>> {
        Ok(None)
    }

    // Independent adapter buffer limit in layer() bytes, not a path/link MTU.
    // Ethernet includes its 14-byte header, not FCS. None means unknown.
    fn max_packet_len(&self) -> Option<usize> {
        None
    }

    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>>;
    // Synchronous TX EMSGSIZE rejects this packet before submission, including
    // timestamp/scheduled TX. Other errors do NOT imply non-submission; async
    // scheduling errors are observations, not synchronous TX rejections.
    fn transmit(&mut self, packet: &[u8]) -> io::Result<TxOutcome>;

    fn tx_scheduling_capabilities(&self) -> Option<TxSchedulingCapabilities> {
        None
    }

    // Validate clock, horizon and optional timestamp sources before submission.
    // WouldBlock consumes neither packet nor request. Never fall back to an
    // immediate send on failure. Submitted is ownership, NOT scheduling success.
    fn transmit_at(
        &mut self,
        _packet: &[u8],
        _when: TransmitTime,
        _timestamp: Option<TxTimestampRequest>,
    ) -> io::Result<TxOutcome> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "scheduled TX unsupported",
        ))
    }

    // Bounded nonblocking polling; absence is NOT evidence of delivery. When
    // timestamps share a queue, callers must budget both polling APIs.
    fn poll_tx_scheduling_error(&mut self) -> io::Result<Option<TxSchedulingError>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "scheduled TX unsupported",
        ))
    }

    fn timestamp_capabilities(&self) -> TimestampCapabilities {
        TimestampCapabilities::default()
    }

    fn receive_with_metadata(&mut self, out: &mut [u8]) -> io::Result<Option<ReceivedPacket>> {
        self.receive(out).map(|packet| {
            packet.map(|len| ReceivedPacket {
                len,
                timestamps: PacketTimestamps::default(),
            })
        })
    }

    // Validate every requested source before submission. Unsupported requests
    // must have no TX side effects. WouldBlock consumes neither packet nor
    // request. Implementations bound outstanding requests/completions and
    // preserve the opaque cookie; callers keep cookies unique while pending.
    // Requesting both sources may produce two separate completions. Submission
    // alone is not a device timestamp, and completion is not a TCP ACK.
    fn transmit_with_timestamp(
        &mut self,
        _packet: &[u8],
        request: TxTimestampRequest,
    ) -> io::Result<TxOutcome> {
        if !request.software && !request.hardware {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty timestamp request",
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamps unsupported",
        ))
    }

    // Release an outstanding request without affecting its submitted packet.
    // True means a request was cancelled; false means none was pending. A
    // backend must discard late completions without binding them to a reused
    // cookie. Cancellation is bounded and nonblocking like completion polling.
    fn cancel_tx_timestamp(&mut self, _cookie: u64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamp cancellation unsupported",
        ))
    }

    // Bounded, nonblocking work returning at most one observation. None means
    // not ready; consumers must budget polls. No clock sampling is implied.
    fn poll_tx_timestamp(&mut self) -> io::Result<Option<TxTimestampCompletion>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TX timestamps unsupported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_defaults_never_submit_timestamp_requests() {
        struct Mock {
            transmitted: usize,
            received: bool,
        }
        impl PacketIo for Mock {
            fn layer(&self) -> PacketLayer {
                PacketLayer::Ip
            }
            fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
                if self.received {
                    return Ok(None);
                }
                if out.is_empty() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                out[0] = 7;
                self.received = true;
                Ok(Some(1))
            }
            fn transmit(&mut self, _: &[u8]) -> io::Result<TxOutcome> {
                self.transmitted += 1;
                Ok(TxOutcome::Submitted)
            }
        }
        let mut mock = Mock {
            transmitted: 0,
            received: false,
        };
        let io: &mut dyn PacketIo = &mut mock;
        assert_eq!(io.local_ip_mtu().unwrap(), None);
        assert_eq!(io.max_packet_len(), None);
        assert_eq!(
            io.timestamp_capabilities(),
            TimestampCapabilities::default()
        );
        assert!(io.receive_with_metadata(&mut []).is_err());
        let mut out = [0];
        assert_eq!(
            io.receive_with_metadata(&mut out).unwrap(),
            Some(ReceivedPacket {
                len: 1,
                timestamps: PacketTimestamps::default(),
            })
        );
        assert_eq!(out, [7]);
        assert_eq!(io.receive_with_metadata(&mut out).unwrap(), None);
        for (software, hardware) in [(true, false), (false, true), (true, true), (false, false)] {
            let error = io
                .transmit_with_timestamp(
                    &[1],
                    TxTimestampRequest {
                        cookie: u64::MAX,
                        software,
                        hardware,
                    },
                )
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if software || hardware {
                    io::ErrorKind::Unsupported
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
        }
        assert_eq!(
            io.poll_tx_timestamp().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            io.cancel_tx_timestamp(u64::MAX).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(io.tx_scheduling_capabilities(), None);
        assert_eq!(
            io.transmit_at(
                &[1],
                TransmitTime {
                    value: 123,
                    clock: ClockDescriptor {
                        domain: ClockDomain::Monotonic,
                        unit: TimestampUnit::Nanoseconds
                    }
                },
                None
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            io.poll_tx_scheduling_error().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(mock.transmitted, 0);
        assert_eq!(mock.transmit(&[1]).unwrap(), TxOutcome::Submitted);
        assert_eq!(mock.transmitted, 1);
    }
}
