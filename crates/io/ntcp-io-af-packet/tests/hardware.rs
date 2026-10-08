#![cfg(target_os = "linux")]

use ntcp_io::{
    ClockDomain, PacketIo, TimestampPoint, TimestampSource, TxOutcome, TxTimestampRequest,
};
use ntcp_io_af_packet::{AfPacket, TimestampConfig};
use std::time::{Duration, Instant};

// Explicit opt-in transmits a test Ethernet frame on two externally connected,
// externally configured NICs. Never changes interface or hwtstamp settings.
#[test]
#[ignore = "requires externally configured hardware and NTCP_HW_{TX,RX}_{IFACE,CLOCK}"]
fn externally_configured_hardware() {
    fn open(side: &str) -> (AfPacket, u64) {
        let name = std::ffi::CString::new(std::env::var(format!("NTCP_HW_{side}_IFACE")).unwrap())
            .unwrap();
        let clock = std::env::var(format!("NTCP_HW_{side}_CLOCK"))
            .unwrap()
            .parse()
            .unwrap();
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        let mut io = AfPacket::bind(index, 0x88b5).unwrap();
        io.enable_timestamps(TimestampConfig {
            rx_software: true,
            rx_hardware: true,
            tx_software: true,
            tx_hardware: true,
            device_clock: Some(clock),
            tx_completion_capacity: 2,
        })
        .unwrap();
        (io, clock)
    }
    let (mut tx, tx_clock) = open("TX");
    let (mut rx, rx_clock) = open("RX");
    let mut frame = [0x5a; 64];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
    assert_eq!(
        tx.transmit_with_timestamp(
            &frame,
            TxTimestampRequest {
                cookie: u64::MAX,
                software: true,
                hardware: true
            }
        )
        .unwrap(),
        TxOutcome::Submitted
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_rx = false;
    let mut got_tx = [false; 2];
    let mut out = [0; 2048];
    while !got_rx || !got_tx.iter().all(|done| *done) {
        assert!(
            Instant::now() < deadline,
            "external NIC timestamp configuration did not yield all requested observations"
        );
        if let Some(packet) = rx.receive_with_metadata(&mut out).unwrap()
            && out[..packet.len] == frame
        {
            let hw = packet
                .timestamps
                .hardware
                .expect("missing hardware RX metadata");
            assert_eq!(hw.source, TimestampSource::Hardware);
            assert_eq!(hw.point, TimestampPoint::DeviceReceive);
            assert_eq!(hw.clock.domain, ClockDomain::Device(rx_clock));
            got_rx = true;
        }
        if let Some(event) = tx.poll_tx_timestamp().unwrap() {
            assert_eq!(event.cookie, u64::MAX);
            let index = usize::from(event.timestamp.source == TimestampSource::Hardware);
            assert!(!got_tx[index]);
            got_tx[index] = true;
            if index == 1 {
                assert_eq!(event.timestamp.point, TimestampPoint::DeviceTransmit);
                assert_eq!(event.timestamp.clock.domain, ClockDomain::Device(tx_clock));
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
