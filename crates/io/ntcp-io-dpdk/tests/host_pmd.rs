use ntcp_io::{PacketIo, PacketLayer, TxOutcome};
use ntcp_io_dpdk::{Eal, Port, PortConfig};
use std::{
    ffi::{CString, c_char, c_void},
    io::ErrorKind,
    net::Ipv4Addr,
};

unsafe extern "C" {
    fn ntcp_host_test_cpu() -> i32;
    fn ntcp_host_test_pools(full: *mut u32) -> u32;
    fn ntcp_host_test_lcore() -> u32;
    fn ntcp_host_test_port_named(name: *const c_char) -> i32;
    fn ntcp_host_test_ring_driver() -> *mut c_void;
    fn ntcp_host_test_mac(port: u16, mac: *mut u8) -> i32;
    fn ntcp_host_test_set_mac(port: u16, mac: *const u8) -> i32;
}

const NO_LCORE: u32 = u32::MAX;

// (pools named by the host module, of which full)
fn pools() -> (u32, u32) {
    let mut full = 0;
    // SAFETY: EAL is initialized; output is writable.
    let pools = unsafe { ntcp_host_test_pools(&mut full) };
    (pools, full)
}

fn port_named(name: &str) -> Option<u16> {
    let name = CString::new(name).unwrap();
    // SAFETY: EAL is initialized; name is NUL-terminated.
    let port = unsafe { ntcp_host_test_port_named(name.as_ptr()) };
    (port >= 0).then_some(port as u16)
}

fn lcore() -> u32 {
    // SAFETY: reads this thread's EAL lcore id.
    unsafe { ntcp_host_test_lcore() }
}

fn frame(fill: u8, len: usize) -> Vec<u8> {
    let mut frame = vec![fill; len];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame
}

// EAL is process-global and initializes once, so this binary holds a single
// test whose steps run in order against one EAL; libtest cannot interleave
// them. Every EAL argument keeps the run off hugepages, shared files and PCI
// devices; the file prefix keeps it apart from other DPDK processes.
#[test]
fn hosted_ring_ports() {
    // SAFETY: returns a function address only.
    assert!(!unsafe { ntcp_host_test_ring_driver() }.is_null());
    // SAFETY: reads this thread's affinity.
    let cpu = unsafe { ntcp_host_test_cpu() };
    assert!(cpu >= 0);
    let args = vec![
        format!("--lcores=0@{cpu}"),
        "--no-huge".into(),
        "--no-pci".into(),
        "--in-memory".into(),
        format!("--file-prefix=ntcp-host-{}", std::process::id()),
        "--no-telemetry".into(),
        "-m".into(),
        "256".into(),
    ];

    let eal = Eal::init(args.clone()).unwrap();
    assert!(std::ptr::eq(eal, Eal::init(args.clone()).unwrap()));
    assert_eq!(eal.args(), args.as_slice());
    assert_eq!(eal.main_lcore(), 0);
    assert_eq!(lcore(), 0); // rte_eal_init made this thread the main lcore.
    let mut different = args.clone();
    different.push("--log-level=8".into());
    assert_eq!(
        Eal::init(different).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    port_lifecycle(eal);
    rejected_configurations(eal);
    mac_addresses(eal);
    outstanding_mbufs_retain_pool(eal);
}

fn port_lifecycle(eal: &'static Eal) {
    let mut config = PortConfig::new("net_ring0");
    config.queues = 4;
    config.rx_desc = 64;
    config.tx_desc = 64;
    config.mbufs_per_queue = 511;
    let port = Port::start(eal, config.clone()).unwrap();
    assert_eq!(port_named("net_ring0"), Some(port.port_id()));
    assert_eq!(port.queues(), 4);
    assert_eq!(pools(), (4, 4));
    assert_eq!(port.clock(), None);
    assert_eq!(
        port.read_clock().unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    // The ring PMD has no address of its own; none is made up.
    assert_eq!(port.mac_address().unwrap(), [0; 6]);
    // ethdev ownership: a second host cannot configure the same port.
    assert_eq!(
        Port::start(eal, config).err().unwrap().kind(),
        ErrorKind::ResourceBusy
    );
    assert_eq!(pools(), (4, 4));

    // The ring PMD has no rte_flow support.
    let error = port
        .steer_ipv4(Ipv4Addr::new(10, 0, 0, 1), 1)
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(error.to_string().contains("rte_flow_create"), "{error}");
    assert_eq!(
        port.steer_ipv4(Ipv4Addr::new(10, 0, 0, 1), 4)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidInput
    );

    assert_eq!(
        port.take_queue(4).err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    // A handle dropped unattached returns its index.
    drop(port.take_queue(0).unwrap());
    let handles: Vec<_> = (0..4).map(|q| port.take_queue(q).unwrap()).collect();
    for q in 0..4 {
        assert_eq!(
            port.take_queue(q).err().unwrap().kind(),
            ErrorKind::AlreadyExists
        );
    }
    let [q0, q1, q2, q3] = <[_; 4]>::try_from(handles).ok().unwrap();

    // Queue 0 on this thread, already the EAL main lcore: no registration.
    let mut main = q0.attach().unwrap();
    assert_eq!(main.queue(), 0);
    assert_eq!(lcore(), 0);

    // Queues 1 and 2 move to a non-EAL worker thread.
    let worker = std::thread::spawn(move || {
        assert_eq!(lcore(), NO_LCORE);
        let mut one = q1.attach().unwrap();
        let registered = lcore();
        assert_ne!(registered, NO_LCORE);
        let mut two = q2.attach().unwrap();
        assert_eq!(lcore(), registered); // One registration per thread.
        assert_eq!((one.queue(), two.queue()), (1, 2));
        assert_eq!(one.layer(), PacketLayer::Ethernet);
        assert_eq!(one.local_ip_mtu().unwrap(), Some(1500));
        assert_eq!(one.clock(), None);
        assert!(!one.timestamp_capabilities().rx_hardware);
        let mut out = vec![0; 4096];
        // Each ring queue pair loops TX i back to RX i.
        for len in [64, 1514, 3000] {
            let sent = frame(len as u8, len);
            assert_eq!(one.transmit(&sent).unwrap(), TxOutcome::Submitted);
            assert_eq!(two.receive(&mut out).unwrap(), None);
            assert_eq!(one.receive(&mut out).unwrap(), Some(len));
            assert_eq!(&out[..len], sent.as_slice());
        }
        let sent = frame(2, 128);
        assert_eq!(two.transmit(&sent).unwrap(), TxOutcome::Submitted);
        let packet = two.receive_with_metadata(&mut out).unwrap().unwrap();
        assert_eq!(&out[..packet.len], sent.as_slice());
        assert_eq!(packet.timestamps.hardware, None);
        drop(one);
        assert_eq!(lcore(), registered); // Still serving queue 2.
        drop(two);
        assert_eq!(lcore(), NO_LCORE); // Unregistered with its last queue.
    });
    worker.join().unwrap();
    // Queues that were attached stay taken after their HostedQueue drops.
    assert_eq!(
        port.take_queue(1).err().unwrap().kind(),
        ErrorKind::AlreadyExists
    );

    let mut out = vec![0; 2048];
    let sent = frame(9, 60);
    assert_eq!(main.transmit(&sent).unwrap(), TxOutcome::Submitted);
    assert_eq!(main.receive(&mut out).unwrap(), Some(60));
    assert_eq!(&out[..60], sent.as_slice());
    drop(main);
    assert_eq!(lcore(), 0);
    assert_eq!(pools(), (4, 4)); // Every mbuf is back.

    // Dropping the Port does not stop it while a queue is still attached.
    let mut last = q3.attach().unwrap();
    let id = port.port_id();
    drop(port);
    assert_eq!(port_named("net_ring0"), Some(id));
    assert_eq!(
        last.read_clock().unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    let sent = frame(3, 100);
    assert_eq!(last.transmit(&sent).unwrap(), TxOutcome::Submitted);
    assert_eq!(last.receive(&mut out).unwrap(), Some(100));
    assert_eq!(pools(), (4, 4));
    drop(last);
    // Closed and detached, and every pool freed: none had an outstanding mbuf.
    assert_eq!(port_named("net_ring0"), None);
    assert_eq!(pools(), (0, 0));
}

fn rejected_configurations(eal: &'static Eal) {
    let mut timestamps = PortConfig::new("net_ring1");
    timestamps.rx_timestamps = true;
    let error = Port::start(eal, timestamps).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(
        error.to_string().contains("RTE_ETH_RX_OFFLOAD_TIMESTAMP"),
        "{error}"
    );
    assert_eq!(port_named("net_ring1"), None); // Released on failure.

    let mut isolate = PortConfig::new("net_ring2");
    isolate.isolate = true;
    let error = Port::start(eal, isolate).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(error.to_string().contains("rte_flow_isolate"), "{error}");
    assert_eq!(port_named("net_ring2"), None);

    let mut queues = PortConfig::new("net_ring3");
    queues.queues = 17; // The ring PMD has 16 queue pairs.
    let error = Port::start(eal, queues).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("queue count"), "{error}");

    let mut small = PortConfig::new("net_ring4");
    small.mbufs_per_queue = 2048; // rx_desc + tx_desc = 2048 by default.
    let error = Port::start(eal, small).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("mbufs_per_queue"), "{error}");
    assert_eq!(port_named("net_ring4"), None);

    let mut none = PortConfig::new("net_ring5");
    none.queues = 0;
    assert_eq!(
        Port::start(eal, none).err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(port_named("net_ring5"), None); // Rejected before probing.
    let error = Port::start(eal, PortConfig::new("net_bogus0"))
        .err()
        .unwrap();
    assert!(error.to_string().contains("claim net_bogus0"), "{error}");
    assert_eq!(pools(), (0, 0));
}

fn device_mac(port: u16) -> [u8; 6] {
    let mut mac = [0; 6];
    // SAFETY: EAL is initialized; the fixture writes six octets.
    assert_eq!(unsafe { ntcp_host_test_mac(port, mac.as_mut_ptr()) }, 0);
    mac
}

// The null PMD draws a random locally administered unicast address at probe
// and accepts a new default address, so the reported MAC can be checked
// against ethdev's own view twice, the second time octet by octet against
// an address of the test's choosing.
fn mac_addresses(eal: &'static Eal) {
    let port = Port::start(eal, PortConfig::new("net_null0")).unwrap();
    let drawn = port.mac_address().unwrap();
    assert_eq!(drawn, device_mac(port.port_id()));
    assert_eq!(drawn[0] & 0b11, 0b10, "{drawn:02x?}");
    assert_eq!(port.mac_address().unwrap(), drawn);

    let queue = port.take_queue(0).unwrap().attach().unwrap();
    assert_eq!(queue.mac_address().unwrap(), drawn);
    let chosen = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    // SAFETY: EAL is initialized; the address has six octets.
    assert_eq!(
        unsafe { ntcp_host_test_set_mac(port.port_id(), chosen.as_ptr()) },
        0
    );
    assert_eq!(port.mac_address().unwrap(), chosen);
    assert_eq!(queue.mac_address().unwrap(), chosen);
    drop(port);
    drop(queue);
    assert_eq!(port_named("net_null0"), None);
    assert_eq!(pools(), (0, 0));
}

// Last: a pool whose mbuf is lost inside the ring PMD is retained, not freed
// under a possible reference. This deliberately leaks it until exit.
fn outstanding_mbufs_retain_pool(eal: &'static Eal) {
    let port = Port::start(eal, PortConfig::new("net_ring9")).unwrap();
    let mut queue = port.take_queue(0).unwrap().attach().unwrap();
    assert_eq!(queue.transmit(&frame(1, 64)).unwrap(), TxOutcome::Submitted);
    drop(port);
    drop(queue); // Ring close frees the ring with the mbuf still in it.
    assert_eq!(port_named("net_ring9"), None);
    assert_eq!(pools(), (1, 0));
}
