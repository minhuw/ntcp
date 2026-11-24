use ntcp_io::{DeviceCounters, PacketIo, PacketLayer, TxOutcome};
use ntcp_io_dpdk::{Eal, Port, PortConfig, Rss, RssAlgorithm};
use std::{
    ffi::{CString, c_char, c_void},
    io::ErrorKind,
    net::Ipv4Addr,
};

// What `receive_frame` put in its frame and returned, together.
struct Received {
    frame: ntcp_io::RxFrame,
    metadata: ntcp_io::ReceivedPacket,
}

trait ReceiveWhole {
    fn receive_whole(&mut self, scratch: &mut [u8]) -> std::io::Result<Option<Received>>;
}

impl<P: PacketIo + ?Sized> ReceiveWhole for P {
    fn receive_whole(&mut self, scratch: &mut [u8]) -> std::io::Result<Option<Received>> {
        let mut frame = None;
        let metadata = self.receive_frame(scratch, &mut frame)?;
        Ok(metadata.map(|metadata| Received {
            frame: frame.expect("a received packet's frame"),
            metadata,
        }))
    }
}

unsafe extern "C" {
    fn ntcp_host_test_cpu() -> i32;
    fn ntcp_host_test_pools(full: *mut u32) -> u32;
    fn ntcp_host_test_pool_geometry(size: *mut u32, object: *mut u32) -> i32;
    fn ntcp_host_test_pool_hold(leave: u32) -> i32;
    fn ntcp_host_test_pool_release();
    fn ntcp_host_test_lcore() -> u32;
    fn ntcp_host_test_port_named(name: *const c_char) -> i32;
    fn ntcp_host_test_ring_driver() -> *mut c_void;
    fn ntcp_host_test_mac(port: u16, mac: *mut u8) -> i32;
    fn ntcp_host_test_set_mac(port: u16, mac: *const u8) -> i32;
    fn ntcp_host_test_rss_conf(
        port: u16,
        rss: *mut i32,
        hf: *mut u64,
        key: *mut u8,
        key_len: *mut u8,
    ) -> i32;
    fn ntcp_host_test_rss_ipv4_hf() -> u64;
    fn ntcp_host_test_rss_key(
        port: u16,
        key: *mut u8,
        key_len: *mut u8,
        algorithm: *mut i32,
    ) -> i32;
    fn ntcp_host_test_reta(port: u16, reta: *mut u16, size: u16) -> i32;
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
        // The default pools without hugepages take 68.3 MB a queue
        // (PortConfig::mbufs_per_queue), and rss_ports starts 4 queues.
        "-m".into(),
        "512".into(),
    ];

    // Refused before EAL runs (it would probe every PCI device), so EAL is
    // still uninitialized for the valid call below.
    let probing: Vec<_> = args.iter().filter(|a| *a != "--no-pci").cloned().collect();
    let refusal = Eal::init(probing).unwrap_err();
    assert_eq!(refusal.kind(), ErrorKind::InvalidInput);
    assert!(refusal.to_string().contains("--no-pci"), "{refusal}");

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
    rss_ports(eal);
    segmentation_not_offered(eal);
    receive_pool_exhausted(eal);
    held_frames(eal);
    hosted_network_e2e(eal);
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
    assert_eq!(port.driver_name().unwrap(), "net_ring");
    assert_eq!(port.queues(), 4);
    assert_eq!(pools(), (4, 4));
    assert_eq!(port.clock(), None);
    assert!(!port.tcp_segmentation()); // Off by default.
    // Checksum offload is asked for by default; the ring PMD offers none.
    assert!(config.checksum_offload && !port.rx_checksum() && !port.tx_checksum());
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

    // The ring PMD has no rte_flow support: the first rule of the set is
    // refused in validation, so none is created.
    let error = port
        .steer_ipv4(Ipv4Addr::new(10, 0, 0, 1), 1)
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    let validate = "rte_flow_validate (eth / ipv4 / tcp priority 1)";
    assert!(error.to_string().contains(validate), "{error}");
    assert_eq!(
        port.steer_ipv4(Ipv4Addr::new(10, 0, 0, 1), 4)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidInput
    );
    // Nor can it validate a masked TCP port rule, so none is created.
    let address = Ipv4Addr::new(10, 0, 0, 1);
    let error = port
        .steer_tcp_port(address, 0x0003, 0x0003, 3)
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(error.to_string().contains("rte_flow_validate"), "{error}");
    for (value, mask, queue) in [(0x0003, 0x0003, 4), (0x0004, 0x0003, 1)] {
        let error = port.steer_tcp_port(address, value, mask, queue).err();
        assert_eq!(error.unwrap().kind(), ErrorKind::InvalidInput);
    }
    // RSS is off by default: nothing to report or set.
    assert_eq!(port.rss().unwrap(), None);
    assert_eq!(
        port.set_reta(&[0; 4]).unwrap_err().kind(),
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
    // The hosted queue forwards the frame path to its adapter. Four queues'
    // caches (1.5 x 255 each) and the rings take the whole of a 511-mbuf
    // pool: nothing may be held.
    assert_eq!(main.rx_frame_budget(), Some(0));
    assert_eq!(main.rx_frame_budget(), main.dpdk().rx_frame_budget());
    assert_eq!(
        main.rx_frames_outstanding(),
        main.dpdk().rx_frames_outstanding()
    );
    let sent = frame(4, 200);
    assert_eq!(main.transmit(&sent).unwrap(), TxOutcome::Submitted);
    let received = main.receive_whole(&mut out).unwrap().unwrap();
    assert_eq!(received.frame.as_slice(), sent.as_slice());
    assert_eq!(received.metadata.len, 200);
    drop(received);
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

    // The ring PMD has no RSS hash types to grant.
    let mut rss = PortConfig::new("net_ring6");
    rss.queues = 2;
    rss.rss = true;
    let error = Port::start(eal, rss).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(error.to_string().contains("rss hash types"), "{error}");
    assert_eq!(port_named("net_ring6"), None);

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
    let config = PortConfig::new("net_null0");
    assert_eq!(config.mbufs_per_queue, 16383);
    let port = Port::start(eal, config).unwrap();
    // The default pool: 16383 mbufs of 2368 octets, as the field documents.
    let (mut size, mut object) = (0, 0);
    // SAFETY: EAL is initialized; outputs are writable.
    assert_eq!(
        unsafe { ntcp_host_test_pool_geometry(&mut size, &mut object) },
        0
    );
    assert_eq!((size, object), (16383, 2368));
    assert_eq!(port.driver_name().unwrap(), "net_null");
    let drawn = port.mac_address().unwrap();
    assert_eq!(drawn, device_mac(port.port_id()));
    assert_eq!(drawn[0] & 0b11, 0b10, "{drawn:02x?}");
    assert_eq!(port.mac_address().unwrap(), drawn);

    let mut queue = port.take_queue(0).unwrap().attach().unwrap();
    assert_eq!(queue.tx_copybreak(), ntcp_io_dpdk::DEFAULT_TX_COPYBREAK);
    queue.set_tx_copybreak(256);
    assert_eq!(queue.tx_copybreak(), 256);
    let mut chunk_source = queue.tx_chunk_source();
    let mut chunk = chunk_source.allocate().unwrap();
    assert_eq!(chunk.append(&[0x5a; 32]), 32);
    let parts = [ntcp_io::TxPart::Chunk(
        ntcp_io::ChunkSlice::new(&chunk, 0..32).unwrap(),
    )];
    let pkt = ntcp_io::TxPacket {
        header: &[0x11; 34],
        payload: &parts,
    };
    assert_eq!(
        queue
            .transmit_packet(&pkt, ntcp_io::TransmitRequest::default())
            .unwrap(),
        TxOutcome::Submitted
    );
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

fn rss_conf(port: u16) -> (bool, u64, Vec<u8>) {
    let (mut rss, mut hf, mut key, mut len) = (0, 0, [0; 255], 0);
    // SAFETY: EAL is initialized; the key buffer holds 255 octets.
    let result =
        unsafe { ntcp_host_test_rss_conf(port, &mut rss, &mut hf, key.as_mut_ptr(), &mut len) };
    assert_eq!(result, 0);
    (rss != 0, hf, key[..usize::from(len)].to_vec())
}

fn device_rss(port: u16, reta_size: u16) -> (Vec<u8>, RssAlgorithm, Vec<u16>) {
    let (mut key, mut len, mut algorithm) = ([0; 255], 0, -1);
    // SAFETY: EAL is initialized; the key buffer holds 255 octets.
    assert_eq!(
        unsafe { ntcp_host_test_rss_key(port, key.as_mut_ptr(), &mut len, &mut algorithm) },
        0
    );
    let algorithm = match algorithm {
        0 => RssAlgorithm::Default,
        1 => RssAlgorithm::Toeplitz,
        other => panic!("the null PMD reports hash function class {other}"),
    };
    let mut reta = vec![0; usize::from(reta_size)];
    // SAFETY: EAL is initialized; reta holds reta_size entries.
    assert_eq!(
        unsafe { ntcp_host_test_reta(port, reta.as_mut_ptr(), reta_size) },
        0
    );
    (key[..usize::from(len)].to_vec(), algorithm, reta)
}

// The null PMD implements RSS in software: a 40-octet key, a 128-entry
// table and every hash type. It stores the configured hash types and the
// table but keeps its own key, so the key passed is checked against ethdev's
// copy of the configuration, and the key reported against the device's. It
// does not report its hash function, which ethdev then gives as the default.
fn rss_ports(eal: &'static Eal) {
    // SAFETY: returns a constant.
    let ipv4 = unsafe { ntcp_host_test_rss_ipv4_hf() };
    let key: Vec<u8> = (1..=40).collect();
    let mut config = PortConfig::new("net_null1");
    config.queues = 4;
    config.rss = true;
    config.rss_key = Some(key.clone());
    let port = Port::start(eal, config).unwrap();
    let id = port.port_id();
    assert_eq!(rss_conf(id), (true, ipv4, key.clone()));
    let rss = port.rss().unwrap().unwrap();
    let (device_key, device_algorithm, device_reta) = device_rss(id, 128);
    assert_eq!(device_algorithm, RssAlgorithm::Default);
    assert_eq!(
        rss,
        Rss {
            key: device_key,
            algorithm: device_algorithm,
            ipv4_tcp: true,
            ipv4: true,
            ipv4_fragments: true,
            reta: device_reta,
        }
    );
    assert_eq!(rss.key.len(), 40);
    assert_ne!(rss.key, key);
    // The null PMD has no rte_flow either: a tagged port rule is refused.
    let error = port
        .steer_tcp_port(Ipv4Addr::new(10, 0, 0, 1), 0xc001, 0xc003, 1)
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    let reta: Vec<u16> = (0..128).map(|i| (i * 7 % 4) as u16).collect();
    port.set_reta(&reta).unwrap();
    assert_eq!(device_rss(id, 128).2, reta);
    assert_eq!(port.rss().unwrap().unwrap().reta, reta);
    let error = port.set_reta(&reta[..64]).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("128"), "{error}");
    let mut wrong = reta.clone();
    wrong[5] = 4;
    let error = port.set_reta(&wrong).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(port.rss().unwrap().unwrap().reta, reta);
    drop(port);
    assert_eq!(port_named("net_null1"), None);

    // Without a key the PMD keeps its own; the device grants the same types.
    let mut config = PortConfig::new("net_null2");
    config.queues = 2;
    config.rss = true;
    let port = Port::start(eal, config).unwrap();
    assert_eq!(rss_conf(port.port_id()), (true, ipv4, Vec::new()));
    let rss = port.rss().unwrap().unwrap();
    assert_eq!(rss.key, device_rss(port.port_id(), 128).0);
    assert!(rss.ipv4_tcp && rss.ipv4 && rss.ipv4_fragments);
    drop(port);

    // One queue has nothing to spread: RSS stays off. A key is still
    // checked, so that a wrong one is not accepted only while it goes unused.
    let mut single = PortConfig::new("net_null3");
    single.rss = true;
    single.rss_key = Some(vec![0; 39]);
    let error = Port::start(eal, single.clone()).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("39 octets"), "{error}");
    assert!(error.to_string().contains("has 40"), "{error}");
    assert_eq!(port_named("net_null3"), None); // Released on failure.
    single.rss_key = Some(vec![0; 40]);
    let port = Port::start(eal, single).unwrap();
    assert_eq!(rss_conf(port.port_id()), (false, 0, Vec::new()));
    assert_eq!(port.rss().unwrap(), None);
    assert_eq!(
        port.set_reta(&[0; 128]).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    drop(port);

    let mut short = PortConfig::new("net_null4");
    short.queues = 2;
    short.rss = true;
    short.rss_key = Some(vec![0; 39]);
    let error = Port::start(eal, short).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("39 octets"), "{error}");
    assert!(error.to_string().contains("has 40"), "{error}");
    assert_eq!(port_named("net_null4"), None); // Released on failure.

    // Rejected before probing.
    let mut isolated = PortConfig::new("net_null5");
    isolated.queues = 2;
    isolated.rss = true;
    isolated.isolate = true;
    let error = Port::start(eal, isolated).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("isolated"), "{error}");
    let mut keyed = PortConfig::new("net_null5");
    keyed.rss_key = Some(key);
    assert_eq!(
        Port::start(eal, keyed).err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(port_named("net_null5"), None);
    assert_eq!(pools(), (0, 0));
}

// The ring PMD offers no TCP segmentation: a port that asks for it starts
// without, and its queues take no aggregates but send frames as before.
fn segmentation_not_offered(eal: &'static Eal) {
    let mut config = PortConfig::new("net_ring7");
    config.tcp_segmentation = true;
    let port = Port::start(eal, config).unwrap();
    assert!(!port.tcp_segmentation());
    let mut queue = port.take_queue(0).unwrap().attach().unwrap();
    assert_eq!(queue.tcp_segmentation_capabilities(), None);
    let (sent, mut out) = (frame(4, 3000), vec![0; 4096]);
    assert_eq!(queue.transmit(&sent).unwrap(), TxOutcome::Submitted);
    assert_eq!(queue.receive(&mut out).unwrap(), Some(sent.len()));
    assert_eq!(&out[..sent.len()], sent.as_slice());
    drop((port, queue));
    assert_eq!(port_named("net_ring7"), None);
    assert_eq!(pools(), (0, 0));
}

// A pcap file of `count` minimum Ethernet frames, each its index in every
// octet after the header.
fn pcap_file(path: &std::path::Path, count: u8) {
    let mut bytes = Vec::new();
    // Global header: magic (microseconds), version 2.4, zone, sigfigs,
    // snaplen 65535, LINKTYPE_ETHERNET.
    bytes.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    for word in [0u32, 0, 65535, 1] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for index in 0..count {
        let frame = frame(index, 60);
        for word in [0u32, 0, 60, 60] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&frame);
    }
    std::fs::write(path, bytes).unwrap();
}

// The pcap PMD allocates each received frame's mbuf from the queue's pool
// as it reads it, and counts rx_nombuf when the pool is empty, the frame
// then lost, as a NIC whose ring has no buffer posted loses one. The port's
// count reaches the queue's device counters (rte_eth_stats rx_nombuf), and
// frames read once mbufs are back arrive. (The ring PMD hands over mbufs
// its peer allocated and counts no rx_nombuf, mlx5 has no virtual device.)
fn receive_pool_exhausted(eal: &'static Eal) {
    let pcap =
        TempFile(std::env::temp_dir().join(format!("ntcp-nombuf-{}.pcap", std::process::id())));
    let path = &pcap.0;
    pcap_file(path, 6);
    let mut config = PortConfig::new(format!("net_pcap0,rx_pcap={}", path.display()));
    config.rx_desc = 64;
    config.tx_desc = 64;
    config.mbufs_per_queue = 511;
    let port = Port::start(eal, config).unwrap();
    assert_eq!(port.driver_name().unwrap(), "net_pcap");
    let mut queue = port.take_queue(0).unwrap().attach().unwrap();
    assert_eq!(queue.device_counters(), DeviceCounters::default());
    let mut out = vec![0; 2048];
    // SAFETY: EAL is initialized and the port's single pool exists.
    assert_eq!(unsafe { ntcp_host_test_pool_hold(0) }, 0);
    for _ in 0..2 {
        assert_eq!(queue.receive(&mut out).unwrap(), None);
    }
    // One frame read and lost per burst the pool could not serve.
    let starved = queue.device_counters();
    assert_eq!(starved.rx_nombuf, 2);
    assert_eq!((starved.rx_missed, starved.tx_nombuf), (0, 0));
    // SAFETY: as above.
    unsafe { ntcp_host_test_pool_release() };
    for index in 2..6 {
        assert_eq!(queue.receive(&mut out).unwrap(), Some(60));
        assert_eq!(&out[..60], frame(index, 60).as_slice());
    }
    assert_eq!(queue.receive(&mut out).unwrap(), None);
    assert_eq!(queue.device_counters().rx_nombuf, 2);
    drop((port, queue));
    drop(pcap);
    assert_eq!(pools(), (0, 0));
}

// A test's scratch file under TMPDIR, named by the process id. Removed on drop
// when the test passes; a failing test keeps it and names it. A test killed
// outright (SIGKILL, a nextest timeout) runs no drop and leaves it behind.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("kept {}", self.0.display());
        } else {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
}

// A hosted queue's frame budget is its pool less the rings and its lcore
// cache (one queue), and its frames are the pool's mbufs, charged the
// pool's element: held until they drop, the queue gone or not, after
// which the port's pool is full and freed.
fn held_frames(eal: &'static Eal) {
    let mut config = PortConfig::new("net_ring8");
    config.rx_desc = 64;
    config.tx_desc = 64;
    config.mbufs_per_queue = 4095;
    let port = Port::start(eal, config).unwrap();
    let mut queue = port.take_queue(0).unwrap().attach().unwrap();
    // 4095 - 64 - 2 x 64 - 1.5 x 256.
    assert_eq!(queue.rx_frame_budget(), Some(3519));
    let (mut size, mut object) = (0, 0);
    // SAFETY: EAL is initialized; outputs are writable.
    assert_eq!(
        unsafe { ntcp_host_test_pool_geometry(&mut size, &mut object) },
        0
    );
    assert_eq!((size, object), (4095, 2368));
    let mut scratch = vec![0; 4096];
    // Multi-burst (>8 packets) HostedQueue equivalence: views-on `receive_frame`
    // matches `receive_with_metadata` in bytes and metadata and returns all mbufs.
    let burst: Vec<Vec<u8>> = (0..12u8)
        .map(|i| frame(i + 1, 60 + usize::from(i) * 100))
        .collect();
    let mut by_view = Vec::new();
    for sent in &burst {
        assert_eq!(queue.transmit(sent).unwrap(), TxOutcome::Submitted);
    }
    let mut held_burst = Vec::new();
    for _ in 0..burst.len() {
        let received = queue.receive_whole(&mut scratch).unwrap().unwrap();
        assert!(!received.frame.is_heap());
        assert_eq!(received.frame.truesize(), 2368);
        by_view.push((received.frame.as_slice().to_vec(), received.metadata));
        held_burst.push(received.frame);
    }
    assert_eq!(queue.receive_whole(&mut scratch).unwrap().map(|_| ()), None);
    assert_eq!(queue.rx_frames_outstanding(), Some(burst.len()));
    drop(held_burst);
    assert_eq!(queue.rx_frames_outstanding(), Some(0));

    let mut by_copy = Vec::new();
    for sent in &burst {
        assert_eq!(queue.transmit(sent).unwrap(), TxOutcome::Submitted);
    }
    for _ in 0..burst.len() {
        let meta = queue.receive_with_metadata(&mut scratch).unwrap().unwrap();
        by_copy.push((scratch[..meta.len].to_vec(), meta));
    }
    assert_eq!(queue.receive_with_metadata(&mut scratch).unwrap(), None);
    assert_eq!(by_view, by_copy);

    let mut frames = Vec::new();
    for len in [60, 1514] {
        let sent = frame(len as u8, len);
        assert_eq!(queue.transmit(&sent).unwrap(), TxOutcome::Submitted);
        let received = queue.receive_whole(&mut scratch).unwrap().unwrap();
        assert_eq!(received.frame.as_slice(), sent.as_slice());
        assert_eq!(received.frame.truesize(), 2368);
        frames.push(received.frame);
    }
    assert_eq!(queue.rx_frames_outstanding(), Some(2));
    assert_eq!(pools(), (1, 0));
    drop(frames.pop());
    assert_eq!(queue.rx_frames_outstanding(), Some(1));
    drop(queue);
    assert_eq!(pools(), (1, 0));
    drop(frames);
    assert_eq!(pools(), (1, 1));
    drop(port);
    assert_eq!(pools(), (0, 0));
}

// End-to-end ntcp-native over two HostedQueues on a 2-queue net_ring port
// (each queue loops TX -> RX, crossed between client and server). Verifies
// small (<= copybreak) and bulk (> copybreak) transfers both ways through
// HostedQueue::transmit_packet, receive_frame, and tx_chunk_source with zero
// mbuf or pool leaks.
fn hosted_network_e2e(eal: &'static Eal) {
    use ntcp_io::{
        ReceivedPacket, RxFrame, TransmitError, TransmitRequest, TxChunkSource, TxPacket,
    };
    use ntcp_io_dpdk::HostedQueue;
    use ntcp_native::{
        EthernetNextHop, Link, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    use std::{cell::RefCell, rc::Rc};

    struct CrossQueue {
        tx: Rc<RefCell<HostedQueue>>,
        rx: Rc<RefCell<HostedQueue>>,
    }

    impl PacketIo for CrossQueue {
        fn layer(&self) -> PacketLayer {
            self.tx.borrow().layer()
        }
        fn local_ip_mtu(&self) -> std::io::Result<Option<u32>> {
            self.tx.borrow().local_ip_mtu()
        }
        fn max_packet_len(&self) -> Option<usize> {
            self.tx.borrow().max_packet_len()
        }
        fn receive(&mut self, out: &mut [u8]) -> std::io::Result<Option<usize>> {
            self.rx.borrow_mut().receive(out)
        }
        fn receive_with_metadata(
            &mut self,
            out: &mut [u8],
        ) -> std::io::Result<Option<ReceivedPacket>> {
            self.rx.borrow_mut().receive_with_metadata(out)
        }
        fn receive_frame(
            &mut self,
            scratch: &mut [u8],
            frame: &mut Option<RxFrame>,
        ) -> std::io::Result<Option<ReceivedPacket>> {
            self.rx.borrow_mut().receive_frame(scratch, frame)
        }
        fn rx_frame_budget(&self) -> Option<usize> {
            self.rx.borrow().rx_frame_budget()
        }
        fn rx_frames_outstanding(&self) -> Option<usize> {
            self.rx.borrow().rx_frames_outstanding()
        }
        fn transmit(&mut self, packet: &[u8]) -> std::io::Result<TxOutcome> {
            self.tx.borrow_mut().transmit(packet)
        }
        fn transmit_packet(
            &mut self,
            packet: &TxPacket<'_>,
            request: TransmitRequest,
        ) -> Result<TxOutcome, TransmitError> {
            self.tx.borrow_mut().transmit_packet(packet, request)
        }
        fn tx_chunk_source(&self) -> Box<dyn TxChunkSource> {
            self.tx.borrow().tx_chunk_source()
        }
    }

    let mut config = PortConfig::new("net_ring_e2e");
    config.queues = 2;
    config.rx_desc = 64;
    config.tx_desc = 64;
    config.mbufs_per_queue = 2047;
    let port = Port::start(eal, config).unwrap();
    let q0 = Rc::new(RefCell::new(port.take_queue(0).unwrap().attach().unwrap()));
    let q1 = Rc::new(RefCell::new(port.take_queue(1).unwrap().attach().unwrap()));

    let io_a = CrossQueue {
        tx: Rc::clone(&q0),
        rx: Rc::clone(&q1),
    };
    let io_b = CrossQueue {
        tx: Rc::clone(&q1),
        rx: Rc::clone(&q0),
    };

    let make_cfg = |addr: &str, side: u8| {
        let mut cfg = NetworkConfig::new(addr.parse().unwrap(), 1500);
        cfg.tcp.max_connections = 2;
        cfg.tcp.connection.send_capacity = 128 * 1024;
        cfg.tcp.connection.receive_capacity = 128 * 1024;
        cfg.tcp.connection.nagle = false;
        cfg.tcp.max_buffer_bytes = 4 * 1024 * 1024;
        cfg.link = Link::Ethernet {
            local_mac: [2, 0, 0, 0, 0, side],
            next_hop: EthernetNextHop::Fixed([2, 0, 0, 0, 0, 3 - side]),
        };
        cfg
    };

    let mut a = Network::new(make_cfg("10.77.0.1", 1), io_a, [5; 32], 0).unwrap();
    let mut b = Network::new(make_cfg("10.77.0.2", 2), io_b, [6; 32], 0).unwrap();
    let listener = b.listen(9200, 1).unwrap();
    let client = a.connect("10.77.0.2:9200".parse().unwrap()).unwrap();

    // Mix small (<= 512 B) and multi-MSS (> 512 B) payloads in both directions.
    let c_to_s: Vec<u8> = (0..(128 + 32 * 1024))
        .map(|i| ((i * 29 + 1) % 251) as u8)
        .collect();
    let s_to_c: Vec<u8> = (0..(96 + 16 * 1024))
        .map(|i| ((i * 37 + 3) % 251) as u8)
        .collect();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut server = None;
    let (mut sent_c, mut sent_s) = (0usize, 0usize);
    let (mut got_s, mut got_c) = (Vec::new(), Vec::new());
    let mut out = vec![0u8; 16384];

    for step in 1..20_000u64 {
        let now = step * 1000;
        if sent_c < c_to_s.len() {
            let chunk = if sent_c < 128 {
                (128 - sent_c).min(64)
            } else {
                (c_to_s.len() - sent_c).min(8192)
            };
            if let Ok(r) = a.try_write(
                client,
                &c_to_s[sent_c..sent_c + chunk],
                WriteOptions::default(),
            ) {
                sent_c += r.accepted;
            }
        }
        a.drive(now, budget).unwrap();
        b.drive(now, budget).unwrap();
        if server.is_none() {
            server = b.accept(listener).ok();
        }
        if let Some(srv) = server {
            if sent_s < s_to_c.len() {
                let chunk = if sent_s < 96 {
                    (96 - sent_s).min(48)
                } else {
                    (s_to_c.len() - sent_s).min(8192)
                };
                if let Ok(r) = b.try_write(
                    srv,
                    &s_to_c[sent_s..sent_s + chunk],
                    WriteOptions::default(),
                ) {
                    sent_s += r.accepted;
                }
            }
            while let Ok(ReadOutcome::Data { len, .. }) = b.try_read(srv, &mut out) {
                got_s.extend_from_slice(&out[..len]);
            }
        }
        while let Ok(ReadOutcome::Data { len, .. }) = a.try_read(client, &mut out) {
            got_c.extend_from_slice(&out[..len]);
        }
        if got_s.len() == c_to_s.len() && got_c.len() == s_to_c.len() {
            break;
        }
    }

    assert_eq!(got_s, c_to_s);
    assert_eq!(got_c, s_to_c);
    assert_eq!(a.counters().tcp_checksum_errors, 0);
    assert_eq!(b.counters().tcp_checksum_errors, 0);

    // Close and drain residual ACKs/FINs so no mbufs remain stranded on rings.
    let _ = a.close(client);
    if let Some(srv) = server {
        let _ = b.close(srv);
    }
    for step in 1..64u64 {
        let now = 25_000_000 + step * 1000;
        a.drive(now, budget).unwrap();
        b.drive(now, budget).unwrap();
    }
    drop((a, b));
    let mut drain_buf = [0u8; 2048];
    while q0.borrow_mut().receive(&mut drain_buf).unwrap().is_some() {}
    while q1.borrow_mut().receive(&mut drain_buf).unwrap().is_some() {}
    drop((q0, q1, port));
    assert_eq!(port_named("net_ring_e2e"), None);
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
