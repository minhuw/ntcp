// A native group on an AF_PACKET Ethernet port whose IPv4 next hops are
// resolved by ARP: an echo server for a duration, or a client that sends
// one stream to a server and checks its echo. Both print the ARP counters.
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ntcp_io_af_packet::AfPacket;
    use ntcp_native::{
        ConnId, Error, EthernetNextHop, Event, Link, Network, NetworkConfig, ReadOutcome,
        WorkBudget, WriteOptions,
    };
    use std::{
        collections::{HashMap, VecDeque},
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{Duration, Instant},
    };

    let args: Vec<_> = std::env::args().collect();
    let usage =
        "usage: arp_echo IFACE MAC LOCAL_IP/PREFIX (server PORT SECONDS | client PEER PORT)";
    if args.len() != 7 {
        return Err(usage.into());
    }
    let index = std::ffi::CString::new(args[1].as_str())?;
    // SAFETY: a terminated interface name.
    let ifindex = unsafe { libc::if_nametoindex(index.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut mac = [0; 6];
    for (octet, text) in mac.iter_mut().zip(args[2].split(':')) {
        *octet = u8::from_str_radix(text, 16)?;
    }
    let (local, prefix) = args[3].split_once('/').ok_or(usage)?;
    let local: Ipv4Addr = local.parse()?;
    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    // ARP beside IPv4, never the port's own transmissions.
    let io = AfPacket::bind_protocols(ifindex, &[0x0800, 0x0806])?;
    let mut config = NetworkConfig::new(IpAddr::V4(local), 1500);
    config.tcp.max_connections = 16;
    config.link = Link::Ethernet {
        local_mac: mac,
        next_hop: EthernetNextHop::Arp {
            prefix_len: prefix.parse()?,
            gateway: None,
        },
    };
    let send_capacity = config.tcp.connection.send_capacity;
    let mut network = Network::new(config, io, secret, 0)?;
    let started = Instant::now();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut events = [Event::NetworkStopped; 64];
    let mut input = [0; 8192];
    let now = || started.elapsed().as_micros().min(u64::MAX as u128) as u64;
    // The drive and wait of one pass.
    let pass = |network: &mut Network<AfPacket>| -> Result<(), Error> {
        let at = now();
        let report = network.drive(at, budget)?;
        if !report.more_work && report.received == 0 && report.transmitted == 0 {
            let wait = report
                .next_deadline
                .map(|d| d.saturating_sub(at))
                .unwrap_or(1000)
                .min(1000);
            std::thread::sleep(Duration::from_micros(wait));
        }
        Ok(())
    };
    let print_counters = |network: &Network<AfPacket>| {
        let c = network.counters();
        println!(
            "COUNTERS arp_sent={} arp_received={} resolution_failures={}",
            c.arp_sent, c.arp_received, c.resolution_failures
        );
    };
    if args[4] == "server" {
        let port: u16 = args[5].parse()?;
        let seconds: u64 = args[6].parse()?;
        let listener = network.listen(port, 16)?;
        let mut echoes: HashMap<ConnId, (VecDeque<u8>, bool)> = HashMap::new();
        println!("READY {local}:{port}");
        std::io::stdout().flush()?;
        while started.elapsed() < Duration::from_secs(seconds) {
            pass(&mut network)?;
            let batch = network.drain_events(&mut events);
            for event in &events[..batch.written] {
                match *event {
                    Event::Acceptable(id) if id == listener => {
                        while let Ok(id) = network.accept(listener) {
                            echoes.insert(id, (VecDeque::new(), false));
                        }
                    }
                    Event::NetworkStopped => return Err("network stopped".into()),
                    _ => {}
                }
            }
            let mut finished = Vec::new();
            for (&id, (queued, eof)) in &mut echoes {
                if !queued.is_empty() {
                    match network.try_write(id, queued.as_slices().0, WriteOptions::default()) {
                        Ok(receipt) => {
                            queued.drain(..receipt.accepted);
                        }
                        Err(e) if e.is_would_block() => {}
                        Err(_) => finished.push(id),
                    }
                }
                if !*eof && queued.len() < send_capacity {
                    let count = input.len().min(send_capacity - queued.len());
                    match network.try_read(id, &mut input[..count]) {
                        Ok(ReadOutcome::Data { len, .. }) => queued.extend(&input[..len]),
                        Ok(ReadOutcome::Eof) => *eof = true,
                        Ok(ReadOutcome::EmptyBuffer) => {}
                        Err(e) if e.is_would_block() => {}
                        Err(_) => finished.push(id),
                    }
                }
                if *eof && queued.is_empty() {
                    finished.push(id);
                }
            }
            for id in finished {
                echoes.remove(&id);
                network.close(id)?;
            }
        }
        print_counters(&network);
        return Ok(());
    }
    if args[4] != "client" {
        return Err(usage.into());
    }
    let peer = SocketAddr::new(args[5].parse()?, args[6].parse()?);
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let connection = network.connect(peer)?;
    let (mut sent, mut received, mut shut) = (0, Vec::new(), false);
    while started.elapsed() < Duration::from_secs(20) {
        pass(&mut network)?;
        network.drain_events(&mut events);
        if sent < payload.len() {
            match network.try_write(connection, &payload[sent..], WriteOptions::default()) {
                Ok(receipt) => sent += receipt.accepted,
                Err(e) if e.is_would_block() => {}
                Err(e) => return Err(e.into()),
            }
        } else if !shut && network.shutdown_write(connection).is_ok() {
            shut = true;
        }
        match network.try_read(connection, &mut input) {
            Ok(ReadOutcome::Data { len, .. }) => received.extend_from_slice(&input[..len]),
            Ok(ReadOutcome::Eof) => break,
            Ok(ReadOutcome::EmptyBuffer) => {}
            Err(e) if e.is_would_block() => {}
            Err(e) => return Err(e.into()),
        }
    }
    if received != payload {
        return Err(format!(
            "echo differs: {} of {} bytes",
            received.len(),
            payload.len()
        )
        .into());
    }
    network.close(connection)?;
    for _ in 0..100 {
        pass(&mut network)?;
    }
    println!("ROUNDTRIP {}", received.len());
    print_counters(&network);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the AF_PACKET example requires Linux");
}
