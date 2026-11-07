#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ntcp_io_tun::Tun;
    use ntcp_native::{
        ConnId, Event, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    use std::{
        io::Read,
        net::{IpAddr, SocketAddr},
        time::{Duration, Instant},
    };

    struct Request {
        id: ConnId,
        payload: Vec<u8>,
        admitted: usize,
        received: usize,
        write_closed: bool,
        finished: bool,
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: tun_roundtrip TUN LOCAL_IP PEER_IP PORT".into());
    }
    let local: IpAddr = args[2].parse()?;
    let peer = SocketAddr::new(args[3].parse()?, args[4].parse()?);
    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let mut config = NetworkConfig::new(local, 1500);
    config.tcp.max_connections = 4;
    // TCP admission waits for the quiet time (2*MSL after host boot and after
    // earlier emission from LOCAL_IP). Boot age comes from CLOCK_BOOTTIME;
    // NTCP_SOURCE_QUIET=SECONDS|never states when emission from LOCAL_IP
    // ceased (never: a newly created address). Unset waits the full 2*MSL.
    let boot_age = {
        let mut clock = ntcp_clock::TransportClock::new()?;
        let ticks = clock.sample()?.ticks;
        clock.boot_age(ticks)?
    };
    let continuity = match std::env::var("NTCP_SOURCE_QUIET").ok().as_deref() {
        None => ntcp::SourceContinuity::Unknown,
        Some("never") => ntcp::SourceContinuity::Never,
        Some(seconds) => ntcp::SourceContinuity::CeasedFor(
            seconds
                .parse()
                .map_err(|_| "NTCP_SOURCE_QUIET must be whole seconds or never")?,
        ),
    };
    config.lifecycle = ntcp::Lifecycle {
        boot_age: Some(boot_age),
        continuity,
    };
    let mut network = Network::new(config, Tun::open(&args[1])?, secret, 0)?;
    let mut requests = Vec::new();
    for seed in 0..4 {
        requests.push(Request {
            id: network.connect(peer)?,
            payload: (0..262144).map(|i| ((i + seed) % 251) as u8).collect(),
            admitted: 0,
            received: 0,
            write_closed: false,
            finished: false,
        });
    }
    let started = Instant::now();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut events = [Event::NetworkStopped; 64];
    let mut input = [0; 8192];
    while requests.iter().any(|r| !r.finished) {
        if started.elapsed() > Duration::from_secs(20) {
            return Err("roundtrip deadline expired".into());
        }
        let now = started.elapsed().as_micros() as u64;
        let report = network.drive(now, budget)?;
        let batch = network.drain_events(&mut events);
        let mut progressed = false;
        for request in requests.iter_mut().filter(|r| !r.finished) {
            if request.admitted < request.payload.len() {
                match network.try_write(
                    request.id,
                    &request.payload[request.admitted..],
                    WriteOptions::default(),
                ) {
                    Ok(receipt) => {
                        if receipt.range.start != request.admitted as u64 {
                            return Err("write range lost request correlation".into());
                        }
                        request.admitted += receipt.accepted;
                        progressed |= receipt.accepted != 0;
                    }
                    Err(e) if e.is_would_block() => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if request.admitted == request.payload.len() && !request.write_closed {
                match network.shutdown_write(request.id) {
                    Ok(()) => {
                        request.write_closed = true;
                        progressed = true;
                    }
                    Err(e) if e.is_would_block() => {}
                    Err(e) => return Err(e.into()),
                }
            }
            match network.try_read(request.id, &mut input) {
                Ok(ReadOutcome::Data { len, range, .. }) => {
                    let end = request.received + len;
                    if range.start != request.received as u64
                        || end > request.payload.len()
                        || input[..len] != request.payload[request.received..end]
                    {
                        return Err("echoed bytes or stream ranges differ".into());
                    }
                    request.received = end;
                    progressed = true;
                }
                Ok(ReadOutcome::Eof) => {
                    if !request.write_closed || request.received != request.payload.len() {
                        return Err("EOF before the request completed".into());
                    }
                    network.close(request.id)?;
                    request.finished = true;
                    progressed = true;
                }
                Ok(ReadOutcome::EmptyBuffer) => unreachable!(),
                Err(e) if e.is_would_block() => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !progressed && report.received == 0 && report.transmitted == 0 && !batch.more {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let verified: usize = requests.iter().map(|r| r.received).sum();
    println!("ROUNDTRIP {} {verified}", requests.len());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the TUN example requires Linux");
}
