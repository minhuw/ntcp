#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ntcp_io_tun::Tun;
    use ntcp_native::{
        ConnId, Event, Network, NetworkConfig, ReadOutcome, WorkBudget, WriteOptions,
    };
    use std::{
        collections::{HashMap, VecDeque},
        io::{Read, Write},
        net::IpAddr,
        time::{Duration, Instant},
    };

    struct Echo {
        queued: VecDeque<u8>,
        eof: bool,
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: tun_echo TUN LOCAL_IP PORT".into());
    }
    let local: IpAddr = args[2].parse()?;
    let port: u16 = args[3].parse()?;
    let mut secret = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let io = Tun::open(&args[1])?;
    let mut config = NetworkConfig::new(local, 1500);
    config.tcp.max_connections = 128;
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
    let send_capacity = config.tcp.connection.send_capacity;
    let mut network = Network::new(config, io, secret, 0)?;
    let listener = network.listen(port, 128)?;
    let started = Instant::now();
    let budget = WorkBudget::new(64, 64, 64, 64);
    let mut events = [Event::NetworkStopped; 64];
    let mut echoes: HashMap<ConnId, Echo> = HashMap::new();
    let mut input = [0; 8192];
    println!("READY {local}:{port}");
    std::io::stdout().flush()?;
    loop {
        let now = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let report = network.drive(now, budget)?;
        let batch = network.drain_events(&mut events);
        for event in &events[..batch.written] {
            match *event {
                Event::Acceptable(id) if id == listener => loop {
                    match network.accept(listener) {
                        Ok(id) => {
                            echoes.insert(
                                id,
                                Echo {
                                    queued: VecDeque::new(),
                                    eof: false,
                                },
                            );
                        }
                        Err(e) if e.is_would_block() => break,
                        Err(e) => return Err(e.into()),
                    }
                },
                Event::Closed { connection, .. } => {
                    echoes.remove(&connection);
                    network.close(connection)?;
                }
                Event::NetworkStopped => return Err("network stopped".into()),
                _ => {}
            }
        }
        let mut finished = Vec::new();
        for (&id, state) in &mut echoes {
            if !state.queued.is_empty() {
                let data = state.queued.as_slices().0;
                match network.try_write(id, data, WriteOptions::default()) {
                    Ok(receipt) => {
                        state.queued.drain(..receipt.accepted);
                    }
                    Err(e) if e.is_would_block() => {}
                    Err(_) => {
                        finished.push(id);
                        continue;
                    }
                }
            }
            // Stop reading at the application queue limit and let TCP's
            // receive window provide backpressure to a peer that cannot read.
            if !state.eof && state.queued.len() < send_capacity {
                let count = input.len().min(send_capacity - state.queued.len());
                match network.try_read(id, &mut input[..count]) {
                    Ok(ReadOutcome::Data { len, .. }) => state.queued.extend(&input[..len]),
                    Ok(ReadOutcome::Eof) => state.eof = true,
                    Ok(ReadOutcome::EmptyBuffer) => {}
                    Err(e) if e.is_would_block() => {}
                    Err(_) => {
                        finished.push(id);
                        continue;
                    }
                }
            }
            if state.eof && state.queued.is_empty() {
                finished.push(id);
            }
        }
        for id in finished {
            echoes.remove(&id);
            network.close(id)?;
        }
        // This portable demonstration polls a TUN. Performance-oriented
        // embeddings choose their own readiness source or busy-poll policy.
        if report.received == 0 && report.transmitted == 0 && !batch.more {
            let wait = report
                .next_deadline
                .map(|d| d.saturating_sub(now))
                .unwrap_or(1000)
                .min(1000);
            if wait != 0 {
                std::thread::sleep(Duration::from_micros(wait));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the TUN example requires Linux");
}
