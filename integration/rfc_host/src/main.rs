// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Real Ethernet embedding only. The gate builds this binary in a separate
// target directory without packet-test or packet-test-controls.
use libc::*;
use ntcp_socket as api;
use std::{
    ffi::CString,
    io::{self, BufRead, Write},
    net::{IpAddr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};

fn check(value: i32) -> io::Result<i32> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
fn option(fd: i32, name: i32, value: i32) -> io::Result<()> {
    check(unsafe { api::setsockopt(fd, IPPROTO_TCP, name, (&value as *const i32).cast(), 4) })?;
    Ok(())
}
fn address(addr: SocketAddr) -> (sockaddr_storage, u32) {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let p = &mut storage as *mut _ as *mut sockaddr_in;
            unsafe {
                *p = sockaddr_in {
                    sin_family: AF_INET as _,
                    sin_port: a.port().to_be(),
                    sin_addr: in_addr {
                        s_addr: u32::from_ne_bytes(a.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
            }
            16
        }
        SocketAddr::V6(a) => {
            let p = &mut storage as *mut _ as *mut sockaddr_in6;
            unsafe {
                *p = sockaddr_in6 {
                    sin6_family: AF_INET6 as _,
                    sin6_port: a.port().to_be(),
                    sin6_flowinfo: a.flowinfo(),
                    sin6_addr: in6_addr {
                        s6_addr: a.ip().octets(),
                    },
                    // A link-local address names its link (RFC 4007 section 11).
                    sin6_scope_id: a.scope_id(),
                };
            }
            28
        }
    };
    (storage, len)
}
// The inverse of `address`, scope included.
fn decode(storage: &sockaddr_storage, len: u32) -> io::Result<SocketAddr> {
    match i32::from(storage.ss_family) {
        AF_INET if len >= 16 => {
            let a = unsafe { &*(storage as *const _ as *const sockaddr_in) };
            Ok(SocketAddr::new(
                IpAddr::from(a.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(a.sin_port),
            ))
        }
        AF_INET6 if len >= 28 => {
            let a = unsafe { &*(storage as *const _ as *const sockaddr_in6) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                a.sin6_addr.s6_addr.into(),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::other("unexpected socket address")),
    }
}
fn pattern(n: usize, salt: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + salt) % 251) as u8).collect()
}
fn hash(bytes: &[u8]) -> String {
    format!(
        "{:016x}",
        bytes
            .iter()
            .fold(0xcbf29ce484222325u64, |h, b| (h ^ u64::from(*b))
                .wrapping_mul(0x100000001b3))
    )
}
fn wait(fd: i32, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "socket deadline"));
        }
        let mut p = pollfd {
            fd,
            events,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut p, 1, 200) };
        if r > 0 {
            return Ok(());
        }
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }
}
fn write_all(fd: i32, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let n = unsafe {
            api::send(
                fd,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                MSG_NOSIGNAL | MSG_DONTWAIT,
            )
        };
        if n > 0 {
            offset += n as usize;
        } else if n < 0 && io::Error::last_os_error().raw_os_error() == Some(EAGAIN) {
            wait(fd, POLLOUT, deadline)?;
        } else {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
fn read_exact(fd: i32, n: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; n];
    let mut offset = 0;
    while offset < n {
        let count = unsafe {
            api::recv(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                n - offset,
                MSG_DONTWAIT,
            )
        };
        if count > 0 {
            offset += count as usize;
        } else if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short stream"));
        } else if io::Error::last_os_error().raw_os_error() == Some(EAGAIN) {
            wait(fd, POLLIN, deadline)?;
        } else {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(bytes)
}
fn eof(fd: i32, deadline: Instant) -> io::Result<()> {
    wait(fd, POLLIN, deadline)?;
    let mut byte = 0u8;
    let n = unsafe { api::recv(fd, (&mut byte as *mut u8).cast(), 1, MSG_DONTWAIT) };
    if n != 0 {
        return Err(io::Error::other(format!("expected EOF, received {n}")));
    }
    Ok(())
}
fn info(fd: i32) -> io::Result<(u8, u8)> {
    let mut bytes = [0u8; 280];
    let mut len = bytes.len() as u32;
    check(unsafe {
        api::getsockopt(
            fd,
            IPPROTO_TCP,
            TCP_INFO,
            bytes.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    Ok((bytes[0], bytes[5]))
}
fn so_error(fd: i32) -> io::Result<i32> {
    let mut error = -1i32;
    let mut len = 4;
    check(unsafe {
        api::getsockopt(
            fd,
            SOL_SOCKET,
            SO_ERROR,
            (&mut error as *mut i32).cast(),
            &mut len,
        )
    })?;
    Ok(error)
}
fn emit(line: String) {
    println!("{line}");
    io::stdout().flush().unwrap();
}
fn verify(bytes: &[u8], salt: usize) -> io::Result<()> {
    if bytes != pattern(bytes.len(), salt) {
        return Err(io::Error::other("stream content mismatch"));
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        emit(format!(
            "{{\"event\":\"error\",\"errno\":{:?},\"message\":{:?}}}",
            e.raw_os_error().unwrap_or(0),
            e.to_string()
        ));
        std::process::exit(1);
    }
}
fn run() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("scoped") {
        return scoped(&args);
    }
    if args.get(1).map(String::as_str) == Some("phased") {
        return phased(&args);
    }
    if args.len() != 9 {
        return Err(io::Error::other(
            "role local peer policy capacity lifetime_us managed disabled",
        ));
    }
    let server = args[1] == "server";
    let local: IpAddr = args[2].parse().unwrap();
    let peer: IpAddr = args[3].parse().unwrap();
    let mut config = api::SocketConfig::new("t5n", local);
    // The harness created this address in a fresh namespace for this run,
    // so nothing was emitted from it before: this states the fact for the
    // IP Identification quiet period.
    config.io.source_quiet = api::SourceQuiet::Never;
    config.io.backend = api::Backend::AfPacket;
    config.io.prefix = Some(if local.is_ipv4() { 24 } else { 64 });
    config.io.next_hop_mac = Some([2, 0, 0, 0, 0, 1]);
    config.tcp.connection.receive_capacity = args[5].parse().unwrap();
    config.fast_open_cookie_lifetime =
        ntcp::FastOpenCookieLifetime::from_micros(args[6].parse().unwrap()).unwrap();
    config.fast_open_managed_keys = Some(args[7] == "1");
    // A key's lease is transport time: CLOCK_BOOTTIME microseconds of this
    // boot, named by its boot id.
    let mut clock = ntcp_clock::TransportClock::new().map_err(io::Error::other)?;
    let now = clock.sample().map_err(io::Error::other)?.ticks;
    let life = config.fast_open_cookie_lifetime.as_micros();
    let lease = ntcp::FastOpenKeyLease {
        not_before: now,
        issue_until: now + life,
        accept_until: now + life,
        units_per_second: 1_000_000,
    };
    if args[4] == "linux" {
        // Raw key bytes come from the OS CSPRNG and remain raw key bytes.
        let mut key = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        config.fast_open_cookie_policy =
            api::FastOpenCookiePolicy::LinuxSipHash24(api::LinuxSipHash24Key::new(key));
        if args[7] == "0" {
            config.fast_open_key_lease = Some(lease);
            config.fast_open_key_boot_id = Some(clock.characterization().boot_id);
        }
    }
    // The `rotate` command selects this configured key: rotation is operator
    // configuration, with the key's own lease.
    let mut rotation = [0u8; 16];
    if server {
        std::fs::File::open("/dev/urandom")?.read_exact(&mut rotation)?;
        config.fast_open_keys.push(api::ConfiguredFastOpenKey {
            key: api::LinuxSipHash24Key::new(rotation),
            lease,
        });
        config.fast_open_key_boot_id = Some(clock.characterization().boot_id);
    }
    let disabled = args[8] == "1";
    config.socket.fast_open_client_enabled = !disabled;
    // The T12 administration cases serve the owner's opt-in path control
    // socket from this runtime (control.socket); absent, none is served.
    if let Some(socket) = std::env::var_os("T12_CONTROL_SOCKET") {
        config.control = Some(ntcp_path_control::ControlConfig {
            socket: socket.into(),
            allow_uids: Vec::new(),
        });
    }
    // The T17 Segment Routing case states one owner `ipv6.srh.<prefix>`
    // line, read by the production configuration parser and installed by
    // the runtime over t5n beside its default route.
    if let Some(line) = std::env::var_os("T17_SEGMENT_ROUTE") {
        let line = line.into_string().map_err(|_| io::Error::other("T17_SEGMENT_ROUTE"))?;
        let text = format!("io.interface = t5n\nio.address = {local}\n{line}\n");
        config.segment_routes = api::SocketConfig::parse(&text)?.segment_routes;
    }
    api::configure_with_packet_io(config, move || {
        let name = CString::new("t5n").unwrap();
        let index = unsafe { if_nametoindex(name.as_ptr()) };
        Ok(api::EthernetPacketIo {
            io: Box::new(ntcp_io_af_packet::AfPacket::bind(
                index,
                if local.is_ipv4() { 0x0800 } else { 0x86dd },
            )?),
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: Some([2, 0, 0, 0, 0, 1]),
        })
    })?;
    let family = if local.is_ipv4() { AF_INET } else { AF_INET6 };
    let listener = if server {
        let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
        if !disabled {
            option(fd, TCP_FASTOPEN, 16)?;
        }
        let (addr, len) = address(SocketAddr::new(local, 18080));
        check(unsafe { api::bind(fd, (&addr as *const sockaddr_storage).cast(), len) })?;
        check(unsafe { api::listen(fd, 16) })?;
        Some(fd)
    } else {
        None
    };
    emit(format!(
        "{{\"event\":\"ready\",\"backend\":\"AfPacket\",\"packet_test\":false,\"role\":{:?}}}",
        args[1]
    ));
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields[0] == "quit" {
            break;
        }
        if fields[0] == "rotate" {
            let fd = listener.ok_or_else(|| io::Error::other("rotation needs listener"))?;
            check(unsafe {
                api::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_KEY, rotation.as_ptr().cast(), 16)
            })?;
            emit("{\"event\":\"rotated\",\"mechanism\":\"TCP_FASTOPEN_KEY\",\"new_policy\":\"linux-raw-cookie\",\"secret_logged\":false}".into());
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        if let Some(listener) = listener {
            let fd = loop {
                wait(listener, POLLIN, deadline)?;
                let value = unsafe {
                    api::accept4(
                        listener,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        SOCK_NONBLOCK,
                    )
                };
                if value >= 0 {
                    break value;
                }
                if io::Error::last_os_error().raw_os_error() != Some(EAGAIN) {
                    return Err(io::Error::last_os_error());
                }
            };
            let (state, options) = info(fd)?;
            let mut early = vec![0u8; 8192];
            let count =
                unsafe { api::recv(fd, early.as_mut_ptr().cast(), early.len(), MSG_DONTWAIT) };
            let early_count = if count >= 0 {
                count as usize
            } else if io::Error::last_os_error().raw_os_error() == Some(EAGAIN) {
                0
            } else {
                return Err(io::Error::last_os_error());
            };
            early.truncate(early_count);
            let early_hash = hash(&early);
            if args[5] == "128" {
                // Constrain actual SYN admission, then let the application
                // provision its normal stream buffer after consuming that
                // prefix. This is a real SO_RCVBUF transition, not ACK editing.
                let capacity = 32768i32; // public socket API doubles SO_RCVBUF
                check(unsafe {
                    api::setsockopt(
                        fd,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        (&capacity as *const i32).cast(),
                        4,
                    )
                })?;
            }
            let mut receive_capacity = 0i32;
            let mut option_len = 4;
            check(unsafe {
                api::getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_RCVBUF,
                    (&mut receive_capacity as *mut i32).cast(),
                    &mut option_len,
                )
            })?;
            early.extend(read_exact(fd, 8192 - early_count, deadline)?);
            let first = early;
            verify(&first, 7)?;
            write_all(fd, &pattern(6144, 11), deadline)?;
            let second = read_exact(fd, 3072, deadline)?;
            verify(&second, 19)?;
            eof(fd, deadline)?;
            write_all(fd, &pattern(1024, 23), deadline)?;
            check(unsafe { api::shutdown(fd, SHUT_WR) })?;
            emit(format!(
                "{{\"event\":\"stream\",\"rx\":11264,\"tx\":7168,\"first_hash\":{:?},\"second_hash\":{:?},\"accept_state\":{state},\"initial_read_count\":{early_count},\"initial_read_hash\":{early_hash:?},\"receive_capacity_after_read\":{receive_capacity},\"tcp_options\":{options},\"eof\":true}}",
                hash(&first),
                hash(&second)
            ));
            check(unsafe { api::close(fd) })?;
        } else {
            let refusal = fields[0].starts_with("refuse-");
            let mode = fields[0].strip_prefix("refuse-").unwrap_or(fields[0]);
            let nonblock = fields.get(1) == Some(&"nonblock");
            let fd = check(unsafe {
                api::socket(
                    family,
                    SOCK_STREAM | if nonblock { SOCK_NONBLOCK } else { 0 },
                    0,
                )
            })?;
            if let Some(cookie) = fields.get(2) {
                let bytes: Vec<u8> = (0..cookie.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&cookie[i..i + 2], 16).unwrap())
                    .collect();
                api::set_fast_open_server_cookie(
                    fd,
                    Some((
                        SocketAddr::new(peer, 18080),
                        api::FastOpenCookie::new(&bytes).unwrap(),
                    )),
                )?;
            }
            let (addr, len) = address(SocketAddr::new(peer, 18080));
            let first = pattern(8192, 7);
            let mut sent = 0;
            let mut stage = "connect";
            let mut option_errno = 0;
            let mut result;
            if mode == "msg" {
                stage = "MSG_FASTOPEN";
                result = unsafe {
                    api::sendto(
                        fd,
                        first.as_ptr().cast(),
                        first.len(),
                        MSG_FASTOPEN | MSG_NOSIGNAL,
                        (&addr as *const sockaddr_storage).cast(),
                        len,
                    )
                };
                if result >= 0 {
                    sent = result as usize;
                }
            } else {
                if mode == "deferred" {
                    if let Err(e) = option(fd, TCP_FASTOPEN_CONNECT, 1) {
                        if e.raw_os_error() != Some(EOPNOTSUPP) {
                            return Err(e);
                        }
                        option_errno = EOPNOTSUPP;
                        stage = "TCP_FASTOPEN_CONNECT-disabled-then-connect";
                    } else {
                        stage = "TCP_FASTOPEN_CONNECT";
                    }
                }
                result = unsafe { api::connect(fd, (&addr as *const sockaddr_storage).cast(), len) }
                    as isize;
            }
            if refusal {
                let initial_errno = if result < 0 {
                    io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                };
                let mut p = pollfd {
                    fd,
                    events: POLLOUT | POLLIN,
                    revents: 0,
                };
                check(unsafe {
                    libc::poll(
                        &mut p,
                        1,
                        if initial_errno == ECONNREFUSED {
                            0
                        } else {
                            25000
                        },
                    )
                })?;
                let completion = so_error(fd)?;
                let consumed = so_error(fd)?;
                let (state, options) = info(fd)?;
                if initial_errno != ECONNREFUSED && completion != ECONNREFUSED {
                    return Err(io::Error::other(format!(
                        "refusal not observed: initial={initial_errno}, SO_ERROR={completion}"
                    )));
                }
                if consumed != 0 || (initial_errno != ECONNREFUSED && p.revents == 0) {
                    return Err(io::Error::other("refusal consumption/readiness"));
                }
                emit(format!(
                    "{{\"event\":\"refused\",\"initial_result\":{result},\"initial_errno\":{initial_errno},\"stage\":{stage:?},\"so_error\":{completion},\"so_error_consumed\":{consumed},\"revents\":{},\"tcp_state\":{state},\"tcp_options\":{options}}}",
                    p.revents
                ));
                check(unsafe { api::close(fd) })?;
                continue;
            }
            let initial_result = result;
            let initial_errno = if result < 0 {
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            if initial_errno == EOPNOTSUPP && mode == "msg" {
                stage = "MSG_FASTOPEN-disabled-then-connect";
                result = unsafe { api::connect(fd, (&addr as *const sockaddr_storage).cast(), len) }
                    as isize;
            }
            let error = if result < 0 {
                io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            if result < 0 && error != EINPROGRESS && error != EAGAIN {
                return Err(io::Error::from_raw_os_error(error));
            }
            // A deferred connect may not emit until this first write.
            write_all(fd, &first[sent..], deadline)?;
            let response = read_exact(fd, 6144, deadline)?;
            verify(&response, 11)?;
            write_all(fd, &pattern(3072, 19), deadline)?;
            check(unsafe { api::shutdown(fd, SHUT_WR) })?;
            let last = read_exact(fd, 1024, deadline)?;
            verify(&last, 23)?;
            eof(fd, deadline)?;
            let (state, options) = info(fd)?;
            emit(format!(
                "{{\"event\":\"stream\",\"tx\":11264,\"rx\":7168,\"first_hash\":{:?},\"second_hash\":{:?},\"initial_result\":{initial_result},\"final_start_result\":{result},\"initial_errno\":{initial_errno},\"option_errno\":{option_errno},\"stage\":{stage:?},\"tcp_state\":{state},\"tcp_options\":{options},\"eof\":true}}",
                hash(&response),
                hash(&last)
            ));
            check(unsafe { api::close(fd) })?;
        }
    }
    Ok(())
}

// Bind `fd` to `addr`, retrying while its address is tentative: the runtime
// refuses a tentative address (EADDRNOTAVAIL) until its Duplicate Address
// Detection completes. Returns the number of attempts.
fn bind_tentative(fd: i32, addr: SocketAddr, deadline: Instant) -> io::Result<u32> {
    let (storage, len) = address(addr);
    let mut attempts = 0;
    loop {
        attempts += 1;
        if unsafe { api::bind(fd, (&storage as *const sockaddr_storage).cast(), len) } == 0 {
            return Ok(attempts);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(EADDRNOTAVAIL) || Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn name(fd: i32, peer: bool) -> io::Result<SocketAddr> {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<sockaddr_storage>() as u32;
    let p = (&mut storage as *mut sockaddr_storage).cast();
    check(unsafe {
        if peer {
            api::getpeername(fd, p, &mut len)
        } else {
            api::getsockname(fd, p, &mut len)
        }
    })?;
    decode(&storage, len)
}
// One connection's scoped names, send MSS and current path MTU (IP_MTU or
// IPV6_MTU by the connection's family).
fn connection(fd: i32, index: u32) -> io::Result<String> {
    let local = name(fd, false)?;
    let (level, option) = if local.is_ipv4() {
        (IPPROTO_IP, IP_MTU)
    } else {
        (IPPROTO_IPV6, IPV6_MTU)
    };
    let mut bytes = [0u8; 280];
    let mut len = bytes.len() as u32;
    check(unsafe {
        api::getsockopt(
            fd,
            IPPROTO_TCP,
            TCP_INFO,
            bytes.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    let mss = u32::from_ne_bytes(bytes[16..20].try_into().unwrap());
    let mut mtu = 0i32;
    let mut len = 4;
    check(unsafe {
        api::getsockopt(
            fd,
            level,
            option,
            (&mut mtu as *mut i32).cast(),
            &mut len,
        )
    })?;
    Ok(format!(
        "\"index\":{index},\"local\":\"{local}\",\"peer\":\"{}\",\"tcp_state\":{},\"snd_mss\":{mss},\"path_mtu\":{mtu}",
        name(fd, true)?,
        bytes[0]
    ))
}
fn accept_one(listener: i32, deadline: Instant) -> io::Result<i32> {
    loop {
        wait(listener, POLLIN, deadline)?;
        let fd = unsafe {
            api::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                SOCK_NONBLOCK,
            )
        };
        if fd >= 0 {
            return Ok(fd);
        }
        if io::Error::last_os_error().raw_os_error() != Some(EAGAIN) {
            return Err(io::Error::last_os_error());
        }
    }
}

// The T18 two-link case (`scoped CONFIG`): one runtime configured from the
// production configuration text CONFIG, whose `io.*` port and `port.<name>`
// ports each resolve their next hops, so one Host and Endpoint own every
// link. Every port has the same link-local address; each socket names its
// link by the interface index as sin6_scope_id. On stdin:
//   listen PORT        on every link bind [LOCAL%link]:PORT, retrying while
//                      the address is tentative, and listen
//   serve N M SALT...  accept one connection on every link's listener, then
//                      on each in link order read N request bytes (pattern
//                      of that link's SALT), answer M bytes (SALT + 100) and
//                      close after EOF
//   pair LPORT PEER RPORT N M SALT...
//                      on every link connect from [LOCAL%link]:LPORT to
//                      [PEER%link]:RPORT (one identical address and port
//                      pair per link), all established before any data; then
//                      on each in link order send N bytes (SALT), read M
//                      (SALT + 100), shut down and read EOF
//   quit
fn scoped(args: &[String]) -> io::Result<()> {
    if args.len() != 3 {
        return Err(io::Error::other("scoped CONFIG"));
    }
    let config = api::SocketConfig::parse(&args[2])?;
    let local = config.io.address;
    let mut links = Vec::new();
    for name in std::iter::once(&config.io.interface).chain(config.ports.iter().map(|p| &p.interface)) {
        let c = CString::new(name.as_str()).map_err(|_| io::Error::other("interface name"))?;
        let index = unsafe { if_nametoindex(c.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        links.push((name.clone(), index));
    }
    api::configure(config)?;
    let at = |ip: IpAddr, port: u16, index: u32| match ip {
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, index)),
        ip => SocketAddr::new(ip, port),
    };
    let family = if local.is_ipv4() { AF_INET } else { AF_INET6 };
    emit(format!(
        "{{\"event\":\"ready\",\"backend\":\"AfPacket\",\"packet_test\":false,\"local\":\"{local}\",\"links\":[{}]}}",
        links
            .iter()
            .map(|(name, index)| format!("{{\"name\":{name:?},\"index\":{index}}}"))
            .collect::<Vec<_>>()
            .join(",")
    ));
    let mut listeners = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let number = |i: usize| -> io::Result<usize> {
            fields
                .get(i)
                .and_then(|f| f.parse().ok())
                .ok_or_else(|| io::Error::other(format!("invalid command {line:?}")))
        };
        let salts = |from: usize| (from..from + links.len()).map(number).collect::<io::Result<Vec<_>>>();
        let deadline = Instant::now() + Duration::from_secs(25);
        match fields.first().copied() {
            None => continue,
            Some("quit") => break,
            Some("listen") => {
                let port = number(1)? as u16;
                let started = Instant::now();
                let mut sockets = Vec::new();
                for &(_, index) in &links {
                    let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
                    let attempts = bind_tentative(fd, at(local, port, index), deadline)?;
                    check(unsafe { api::listen(fd, 4) })?;
                    sockets.push(format!(
                        "{{\"index\":{index},\"local\":\"{}\",\"bind_attempts\":{attempts}}}",
                        name(fd, false)?
                    ));
                    listeners.push(fd);
                }
                emit(format!(
                    "{{\"event\":\"listening\",\"sockets\":[{}],\"waited_ms\":{}}}",
                    sockets.join(","),
                    started.elapsed().as_millis()
                ));
            }
            Some("serve") => {
                let (n, m, salts) = (number(1)?, number(2)?, salts(3)?);
                if listeners.len() != links.len() {
                    return Err(io::Error::other("serve needs listen"));
                }
                let mut children = Vec::new();
                for &listener in &listeners {
                    children.push(accept_one(listener, deadline)?);
                }
                // Every link's child exists before any is served.
                let mut results = Vec::new();
                for ((&fd, &(_, index)), salt) in children.iter().zip(&links).zip(salts) {
                    let accepted = connection(fd, index)?;
                    let request = read_exact(fd, n, deadline)?;
                    verify(&request, salt)?;
                    write_all(fd, &pattern(m, salt + 100), deadline)?;
                    eof(fd, deadline)?;
                    let done = connection(fd, index)?;
                    check(unsafe { api::shutdown(fd, SHUT_WR) })?;
                    check(unsafe { api::close(fd) })?;
                    results.push(format!(
                        "{{\"accepted\":{{{accepted}}},\"done\":{{{done}}},\"rx\":{n},\"tx\":{m},\"request_hash\":{:?},\"salt\":{salt}}}",
                        hash(&request)
                    ));
                }
                emit(format!("{{\"event\":\"served\",\"connections\":[{}]}}", results.join(",")));
            }
            Some("pair") => {
                let lport = number(1)? as u16;
                let peer: IpAddr = fields
                    .get(2)
                    .and_then(|f| f.parse().ok())
                    .ok_or_else(|| io::Error::other("invalid peer"))?;
                let (rport, n, m, salts) = (number(3)? as u16, number(4)?, number(5)?, salts(6)?);
                let mut sockets = Vec::new();
                for &(_, index) in &links {
                    let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
                    bind_tentative(fd, at(local, lport, index), deadline)?;
                    let (addr, len) = address(at(peer, rport, index));
                    if unsafe { api::connect(fd, (&addr as *const sockaddr_storage).cast(), len) } < 0
                        && io::Error::last_os_error().raw_os_error() != Some(EINPROGRESS)
                    {
                        return Err(io::Error::last_os_error());
                    }
                    sockets.push(fd);
                }
                let mut established = Vec::new();
                for (&fd, &(_, index)) in sockets.iter().zip(&links) {
                    wait(fd, POLLOUT, deadline)?;
                    match so_error(fd)? {
                        0 => established.push(connection(fd, index)?),
                        error => return Err(io::Error::from_raw_os_error(error)),
                    }
                }
                let mut results = Vec::new();
                for (((&fd, &(_, index)), salt), established) in
                    sockets.iter().zip(&links).zip(salts).zip(established)
                {
                    write_all(fd, &pattern(n, salt), deadline)?;
                    let response = read_exact(fd, m, deadline)?;
                    verify(&response, salt + 100)?;
                    check(unsafe { api::shutdown(fd, SHUT_WR) })?;
                    eof(fd, deadline)?;
                    let done = connection(fd, index)?;
                    check(unsafe { api::close(fd) })?;
                    results.push(format!(
                        "{{\"established\":{{{established}}},\"done\":{{{done}}},\"tx\":{n},\"rx\":{m},\"response_hash\":{:?},\"salt\":{salt}}}",
                        hash(&response)
                    ));
                }
                emit(format!("{{\"event\":\"paired\",\"connections\":[{}]}}", results.join(",")));
            }
            Some(other) => return Err(io::Error::other(format!("unknown command {other}"))),
        }
    }
    Ok(())
}

// The T19 proxy/gateway cases (`phased CONFIG`): one runtime configured from
// the production configuration text CONFIG (a resolving `io.*` port), whose
// named connections the harness drives phase by phase, so every stream is
// established before the path changes. On stdin (ID names a connection):
//   listen PORT          bind [LOCAL]:PORT (retrying while tentative), listen
//   accept ID            accept one connection on that listener
//   connect ID PEER PORT actively open to [PEER]:PORT and wait until established
//   start ID PEER PORT   nonblocking connect only: report what it returned
//   pending ID           report readiness and SO_ERROR without waiting
//   finish ID            wait for writability, then report SO_ERROR
//   send ID N SALT       write N bytes (pattern SALT)
//   recv ID N SALT       read and verify N bytes (pattern SALT)
//   shutdown ID          shut down the sending direction
//   eof ID               read EOF
//   query ID             report names, state, send MSS and IP_MTU/IPV6_MTU
//   close ID
//   quit
fn phased(args: &[String]) -> io::Result<()> {
    if args.len() != 3 {
        return Err(io::Error::other("phased CONFIG"));
    }
    let config = api::SocketConfig::parse(&args[2])?;
    let local = config.io.address;
    let c = CString::new(config.io.interface.as_str()).map_err(|_| io::Error::other("interface name"))?;
    let index = unsafe { if_nametoindex(c.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    // A fixed next hop is the T5 topology: a userspace-owned port whose
    // address the kernel does not hold, explicitly assigned as in `run`.
    match config.io.next_hop_mac {
        Some(next_hop_mac) => api::configure_with_packet_io(config, move || {
            Ok(api::EthernetPacketIo {
                io: Box::new(ntcp_io_af_packet::AfPacket::bind(
                    index,
                    if local.is_ipv4() { 0x0800 } else { 0x86dd },
                )?),
                local_mac: [2, 0, 0, 0, 0, 2],
                next_hop_mac: Some(next_hop_mac),
            })
        })?,
        None => api::configure(config)?,
    }
    let family = if local.is_ipv4() { AF_INET } else { AF_INET6 };
    emit(format!(
        "{{\"event\":\"ready\",\"backend\":\"AfPacket\",\"packet_test\":false,\"local\":\"{local}\",\"index\":{index}}}"
    ));
    let mut listener = None;
    let mut connections: Vec<(String, i32)> = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        let invalid = || io::Error::other(format!("invalid command {line:?}"));
        let number = |i: usize| -> io::Result<usize> {
            fields.get(i).and_then(|f| f.parse().ok()).ok_or_else(invalid)
        };
        let id = fields.get(1).map(|s| s.to_string()).unwrap_or_default();
        let fd = || {
            connections
                .iter()
                .find(|(name, _)| *name == id)
                .map(|&(_, fd)| fd)
                .ok_or_else(|| io::Error::other(format!("unknown connection {id:?}")))
        };
        let deadline = Instant::now() + Duration::from_secs(25);
        match fields.first().copied() {
            None => continue,
            Some("quit") => break,
            Some("listen") => {
                let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
                let attempts = bind_tentative(fd, SocketAddr::new(local, number(1)? as u16), deadline)?;
                check(unsafe { api::listen(fd, 4) })?;
                listener = Some(fd);
                emit(format!(
                    "{{\"event\":\"listening\",\"local\":\"{}\",\"bind_attempts\":{attempts}}}",
                    name(fd, false)?
                ));
            }
            Some("accept") => {
                let fd = accept_one(listener.ok_or_else(|| io::Error::other("accept needs listen"))?, deadline)?;
                connections.push((id.clone(), fd));
                emit(format!("{{\"event\":\"accepted\",\"id\":{id:?},{}}}", connection(fd, index)?));
            }
            Some("connect") => {
                let peer: IpAddr = fields.get(2).and_then(|f| f.parse().ok()).ok_or_else(invalid)?;
                let (addr, len) = address(SocketAddr::new(peer, number(3)? as u16));
                // The runtime refuses a source address that is still
                // tentative (EADDRNOTAVAIL) until its Duplicate Address
                // Detection completes: retry with a fresh socket.
                let mut attempts = 0;
                let fd = loop {
                    attempts += 1;
                    let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
                    if unsafe { api::connect(fd, (&addr as *const sockaddr_storage).cast(), len) } == 0 {
                        break fd;
                    }
                    let error = io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(EINPROGRESS) => break fd,
                        Some(EADDRNOTAVAIL) if Instant::now() < deadline => {
                            check(unsafe { api::close(fd) })?;
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        _ => return Err(error),
                    }
                };
                wait(fd, POLLOUT, deadline)?;
                match so_error(fd)? {
                    0 => {}
                    error => return Err(io::Error::from_raw_os_error(error)),
                }
                connections.push((id.clone(), fd));
                emit(format!(
                    "{{\"event\":\"connected\",\"id\":{id:?},\"attempts\":{attempts},{}}}",
                    connection(fd, index)?
                ));
            }
            Some("start") => {
                let peer: IpAddr = fields.get(2).and_then(|f| f.parse().ok()).ok_or_else(invalid)?;
                let (addr, len) = address(SocketAddr::new(peer, number(3)? as u16));
                let fd = check(unsafe { api::socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0) })?;
                let result = unsafe { api::connect(fd, (&addr as *const sockaddr_storage).cast(), len) };
                let error = if result < 0 {
                    io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                };
                connections.push((id.clone(), fd));
                emit(format!(
                    "{{\"event\":\"started\",\"id\":{id:?},\"result\":{result},\"errno\":{error}}}"
                ));
            }
            Some("pending") => {
                let fd = fd()?;
                let mut p = pollfd {
                    fd,
                    events: POLLIN | POLLOUT,
                    revents: 0,
                };
                check(unsafe { libc::poll(&mut p, 1, 0) })?;
                emit(format!(
                    "{{\"event\":\"pending\",\"id\":{id:?},\"revents\":{},\"so_error\":{}}}",
                    p.revents,
                    so_error(fd)?
                ));
            }
            Some("finish") => {
                let fd = fd()?;
                wait(fd, POLLOUT, deadline)?;
                emit(format!(
                    "{{\"event\":\"finished\",\"id\":{id:?},\"so_error\":{}}}",
                    so_error(fd)?
                ));
            }
            Some("send") => {
                let (n, salt) = (number(2)?, number(3)?);
                write_all(fd()?, &pattern(n, salt), deadline)?;
                emit(format!("{{\"event\":\"sent\",\"id\":{id:?},\"tx\":{n},\"salt\":{salt}}}"));
            }
            Some("recv") => {
                let (n, salt) = (number(2)?, number(3)?);
                let bytes = read_exact(fd()?, n, deadline)?;
                verify(&bytes, salt)?;
                emit(format!(
                    "{{\"event\":\"received\",\"id\":{id:?},\"rx\":{n},\"salt\":{salt},\"hash\":{:?}}}",
                    hash(&bytes)
                ));
            }
            Some("shutdown") => {
                check(unsafe { api::shutdown(fd()?, SHUT_WR) })?;
                emit(format!("{{\"event\":\"shutdown\",\"id\":{id:?}}}"));
            }
            Some("eof") => {
                eof(fd()?, deadline)?;
                emit(format!("{{\"event\":\"eof\",\"id\":{id:?}}}"));
            }
            Some("query") => {
                emit(format!("{{\"event\":\"query\",\"id\":{id:?},{}}}", connection(fd()?, index)?));
            }
            Some("close") => {
                check(unsafe { api::close(fd()?) })?;
                connections.retain(|(name, _)| *name != id);
                emit(format!("{{\"event\":\"closed\",\"id\":{id:?}}}"));
            }
            Some(other) => return Err(io::Error::other(format!("unknown command {other}"))),
        }
    }
    Ok(())
}
use std::io::Read;
