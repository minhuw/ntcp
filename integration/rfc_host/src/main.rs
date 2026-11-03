// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
// Real Ethernet embedding only. The gate builds this binary in a separate
// target directory without packet-test or packet-test-controls.
use libc::*;
use ntcp_socket as api;
use std::{
    ffi::CString,
    io::{self, BufRead, Write},
    net::{IpAddr, SocketAddr},
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
                    sin6_flowinfo: 0,
                    sin6_addr: in6_addr {
                        s6_addr: a.ip().octets(),
                    },
                    sin6_scope_id: 0,
                };
            }
            28
        }
    };
    (storage, len)
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
    if args.len() != 9 {
        return Err(io::Error::other(
            "role local peer policy capacity lifetime_us managed disabled",
        ));
    }
    let server = args[1] == "server";
    let local: IpAddr = args[2].parse().unwrap();
    let peer: IpAddr = args[3].parse().unwrap();
    let mut config = api::SocketConfig::new("t5n", local);
    config.io.backend = api::Backend::AfPacket;
    config.io.prefix = Some(if local.is_ipv4() { 24 } else { 64 });
    config.io.next_hop_mac = Some([2, 0, 0, 0, 0, 1]);
    config.tcp.connection.receive_capacity = args[5].parse().unwrap();
    config.fast_open_cookie_lifetime =
        ntcp::FastOpenCookieLifetime::from_micros(args[6].parse().unwrap()).unwrap();
    config.fast_open_managed_keys = Some(args[7] == "1");
    if args[4] == "linux" {
        // Raw key bytes come from the OS CSPRNG and remain raw key bytes.
        let mut key = [0; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
        config.fast_open_cookie_policy =
            api::FastOpenCookiePolicy::LinuxSipHash24(api::LinuxSipHash24Key::new(key));
        if args[7] == "0" {
            let life = config.fast_open_cookie_lifetime.as_micros();
            config.fast_open_key_lease = Some(ntcp::FastOpenKeyLease {
                not_before: 0,
                issue_until: life,
                accept_until: life,
                units_per_second: 1_000_000,
            });
        }
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
        // Those cases also state the deployment knowledge io.source_quiet
        // = never: the harness created this address in a fresh namespace,
        // so nothing emitted from it before (DF-clear output of a disabled
        // IPv4 route needs Identifications at once).
        config.io.source_quiet = api::SourceQuiet::Never;
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
            next_hop_mac: [2, 0, 0, 0, 0, 1],
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
            let mut key = [0u8; 16];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
            check(unsafe {
                api::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_KEY, key.as_ptr().cast(), 16)
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
use std::io::Read;
