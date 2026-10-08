// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use ntcp::IpMetadata;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    slice, thread,
    time::{Duration, Instant},
};
const BYTES: usize = 65535;
const TCP_INFO_SIZE: usize = 280;
struct Adapter;
impl Adapter {
    fn start(_: (Ipv4Addr, ntcp_socket::packet_test::Profile)) -> Result<Self, i32> {
        let mut table = [0usize; 64];
        unsafe {
            packetdrill_interface_init(
                c"baseline,local=192.0.2.1".as_ptr(),
                table.as_mut_ptr().cast(),
            );
        }
        if !ACTIVE.load(Ordering::Acquire) {
            return Err(EIO);
        }
        Ok(Self)
    }
}
impl Drop for Adapter {
    fn drop(&mut self) {
        unsafe {
            ntcp_free(USERDATA);
        }
    }
}
use ntcp_socket::packet_test::Profile;
struct Response {
    value: i64,
    bytes: Vec<u8>,
}
fn errno() -> i32 {
    unsafe { *__errno_location() }
}
fn call(
    _: &Adapter,
    op: i32,
    fd: i32,
    a: i32,
    bytes: Vec<u8>,
    capacity: usize,
) -> Result<Response, i32> {
    let mut output = vec![0; capacity];
    let value = unsafe {
        match op {
            1 => ntcp_socket::packet_test::packet_socket(AF_INET, SOCK_STREAM | a, IPPROTO_TCP)
                as i64,
            2 => ntcp_socket::bind(fd, bytes.as_ptr().cast(), bytes.len() as socklen_t) as i64,
            3 => ntcp_socket::listen(fd, a) as i64,
            4 => {
                let mut n = capacity as socklen_t;
                ntcp_socket::accept(fd, output.as_mut_ptr().cast(), &mut n) as i64
            }
            5 => ntcp_socket::connect(fd, bytes.as_ptr().cast(), bytes.len() as socklen_t) as i64,
            8 => ntcp_socket::close(fd) as i64,
            9 => ntcp_socket::shutdown(fd, a) as i64,
            14 => ntcp_net_send(USERDATA, bytes.as_ptr().cast(), bytes.len()) as i64,
            15 => {
                let mut n = capacity;
                let mut stamp = 0;
                let r = ntcp_net_receive(USERDATA, output.as_mut_ptr().cast(), &mut n, &mut stamp);
                if r < 0 {
                    -1
                } else {
                    output.truncate(n);
                    n as i64
                }
            }
            18 => {
                let (level, name) = match a {
                    1 => (IPPROTO_TCP, TCP_INFO),
                    2 => (IPPROTO_TCP, TCP_CC_INFO),
                    _ => (SOL_SOCKET, SO_MEMINFO),
                };
                let mut n = capacity as socklen_t;
                let r =
                    ntcp_socket::getsockopt(fd, level, name, output.as_mut_ptr().cast(), &mut n);
                if r < 0 {
                    -1
                } else {
                    output.truncate(n as usize);
                    n as i64
                }
            }
            _ => panic!("unported ABI op {op}"),
        }
    };
    if value < 0 {
        Err(errno())
    } else {
        Ok(Response {
            value,
            bytes: output,
        })
    }
}
fn parse_frame(bytes: &[u8]) -> Result<(IpMetadata, &[u8]), i32> {
    let p = ntcp_ip::parse(bytes, false).map_err(|_| EINVAL)?;
    Ok((p.ip, p.payload))
}
fn frame(tx: ntcp::Transmit, tcp: &[u8]) -> Result<Vec<u8>, i32> {
    let mut packet = vec![0; 20 + tcp.len()];
    packet[20..].copy_from_slice(tcp);
    ntcp_ip::encode(&mut packet, tx, 0).map_err(|_| EINVAL)?;
    Ok(packet)
}
fn encode_addr(addr: SocketAddr) -> Vec<u8> {
    let IpAddr::V4(ip) = addr.ip() else { panic!() };
    let raw = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        slice::from_raw_parts(
            (&raw as *const sockaddr_in).cast(),
            std::mem::size_of::<sockaddr_in>(),
        )
        .to_vec()
    }
}
fn packet_header(bytes: &[u8]) -> ntcp::wire::Header {
    let (ip, tcp) = parse_frame(bytes).unwrap();
    ntcp::wire::parse(ip, tcp).unwrap().header
}

fn local() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}

fn syn(sequence: u32, destination_port: u16) -> Vec<u8> {
    syn_with_options(sequence, destination_port, &[])
}

fn syn_with_options(sequence: u32, destination_port: u16, options: &[u8]) -> Vec<u8> {
    let ip = IpMetadata {
        source: Ipv4Addr::new(192, 0, 2, 2).into(),
        destination: local().into(),
    };
    let header = ntcp::wire::Header {
        source_port: 50000,
        destination_port,
        sequence,
        acknowledgment: 0,
        flags: ntcp::wire::SYN,
        window: 65535,
        urgent_pointer: 0,
    };
    let mut tcp = [0; 64];
    let n = ntcp::wire::encode(ip, header, options, &[], &mut tcp).unwrap();
    frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len: n,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..n],
    )
    .unwrap()
}

#[test]
fn abi_table_null_counts_vectors_variadics_and_host_clock() {
    unsafe extern "C" {
        fn ntcp_abi_check(userdata: *mut c_void);
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let userdata = USERDATA;
    unsafe {
        signal(SIGPIPE, SIG_IGN);
    }
    unsafe {
        ntcp_abi_check(userdata);
    }

    // Drive a real handshake and queued payload through the owner before ABI faults.
    let listener = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    call(
        &adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, listener, 1, vec![], 0).unwrap();
    call(&adapter, 14, 0, 0, syn(100, 8080), 0).unwrap();
    let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&syn(100, 8080))
        .map(|(ip, _)| (ip, packet_header(&packet)))
        .unwrap();
    let mut bytes = [0; 128];
    let header = ntcp::wire::Header {
        source_port: 50000,
        destination_port: 8080,
        sequence: 101,
        acknowledgment: tcp.sequence.wrapping_add(1),
        flags: ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    let len = ntcp::wire::encode(ip, header, &[], b"abcdef", &mut bytes).unwrap();
    let packet = frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &bytes[..len],
    )
    .unwrap();
    call(&adapter, 14, 0, 0, packet, 0).unwrap();
    let accepted = call(&adapter, 4, listener, 0, vec![], 16).unwrap().value as i32;
    unsafe extern "C" {
        fn ntcp_abi_fault_check(userdata: *mut c_void, fd: i32);
    }
    unsafe {
        ntcp_abi_fault_check(userdata, accepted);
    }
    unsafe extern "C" {
        fn ntcp_abi_send_error_check(userdata: *mut c_void, fd: i32, first_error: i32);
    }
    unsafe extern "C" {
        fn ntcp_abi_zerocopy_check(userdata: *mut c_void, fd: i32);
    }
    unsafe { ntcp_abi_zerocopy_check(userdata, accepted) };
    call(&adapter, 9, accepted, SHUT_WR, vec![], 0).unwrap();
    unsafe { ntcp_abi_send_error_check(userdata, accepted, EPIPE) };
    let mut reset = header;
    reset.sequence += 6;
    reset.flags = ntcp::wire::RST;
    let len = ntcp::wire::encode(ip, reset, &[], &[], &mut bytes).unwrap();
    let packet = frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &bytes[..len],
    )
    .unwrap();
    call(&adapter, 14, 0, 0, packet, 0).unwrap();
    for how in [SHUT_RD, SHUT_WR, SHUT_RDWR] {
        assert_eq!(
            call(&adapter, 9, accepted, how, vec![], 0).err(),
            Some(ENOTCONN)
        );
    }
    unsafe { ntcp_abi_send_error_check(userdata, accepted, ECONNRESET) };
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    assert_eq!(
        call(
            &adapter,
            5,
            fd,
            0,
            encode_addr(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 8080)),
            0
        )
        .err(),
        Some(EINPROGRESS)
    );
    let mut info = [0xa5u8; TCP_INFO_SIZE + 8];
    let mut n = info.len() as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            0
        );
    }
    assert_eq!(n as usize, TCP_INFO_SIZE);
    assert_eq!((info[0], info[1]), (2, 0));
    assert_eq!(&info[TCP_INFO_SIZE..], &[0xa5; 8]);
    let expected = call(&adapter, 18, fd, 1, vec![], TCP_INFO_SIZE)
        .unwrap()
        .bytes;
    assert_eq!(&info[..TCP_INFO_SIZE], expected);
    for (option, length) in [(TCP_CC_INFO, 0), (TCP_INFO, TCP_INFO_SIZE)] {
        for capacity in [0, 1, 7, TCP_INFO_SIZE + 8] {
            info.fill(0xa5);
            n = capacity as socklen_t;
            unsafe {
                assert_eq!(
                    getsockopt(fd, IPPROTO_TCP, option, info.as_mut_ptr().cast(), &mut n),
                    0
                );
            }
            assert_eq!(n as usize, capacity.min(length));
            assert!(info[n as usize..].iter().all(|b| *b == 0xa5));
        }
    }
    n = 36;
    unsafe {
        assert_eq!(
            getsockopt(fd, SOL_SOCKET, SO_MEMINFO, info.as_mut_ptr().cast(), &mut n),
            0
        );
    }
    assert_eq!(n, 36);
    assert_eq!(u32::from_ne_bytes(info[4..8].try_into().unwrap()), 65535);
    unsafe {
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, ptr::null_mut(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EFAULT);
        assert_eq!(
            getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_INFO,
                info.as_mut_ptr().cast(),
                ptr::null_mut()
            ),
            -1
        );
        assert_eq!(*__errno_location(), EFAULT);
    }
    n = TCP_INFO_SIZE as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(-1, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EBADF);
        // Keep fd reserved until dup2 atomically replaces our own descriptor.
        // Closing first lets parallel tests reuse it before the assertions or dup2.
        let host = libc::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert!(host >= 0);
        if host != fd {
            assert_eq!(dup2(host, fd), fd);
            libc::close(host);
        }
        assert_eq!(
            getsockopt(fd, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_ne!(*__errno_location(), ENOTCONN);
        let mut domain = 0;
        n = 4;
        assert_eq!(
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_DOMAIN,
                (&mut domain as *mut i32).cast(),
                &mut n
            ),
            0
        );
        assert_eq!(domain, AF_UNIX);
        assert_eq!(
            call(&adapter, 18, fd, 1, vec![], TCP_INFO_SIZE).err(),
            Some(EOPNOTSUPP)
        );
        libc::close(fd);
    }
    drop(adapter);
    n = TCP_INFO_SIZE as socklen_t;
    unsafe {
        assert_eq!(
            getsockopt(-1, IPPROTO_TCP, TCP_INFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
        assert_eq!(*__errno_location(), EBADF);
        assert_eq!(ntcp_plugin_active(userdata), 0);
        assert_eq!(*__errno_location(), EIO);
    }
}

#[test]
fn host_bridge_preloaded_process_and_lifecycle() {
    use std::process::Command;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("libntcp_packetdrill.so");
    // cargo test alone need not refresh its companion cdylib.
    let mut build = Command::new("cargo");
    build
        .args(["build", "-p", "ntcp-packetdrill", "--manifest-path"])
        .arg(root.join("Cargo.toml"));
    if library
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        == "release"
    {
        build.arg("--release");
    }
    build.arg("--target-dir").arg(
        library
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap(),
    );
    assert!(build.status().unwrap().success());
    assert!(library.exists(), "missing cdylib: {}", library.display());
    let dir = std::env::temp_dir().join(format!("ntcp-bridge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("check.c");
    std::fs::write(&source, r#"
#define _GNU_SOURCE
#include "packetdrill.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/syscall.h>
#include <pthread.h>
static void *blocked(void *arg) {
    struct packetdrill_interface *p = arg;
    unsigned char packet[65535]; size_t n = sizeof(packet); long long t;
    assert(p->netdev_receive(p->userdata, packet, &n, &t) == -1);
    assert(errno == ECANCELED || errno == EIO);
    return NULL;
}
int main(void) {
    void (*init)(const char *, struct packetdrill_interface *) = dlsym(RTLD_DEFAULT, "packetdrill_interface_init");
    assert(init);
    struct packetdrill_interface p, other;
    init("local=192.0.2.1,upstream-sack", &p); assert(p.userdata);
    init("local=192.0.2.1,baseline", &other); assert(!other.userdata);
    int fd = p.socket(p.userdata, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(8080), .sin_addr={htonl(0xc0000202)}};
    assert(p.connect(p.userdata, fd, (void *)&addr, sizeof(addr)) == -1 && errno == EINPROGRESS);
    unsigned char info[288], abi[280]; memset(info, 0xa5, sizeof(info)); socklen_t n = sizeof(info);
    assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &n) == 0 && n == 280 && info[0] == 2);
    n = sizeof(abi); assert(p.getsockopt(p.userdata, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == 0);
    assert(memcmp(info, abi, sizeof(abi)) == 0 && info[280] == 0xa5);
    n = sizeof(abi); assert(syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == -1);
    n = sizeof(abi); assert(getsockopt(fd, IPPROTO_TCP, TCP_CC_INFO, abi, &n) == 0 && n == 0);
    n = sizeof(abi); assert(getsockopt(fd, SOL_SOCKET, SO_MEMINFO, abi, &n) == 0 && n == 36);
    int domain; n = sizeof(domain); assert(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &n) == 0 && domain == AF_INET);
    int host = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(host >= 0);
    unsigned char kernel[104], forwarded[104]; socklen_t k = sizeof(kernel); n = sizeof(forwarded);
    assert(syscall(SYS_getsockopt, host, IPPROTO_TCP, TCP_INFO, kernel, &k) == 0);
    assert(getsockopt(host, IPPROTO_TCP, TCP_INFO, forwarded, &n) == 0 && k == n && !memcmp(kernel, forwarded, n)); close(host);
    // Drain SYN output; next netdev callback blocks until teardown cancels it.
    unsigned char packet[65535]; size_t size = sizeof(packet); long long t;
    assert(p.netdev_receive(p.userdata, packet, &size, &t) == 0);
    pthread_t thread; assert(!pthread_create(&thread, NULL, blocked, &p)); usleep(10000);
    p.free(p.userdata); assert(!pthread_join(thread, NULL));
    p.free(p.userdata); // Stale userdata never dereferenced.
    n = sizeof(info); assert(getsockopt(fd, IPPROTO_TCP, TCP_INFO, info, &n) == -1 && errno == EBADF);
    init("local=192.0.2.1,baseline", &p); assert(!p.userdata);
    return 0;
}
"#).unwrap();
    let executable = dir.join("check");
    assert!(
        Command::new("cc")
            .args(["-Wall", "-Wextra", "-Werror", "-pthread"])
            .arg("-I")
            .arg(root)
            .arg(&source)
            .args(["-ldl", "-o"])
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(&executable)
        .env("LD_PRELOAD", library)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("preload helper deadlocked");
        }
        thread::sleep(Duration::from_millis(10));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn isolated(name: &str) -> bool {
    if std::env::var_os("NTCP_PACKET_ABI_CHILD").is_some() {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1"])
        .env("NTCP_PACKET_ABI_CHILD", "1")
        .status()
        .unwrap();
    assert!(status.success());
    true
}
fn set_buffer(fd: i32, name: i32, value: i32) {
    unsafe {
        assert_eq!(
            ntcp_socket::setsockopt(fd, SOL_SOCKET, name, (&value as *const i32).cast(), 4),
            0
        );
    }
}
fn get_buffer(fd: i32, name: i32) -> i32 {
    let mut value = 0;
    let mut n = 4;
    unsafe {
        assert_eq!(
            ntcp_socket::getsockopt(
                fd,
                SOL_SOCKET,
                name,
                (&mut value as *mut i32).cast(),
                &mut n
            ),
            0
        );
    }
    assert_eq!(n, 4);
    value
}
fn inject(ip: IpMetadata, header: ntcp::wire::Header, payload: &[u8]) {
    let mut tcp = vec![0; 20 + payload.len()];
    let len = ntcp::wire::encode(ip, header, &[], payload, &mut tcp).unwrap();
    let bytes = frame(
        ntcp::Transmit {
            connection: None,
            ip,
            len,
            hop_limit: 64,
            dscp: 0,
            ecn: 0,
            ipv4_options: Default::default(),
        },
        &tcp[..len],
    )
    .unwrap();
    unsafe {
        assert_eq!(
            ntcp_net_send(USERDATA, bytes.as_ptr().cast(), bytes.len()),
            0
        );
    }
}
fn connect_listener(
    adapter: &Adapter,
    port: u16,
    buffers: bool,
) -> (i32, i32, IpMetadata, ntcp::wire::Header) {
    let listener = call(adapter, 1, 0, SOCK_NONBLOCK, vec![], 0).unwrap().value as i32;
    if buffers {
        set_buffer(listener, SO_SNDBUF, 4096);
        set_buffer(listener, SO_RCVBUF, 131072);
    }
    call(
        adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), port)),
        0,
    )
    .unwrap();
    call(adapter, 3, listener, 1, vec![], 0).unwrap();
    call(adapter, 14, 0, 0, syn(100, port), 0).unwrap();
    let packet = loop {
        let p = call(adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        if packet_header(&p).source_port == port && packet_header(&p).flags & ntcp::wire::SYN != 0 {
            break p;
        }
    };
    let outgoing = ntcp_ip::parse(&packet, false).unwrap();
    let sent = ntcp::wire::parse(outgoing.ip, outgoing.payload)
        .unwrap()
        .header;
    let ip = IpMetadata {
        source: outgoing.ip.destination,
        destination: outgoing.ip.source,
    };
    if buffers {
        set_buffer(listener, SO_SNDBUF, 0);
        set_buffer(listener, SO_RCVBUF, 0);
    }
    let header = ntcp::wire::Header {
        source_port: 50000,
        destination_port: port,
        sequence: 101,
        acknowledgment: sent.sequence.wrapping_add(1),
        flags: ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    inject(ip, header, &[]);
    let fd = call(adapter, 4, listener, 0, vec![], 16).unwrap().value as i32;
    (listener, fd, ip, header)
}

#[test]
fn sndbuf_rcvbuf_end_to_end_shared_abi() {
    if isolated("tests::sndbuf_rcvbuf_end_to_end_shared_abi") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let (listener, fd, ip, header) = connect_listener(&adapter, 8081, true);
    let epfd = unsafe { libc::epoll_create1(EPOLL_CLOEXEC) };
    assert!(epfd >= 0);
    let mut event = epoll_event {
        events: EPOLLIN as u32,
        u64: 0x1234,
    };
    unsafe {
        assert_eq!(libc::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &mut event), 0);
        assert_eq!(libc::epoll_wait(epfd, &mut event, 1, 0), 0);
    }

    assert_eq!(get_buffer(fd, SO_SNDBUF), 8192);
    assert_eq!(get_buffer(fd, SO_RCVBUF), 262144);
    set_buffer(fd, SO_RCVBUF, 0);
    assert_eq!(get_buffer(fd, SO_RCVBUF), 2304);
    let mut pollfd = pollfd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    let before = Instant::now();
    unsafe {
        assert_eq!(libc::poll(&mut pollfd, 1, 5), 0);
    }
    assert!(before.elapsed() >= Duration::from_millis(4));
    assert!(before.elapsed() < Duration::from_secs(1));
    let data = vec![42u8; 8192];
    inject(ip, header, &data);
    unsafe {
        assert_eq!(libc::epoll_wait(epfd, &mut event, 1, 0), 1);
    }
    let token = event.u64;
    assert_eq!(token, 0x1234);

    unsafe {
        assert_eq!(libc::poll(&mut pollfd, 1, 0), 1);
    }
    assert_eq!(pollfd.revents, POLLIN);
    unsafe {
        assert_eq!(
            ntcp_socket::recv(fd, ptr::dangling_mut::<c_void>(), data.len(), MSG_DONTWAIT),
            -1
        );
    }
    assert_eq!(errno(), EFAULT);
    let mut info = [0u8; 36];
    let mut size = 36;
    unsafe {
        assert_eq!(
            ntcp_socket::getsockopt(
                fd,
                SOL_SOCKET,
                SO_MEMINFO,
                info.as_mut_ptr().cast(),
                &mut size
            ),
            0
        );
    }
    assert_eq!(u32::from_ne_bytes(info[..4].try_into().unwrap()), 8192);
    let mut received = vec![0; 8192];
    unsafe {
        assert_eq!(
            ntcp_socket::recv(
                fd,
                received.as_mut_ptr().cast(),
                received.len(),
                MSG_DONTWAIT
            ),
            8192
        );
    }
    assert_eq!(received, data);
    unsafe {
        assert_eq!(
            ntcp_socket::send(
                fd,
                data.as_ptr().cast(),
                data.len(),
                MSG_DONTWAIT | MSG_NOSIGNAL
            ),
            8192
        );
    }
    pollfd.events = POLLOUT;
    unsafe {
        assert_eq!(libc::poll(&mut pollfd, 1, 0), 0);
        assert_eq!(
            ntcp_socket::send(fd, c"x".as_ptr().cast(), 1, MSG_DONTWAIT | MSG_NOSIGNAL),
            -1
        );
    }
    assert_eq!(errno(), EAGAIN);
    set_buffer(fd, SO_SNDBUF, 8192);
    assert_eq!(get_buffer(fd, SO_SNDBUF), 16384);
    unsafe {
        assert_eq!(libc::poll(&mut pollfd, 1, 0), 1);
        assert_eq!(
            ntcp_socket::send(fd, c"x".as_ptr().cast(), 1, MSG_DONTWAIT | MSG_NOSIGNAL),
            1
        );
    }
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    call(&adapter, 8, listener, 0, vec![], 0).unwrap();
    unsafe {
        assert_eq!(libc::epoll_wait(epfd, &mut event, 1, 0), 0);
        assert_eq!(ntcp_socket::close(epfd), 0);
    }
}

#[test]
fn shutdown_completes_pending_reads_poll_and_blocked_writes() {
    if isolated("tests::shutdown_completes_pending_reads_poll_and_blocked_writes") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    for (i, how) in [SHUT_RD, SHUT_WR, SHUT_RDWR].into_iter().enumerate() {
        let (listener, fd, _, _) = connect_listener(&adapter, 8080 + i as u16, false);
        let data = vec![0u8; 65535];
        unsafe {
            assert_eq!(
                ntcp_socket::send(
                    fd,
                    data.as_ptr().cast(),
                    data.len(),
                    MSG_DONTWAIT | MSG_NOSIGNAL
                ),
                65535
            );
            assert_eq!(
                ntcp_socket::send(fd, c"x".as_ptr().cast(), 1, MSG_DONTWAIT | MSG_NOSIGNAL),
                1
            );
        }
        let (rt, received) = std::sync::mpsc::sync_channel(1);
        let (st, sent) = std::sync::mpsc::sync_channel(1);
        let (pt, polled) = std::sync::mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut bytes = [0u8; 10];
            let n = unsafe { ntcp_socket::recv(fd, bytes.as_mut_ptr().cast(), 10, 0) };
            rt.send((n, errno())).unwrap();
        });
        let sender = thread::spawn(move || {
            let n = unsafe { ntcp_socket::send(fd, c"x".as_ptr().cast(), 1, MSG_NOSIGNAL) };
            st.send((n, errno())).unwrap();
        });
        let poller = thread::spawn(move || {
            let mut p = pollfd {
                fd,
                events: POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut p, 1, -1) };
            pt.send((n, p.revents)).unwrap();
        });
        thread::sleep(Duration::from_millis(5));
        assert!(received.try_recv().is_err());
        assert!(sent.try_recv().is_err());
        assert!(polled.try_recv().is_err());
        unsafe {
            assert_eq!(ntcp_socket::shutdown(fd, how), 0);
        }
        if how != SHUT_WR {
            assert_eq!(received.recv_timeout(Duration::from_secs(1)).unwrap().0, 0);
            let (n, revents) = polled.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(n, 1);
            assert_ne!(revents & POLLIN, 0);
        }
        if how != SHUT_RD {
            assert_eq!(
                sent.recv_timeout(Duration::from_secs(1)).unwrap(),
                (-1, EPIPE)
            );
        }
        if how == SHUT_WR {
            assert!(received.recv_timeout(Duration::from_millis(20)).is_err());
            assert!(polled.try_recv().is_err());
        }
        if how == SHUT_RD {
            assert!(sent.recv_timeout(Duration::from_millis(20)).is_err());
        }
        unsafe {
            assert_eq!(ntcp_socket::close(fd), 0);
        }
        reader.join().unwrap();
        sender.join().unwrap();
        poller.join().unwrap();
        call(&adapter, 8, listener, 0, vec![], 0).unwrap();
    }
}

#[test]
fn token_partial_allocation_failure_closes_first_descriptor() {
    if isolated("tests::token_partial_allocation_failure_closes_first_descriptor") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    unsafe {
        let probe = syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) as i32;
        assert!(probe >= 0);
        assert_eq!(syscall(SYS_close, probe), 0);
        let mut limit: rlimit = std::mem::zeroed();
        assert_eq!(getrlimit(RLIMIT_NOFILE, &mut limit), 0);
        let restricted = rlimit {
            rlim_cur: (probe + 1) as rlim_t,
            rlim_max: limit.rlim_max,
        };
        assert_eq!(setrlimit(RLIMIT_NOFILE, &restricted), 0);
        let result = ntcp_socket::packet_test::packet_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        let error = errno();
        assert_eq!(setrlimit(RLIMIT_NOFILE, &limit), 0);
        assert_eq!(result, -1);
        assert_eq!(error, EMFILE);
        assert_eq!(syscall(SYS_fcntl, probe, F_GETFD), -1);
        assert_eq!(errno(), EBADF);
    }
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as i32;
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
}

#[test]
fn token_explicit_close_host_close_and_foreign_replacement() {
    if isolated("tests::token_explicit_close_host_close_and_foreign_replacement") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as i32;
    assert_eq!(get_buffer(fd, SO_DOMAIN), AF_INET);
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    unsafe {
        assert_eq!(syscall(SYS_fcntl, fd, F_GETFD), -1);
    }
    assert_eq!(errno(), EBADF);
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as i32;
    unsafe {
        assert_eq!(libc::close(fd), 0);
        assert_eq!(syscall(SYS_fcntl, fd, F_GETFD), -1);
    }
    assert_eq!(errno(), EBADF);
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as i32;
    let foreign = unsafe { libc::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    assert!(foreign >= 0);
    unsafe {
        assert_eq!(libc::dup2(foreign, fd), fd);
        assert_eq!(libc::close(foreign), 0);
    }
    assert_eq!(get_buffer(fd, SO_DOMAIN), AF_UNIX);
    drop(adapter); // Free must not close the foreign replacement.
    unsafe {
        assert!(syscall(SYS_fcntl, fd, F_GETFD) >= 0);
        assert_eq!(libc::close(fd), 0);
    }
}
