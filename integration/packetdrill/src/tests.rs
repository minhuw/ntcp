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
    fn start((local, profile): (Ipv4Addr, ntcp_socket::packet_test::Profile)) -> Result<Self, i32> {
        let profile = profile.flags();
        let flags = std::ffi::CString::new(format!("{profile},local={local}")).unwrap();
        let mut table = [0usize; 64];
        unsafe {
            packetdrill_interface_init(flags.as_ptr(), table.as_mut_ptr().cast());
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
                let deadline = Instant::now() + Duration::from_secs(3);
                let (r, n) = loop {
                    let mut n = capacity;
                    let mut stamp = 0;
                    let r =
                        ntcp_net_receive(USERDATA, output.as_mut_ptr().cast(), &mut n, &mut stamp);
                    if r != 0 || n != 0 || Instant::now() >= deadline {
                        break (r, n);
                    }
                    thread::sleep(Duration::from_millis(1));
                };
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
                    _ => panic!("unsupported transport test option {a}"),
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
            tx_timestamp: None,
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
            tx_timestamp: None,
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
            tx_timestamp: None,
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
    info.fill(0xa5);
    unsafe {
        assert_eq!(
            getsockopt(fd, SOL_SOCKET, SO_MEMINFO, info.as_mut_ptr().cast(), &mut n),
            -1
        );
    }
    assert_eq!(errno(), ENOSYS);
    assert_eq!(n, 36);
    assert!(info.iter().all(|b| *b == 0xa5));
    assert_eq!(get_buffer(fd, SO_RCVBUF), 65535);
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
    #[cfg(feature = "tfo-linux-cookie")]
    build.args(["--features", "tfo-linux-cookie"]);
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
#include <fcntl.h>
#include <time.h>
static void *empty_capture(void *arg) {
    struct packetdrill_interface *p = arg;
    unsigned char packet[65535]; size_t n = sizeof(packet); long long t;
    struct timespec before, after;
    assert(!clock_gettime(CLOCK_MONOTONIC, &before));
    assert(p->netdev_receive(p->userdata, packet, &n, &t) == 0);
    assert(n == 0);
    assert(!clock_gettime(CLOCK_MONOTONIC, &after));
    assert(after.tv_sec - before.tv_sec < 2);
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    void (*init)(const char *, struct packetdrill_interface *) = dlsym(RTLD_DEFAULT, "packetdrill_interface_init");
    int preloaded = init != NULL;
    void *plugin = NULL;
    if (!init) {
        plugin = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); assert(plugin);
        init = dlsym(plugin, "packetdrill_interface_init");
    }
    assert(init);
#define GETOPT(fd, level, name, value, len) (preloaded ? getsockopt(fd, level, name, value, len) : p.getsockopt(p.userdata, fd, level, name, value, len))
    struct packetdrill_interface p, other;
    init("upstream,local=192.0.2.1", &p); assert(p.userdata);
    init("local=192.0.2.1,baseline", &other); assert(!other.userdata);
    int fd = p.socket(p.userdata, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP); assert(fd >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(8080), .sin_addr={htonl(0xc0000202)}};
    assert(p.connect(p.userdata, fd, (void *)&addr, sizeof(addr)) == -1 && errno == EINPROGRESS);
    unsigned char info[288], abi[280]; memset(info, 0xa5, sizeof(info)); socklen_t n = sizeof(info);
    assert(GETOPT(fd, IPPROTO_TCP, TCP_INFO, info, &n) == 0 && n == 280 && info[0] == 2);
    n = sizeof(abi); assert(p.getsockopt(p.userdata, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == 0);
    assert(memcmp(info, abi, sizeof(abi)) == 0 && info[280] == 0xa5);
    n = sizeof(abi); assert(syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_INFO, abi, &n) == -1);
    n = sizeof(abi); assert(GETOPT(fd, IPPROTO_TCP, TCP_CC_INFO, abi, &n) == 0 && n == 0);
    n = sizeof(abi); assert(GETOPT(fd, SOL_SOCKET, SO_MEMINFO, abi, &n) == -1 && errno == ENOSYS);
    int domain; n = sizeof(domain); assert(GETOPT(fd, SOL_SOCKET, SO_DOMAIN, &domain, &n) == 0 && domain == AF_INET);
    // Register through the shared ABI, but close through ordinary host libc.
    int epfd = p.epoll_create(p.userdata, 1); assert(epfd >= 0);
    struct epoll_event event = {.events = EPOLLOUT, .data.u64 = 123};
    int retained = 0;
    while (syscall(SYS_fcntl, retained, F_GETFD) >= 0) ++retained;
    assert(p.epoll_ctl(p.userdata, epfd, EPOLL_CTL_ADD, fd, &event) == 0);
    assert(syscall(SYS_fcntl, retained, F_GETFD) >= 0);
    assert(close(epfd) == 0);
    if (preloaded) assert(syscall(SYS_fcntl, retained, F_GETFD) == -1 && errno == EBADF);
    int native = syscall(SYS_epoll_create1, EPOLL_CLOEXEC); assert(native >= 0);
    if (native != epfd) { assert(dup2(native, epfd) == epfd); assert(close(native) == 0); }
    if (preloaded) {
        // A stale registration would incorrectly make MOD succeed here.
        assert(p.epoll_ctl(p.userdata, epfd, EPOLL_CTL_MOD, fd, &event) == -1 && errno == ENOENT);
        assert(close(epfd) == 0);
        native = syscall(SYS_epoll_create1, EPOLL_CLOEXEC); assert(native >= 0);
        if (native != epfd) { assert(dup2(native, epfd) == epfd); assert(close(native) == 0); }
    }
    int host = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(host >= 0);
    unsigned char kernel[104], forwarded[104]; socklen_t k = sizeof(kernel); n = sizeof(forwarded);
    assert(syscall(SYS_getsockopt, host, IPPROTO_TCP, TCP_INFO, kernel, &k) == 0);
    assert(getsockopt(host, IPPROTO_TCP, TCP_INFO, forwarded, &n) == 0 && k == n && !memcmp(kernel, forwarded, n));
    k = sizeof(kernel); n = sizeof(forwarded);
    assert(syscall(SYS_getsockopt, host, SOL_SOCKET, SO_MEMINFO, kernel, &k) == 0);
    assert(GETOPT(host, SOL_SOCKET, SO_MEMINFO, forwarded, &n) == 0 && k == n && !memcmp(kernel, forwarded, n)); close(host);
    // Drain SYN output; an empty callback returns promptly before teardown.
    unsigned char packet[65535]; size_t size = sizeof(packet); long long t;
    assert(p.netdev_receive(p.userdata, packet, &size, &t) == 0);
    pthread_t thread; assert(!pthread_create(&thread, NULL, empty_capture, &p));
    assert(!pthread_join(thread, NULL));
    p.free(p.userdata);
    size = sizeof(packet);
    assert(p.netdev_receive(p.userdata, packet, &size, &t) == -1);
    assert(size == 0 && (errno == ECANCELED || errno == EIO));
    p.free(p.userdata); // Stale userdata never dereferenced.
    if (!preloaded) assert(syscall(SYS_fcntl, retained, F_GETFD) == -1 && errno == EBADF);
    assert(fcntl(epfd, F_GETFD) >= 0); // Neither mode may close the foreign epoll.
    assert(close(epfd) == 0);
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
    for preloaded in [true, false] {
        let mut command = Command::new(&executable);
        command.arg(&library).env_remove("LD_PRELOAD");
        if preloaded {
            command.env("LD_PRELOAD", &library);
        }
        let mut child = command
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().unwrap();
                let logs = String::from_utf8_lossy(&output.stderr);
                assert!(status.success(), "{logs}");
                assert!(
                    logs.contains("NTCP_PACKETDRILL_UNSUPPORTED: socket option"),
                    "{logs}"
                );
                break;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("preload helper deadlocked");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn isolated(name: &str) -> bool {
    if std::env::var_os("NTCP_PACKET_ABI_CHILD").is_some() {
        return false;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1"])
        .env("NTCP_PACKET_ABI_CHILD", "1")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("isolated ABI test timed out: {name}");
        }
        thread::sleep(Duration::from_millis(10));
    }
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
            tx_timestamp: None,
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
    ip_policy: Option<(i32, i32)>,
) -> (i32, i32, IpMetadata, ntcp::wire::Header) {
    let listener = call(adapter, 1, 0, SOCK_NONBLOCK, vec![], 0).unwrap().value as i32;
    if let Some((tos, pmtu)) = ip_policy {
        for (name, value) in [(IP_TOS, tos), (IP_MTU_DISCOVER, pmtu)] {
            unsafe {
                assert_eq!(
                    ntcp_socket::setsockopt(
                        listener,
                        IPPROTO_IP,
                        name,
                        (&value as *const i32).cast(),
                        4
                    ),
                    0
                );
            }
        }
    }
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
    let (listener, fd, ip, header) = connect_listener(&adapter, 8081, true, None);
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
    // The successful full read below proves EFAULT did not consume queued bytes.
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
        let (listener, fd, _, _) = connect_listener(&adapter, 8080 + i as u16, false, None);
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

#[test]
fn receive_callbacks_reject_flags_but_accept_large_requests() {
    if std::env::var_os("NTCP_PACKET_ABI_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::receive_callbacks_reject_flags_but_accept_large_requests",
                "--test-threads=1",
            ])
            .env("NTCP_PACKET_ABI_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let logs = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            logs.matches("NTCP_PACKETDRILL_UNSUPPORTED:").count(),
            3,
            "{logs}"
        );
        assert_eq!(logs.matches("send/recv flags").count(), 3, "{logs}");
        assert_eq!(
            logs.matches("65535-byte adapter bound").count(),
            0,
            "{logs}"
        );
        return;
    }
    unsafe extern "C" {
        fn ntcp_abi_receive_unsupported(u: *mut c_void);
    }
    let _adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    unsafe {
        ntcp_abi_receive_unsupported(USERDATA);
    }
}

#[test]
fn pending_accept_cancelled_by_real_descriptor_replacement() {
    if isolated("tests::pending_accept_cancelled_by_real_descriptor_replacement") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let fd = call(&adapter, 1, 0, 0, vec![], 0).unwrap().value as i32;
    call(
        &adapter,
        2,
        fd,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    call(&adapter, 3, fd, 1, vec![], 0).unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let (completed, result) = std::sync::mpsc::channel();
    let waiter = thread::spawn(move || {
        started.send(()).unwrap();
        let r = unsafe { ntcp_socket::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        completed.send((r, errno())).unwrap();
    });
    ready.recv().unwrap();
    thread::sleep(Duration::from_millis(20));
    assert!(
        !waiter.is_finished(),
        "accept must still be blocked before replacement"
    );
    let foreign = unsafe { libc::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    assert!(foreign >= 0);
    unsafe {
        assert_eq!(libc::dup2(foreign, fd), fd);
        assert_eq!(libc::close(foreign), 0);
    }
    assert_eq!(
        result.recv_timeout(Duration::from_secs(1)).unwrap(),
        (-1, EBADF)
    );
    waiter.join().unwrap();
    assert_eq!(get_buffer(fd, SO_DOMAIN), AF_UNIX);
    drop(adapter);
    unsafe {
        assert!(syscall(SYS_fcntl, fd, F_GETFD) >= 0);
        assert_eq!(libc::close(fd), 0);
    }
}

#[test]
fn detached_fin_keeps_ip_policy_after_real_descriptor_reuse() {
    if isolated("tests::detached_fin_keeps_ip_policy_after_real_descriptor_reuse") {
        return;
    }
    let adapter = Adapter::start((local(), Profile::Baseline)).unwrap();
    let (listener, fd, ip, mut ack) =
        connect_listener(&adapter, 8080, false, Some((184, IP_PMTUDISC_DONT)));
    let set = |fd, name, value: i32| unsafe {
        assert_eq!(
            ntcp_socket::setsockopt(fd, IPPROTO_IP, name, (&value as *const i32).cast(), 4),
            0
        );
    };
    for (name, expected) in [(IP_TOS, 184), (IP_MTU_DISCOVER, IP_PMTUDISC_DONT)] {
        let mut value = 0i32;
        let mut n = 4;
        unsafe {
            assert_eq!(
                ntcp_socket::getsockopt(
                    fd,
                    IPPROTO_IP,
                    name,
                    (&mut value as *mut i32).cast(),
                    &mut n
                ),
                0
            );
        }
        assert_eq!(value, expected);
    }
    let replacement = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    set(replacement, IP_TOS, 4);
    set(replacement, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
    unsafe {
        assert_eq!(libc::dup2(replacement, fd), fd);
        assert_eq!(libc::close(replacement), 0);
    }
    let fin = loop {
        let bytes = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        let header = packet_header(&bytes);
        if header.source_port == 8080 && header.flags & ntcp::wire::FIN != 0 {
            assert_eq!(bytes[1], 184);
            assert_eq!(bytes[6] & 0x40, 0);
            break header;
        }
    };
    let mut tos = 0i32;
    let mut n = 4;
    unsafe {
        assert_eq!(
            ntcp_socket::getsockopt(
                fd,
                IPPROTO_IP,
                IP_TOS,
                (&mut tos as *mut i32).cast(),
                &mut n
            ),
            0
        );
    }
    assert_eq!(tos, 4);
    ack.acknowledgment = fin.sequence.wrapping_add(1);
    ack.flags |= ntcp::wire::FIN;
    inject(ip, ack, &[]);
    let bytes = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    assert_eq!(
        packet_header(&bytes).acknowledgment,
        ack.sequence.wrapping_add(1)
    );
    assert_eq!(bytes[1], 184);
    assert_eq!(bytes[6] & 0x40, 0);
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    call(&adapter, 8, listener, 0, vec![], 0).unwrap();
}

// These are live raw-IP/ABI liveness checks, not precise pacing-rate tests.
// Owner.test_now tests cover burst/deadline accounting without scheduler jitter.
fn pipeline_wire_segments(profile: Profile, bounded: bool) {
    let adapter = if bounded {
        // The C initializer has no queue-size option. Exercise the public Rust
        // constructor, then use the same plugin callbacks and teardown as C.
        ntcp_socket::packet_test::start_with_options(
            (local(), profile),
            ntcp_socket::packet_test::Options {
                queue_capacity: 1,
                egress_capacity: 1,
            },
        )
        .unwrap();
        ACTIVE.store(true, Ordering::Release);
        Adapter
    } else {
        Adapter::start((local(), profile)).unwrap()
    };
    let (_, fd, _, ack) = connect_listener(&adapter, 8080, false, None);
    // No MSS option in this peer's SYN: RFC default IPv4 sender MSS is 536.
    // Three full segments fit the baseline initial window; no ACK is injected
    // to rescue a stalled egress/pacing timer or a software-GSO remainder.
    let payload: Vec<u8> = (0..3 * 536).map(|i| (i % 251) as u8).collect();
    let started = Instant::now();
    unsafe {
        assert_eq!(
            ntcp_socket::send(fd, payload.as_ptr().cast(), payload.len(), MSG_NOSIGNAL),
            payload.len() as isize
        );
    }
    let deadline = started + Duration::from_secs(3);
    loop {
        match ntcp_socket::packet_test::try_capture(0) {
            Err(EMSGSIZE) => break, // Peek failure must retain the first segment.
            Err(EAGAIN) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            other => panic!("output did not become capturable: {other:?}"),
        }
    }
    // Also check the C ABI's non-consuming short-buffer path.
    let mut byte = 0u8;
    let mut n = 0;
    let mut stamp = 0;
    unsafe {
        assert_eq!(
            ntcp_net_receive(USERDATA, (&mut byte as *mut u8).cast(), &mut n, &mut stamp),
            -1
        );
    }
    assert_eq!(errno(), EMSGSIZE);
    let (sent, received) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        loop {
            let mut bytes = vec![0; BYTES];
            let mut n = bytes.len();
            let mut stamp = 0;
            let result = unsafe {
                ntcp_net_receive(USERDATA, bytes.as_mut_ptr().cast(), &mut n, &mut stamp)
            };
            if result == 0 && n == 0 {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            let capture = if result == 0 {
                bytes.truncate(n);
                Ok((bytes, stamp, Instant::now()))
            } else {
                Err(errno())
            };
            let done = capture.is_err();
            if sent.send(capture).is_err() || done {
                break;
            }
        }
    });
    let mut previous = started;
    for i in 0..3 {
        let (bytes, stamp, observed) = received
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        assert!(observed >= previous);
        previous = observed;
        assert!(stamp > 0); // Epoch submission timestamp, NOT the pacing clock.
        assert_eq!(
            bytes.len(),
            20 + 20 + 536,
            "capture must not expose a GSO super-packet"
        );
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        assert_eq!(ip.source, IpAddr::V4(local()));
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(
            segment.header.sequence,
            ack.acknowledgment.wrapping_add((i * 536) as u32)
        );
        assert_eq!(segment.header.acknowledgment, ack.sequence);
        assert_eq!(
            segment.header.flags
                & (ntcp::wire::ACK | ntcp::wire::SYN | ntcp::wire::FIN | ntcp::wire::RST),
            ntcp::wire::ACK
        );
        assert_eq!(segment.payload, &payload[i * 536..(i + 1) * 536]);
    }
    // Only a liveness bound, no Linux fq timing/tolerance assertion. In paced
    // profiles this observes real monotonic delivery with no fake clock advance.
    assert!(previous.duration_since(started) < Duration::from_secs(3));
    assert!(received.recv_timeout(Duration::from_millis(10)).is_err());
    drop(adapter); // The next polling callback observes teardown, even with bounded queues.
    let error = received
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, ECANCELED | EIO));
    reader.join().unwrap();
}

#[test]
fn pipeline_scalar_wire_segments() {
    if isolated("tests::pipeline_scalar_wire_segments") {
        return;
    }
    pipeline_wire_segments(Profile::Pipeline, false);
}

#[test]
fn pipeline_gso_wire_segments() {
    if isolated("tests::pipeline_gso_wire_segments") {
        return;
    }
    pipeline_wire_segments(Profile::PipelineGso, false);
}

#[test]
fn pipeline_paced_wire_segments() {
    if isolated("tests::pipeline_paced_wire_segments") {
        return;
    }
    pipeline_wire_segments(Profile::PipelinePaced, false);
}

#[test]
fn pipeline_paced_gso_wire_segments() {
    if isolated("tests::pipeline_paced_gso_wire_segments") {
        return;
    }
    pipeline_wire_segments(Profile::PipelinePacedGso, false);
}

#[test]
fn pipeline_gso_capacity_one_wire_segments_and_cancel() {
    if isolated("tests::pipeline_gso_capacity_one_wire_segments_and_cancel") {
        return;
    }
    pipeline_wire_segments(Profile::PipelineGso, true);
}

#[test]
fn adapter_start_forwards_local_address_and_profile() {
    if isolated("tests::adapter_start_forwards_local_address_and_profile") {
        return;
    }
    let address = Ipv4Addr::new(192, 0, 2, 9);
    let adapter = Adapter::start((address, Profile::Sack)).unwrap();
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    assert_eq!(
        call(
            &adapter,
            5,
            fd,
            0,
            encode_addr("192.0.2.2:8080".parse().unwrap()),
            0
        )
        .err(),
        Some(EINPROGRESS)
    );
    let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&packet).unwrap();
    assert_eq!(ip.source, IpAddr::V4(address));
    assert_ne!(packet_header(&packet).flags & ntcp::wire::SYN, 0);
    let header_len = (tcp[12] >> 4) as usize * 4;
    assert!(
        tcp[20..header_len]
            .windows(2)
            .any(|option| option == [4, 2]),
        "Sack profile must advertise SACK-permitted, unlike Baseline"
    );
}

#[test]
fn fast_open_profile_keeps_socket_opt_in_and_disables_timestamps() {
    if isolated("tests::fast_open_profile_keeps_socket_opt_in_and_disables_timestamps") {
        return;
    }
    let adapter = Adapter::start((
        local(),
        upstream_tests("no-timestamps,budget224m,prealloc3"),
    ))
    .unwrap();
    // Enabling one client must not enable the next ordinary client or listener.
    for enabled in [true, false] {
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as i32;
        for option in [TCP_FASTOPEN, TCP_FASTOPEN_CONNECT] {
            let mut value = -1i32;
            let mut len = 4;
            unsafe {
                assert_eq!(
                    ntcp_socket::getsockopt(
                        fd,
                        IPPROTO_TCP,
                        option,
                        (&mut value as *mut i32).cast(),
                        &mut len
                    ),
                    0
                );
            }
            assert_eq!((value, len), (0, 4));
        }
        if enabled {
            let value = 1i32;
            unsafe {
                assert_eq!(
                    ntcp_socket::setsockopt(
                        fd,
                        IPPROTO_TCP,
                        TCP_FASTOPEN_CONNECT,
                        (&value as *const i32).cast(),
                        4
                    ),
                    0
                );
            }
        }
        assert_eq!(
            call(
                &adapter,
                5,
                fd,
                0,
                encode_addr("192.0.2.2:8080".parse().unwrap()),
                0
            )
            .err(),
            Some(EINPROGRESS)
        );
        let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        let (ip, tcp) = parse_frame(&packet).unwrap();
        let parsed = ntcp::wire::parse(ip, tcp).unwrap();
        assert!(parsed.options.timestamps.is_none());
        assert!(parsed.options.sack_permitted);
        assert_eq!(parsed.options.window_scale, Some(8));
        assert_eq!(parsed.options.fast_open.is_some(), enabled);
        if enabled {
            assert!(parsed.options.fast_open.unwrap().as_bytes().is_empty());
        }
        call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    }
    let listener = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    call(
        &adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8081)),
        0,
    )
    .unwrap();
    call(&adapter, 3, listener, 1, vec![], 0).unwrap();
    call(
        &adapter,
        14,
        0,
        0,
        syn_with_options(100, 8081, &[34, 2, 1, 1]),
        0,
    )
    .unwrap();
    let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&packet).unwrap();
    let parsed = ntcp::wire::parse(ip, tcp).unwrap();
    assert_eq!(parsed.header.source_port, 8081);
    assert!(parsed.options.timestamps.is_none());
    assert!(parsed.options.fast_open.is_none());
}

fn profile_cookie_response(profile: Profile, linux: bool) {
    let local = Ipv4Addr::new(192, 168, 0, 1);
    let adapter = Adapter::start((local, profile)).unwrap();
    // Check default-off both before and after the cookie service is enabled.
    for (port, enabled) in [(8080, false), (8081, true), (8082, false)] {
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as i32;
        call(
            &adapter,
            2,
            fd,
            0,
            encode_addr(SocketAddr::new(local.into(), port)),
            0,
        )
        .unwrap();
        call(&adapter, 3, fd, 2, vec![], 0).unwrap();
        if enabled {
            let limit = 2i32;
            unsafe {
                assert_eq!(
                    ntcp_socket::setsockopt(
                        fd,
                        IPPROTO_TCP,
                        TCP_FASTOPEN,
                        (&limit as *const i32).cast(),
                        4
                    ),
                    0
                );
            }
        }
        let ip = IpMetadata {
            source: Ipv4Addr::new(192, 0, 2, 1).into(),
            destination: local.into(),
        };
        let header = ntcp::wire::Header {
            source_port: 50000,
            destination_port: port,
            sequence: 100,
            acknowledgment: 0,
            flags: ntcp::wire::SYN,
            window: 65535,
            urgent_pointer: 0,
        };
        let mut tcp = [0; 64];
        let n = ntcp::wire::encode(ip, header, &[34, 2, 1, 1], &[], &mut tcp).unwrap();
        let packet = frame(
            ntcp::Transmit {
                tx_timestamp: None,
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
        .unwrap();
        call(&adapter, 14, 0, 0, packet, 0).unwrap();
        let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        let (ip, tcp) = parse_frame(&packet).unwrap();
        let parsed = ntcp::wire::parse(ip, tcp).unwrap();
        assert_eq!(parsed.options.fast_open.is_some(), enabled);
        if enabled {
            assert_eq!(
                parsed.options.fast_open.unwrap().as_bytes()
                    == [0x30, 0x21, 0xb9, 0xd8, 0x89, 0x01, 0x7e, 0xeb],
                linux
            );
        }
    }
}

#[test]
fn original_fast_open_profile_retains_hmac_default() {
    if isolated("tests::original_fast_open_profile_retains_hmac_default") {
        return;
    }
    profile_cookie_response(upstream_tests("no-timestamps,budget224m,prealloc3"), false);
}

#[test]
#[cfg(feature = "tfo-linux-cookie")]
fn linux_cookie_profile_applies_key_after_endpoint_replacement_without_enabling_listeners() {
    if isolated(
        "tests::linux_cookie_profile_applies_key_after_endpoint_replacement_without_enabling_listeners",
    ) {
        return;
    }
    profile_cookie_response(
        upstream_tests("no-timestamps,budget224m,prealloc3,linux-cookie"),
        true,
    );
}

#[test]
fn pmtud_fast_open_profile_retains_hmac_default() {
    if isolated("tests::pmtud_fast_open_profile_retains_hmac_default") {
        return;
    }
    profile_cookie_response(
        upstream_tests("no-timestamps,budget224m,prealloc3,pmtud1500"),
        false,
    );
}

fn upstream_tests(options: &str) -> Profile {
    ntcp_socket::packet_test::profile(&format!("upstream,local=192.0.2.1,{options}"))
        .unwrap()
        .1
}

#[test]
fn tcp_info_complete_reply_after_pmtu_resegmentation_preserves_abi_buffer() {
    if isolated("tests::tcp_info_complete_reply_after_pmtu_resegmentation_preserves_abi_buffer") {
        return;
    }
    let adapter = Adapter::start((local(), upstream_tests("no-timestamps,pmtud1500"))).unwrap();
    let (_listener, fd, peer_ip, mut peer_ack) = connect_listener(&adapter, 8080, false, None);
    let mut complete = [0xa5u8; 512];
    let mut n = complete.len() as socklen_t;
    unsafe {
        assert_eq!(
            ntcp_socket::getsockopt(
                fd,
                IPPROTO_TCP,
                TCP_INFO,
                complete.as_mut_ptr().cast(),
                &mut n
            ),
            0
        );
    }
    assert_eq!(n, 280);
    assert_eq!(complete[0], 1); // ESTABLISHED.
    assert!(complete[280..].iter().all(|&b| b == 0xa5));
    let payload = [0x42u8; 536];
    unsafe {
        assert_eq!(
            ntcp_socket::write(fd, payload.as_ptr().cast(), payload.len()),
            536
        );
    }
    let first = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&first).unwrap();
    let first_payload = ntcp::wire::parse(ip, tcp).unwrap().payload.len();
    // The initial peer has no MSS option:536-byte packets. A matched ICMP
    // MTU300 requires partial retransmission. Both byte and packet-unit
    // delivery statistics must remain available after repacketization.
    assert_eq!(first_payload, 536);
    let mut feedback = vec![0u8; 56];
    feedback[0] = 0x45;
    feedback[2..4].copy_from_slice(&56u16.to_be_bytes());
    feedback[8] = 64;
    feedback[9] = 1;
    feedback[12..16].copy_from_slice(&[192, 0, 2, 2]);
    feedback[16..20].copy_from_slice(&local().octets());
    feedback[20..22].copy_from_slice(&[3, 4]);
    feedback[26..28].copy_from_slice(&300u16.to_be_bytes());
    feedback[28..56].copy_from_slice(&first[..28]);
    let checksum = ntcp_ip::checksum(&feedback[20..]);
    feedback[22..24].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ntcp_ip::checksum(&feedback[..20]);
    feedback[10..12].copy_from_slice(&checksum.to_be_bytes());
    call(&adapter, 14, 0, 0, feedback, 0).unwrap();
    let retry = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    assert_eq!(
        packet_header(&retry).sequence,
        packet_header(&first).sequence
    );
    assert_eq!(retry.len(), 300);
    for requested in [0, 1, 6, 7, 191, 192, 193, 196, 280, 512] {
        let mut bytes = [0xa5u8; 512];
        let mut len = requested;
        unsafe {
            assert_eq!(
                ntcp_socket::getsockopt(
                    fd,
                    IPPROTO_TCP,
                    TCP_INFO,
                    bytes.as_mut_ptr().cast(),
                    &mut len,
                ),
                0
            );
        }
        assert_eq!(len, requested.min(280));
        if len > 0 {
            assert_eq!(bytes[0], 1);
        }
        if len >= 6 {
            assert_eq!(bytes[5] & 32, 0);
        }
        if len >= 196 {
            assert_eq!(u32::from_ne_bytes(bytes[192..196].try_into().unwrap()), 1);
        }
        assert!(bytes[len as usize..].iter().all(|&b| b == 0xa5));
    }
    let mut repaired = 260;
    loop {
        peer_ack.acknowledgment = packet_header(&first).sequence.wrapping_add(repaired as u32);
        inject(peer_ip, peer_ack, &[]);
        let snapshot = call(&adapter, 18, fd, 1, vec![], 280).unwrap().bytes;
        assert_eq!(snapshot.len(), 280);
        if repaired == payload.len() {
            assert_eq!(
                u32::from_ne_bytes(snapshot[192..196].try_into().unwrap()),
                4
            ); // SYN+three repaired units.
            break;
        }
        let bytes = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        assert_eq!(
            packet_header(&bytes).sequence,
            packet_header(&first).sequence.wrapping_add(repaired as u32)
        );
        let (ip, tcp) = parse_frame(&bytes).unwrap();
        let segment = ntcp::wire::parse(ip, tcp).unwrap();
        assert!(bytes.len() <= 300);
        repaired += segment.payload.len();
        assert!(repaired <= payload.len());
    }
}

#[test]
fn tcp_info_fresh_bound_listener_queue_and_closed_connection_states() {
    if isolated("tests::tcp_info_fresh_bound_listener_queue_and_closed_connection_states") {
        return;
    }
    let adapter = Adapter::start((local(), upstream_tests("no-timestamps"))).unwrap();
    let listener = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    let query = |fd, expected_state| {
        let info = call(&adapter, 18, fd, 1, vec![], 512).unwrap().bytes;
        assert_eq!(info.len(), 280);
        assert_eq!(info[0], expected_state);
        info
    };
    let fresh = query(listener, 7);
    assert_eq!(&fresh[192..196], &[0; 4]);
    call(
        &adapter,
        2,
        listener,
        0,
        encode_addr(SocketAddr::new(local().into(), 8080)),
        0,
    )
    .unwrap();
    query(listener, 7); // Binding alone creates no TCP connection.
    call(&adapter, 3, listener, 3, vec![], 0).unwrap();
    let info = query(listener, 10);
    assert_eq!(u32::from_ne_bytes(info[24..28].try_into().unwrap()), 0);
    assert_eq!(u32::from_ne_bytes(info[28..32].try_into().unwrap()), 3);
    call(&adapter, 14, 0, 0, syn(100, 8080), 0).unwrap();
    let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let parsed = ntcp_ip::parse(&packet, false).unwrap();
    let sent = packet_header(&packet);
    let ip = IpMetadata {
        source: parsed.ip.destination,
        destination: parsed.ip.source,
    };
    let mut ack = ntcp::wire::Header {
        source_port: 50000,
        destination_port: 8080,
        sequence: 101,
        acknowledgment: sent.sequence.wrapping_add(1),
        flags: ntcp::wire::ACK,
        window: 65535,
        urgent_pointer: 0,
    };
    query(listener, 10); // An in-progress passive handshake is still LISTEN.
    inject(ip, ack, &[]);
    let info = query(listener, 10);
    assert_eq!(u32::from_ne_bytes(info[24..28].try_into().unwrap()), 1);
    let fd = call(&adapter, 4, listener, SOCK_NONBLOCK, vec![], 16)
        .unwrap()
        .value as i32;
    query(fd, 1);
    assert_eq!(
        u32::from_ne_bytes(query(listener, 10)[24..28].try_into().unwrap()),
        0
    );
    ack.flags |= ntcp::wire::FIN;
    inject(ip, ack, &[]);
    let response = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    assert_eq!(packet_header(&response).acknowledgment, 102);
    query(fd, 8); // CLOSE_WAIT.
    call(&adapter, 9, fd, SHUT_WR, vec![], 0).unwrap();
    let fin = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    query(fd, 9); // LAST_ACK.
    ack.flags = ntcp::wire::ACK;
    ack.sequence = 102;
    ack.acknowledgment = packet_header(&fin).sequence.wrapping_add(1);
    inject(ip, ack, &[]);
    let closed = query(fd, 7); // TCP closed, application descriptor still valid.
    assert_eq!(u32::from_ne_bytes(closed[192..196].try_into().unwrap()), 2); // SYN+FIN.
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    assert_eq!(call(&adapter, 18, fd, 1, vec![], 280).err(), Some(EBADF));
}

#[test]
fn icmp_network_errors_cross_shared_abi_without_soft_stream_failure() {
    if isolated("tests::icmp_network_errors_cross_shared_abi_without_soft_stream_failure") {
        return;
    }
    let adapter = Adapter::start((local(), upstream_tests("no-timestamps"))).unwrap();
    let (_listener, fd, _ip, _ack) = connect_listener(&adapter, 8080, false, None);
    let payload = [0x42u8; 536];
    unsafe {
        assert_eq!(
            ntcp_socket::write(fd, payload.as_ptr().cast(), payload.len()),
            536
        );
    }
    let packet = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let report = |kind: u8, code: u8| {
        let mut bytes = vec![0u8; 56];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&56u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 1;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 254]);
        bytes[16..20].copy_from_slice(&local().octets());
        bytes[20] = kind;
        bytes[21] = code;
        bytes[28..56].copy_from_slice(&packet[..28]);
        let checksum = ntcp_ip::checksum(&bytes[20..]);
        bytes[22..24].copy_from_slice(&checksum.to_be_bytes());
        let checksum = ntcp_ip::checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        call(&adapter, 14, 0, 0, bytes, 0).unwrap();
    };
    report(3, 1); // Host unreachable is a nonterminal notification.
    unsafe {
        assert_eq!(
            ntcp_socket::write(fd, payload.as_ptr().cast(), payload.len()),
            536
        );
    }
    let next = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    assert_eq!(
        packet_header(&next).sequence,
        packet_header(&packet).sequence.wrapping_add(536)
    );
    report(4, 0); // Source Quench must not clear a pending real notification.
    assert_eq!(get_buffer(fd, SO_ERROR), EHOSTUNREACH);
    assert_eq!(get_buffer(fd, SO_ERROR), 0);
    report(11, 0);
    report(3, 3); // Existing core hard-error policy wins over the soft report.
    assert_eq!(get_buffer(fd, SO_ERROR), EHOSTUNREACH);
    assert_eq!(get_buffer(fd, SO_ERROR), 0);
    let info = call(&adapter, 18, fd, 1, vec![], 280).unwrap().bytes;
    assert_eq!(info.len(), 280);
    assert_eq!(info[0], 7); // TCP closed; application descriptor still valid.
}

#[test]
fn timestamp_control_abi_changes_only_future_connection_defaults() {
    if isolated("tests::timestamp_control_abi_changes_only_future_connection_defaults") {
        return;
    }
    unsafe {
        assert_eq!(
            ntcp_packetdrill_control(USERDATA, c"ntcp-local-timestamps-off".as_ptr()),
            -1
        );
        assert_eq!(errno(), EINVAL);
    }
    let adapter = Adapter::start((local(), upstream_tests("budget224m"))).unwrap();
    unsafe {
        assert_eq!(ntcp_packetdrill_control(USERDATA, ptr::null()), -1);
        assert_eq!(errno(), EINVAL);
        for command in [
            c"ntcp-local-timestamps-maybe",
            c"ntcp-local-timestamps-off; true",
            c"ntcp-local-timestamps-on-clear-tfo-cache; true",
        ] {
            assert_eq!(ntcp_packetdrill_control(USERDATA, command.as_ptr()), -1);
            assert_eq!(errno(), EOPNOTSUPP);
        }
    }
    for (index, enabled) in [true, false, true].into_iter().enumerate() {
        if index != 0 {
            let command = if enabled {
                c"ntcp-local-timestamps-on-clear-tfo-cache"
            } else {
                c"ntcp-local-timestamps-off"
            };
            assert_eq!(
                unsafe { ntcp_packetdrill_control(USERDATA, command.as_ptr()) },
                0
            );
        }
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as i32;
        assert_eq!(
            call(
                &adapter,
                5,
                fd,
                0,
                encode_addr("192.0.2.2:8080".parse().unwrap()),
                0
            )
            .err(),
            Some(EINPROGRESS)
        );
        let syn = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
        let (ip, tcp) = parse_frame(&syn).unwrap();
        assert_eq!(
            ntcp::wire::parse(ip, tcp)
                .unwrap()
                .options
                .timestamps
                .is_some(),
            enabled
        );
    }
}

#[test]
fn client_tfo_permission_native_api_and_control_abi_share_policy() {
    if isolated("tests::client_tfo_permission_native_api_and_control_abi_share_policy") {
        return;
    }
    // A premature management call does not commit either configuration singleton.
    assert_eq!(
        ntcp_socket::set_fast_open_client_enabled(false)
            .unwrap_err()
            .raw_os_error(),
        Some(EINVAL)
    );
    ntcp_socket::configure(ntcp_socket::SocketConfig::new("unused", local())).unwrap();
    let adapter = Adapter::start((local(), upstream_tests("no-timestamps,budget224m"))).unwrap();
    let set_option = |fd: i32| unsafe {
        let value = 1i32;
        ntcp_socket::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            (&value as *const i32).cast(),
            4,
        )
    };
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    assert_eq!(
        unsafe { ntcp_packetdrill_control(USERDATA, c"ntcp-local-tfo-client-off".as_ptr()) },
        0
    );
    assert_eq!(set_option(fd), -1);
    assert_eq!(errno(), EOPNOTSUPP);
    assert_eq!(
        unsafe { ntcp_packetdrill_control(USERDATA, c"ntcp-local-tfo-client-on; true".as_ptr()) },
        -1
    );
    assert_eq!(errno(), EOPNOTSUPP);
    assert_eq!(set_option(fd), -1); // The rejected command did not re-enable TFO.
    ntcp_socket::set_fast_open_client_enabled(true).unwrap();
    assert_eq!(set_option(fd), 0);
    ntcp_socket::set_fast_open_client_enabled(false).unwrap();
    assert_eq!(
        call(
            &adapter,
            5,
            fd,
            0,
            encode_addr("192.0.2.2:8080".parse().unwrap()),
            0
        )
        .err(),
        Some(EINPROGRESS)
    );
    let bytes = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&bytes).unwrap();
    assert!(
        ntcp::wire::parse(ip, tcp)
            .unwrap()
            .options
            .fast_open
            .is_none()
    );
    assert_eq!(
        unsafe { ntcp_packetdrill_control(USERDATA, c"ntcp-local-tfo-client-on".as_ptr()) },
        0
    );
    let second = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    assert_eq!(set_option(second), 0);
    assert_eq!(
        call(
            &adapter,
            5,
            second,
            0,
            encode_addr("192.0.2.2:8080".parse().unwrap()),
            0
        )
        .err(),
        Some(EINPROGRESS)
    );
    let bytes = call(&adapter, 15, 0, 0, vec![], BYTES).unwrap().bytes;
    let (ip, tcp) = parse_frame(&bytes).unwrap();
    assert_eq!(
        ntcp::wire::parse(ip, tcp).unwrap().options.fast_open,
        Some(ntcp::wire::FastOpenCookie::request())
    );
    drop(adapter);
    assert_eq!(
        ntcp_socket::set_fast_open_client_enabled(false)
            .unwrap_err()
            .raw_os_error(),
        Some(ECANCELED)
    );
}

#[test]
fn listener_assertion_port_rejects_noncanonical_or_shell_arguments() {
    for (text, expected) in [("1", 1), ("8080", 8080), ("65535", 65535)] {
        assert_eq!(
            listener_assertion_port(format!("ntcp-local-assert-listener {text}").as_bytes()),
            Ok(expected)
        );
    }
    for text in [
        "",
        "0",
        "00",
        "08080",
        "+1",
        "-1",
        "65536",
        "123456",
        "0x1F90",
        "1 ",
        "1\n",
        "1\0x",
        "8080; true",
        "8080 && true",
    ] {
        assert_eq!(
            listener_assertion_port(format!("ntcp-local-assert-listener {text}").as_bytes()),
            Err(EOPNOTSUPP)
        );
    }
    assert_eq!(
        listener_assertion_port(b"ntcp-local-assert-listener"),
        Err(EOPNOTSUPP)
    );
}

#[test]
fn listener_assertion_control_uses_real_membership_at_requested_port() {
    if isolated("tests::listener_assertion_control_uses_real_membership_at_requested_port") {
        return;
    }
    let assertion = |port: u16| {
        let command = std::ffi::CString::new(format!("ntcp-local-assert-listener {port}")).unwrap();
        unsafe { ntcp_packetdrill_control(USERDATA, command.as_ptr()) }
    };
    assert_eq!(assertion(43210), -1);
    assert_eq!(errno(), EINVAL);
    let adapter = Adapter::start((local(), Profile::Upstream(Default::default()))).unwrap();
    assert_eq!(assertion(43210), -1);
    assert_eq!(errno(), ENOENT);
    let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
        .unwrap()
        .value as i32;
    call(
        &adapter,
        2,
        fd,
        0,
        encode_addr(SocketAddr::new(local().into(), 43210)),
        0,
    )
    .unwrap();
    assert_eq!(assertion(43210), -1); // A bound stream socket is not listening.
    assert_eq!(errno(), ENOENT);
    call(&adapter, 3, fd, 4, vec![], 0).unwrap();
    assert_eq!(assertion(43210), 0);
    for port in [8080, 43211] {
        assert_eq!(assertion(port), -1);
        assert_eq!(errno(), ENOENT);
    }
    unsafe {
        assert_eq!(
            ntcp_packetdrill_control(USERDATA, c"ntcp-local-assert-listener 43210; true".as_ptr()),
            -1
        );
        assert_eq!(errno(), EOPNOTSUPP);
    }
    assert_eq!(assertion(43210), 0);
    call(&adapter, 8, fd, 0, vec![], 0).unwrap();
    assert_eq!(assertion(43210), -1);
    assert_eq!(errno(), ENOENT);
}

#[test]
fn destination_route_command_is_canonical_and_bounded() {
    let (destination, policy) =
        route_command(b"ntcp-local-route-set 192.0.2.1 640 600 552").unwrap();
    assert_eq!(destination, "192.0.2.1".parse::<Ipv4Addr>().unwrap());
    assert_eq!(policy.unwrap().mtu, Some(640));
    assert_eq!(
        route_command(b"ntcp-local-route-remove 192.0.2.1")
            .unwrap()
            .1,
        None
    );
    assert_eq!(
        route_command(b"ntcp-local-route-set 192.0.2.1 - - -")
            .unwrap()
            .1,
        Some(ntcp_socket::RoutePolicy::default())
    );
    for bad in [
        "ntcp-local-route-set 192.0.2.1 640 600 552; true",
        "ntcp-local-route-set 192.0.2.1 0640 600 552",
        "ntcp-local-route-set 192.0.2.1 640 65536 552",
        "ntcp-local-route-set 192.0.2.1 4294967296 600 552",
        "ntcp-local-route-set 192.0.2.1 640 600",
        "ntcp-local-route-set 192.0.2.1  640 600 552",
        "ntcp-local-route-remove 192.0.2.1\n",
        "ntcp-local-route-remove 192.0.2.1 trailing",
        "ntcp-local-route-set ::1 640 600 552",
    ] {
        assert_eq!(route_command(bad.as_bytes()), Err(EOPNOTSUPP), "{bad}");
    }
}

#[test]
fn destination_route_control_and_native_api_share_actual_future_syn_policy() {
    if isolated("tests::destination_route_control_and_native_api_share_actual_future_syn_policy") {
        return;
    }
    let profile = ntcp_socket::packet_test::profile(&format!(
        "upstream,local={},pmtud1500,budget128m,no-gso",
        local()
    ))
    .unwrap()
    .1;
    let adapter = Adapter::start((local(), profile)).unwrap();
    let control = |text: &str| {
        let command = std::ffi::CString::new(text).unwrap();
        unsafe { ntcp_packetdrill_control(USERDATA, command.as_ptr()) }
    };
    assert_eq!(control("ntcp-local-route-set 192.0.2.2 640 600 552"), 0);
    let open = || {
        let fd = call(&adapter, 1, 0, SOCK_NONBLOCK, vec![], 0)
            .unwrap()
            .value as i32;
        assert_eq!(
            call(
                &adapter,
                5,
                fd,
                0,
                encode_addr("192.0.2.2:8080".parse().unwrap()),
                0
            )
            .err(),
            Some(EINPROGRESS)
        );
        let b = call(&adapter, 15, 0, 0, vec![], 65535).unwrap().bytes;
        ntcp::wire::parse(
            ntcp::IpMetadata {
                source: local().into(),
                destination: "192.0.2.2".parse().unwrap(),
            },
            &b[20..],
        )
        .unwrap()
        .options
        .mss
        .unwrap()
    };
    assert_eq!(open(), 600);
    assert_eq!(
        control("ntcp-local-route-set 192.0.2.2 1500 1460 552; false"),
        -1
    );
    assert_eq!(errno(), EOPNOTSUPP);
    ntcp_socket::set_destination_route(
        "192.0.2.2".parse().unwrap(),
        Some(ntcp_socket::RoutePolicy {
            mtu: Some(1500),
            advertised_mss: Some(1460),
            initial_search_low: Some(552),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(open(), 1460);
    assert_eq!(control("ntcp-local-route-remove 192.0.2.2"), 0);
    assert_eq!(open(), 1460);
}
