// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::*;

#[test]
fn syncnt_raw_values_faults_and_aliases() {
    if std::env::var_os("NTCP_SYNCNT_CHILD").is_none() {
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "syncnt_abi_tests::syncnt_raw_values_faults_and_aliases",
                    "--test-threads=1"
                ])
                .env("NTCP_SYNCNT_CHILD", "1")
                .status()
                .unwrap()
                .success()
        );
        return;
    }
    assert!(RUNTIME.set(Ok(Runtime::in_memory_test())).is_ok());
    let id = call(0, Op::New(SOCK_NONBLOCK)).unwrap().value as u64;
    let (fd, token) = token(SOCK_CLOEXEC).unwrap();
    install(fd, token, id).unwrap();
    unsafe {
        let alias = dup(fd);
        assert!(alias >= 0);
        for value in [0i32, 1, 127, 2] {
            if value != 0 {
                assert_eq!(
                    setsockopt(
                        fd,
                        IPPROTO_TCP,
                        TCP_SYNCNT,
                        (&value as *const i32).cast(),
                        4
                    ),
                    0
                );
            }
            for size in 0..=6u32 {
                let mut len = size;
                let mut bytes = [0xa5; 6];
                assert_eq!(
                    getsockopt(
                        alias,
                        IPPROTO_TCP,
                        TCP_SYNCNT,
                        bytes.as_mut_ptr().cast(),
                        &mut len
                    ),
                    0
                );
                assert_eq!(len, size.min(4));
                assert_eq!(&bytes[..len as usize], &value.to_ne_bytes()[..len as usize]);
                assert!(bytes[len as usize..].iter().all(|b| *b == 0xa5));
            }
            for invalid in [0i32, -1, i32::MIN, 128, 256, i32::MAX] {
                assert_eq!(
                    setsockopt(
                        alias,
                        IPPROTO_TCP,
                        TCP_SYNCNT,
                        (&invalid as *const i32).cast(),
                        4
                    ),
                    -1
                );
                assert_eq!(errno(), EINVAL);
                assert_eq!(
                    call(id, Op::Get(IPPROTO_TCP, TCP_SYNCNT)).unwrap().value,
                    value
                );
            }
            for len in [0, 1, 3] {
                assert_eq!(
                    setsockopt(
                        fd,
                        IPPROTO_TCP,
                        TCP_SYNCNT,
                        (&value as *const i32).cast(),
                        len
                    ),
                    -1
                );
                assert_eq!(errno(), EINVAL);
            }
            assert_eq!(setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, ptr::null(), 4), -1);
            assert_eq!(errno(), EFAULT);
            let mut len = u32::MAX;
            assert_eq!(
                getsockopt(
                    fd,
                    IPPROTO_TCP,
                    TCP_SYNCNT,
                    (&mut 0i32 as *mut i32).cast(),
                    &mut len
                ),
                -1
            );
            assert_eq!(errno(), EINVAL);
            len = 4;
            assert_eq!(
                getsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, ptr::null_mut(), &mut len),
                -1
            );
            assert_eq!(errno(), EFAULT);
            assert_eq!(
                call(id, Op::Get(IPPROTO_TCP, TCP_SYNCNT)).unwrap().value,
                value
            );
        }
        assert_eq!(close(fd), 0);
        let mut value = 0i32;
        let mut len = 4;
        assert_eq!(
            getsockopt(
                alias,
                IPPROTO_TCP,
                TCP_SYNCNT,
                (&mut value as *mut i32).cast(),
                &mut len
            ),
            0
        );
        assert_eq!(value, 2);
        assert_eq!(close(alias), 0);
    }
}
