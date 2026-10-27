// SPDX-License-Identifier: MIT AND GPL-2.0-or-later
use super::memory::tests::{cid, exchange, owner};
use super::tests::new;
use super::*;
use crate::packet_profile::Profile;

#[test]
fn established_reset_before_accept_preserves_socket_error_data_and_readiness() {
    for size in [0, 10] {
        for error_first in 0..3 {
            let mut a = owner(1, Profile::Pipeline, 16);
            let mut b = owner(2, Profile::Pipeline, 16);
            let listener = new(&mut b, SOCK_NONBLOCK);
            b.execute(listener, Op::Bind("192.0.2.2:8080".parse().unwrap()))
                .unwrap();
            b.execute(listener, Op::Listen(2)).unwrap();
            let client = new(&mut a, SOCK_NONBLOCK);
            assert_eq!(
                a.execute(client, Op::Connect("192.0.2.2:8080".parse().unwrap()))
                    .unwrap_err(),
                EINPROGRESS
            );
            exchange(&mut a, &mut b);
            if size != 0 {
                assert_eq!(
                    a.execute(client, Op::Write(vec![7; size])).unwrap().value as usize,
                    size
                );
                exchange(&mut a, &mut b);
            }
            assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
            a.endpoint.abort(cid(&a, client)).unwrap();
            exchange(&mut a, &mut b);
            assert_ne!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
            let server = b
                .execute(listener, Op::Accept(SOCK_NONBLOCK))
                .unwrap()
                .value as u64;
            let connection = cid(&b, server);
            assert_eq!(b.endpoint.state(connection).unwrap(), State::Closed);
            let info = b.execute(server, Op::Transport(1)).unwrap().bytes;
            assert_eq!(info[0], 7); // TCP_CLOSE
            assert_eq!(info[5] & 32, 0); // TCPI_OPT_SYN_DATA
            assert_ne!(b.execute(server, Op::Ready).unwrap().value & EPOLLERR, 0);
            match error_first {
                0 => {
                    if size != 0 {
                        assert_eq!(
                            b.execute(server, Op::Peek(32)).unwrap().bytes,
                            vec![7; size]
                        );
                        assert_eq!(
                            b.execute(server, Op::Read(32)).unwrap().bytes,
                            vec![7; size]
                        );
                    }
                    assert_eq!(b.execute(server, Op::Read(1)).unwrap_err(), ECONNRESET);
                }
                1 => {
                    assert_eq!(
                        b.execute(server, Op::Write(vec![8; 10])).unwrap_err(),
                        ECONNRESET
                    );
                    if size != 0 {
                        assert_eq!(
                            b.execute(server, Op::Read(32)).unwrap().bytes,
                            vec![7; size]
                        );
                    }
                }
                _ => {
                    assert_eq!(
                        b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                            .unwrap()
                            .value,
                        ECONNRESET
                    );
                    assert_eq!(
                        b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                            .unwrap()
                            .value,
                        0
                    );
                    if size != 0 {
                        assert_eq!(
                            b.execute(server, Op::Read(32)).unwrap().bytes,
                            vec![7; size]
                        );
                    }
                }
            }
            assert!(b.execute(server, Op::Read(1)).unwrap().bytes.is_empty());
            assert_eq!(
                b.execute(server, Op::Write(vec![8; 10])).unwrap_err(),
                EPIPE
            );
            assert_eq!(
                b.execute(server, Op::Get(SOL_SOCKET, SO_ERROR))
                    .unwrap()
                    .value,
                0
            );
            let ready = b.execute(server, Op::Ready).unwrap().value;
            assert_eq!(ready & EPOLLERR, 0);
            assert_ne!(ready & EPOLLIN, 0); // EOF stays readable.
            assert_eq!(
                b.execute(listener, Op::Accept(SOCK_NONBLOCK)).unwrap_err(),
                EAGAIN
            );
            assert_eq!(b.execute(listener, Op::Ready).unwrap().value & EPOLLIN, 0);
            b.execute(server, Op::Close).unwrap();
            assert!(!b.sockets.contains_key(&server));
        }
    }
}
