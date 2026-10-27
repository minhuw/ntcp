use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

fn config() -> Config {
    Config {
        max_flows: 3,
        max_packets: 16,
        max_retained_bytes: 100,
        quantum: 1000,
    }
}

fn metadata(wire_bytes: u64, retained_bytes: usize, not_before: u64) -> Metadata {
    Metadata {
        wire_bytes,
        retained_bytes,
        not_before,
    }
}

fn ready<P>(scheduler: &mut Scheduler<P>, now: u64) -> TryToken {
    let mut budget = 100;
    match scheduler.poll_ready(now, &mut budget).unwrap() {
        Poll::Ready(attempt) => attempt.token,
        _ => panic!("expected ready"),
    }
}

fn returned<P>(scheduler: &mut Scheduler<P>, token: TryToken, outcome: Outcome) -> Returned<P> {
    match scheduler.resolve(token, outcome).unwrap() {
        Resolution::Returned(packet) => packet,
        Resolution::Retried => panic!("expected returned ownership"),
    }
}

#[test]
fn byte_fairness_mixed_packet_sizes_and_fifo() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            max_packets: 4000,
            max_retained_bytes: 0,
            ..config()
        },
    )
    .unwrap();
    let small = scheduler.open_flow(1).unwrap();
    let large = scheduler.open_flow(2).unwrap();
    for ordinal in 0..2000 {
        scheduler
            .enqueue(small, metadata(100, 0, 0), (0, ordinal))
            .unwrap();
        scheduler
            .enqueue(large, metadata(900, 0, 0), (1, ordinal))
            .unwrap();
    }
    let mut bytes = [0_u64; 2];
    let mut counts = [0; 2];
    for _ in 0..1500 {
        let token = ready(&mut scheduler, 0);
        let packet = returned(&mut scheduler, token, Outcome::Accepted);
        let (flow, ordinal) = packet.payload;
        assert_eq!(ordinal, counts[flow]);
        counts[flow] += 1;
        bytes[flow] += packet.metadata.wire_bytes;
        assert!(bytes[0].abs_diff(bytes[1]) <= 1900, "{bytes:?}");
    }
    assert!(counts[0] > counts[1] * 8);
}

#[test]
fn delayed_fifo_head_and_blocked_backend_do_not_block_other_flows() {
    let mut scheduler = Scheduler::new(1, config()).unwrap();
    let a = scheduler.open_flow(10).unwrap();
    let b = scheduler.open_flow(20).unwrap();
    scheduler.enqueue(a, metadata(1, 1, 50), "a-first").unwrap();
    scheduler.enqueue(a, metadata(1, 1, 0), "a-second").unwrap();
    scheduler.enqueue(b, metadata(1, 1, 0), "b-first").unwrap();
    let token = ready(&mut scheduler, 10);
    assert_eq!(*scheduler.view(token).unwrap().payload, "b-first");
    scheduler
        .resolve(token, Outcome::Retry { not_before: 80 })
        .unwrap();
    assert!(matches!(
        scheduler.poll_ready(49, &mut 20).unwrap(),
        Poll::Idle
    ));
    let token = ready(&mut scheduler, 50);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        "a-first"
    );
    let token = ready(&mut scheduler, 50);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        "a-second"
    );
    let token = ready(&mut scheduler, 80);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        "b-first"
    );
}

#[test]
fn multiple_leases_retry_cancel_and_stale_handles() {
    let mut scheduler = Scheduler::new(1, config()).unwrap();
    let a = scheduler.open_flow(10).unwrap();
    let b = scheduler.open_flow(20).unwrap();
    let first = scheduler.enqueue(a, metadata(600, 5, 0), 1).unwrap();
    let second = scheduler.enqueue(a, metadata(600, 5, 0), 2).unwrap();
    scheduler.enqueue(b, metadata(100, 5, 0), 3).unwrap();
    let t1 = ready(&mut scheduler, 0);
    let t2 = ready(&mut scheduler, 0);
    assert_eq!(t1.packet_id(), first);
    assert_eq!(t2.packet_id().flow, b);
    assert_eq!(scheduler.view(t1).unwrap().payload, &1);
    assert!(matches!(scheduler.cancel(first), Err(Error::Busy)));
    assert_eq!(scheduler.disable_flow(a), Err(Error::Busy));
    assert!(matches!(
        scheduler.poll_ready(0, &mut 20).unwrap(),
        Poll::Idle
    ));
    assert!(matches!(
        scheduler.resolve(
            t1,
            Outcome::Retry {
                not_before: u64::MAX
            }
        ),
        Err(Error::InvalidMetadata)
    ));
    assert!(scheduler.view(t1).is_ok());
    let deficit = scheduler.flows[a.slot].deficit;
    scheduler
        .resolve(t1, Outcome::Retry { not_before: 0 })
        .unwrap();
    assert!(matches!(
        scheduler.resolve(t1, Outcome::Accepted),
        Err(Error::StaleToken)
    ));
    for _ in 0..10 {
        let token = ready(&mut scheduler, 0);
        assert_eq!(token.packet_id(), first);
        assert_eq!(scheduler.flows[a.slot].deficit, deficit);
        scheduler
            .resolve(token, Outcome::Retry { not_before: 0 })
            .unwrap();
    }
    assert_eq!(scheduler.cancel(first).unwrap().payload, 1);
    assert_eq!(scheduler.flows[a.slot].deficit, deficit); // No refund on cancel.
    assert!(scheduler.cancel(first).is_err());
    let t3 = ready(&mut scheduler, 0);
    assert_eq!(t3.packet_id(), second);
    assert_eq!(
        returned(&mut scheduler, t3, Outcome::Dropped).disposition,
        Disposition::Dropped
    );
    assert_eq!(
        returned(&mut scheduler, t2, Outcome::Unknown).disposition,
        Disposition::Quarantined
    );
    assert!(matches!(
        scheduler.resolve(t2, Outcome::Accepted),
        Err(Error::StaleToken)
    ));
    assert_eq!(scheduler.usage().packets, 0);
    assert_eq!(scheduler.usage().retained_bytes, 0);
    scheduler.disable_flow(a).unwrap();
    let replacement = scheduler.open_flow(10).unwrap();
    assert_ne!(replacement, a);
    let failure = scheduler.enqueue(a, metadata(1, 1, 0), 99).unwrap_err();
    assert_eq!((failure.error, failure.payload), (Error::StaleKey, 99));
    assert_eq!(scheduler.disable_flow(a), Err(Error::StaleKey));
}

#[test]
fn bounded_admission_rolls_back_and_returns_payload_exactly_once() {
    #[derive(Debug)]
    struct Payload(Rc<Cell<usize>>);
    impl Drop for Payload {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut scheduler = Scheduler::new(
        1,
        Config {
            max_flows: 1,
            max_packets: 2,
            max_retained_bytes: 10,
            ..config()
        },
    )
    .unwrap();
    let key = scheduler.open_flow(1).unwrap();
    assert_eq!(scheduler.open_flow(2), Err(Error::FlowLimit));
    let first = scheduler
        .enqueue(key, metadata(1, 7, 0), Payload(drops.clone()))
        .unwrap();
    let usage = scheduler.usage();
    let ordinal = scheduler.ordinal;
    let failure = scheduler
        .enqueue(key, metadata(1, 4, 0), Payload(drops.clone()))
        .unwrap_err();
    assert_eq!(failure.error, Error::RetainedLimit);
    assert_eq!(scheduler.usage(), usage);
    assert_eq!(scheduler.ordinal, ordinal);
    assert_eq!(drops.get(), 0);
    let second = scheduler
        .enqueue(key, metadata(1, 3, 0), failure.payload)
        .unwrap();
    let failure = scheduler
        .enqueue(key, metadata(1, 0, 0), Payload(drops.clone()))
        .unwrap_err();
    assert_eq!(failure.error, Error::PacketLimit);
    assert_eq!(scheduler.usage().retained_bytes, 10);
    drop(failure.payload);
    assert_eq!(drops.get(), 1);
    drop(scheduler.cancel(second).unwrap()); // Tail unlink.
    drop(scheduler.cancel(first).unwrap());
    assert_eq!(drops.get(), 3);
    assert_eq!(
        scheduler.usage(),
        Usage {
            flows: 1,
            packets: 0,
            retained_bytes: 0
        }
    );
    scheduler
        .enqueue(key, metadata(1, 10, 0), Payload(drops.clone()))
        .unwrap();
    drop(scheduler);
    assert_eq!(drops.get(), 4);
    assert!(matches!(
        Scheduler::<()>::new(
            1,
            Config {
                max_packets: usize::MAX,
                ..config()
            }
        ),
        Err(Error::Allocation)
    ));
}

#[test]
fn cancellation_unlinks_middle_and_retained_sum_cannot_overflow() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            max_retained_bytes: usize::MAX,
            ..config()
        },
    )
    .unwrap();
    let key = scheduler.open_flow(1).unwrap();
    let first = scheduler
        .enqueue(key, metadata(1, usize::MAX, 0), 1)
        .unwrap();
    let failure = scheduler.enqueue(key, metadata(1, 1, 0), 99).unwrap_err();
    assert_eq!(failure.error, Error::RetainedLimit);
    let middle = scheduler.enqueue(key, metadata(1, 0, 0), 2).unwrap();
    scheduler.enqueue(key, metadata(1, 0, 0), 3).unwrap();
    assert_eq!(scheduler.cancel(middle).unwrap().payload, 2);
    assert_eq!(scheduler.cancel(first).unwrap().payload, 1);
    let token = ready(&mut scheduler, 0);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        3
    );
    assert_eq!(scheduler.usage().retained_bytes, 0);
}

#[test]
fn bounded_poll_progress_and_monotonic_clock_at_max() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            quantum: 1,
            ..config()
        },
    )
    .unwrap();
    let key = scheduler.open_flow(1).unwrap();
    for meta in [metadata(0, 0, 0), metadata(1, 0, u64::MAX)] {
        assert_eq!(
            scheduler.enqueue(key, meta, ()).unwrap_err().error,
            Error::InvalidMetadata
        );
    }
    scheduler
        .enqueue(key, metadata(3, 0, u64::MAX - 1), ())
        .unwrap();
    assert!(matches!(
        scheduler.poll_ready(u64::MAX - 2, &mut 10).unwrap(),
        Poll::Idle
    ));
    assert!(matches!(
        scheduler.poll_ready(u64::MAX - 1, &mut 0).unwrap(),
        Poll::BudgetExhausted
    ));
    let mut budget = 1;
    assert!(matches!(
        scheduler.poll_ready(u64::MAX - 1, &mut budget).unwrap(),
        Poll::BudgetExhausted
    ));
    assert_eq!(budget, 0);
    assert!(matches!(
        scheduler.poll_ready(u64::MAX, &mut 10),
        Err(Error::InvalidClock)
    ));
    assert!(matches!(
        scheduler.poll_ready(0, &mut 10),
        Err(Error::InvalidClock)
    ));
    let token = ready(&mut scheduler, u64::MAX - 1);
    returned(&mut scheduler, token, Outcome::Accepted);
    assert!(matches!(
        scheduler.poll_ready(u64::MAX - 1, &mut 10).unwrap(),
        Poll::Idle
    ));
}

#[test]
fn counters_fail_closed_and_large_deficits_do_not_wrap() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            quantum: u64::MAX,
            ..config()
        },
    )
    .unwrap();
    scheduler.generation = u64::MAX - 1;
    let key = scheduler.open_flow(1).unwrap();
    assert_eq!(scheduler.open_flow(2), Err(Error::Exhausted));
    scheduler.ordinal = u64::MAX - 1;
    let first = scheduler.enqueue(key, metadata(u64::MAX, 1, 0), 1).unwrap();
    assert_eq!(
        scheduler
            .enqueue(key, metadata(1, 1, 0), 2)
            .unwrap_err()
            .error,
        Error::Exhausted
    );
    scheduler.attempt = u64::MAX - 1;
    let token = ready(&mut scheduler, 0);
    assert_eq!(scheduler.flows[key.slot].deficit, 0);
    scheduler
        .resolve(token, Outcome::Retry { not_before: 0 })
        .unwrap();
    assert!(matches!(
        scheduler.poll_ready(0, &mut 10),
        Err(Error::Exhausted)
    ));
    assert_eq!(scheduler.cancel(first).unwrap().payload, 1);
    scheduler.disable_flow(key).unwrap();
    assert_eq!(scheduler.open_flow(1), Err(Error::Exhausted));
}

#[test]
fn pending_leases_preserve_credit_and_namespace_rejects_foreign_tokens() {
    let mut scheduler = Scheduler::new(1, config()).unwrap();
    let key = scheduler.open_flow(1).unwrap();
    scheduler.enqueue(key, metadata(1, 0, 0), 1).unwrap();
    scheduler.enqueue(key, metadata(1, 0, 0), 2).unwrap();
    let token = ready(&mut scheduler, 0);
    for _ in 0..20 {
        assert!(matches!(
            scheduler.poll_ready(0, &mut 10).unwrap(),
            Poll::Idle
        ));
    }
    assert_eq!(scheduler.flows[key.slot].deficit, 999);
    returned(&mut scheduler, token, Outcome::Accepted);
    let token = ready(&mut scheduler, 0);
    assert_eq!(scheduler.flows[key.slot].deficit, 998);
    let mut foreign = Scheduler::new(2, config()).unwrap();
    let other = foreign.open_flow(1).unwrap();
    foreign.enqueue(other, metadata(1, 0, 0), 1).unwrap();
    let foreign_token = ready(&mut foreign, 0);
    assert!(matches!(
        scheduler.resolve(foreign_token, Outcome::Accepted),
        Err(Error::StaleToken)
    ));
    assert!(scheduler.view(token).is_ok());
}

#[test]
fn large_packet_credit_work_is_bounded_and_does_not_starve_small_flow() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            quantum: 1,
            ..config()
        },
    )
    .unwrap();
    let large = scheduler.open_flow(1).unwrap();
    let small = scheduler.open_flow(2).unwrap();
    scheduler
        .enqueue(large, metadata(u64::MAX, 0, 0), 1)
        .unwrap();
    scheduler.enqueue(small, metadata(1, 0, 0), 2).unwrap();
    let token = ready(&mut scheduler, 0);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        2
    );
    let mut budget = 100;
    assert!(matches!(
        scheduler.poll_ready(0, &mut budget).unwrap(),
        Poll::BudgetExhausted
    ));
    assert_eq!(budget, 0);
    assert_eq!(scheduler.usage().packets, 1);
}

#[test]
fn deficit_above_u64_and_reused_packet_slots_are_safe() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            quantum: u64::MAX,
            ..config()
        },
    )
    .unwrap();
    let key = scheduler.open_flow(1).unwrap();
    let old_id = scheduler
        .enqueue(key, metadata(u64::MAX - 1, 0, 0), 1)
        .unwrap();
    scheduler.enqueue(key, metadata(u64::MAX, 0, 0), 2).unwrap();
    let old_token = ready(&mut scheduler, 0);
    returned(&mut scheduler, old_token, Outcome::Accepted);
    assert_eq!(scheduler.flows[key.slot].deficit, 1);
    let new_id = scheduler.enqueue(key, metadata(1, 0, 0), 3).unwrap();
    assert_eq!(old_id.slot, new_id.slot);
    assert!(matches!(scheduler.cancel(old_id), Err(Error::StalePacket)));
    assert!(matches!(
        scheduler.resolve(old_token, Outcome::Accepted),
        Err(Error::StaleToken)
    ));
    let token = ready(&mut scheduler, 0);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        2
    );
    assert_eq!(scheduler.flows[key.slot].deficit, 1);
    let token = ready(&mut scheduler, 0);
    assert_eq!(
        returned(&mut scheduler, token, Outcome::Accepted).payload,
        3
    );
}

#[test]
fn immediate_retry_keeps_retained_charge_without_hogging_other_flows() {
    let mut scheduler = Scheduler::new(
        1,
        Config {
            max_packets: 33,
            ..config()
        },
    )
    .unwrap();
    let blocked = scheduler.open_flow(1).unwrap();
    let working = scheduler.open_flow(2).unwrap();
    let blocked_id = scheduler.enqueue(blocked, metadata(1000, 1, 0), 0).unwrap();
    for ordinal in 1..=32 {
        scheduler
            .enqueue(working, metadata(1000, 1, 0), ordinal)
            .unwrap();
    }
    let mut completed = 0;
    for _ in 0..100 {
        let token = ready(&mut scheduler, 0);
        if token.packet_id() == blocked_id {
            let before = scheduler.usage();
            scheduler
                .resolve(token, Outcome::Retry { not_before: 0 })
                .unwrap();
            assert_eq!(scheduler.usage(), before);
            assert_eq!(scheduler.flows[blocked.slot].deficit, 0);
        } else {
            completed += 1;
            assert_eq!(
                returned(&mut scheduler, token, Outcome::Accepted).payload,
                completed
            );
        }
        assert_eq!(scheduler.usage().retained_bytes, 33 - completed);
        if completed == 32 {
            break;
        }
    }
    assert_eq!(completed, 32);
    assert_eq!(scheduler.usage().packets, 1);
    assert_eq!(
        scheduler.cancel(blocked_id).unwrap().disposition,
        Disposition::Cancelled
    );
    assert_eq!(scheduler.usage().retained_bytes, 0);
}

#[test]
fn continuously_refilled_flow_does_not_starve_backlogged_flow() {
    let mut scheduler = Scheduler::new(1, config()).unwrap();
    let a = scheduler.open_flow(1).unwrap();
    let b = scheduler.open_flow(2).unwrap();
    scheduler.enqueue(a, metadata(1000, 1, 0), (0, 0)).unwrap();
    for ordinal in 0..8 {
        scheduler
            .enqueue(b, metadata(1000, 1, 0), (1, ordinal))
            .unwrap();
    }
    let mut counts = [0_usize; 2];
    for _ in 0..16 {
        let token = ready(&mut scheduler, 0);
        let (flow, ordinal) = returned(&mut scheduler, token, Outcome::Accepted).payload;
        assert_eq!(ordinal, counts[flow]);
        counts[flow] += 1;
        if flow == 0 {
            assert!(scheduler.flows[a.slot].head.is_none());
            scheduler
                .enqueue(a, metadata(1000, 1, 0), (0, counts[0]))
                .unwrap();
        }
        assert!(counts[0].abs_diff(counts[1]) <= 1, "{counts:?}");
    }
    assert_eq!(counts, [8, 8]);
}

#[test]
fn exhausted_poll_preserves_all_state_and_previous_clock() {
    let mut scheduler = Scheduler::new(1, config()).unwrap();
    let a = scheduler.open_flow(1).unwrap();
    let b = scheduler.open_flow(2).unwrap();
    let payload = Rc::new(());
    scheduler
        .enqueue(a, metadata(100, 3, 0), payload.clone())
        .unwrap();
    let lease = ready(&mut scheduler, 5);
    scheduler
        .enqueue(b, metadata(1500, 7, 0), payload.clone())
        .unwrap();
    scheduler
        .enqueue(b, metadata(100, 9, 30), payload.clone())
        .unwrap();
    scheduler.attempt = u64::MAX;
    // Snapshot every scheduler field, including FIFO/free links and payload ownership.
    let snapshot = |s: &Scheduler<Rc<()>>| {
        (
            (
                s.namespace,
                s.config,
                s.free,
                s.usage,
                s.generation,
                s.ordinal,
                s.attempt,
                s.now,
                s.cursor,
            ),
            s.flows
                .iter()
                .map(|f| (f.key, f.head, f.tail, f.deficit, f.in_turn))
                .collect::<Vec<_>>(),
            s.packets
                .iter()
                .map(|slot| {
                    (
                        slot.next,
                        slot.packet.as_ref().map(|p| {
                            (
                                p.id,
                                Rc::as_ptr(&p.payload),
                                Rc::strong_count(&p.payload),
                                p.metadata,
                                p.lease,
                                p.paid,
                            )
                        }),
                    )
                })
                .collect::<Vec<_>>(),
        )
    };
    let before = snapshot(&scheduler);
    let mut budget = 20;
    assert!(matches!(
        scheduler.poll_ready(10, &mut budget),
        Err(Error::Exhausted)
    ));
    assert_eq!(budget, 20);
    assert_eq!(snapshot(&scheduler), before);
    assert!(scheduler.view(lease).is_ok());
    assert!(matches!(
        scheduler.poll_ready(5, &mut budget),
        Err(Error::Exhausted)
    ));
    assert_eq!(snapshot(&scheduler), before);
    assert_eq!(budget, 20);
    // Restore only the test-injected exhaustion to demonstrate the old clock still works.
    scheduler.attempt = 1;
    let token = ready(&mut scheduler, 5);
    assert_eq!(token.packet_id().flow, b);
    assert!(scheduler.view(lease).is_ok());
}
