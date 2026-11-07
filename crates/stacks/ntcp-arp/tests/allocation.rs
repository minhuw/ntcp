// Storage is allocated fallibly at construction and never afterwards: the
// allocator counts (and can refuse) this thread's allocations.
use core::alloc::{GlobalAlloc, Layout};
use core::net::Ipv4Addr;
use ntcp_arp::*;
use std::{alloc::System, cell::Cell};

std::thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
    static REFUSE: Cell<bool> = const { Cell::new(false) };
}

fn allocate(call: impl FnOnce() -> *mut u8) -> *mut u8 {
    let refuse = REFUSE.try_with(Cell::get).unwrap_or(false);
    let _ = COUNT.try_with(|count| count.set(count.get() + 1));
    if refuse {
        core::ptr::null_mut()
    } else {
        call()
    }
}

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocate(|| unsafe { System.alloc(layout) })
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocate(|| unsafe { System.alloc_zeroed(layout) })
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocate(|| unsafe { System.realloc(ptr, layout, size) })
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn allocations<R>(call: impl FnOnce() -> R) -> (R, usize) {
    let before = COUNT.with(Cell::get);
    let result = call();
    (result, COUNT.with(Cell::get) - before)
}

fn half() -> Option<u32> {
    Some(1 << 31)
}

#[test]
fn storage_is_allocated_fallibly_once() {
    let limits = ArpLimits {
        links: 1,
        entries: 2,
        held: 2,
        replies: 1,
        addresses: 2,
    };
    REFUSE.with(|refuse| refuse.set(true));
    let refused = ArpCache::<u8, u8>::new(limits, ArpTimers::default(), 1000);
    REFUSE.with(|refuse| refuse.set(false));
    assert_eq!(refused.err(), Some(Error::Allocation));

    let mut cache = ArpCache::<u8, u8>::new(limits, ArpTimers::default(), 1000).unwrap();
    let peer = Ipv4Addr::new(192, 0, 2, 2);
    let request = Arp {
        operation: Operation::Request,
        sender_mac: [2, 0, 0, 0, 0, 3],
        sender_ip: Ipv4Addr::new(192, 0, 2, 3),
        target_mac: [0; 6],
        target_ip: Ipv4Addr::new(192, 0, 2, 1),
    };
    let reply = Arp {
        operation: Operation::Reply,
        sender_mac: [2, 0, 0, 0, 0, 2],
        sender_ip: peer,
        target_mac: [2, 0, 0, 0, 0, 1],
        target_ip: Ipv4Addr::new(192, 0, 2, 1),
    };
    let ((), count) = allocations(|| {
        cache.add_link(0, [2, 0, 0, 0, 0, 1], &mut half).unwrap();
        let local = Ipv4Addr::new(192, 0, 2, 1);
        cache.add_address(0, local, AddressKind::Local).unwrap();
        let published = AddressKind::Published([2, 0, 0, 0, 0, 9]);
        cache
            .add_address(0, Ipv4Addr::new(192, 0, 2, 9), published)
            .unwrap();
        // Tables at their bounds: refusals, eviction and overflow.
        assert_eq!(cache.resolve(0, peer, 0, 1), Ok(Resolution::Held));
        cache.receive(0, &request, 0, &mut half).unwrap();
        cache.receive(0, &request, 0, &mut half).unwrap();
        let third = Ipv4Addr::new(192, 0, 2, 4);
        assert_eq!(cache.resolve(0, third, 0, 2), Ok(Resolution::Held));
        assert_eq!(cache.resolve(0, peer, 0, 3), Err(Error::Capacity));
        let mut frame = [0; 60];
        for now in (0..40_000).step_by(500) {
            cache.service(now, &mut |_| {});
            while let Some((control, token)) = cache.next_control(0, now) {
                control.encode(&mut frame).unwrap();
                cache.complete(token, ControlOutcome::Submitted, now);
            }
            if now == 500 {
                cache.receive(0, &reply, now, &mut half).unwrap();
            }
            while cache.next_wake(|_| true).is_some() {}
            let _ = cache.resolve(0, peer, now, 1);
            cache.confirm(0, peer, now, now, &mut half).unwrap();
            let _ = cache.next_deadline();
        }
        cache.remove_link(0);
    });
    assert_eq!(count, 0);
}
