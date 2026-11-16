extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use std::{alloc::System, cell::Cell};

std::thread_local! {
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    // Net bytes allocated on this thread while `counting` runs.
    static COUNTING: Cell<Option<isize>> = const { Cell::new(None) };
}

fn count(bytes: isize) {
    let _ = COUNTING.try_with(|live| {
        if let Some(total) = live.get() {
            live.set(Some(total + bytes));
        }
    });
}

fn fail() -> bool {
    FAIL_AFTER
        .try_with(|count| match count.get() {
            Some(0) => {
                count.set(None);
                true
            }
            Some(n) => {
                count.set(Some(n - 1));
                false
            }
            None => false,
        })
        .unwrap_or(false)
}

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail() {
            return core::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            count(layout.size() as isize);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail() {
            return core::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            count(layout.size() as isize);
        }
        pointer
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail() {
            return core::ptr::null_mut();
        }
        let pointer = unsafe { System.realloc(ptr, layout, size) };
        if !pointer.is_null() {
            count(size as isize - layout.size() as isize);
        }
        pointer
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
}

pub(crate) fn fail_after<T>(count: usize, call: impl FnOnce() -> T) -> T {
    FAIL_AFTER.with(|remaining| remaining.set(Some(count)));
    let result = call();
    FAIL_AFTER.with(|remaining| remaining.set(None));
    result
}

// Runs `call` with this thread's allocations counted into `live`: the net
// bytes allocated by everything `call` does, frees of memory allocated
// earlier included.
pub(crate) fn counting<T>(live: &mut isize, call: impl FnOnce() -> T) -> T {
    COUNTING.with(|count| count.set(Some(*live)));
    let result = call();
    *live = COUNTING.with(|count| count.take()).unwrap();
    result
}
