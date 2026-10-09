extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use std::{alloc::System, cell::Cell};

std::thread_local! {
    static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
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
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail() {
            core::ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if fail() {
            core::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

pub(crate) fn fail_after<T>(count: usize, call: impl FnOnce() -> T) -> T {
    FAIL_AFTER.with(|remaining| remaining.set(Some(count)));
    let result = call();
    FAIL_AFTER.with(|remaining| remaining.set(None));
    result
}
