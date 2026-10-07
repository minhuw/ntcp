use crate::*;
boundary_entry!(fdopen, "ntcp_c_fdopen", (fd: i32, mode: *const c_char) -> *mut FILE);
boundary_entry!(fileno, "ntcp_c_fileno", (stream: *mut FILE) -> i32);
boundary_entry!(fileno_unlocked, "ntcp_c_fileno_unlocked", (stream: *mut FILE) -> i32);
