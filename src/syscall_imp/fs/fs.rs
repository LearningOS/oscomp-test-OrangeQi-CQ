use core::ffi::c_char;

use arceos_posix_api as api;

pub(crate) fn sys_getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    api::sys_getcwd(buf, size)
}