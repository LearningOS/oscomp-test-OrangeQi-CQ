use core::{error, ffi::{c_char, c_int, c_void}, ptr::null};

use arceos_posix_api::{self as api, ctypes::mode_t};
use axerrno::{LinuxResult, LinuxError};
use linux_raw_sys::{ctypes, general::__kernel_size_t};
// use linux_raw_sys::general::iovec;

use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut ctypes::c_void,
    pub iov_len: __kernel_size_t,
}

impl Default for iovec {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}


impl PartialEq for iovec {
    fn eq(&self, other: &Self) -> bool {
        self.iov_base == other.iov_base && self.iov_len == other.iov_len
    }
}


impl Eq for iovec {}

pub fn sys_read(fd: i32, buf: UserPtr<c_void>, count: usize) -> LinuxResult<isize> {
    let buf = buf.get_as_bytes(count)?;
    Ok(api::sys_read(fd, buf, count))
}

pub fn sys_readv(fd: c_int, iov: UserPtr<iovec>, iocnt: usize) -> LinuxResult<isize> {
    if !(0..=1024).contains(&iocnt) {
        return Err(LinuxError::EINVAL);
    }

    let iovs = iov.get_as_mut_slice(iocnt)?;
    let mut ret = 0;

    
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let buf = UserPtr::<u8>::from(iov.iov_base as usize);
        let buf = buf.get_as_mut_slice(iov.iov_len as _)?;
        let read = api::get_file_like(fd)?.read(buf)?;
        
        ret += read as isize;
        if read < buf.len() {
            break;
        }
    }
    error!("check sys_readv");
    Ok(ret)
}


pub fn sys_write(fd: i32, buf: UserConstPtr<c_void>, count: usize) -> LinuxResult<isize> {
    let buf = buf.get_as_bytes(count)?;
    Ok(api::sys_write(fd, buf, count))
}

pub fn sys_writev(fd: i32, iov: UserConstPtr<iovec>, iocnt: usize) -> LinuxResult<isize> {
    if !(0..=1024).contains(&iocnt) {
        return Err(LinuxError::EINVAL);
    }

    let iovs = iov.get_as_slice(iocnt)?;
    let mut ret = 0;
    for iov in iovs {
        if iov.iov_len == 0 {
            continue;
        }
        let buf = UserConstPtr::<u8>::from(iov.iov_base as usize);
        let buf = buf.get_as_slice(iov.iov_len as _)?;
        debug!(
            "sys_writev <= fd: {}, buf: {:p}, len: {}",
            fd,
            buf.as_ptr(),
            buf.len()
        );

        let written = api::get_file_like(fd)?.write(buf)?;
        ret += written as isize;

        if written < buf.len() {
            break;
        }
    }

    Ok(ret)
}

// pub fn sys_writev(
//     fd: i32,
//     iov: UserConstPtr<api::ctypes::iovec>,
//     iocnt: i32,
// ) -> LinuxResult<isize> {
//     let iov = iov.get_as_bytes(iocnt as _)?;
//     unsafe { Ok(api::sys_writev(fd, iov, iocnt)) }
// }

pub fn sys_openat(
    dirfd: i32,
    path: UserConstPtr<c_char>,
    flags: i32,
    modes: mode_t,
) -> LinuxResult<isize> {
    let path = path.get_as_null_terminated()?;
    Ok(api::sys_openat(dirfd, path.as_ptr(), flags, modes) as _)
}

pub fn sys_open(path: UserConstPtr<c_char>, flags: i32, modes: mode_t) -> LinuxResult<isize> {
    use arceos_posix_api::AT_FDCWD;
    sys_openat(AT_FDCWD as _, path, flags, modes)
}

pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> LinuxResult<isize> {
    Ok(api::sys_lseek(fd, offset, whence) as isize)
}