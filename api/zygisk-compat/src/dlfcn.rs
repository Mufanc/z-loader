use std::ffi::{c_void, CStr, CString};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr;

use anyhow::{bail, Result};

#[repr(C)]
struct ExtInfo {
    flags: u64,
    reserved_addr: *const c_void,
    reserved_size: libc::size_t,
    relro_fd: libc::c_int,
    library_fd: libc::c_int,
    library_fd_offset: libc::off64_t,
    library_namespace: *const c_void,
}

extern "C" {
    fn android_dlopen_ext(filename: *const libc::c_char, flags: libc::c_int, ext_info: *const ExtInfo) -> *const c_void;
}

fn dlerror() -> Result<()> {
    let err = unsafe {
        CStr::from_ptr(libc::dlerror()).to_string_lossy()
    };
    
    bail!("dlopen failed: {err}");  // Todo: error handling
}

pub struct LibraryHandle(*const c_void);

pub fn dlopen_fd(fd: BorrowedFd, flags: libc::c_int) -> Result<LibraryHandle> {
    let filename = c"/jit-cache";
    let info = ExtInfo {
        flags: 0x10,  // ANDROID_DLEXT_USE_LIBRARY_FD
        reserved_addr: ptr::null(),
        reserved_size: 0,
        relro_fd: 0,
        library_fd: fd.as_raw_fd(),
        library_fd_offset: 0,
        library_namespace: ptr::null(),
    };

    unsafe {
        let handle = android_dlopen_ext(filename.as_ptr() as _, flags, &info);

        if handle.is_null() {
            dlerror()?;
        }

        Ok(LibraryHandle(handle))
    }
}

pub fn dlsym(handle: LibraryHandle, symbol: &str) -> Result<*const c_void> {
    let symbol = CString::new(symbol).unwrap();
    
    unsafe {
        let addr = libc::dlsym(handle.0 as _, symbol.as_ptr());
        
        if addr.is_null() {
            dlerror()?;
        }
        
        Ok(addr)
    }
}
