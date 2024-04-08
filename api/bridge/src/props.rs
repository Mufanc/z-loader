use std::ffi::{CStr, CString};

extern "C" {
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> u32;
}

pub fn getprop(name: &str) -> String {
    let name = CString::new(name).unwrap();
    let mut buffer = [0u8; 128];
    
    let prop = unsafe {
        __system_property_get(name.as_ptr(), buffer.as_mut_ptr() as _);
        CStr::from_bytes_until_nul(&buffer).unwrap()
    };
    
    prop.to_string_lossy().into()
}
