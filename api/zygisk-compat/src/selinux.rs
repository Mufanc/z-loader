use std::ffi::{CStr, CString};
use std::path::Path;

use anyhow::Result;
use nix::errno::Errno;
use nix::NixPath;

const XATTR_NAME_SELINUX: &CStr = c"security.selinux";

pub fn chcon<P : AsRef<Path>>(file: P, con: &str) -> Result<()> {
    let file = CString::new(file.as_ref().to_str().unwrap())?;
    let con = CString::new(con)?;

    Errno::result(unsafe {
        libc::lsetxattr(
            file.as_ptr(),
            XATTR_NAME_SELINUX.as_ptr(),
            con.as_ptr() as _,
            con.len() + 1,
            0
        )
    })?;
    
    Ok(())
}
