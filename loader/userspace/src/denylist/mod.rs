use std::env;
use nix::libc;
use common::lazy::Lazy;

mod magisk;
mod kernelsu;

#[derive(Copy, Clone)]
enum RootImpl {
    Magisk,
    KernelSU
}

impl RootImpl {
    fn current() -> Self {
        static CURRENT: Lazy<RootImpl> = Lazy::new(|| {
            if env::var("KSU").is_ok() {
                RootImpl::KernelSU
            } else {
                RootImpl::Magisk
            }
        });
        
        *CURRENT
    }
}

// check if uid contains in denylist
pub fn check(uid: libc::uid_t) -> bool {
    match RootImpl::current() {
        RootImpl::Magisk => {}
        RootImpl::KernelSU => {}
    }
    
    false
}
