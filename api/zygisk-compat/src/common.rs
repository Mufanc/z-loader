use std::mem;

#[derive(Debug)]
#[repr(u8)]
pub enum DaemonSocketAction {
    ReadModules,
}

impl From<u8> for DaemonSocketAction {
    fn from(value: u8) -> Self {
        unsafe { mem::transmute(value) }
    }
}

impl From<DaemonSocketAction> for u8 {
    fn from(value: DaemonSocketAction) -> Self {
        unsafe { mem::transmute(value )}
    }
}
