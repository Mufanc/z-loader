#![no_std]

#[derive(Debug)]
#[repr(C)]
pub enum EbpfEvent {
    ZygoteStarted(i32),
    ZygoteForked(i32),
    ZygoteCrashed(i32),
    RequireUprobeAttach(i32),
    RequireInject(i32, usize),
    RequireUmount(i32, u32),
}
