#![no_std]

#[derive(Debug)]
pub enum EbpfEvent {
    ZygoteStarted(i32),
    ZygoteForked(i32),
    UprobeAttach(i32)
}
