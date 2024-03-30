use std::arch::asm;

use ctor::ctor;
use log::info;


#[no_mangle]
pub static mut BRIDGE_CALLBACK_BEFORE: usize = 0;

#[no_mangle]
pub static mut BRIDGE_TRAMPOLINE: usize = 0;

#[no_mangle]
pub static mut BRIDGE_RETURN_ADDR: usize = 0;


#[ctor]
fn constructor() {
    unsafe {
        BRIDGE_CALLBACK_BEFORE = pre_specialize as usize;
        BRIDGE_TRAMPOLINE = trampoline as usize;
    }
}


// `args[n]` is not valid after return, copy and save them.
extern "C" fn pre_specialize(_args: *const u64, _args_len: usize) {
    info!("pre specialize");
}

extern "C" fn post_specialize() {
    info!("post specialize");
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn trampoline() {
    asm!(
        "push {ra}",    // 1. backup return address
        "push 0",       // 2. keep stack aligned (*)
        "call {hook}",  // 3. call hook callback
        "pop rax",      // 4. (*) skip
        "pop rax",      // 5. restore return address
        "jmp rax",      // 6. jump out!
        hook = sym post_specialize,
        ra = in(reg) BRIDGE_RETURN_ADDR,
        options(nostack)
    )
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" fn trampoline() {
    asm!(
        "stp {ra}, xzr, [sp, -0x10]!",  // 1. backup return address
        "bl {hook}",                    // 2. call hook callback
        "ldp x30, xzr, [sp], 0x10",     // 3. restore return address
        "ret",                          // 4. jump out!
        hook = sym post_specialize,
        ra = in(reg) BRIDGE_RETURN_ADDR,
        options(nostack)
    )
}
