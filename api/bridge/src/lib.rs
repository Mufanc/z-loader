use std::arch::asm;
use std::env;

use ctor::ctor;
use log::{debug, error, LevelFilter};
use common::debug_select;
use common::zygote::SpecializeArgs;

use common::lazy::LateInit;

#[no_mangle]
pub static mut ZLB_CALLBACK_PRE: usize = 0;

#[no_mangle]
pub static mut ZLB_TRAMPOLINE: usize = 0;

#[no_mangle]
pub static mut ZLB_RETURN_ADDRESS: usize = 0;

static G_BRIDGE: LateInit<Box<dyn ApiBridge>> = LateInit::new();

extern {
    fn bridge_main();
}

pub trait ApiBridge: Send + Sync {
    fn on_dlopen(&self);
    fn on_specialize(&self, args: SpecializeArgs);
    fn after_specialize(&self);
}

#[ctor]
fn init() {
    if env::var("ZLB_NOLOAD").is_ok() {
        return;
    }
    
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("ZLoader-Bridge")
    );

    unsafe {
        ZLB_CALLBACK_PRE = on_specialize as usize;
        ZLB_TRAMPOLINE = trampoline as usize;
    }

    debug!("api bridge initialized");

    unsafe {
        bridge_main();
    }

    G_BRIDGE.on_dlopen()
}

pub fn register(bridge: impl ApiBridge + 'static) {
    if G_BRIDGE.init(Box::new(bridge)).is_err() {
        error!("failed to initialize api bridge");
    }
}

// `args[n]` is not valid after return, copy and save them
extern "C" fn on_specialize(args: *mut u64, _args_len: usize) {
    let args = SpecializeArgs::from(args);

    debug!("on specialize");
    debug!("specialize args = {args:?}");

    G_BRIDGE.on_specialize(args);
}

extern "C" fn after_specialize() {
    debug!("after specialize");

    G_BRIDGE.after_specialize();
    
    // Todo: dlclose
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
        hook = sym after_specialize,
        ra = in(reg) ZLB_RETURN_ADDRESS,
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
        hook = sym after_specialize,
        ra = in(reg) ZLB_RETURN_ADDRESS,
        options(nostack)
    )
}
