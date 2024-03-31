use std::arch::asm;
use ctor::ctor;
use log::{debug, info, LevelFilter, warn};
use once_cell::sync::OnceCell;

#[no_mangle]
pub static mut ZLB_CALLBACK_PRE: usize = 0;

#[no_mangle]
pub static mut ZLB_TRAMPOLINE: usize = 0;

#[no_mangle]
pub static mut ZLB_RETURN_ADDRESS: usize = 0;

static mut G_BRIDGE: OnceCell<Box<dyn ApiBridge>> = OnceCell::new();

extern {
    fn bridge_main();
}

pub trait ApiBridge: Send + Sync {
    fn on_dlopen(&mut self);
    fn on_specialize(&mut self, args: &mut [u64]);
    fn after_specialize(&mut self);
}

fn require_bridge<'a>() -> &'a mut dyn ApiBridge {
    unsafe {
        G_BRIDGE.get_mut().expect("use of uninitialized api bridge").as_mut()
    }
}

#[ctor]
fn init() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("ZLoader-Bridge")
    );

    unsafe {
        ZLB_CALLBACK_PRE = on_specialize as usize;
        ZLB_TRAMPOLINE = trampoline as usize;
    }

    info!("api bridge initialized");

    unsafe {
        bridge_main();
    }

    require_bridge().on_dlopen();
}

pub fn register(bridge: impl ApiBridge + 'static) {
    unsafe {
        if G_BRIDGE.set(Box::new(bridge)).is_err() {
            warn!("api bridge is already initialized");
        }
    }
}

// `args[n]` is not valid after return, copy and save them
extern "C" fn on_specialize(args: *mut u64, args_len: usize) {
    let args = unsafe {
        std::slice::from_raw_parts_mut(args, args_len)
    };

    info!("on specialize");
    debug!("specialize args = {args:?}");

    require_bridge().on_specialize(args);
}

extern "C" fn after_specialize() {
    info!("after specialize");

    require_bridge().after_specialize();
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
