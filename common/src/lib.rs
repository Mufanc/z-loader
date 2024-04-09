use std::panic;
use log::debug;

#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug_select {
    ($debug: expr, $release: expr) => {
        $debug
    };
}

#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug_select {
    ($debug: expr, $release: expr) => {
        $release
    };
}

pub fn dump_tombstone_on_panic() {
    let default_handler = panic::take_hook();

    panic::set_hook(Box::new(move |info| {
        // dump tombstone
        // https://cs.android.com/android/platform/superproject/+/android14-release:bionic/libc/platform/bionic/reserved_signals.h;l=41
        unsafe {
            libc::raise(35 /* BIONIC_SIGNAL_DEBUGGER */);
            debug!("dumping tombstone...");
        }

        default_handler(info);
    }));
}
