#![feature(try_blocks)]

use std::{env, panic};

use anyhow::Result;
use log::LevelFilter;
use nix::libc::raise;
use crate::bridge::ApiBridge;

mod macros;
mod monitor;
mod symbols;
mod loader;
mod bridge;

fn install_panic_handler() {
    let default_handler = panic::take_hook();
    
    panic::set_hook(Box::new(move |info| {
        // dump tombstone
        // https://cs.android.com/android/platform/superproject/+/android14-release:bionic/libc/platform/bionic/reserved_signals.h;l=41
        unsafe {
            raise(35 /* BIONIC_SIGNAL_DEBUGGER */);
        }

        default_handler(info);
    }));
}

fn init_logger() {
    if env::var("MAGISK_VER").is_ok() {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(debug_select!(LevelFilter::Trace, LevelFilter::Info))
                .with_tag("ZLoader")
        );
    } else {
        env_logger::init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    install_panic_handler();
    
    // Todo: load from args or environ
    let bridge = ApiBridge {
        library: "/debug_ramdisk/zloader/libzygisk.so".into(),
        specialize_hooks: (
            "specialize_pre".into(),
            "specialize_post".into()
        )
    };
    
    monitor::main(&bridge).await?;

    Ok(())
}
