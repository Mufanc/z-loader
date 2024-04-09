#![feature(try_blocks)]
#![feature(duration_constructors)]

use std::env;

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use common::{debug_select, dump_tombstone_on_panic};

mod macros;
mod monitor;
mod symbols;
mod loader;

#[derive(Parser, Debug)]
struct Args {
    #[clap(index = 1)]
    bridge: String,
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
    dump_tombstone_on_panic();

    let args = Args::parse();
    monitor::main(&args.bridge).await?;

    Ok(())
}
