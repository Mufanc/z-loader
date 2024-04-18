#![feature(try_blocks)]
#![feature(duration_constructors)]

use anyhow::Result;
use clap::Parser;
use log::LevelFilter;
use common::debug_select;
use common::utils::dump_tombstone_on_panic;

mod macros;
mod monitor;
mod symbols;
mod loader;
mod denylist;

#[derive(Parser, Debug)]
struct Args {
    #[clap(index = 1)]
    bridge: String,
    
    #[clap(short, long)]
    filter: Option<String>
}

fn init_logger() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("ZLoader-Core")
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    dump_tombstone_on_panic();

    let args = Args::parse();
    monitor::main(&args.bridge, args.filter.as_deref()).await?;

    Ok(())
}
