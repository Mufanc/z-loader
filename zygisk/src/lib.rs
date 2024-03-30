use ctor::ctor;
use log::{info, LevelFilter};

mod bridge;


#[ctor]
fn main() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("ZLoader-Zygisk")
    );

    info!("bridge: loaded");
}
