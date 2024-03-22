use ctor::ctor;
use log::{info, LevelFilter};

#[ctor]
fn init() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("ZLoader-Zygisk")
    );

    info!("loaded");
}

#[no_mangle]
extern "C" fn specialize_pre() {
    info!("pre specialize");
}

#[no_mangle]
extern "C" fn specialize_post() {
    info!("post specialize");
}
