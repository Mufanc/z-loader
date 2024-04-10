use std::process;
use common::lazy::Lazy;

pub static PID: Lazy<i32> = Lazy::new(|| process::id() as i32);

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! info {
    ($fmt: literal $( ,$args: expr )*) => {
        log::info!(concat!("[{}] ", $fmt), *crate::logs::PID, $( $args ),*);
    };
}

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! debug {
    ($fmt: literal $( ,$args: expr )*) => {
        log::debug!(concat!("[{}] ", $fmt), *crate::logs::PID, $( $args ),*);
    };
}
