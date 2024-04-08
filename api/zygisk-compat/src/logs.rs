use std::ops::Deref;
use std::process;
use std::sync::OnceLock;

pub static PID: Lazy<i32> = Lazy::new(|| process::id() as i32);


pub struct Lazy<T> {
    lock: OnceLock<T>,
    init_fn: fn() -> T
}

impl<T> Lazy<T> {
    pub const fn new(init_fn: fn() -> T) -> Self {
        Self {
            lock: OnceLock::new(),
            init_fn
        }
    }

    pub fn initialized(&self) -> bool {
        self.lock.get().is_some()
    }
}

impl<T> Deref for Lazy<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        if !self.initialized() {
            let _ = self.lock.set((self.init_fn)());
        }
        
        self.lock.get().unwrap()
    }
}

#[macro_export]
macro_rules! info {
    ($fmt: literal $( ,$args: expr )*) => {
        log::info!(concat!("[{}] ", $fmt), *crate::logs::PID, $( $args ),*);
    };
}

#[macro_export]
macro_rules! debug {
    ($fmt: literal $( ,$args: expr )*) => {
        log::debug!(concat!("[{}] ", $fmt), *crate::logs::PID, $( $args ),*);
    };
}
