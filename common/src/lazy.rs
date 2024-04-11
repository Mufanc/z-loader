use std::ops::Deref;
use std::sync::OnceLock;

pub use once_cell::sync::Lazy;

pub struct LateInit<T> {
    lock: OnceLock<T>
}

impl<T> LateInit<T> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self { lock: OnceLock::new() }
    }

    pub fn init(&self, value: T) -> Result<(), T> {
        self.lock.set(value)
    }
    
    pub fn initialized(&self) -> bool {
        self.lock.get().is_some()
    }
}

impl<T> Deref for LateInit<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.lock.get().unwrap()
    }
}
