use std::ops::Deref;
use std::sync::OnceLock;

pub struct LateInit<T> {
    lock: OnceLock<T>
}

impl<T> LateInit<T> {
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

pub struct Lazy<T> {
    initializer: fn() -> T,
    holder: LateInit<T>
}

impl<T> Lazy<T> {
    pub const fn new(initializer: fn() -> T) -> Self {
        Self {
            initializer,
            holder: LateInit::new()
        }
    }
}

impl<T> Deref for Lazy<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        if !self.holder.initialized() {
            let _ = self.holder.init((self.initializer)());
        }
        
        &self.holder
    }
}
