use bridge::ApiBridge;

struct ZygiskCompat {
    args: Vec<u64>
}

impl ZygiskCompat {
    fn new() -> Self {
        Self {
            args: Vec::new()
        }
    }
}

impl ApiBridge for ZygiskCompat {
    fn on_dlopen(&mut self) {
        
    }

    fn on_specialize(&mut self, args: &mut [u64]) {
        self.args.extend(args.iter())
    }

    fn after_specialize(&mut self) {
        
    }
}

#[no_mangle]
pub fn bridge_main() {
    bridge::register(ZygiskCompat::new());
}
