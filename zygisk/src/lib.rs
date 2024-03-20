use ctor::ctor;

#[ctor]
fn main() {
    
}

#[no_mangle]
extern "C" fn specialize_hook(backup: u64, args: &[u64]) {
    
}
