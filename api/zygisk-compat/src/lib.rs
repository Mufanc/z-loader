use std::fs::File;
use std::pin::Pin;
use std::sync::Mutex;

use fragile::Fragile;
use log::LevelFilter;

use bridge::{ApiBridge, SpecializeArgs};

use crate::api::ZygiskModule;

mod api;
mod dlfcn;
mod logs;
mod abi;

struct ZygiskContext {
    args: Vec<u64>,
    modules: Vec<Pin<Box<ZygiskModule>>>
}

impl ZygiskContext {
    fn new() -> Self {
        Self {
            args: Vec::new(),
            modules: Vec::new()
        }
    }
}


struct ZygiskCompat {
    ctx: Mutex<ZygiskContext>
}

impl ZygiskCompat {
    fn new() -> Self {
        Self { ctx: Mutex::new(ZygiskContext::new()) }
    }
}

impl ApiBridge for ZygiskCompat {
    fn on_dlopen(&self) {
        let file = File::open("/debug_ramdisk/liblsposed.so").unwrap();
        let mut lock = self.ctx.lock().unwrap();
        let module = ZygiskModule::new("zygisk-lsposed".into(), file.into()).unwrap();
        lock.modules.push(module);
    }

    fn on_specialize(&self, args: SpecializeArgs) {
        let env = args.env();

        let mut lock = self.ctx.lock().unwrap();
        let module = lock.modules.first().unwrap();

        module.entry(env);

        if args.is_system_server() {
            let args = module.args_server(&args);
            module.prss(&args);
            info!("preServerSpecialize called");
        } else {
            let args = module.args_app(&args);
            module.pras(&args);
            info!("preAppSpecialize called");
        }

        lock.args.extend(args.as_slice());
    }

    fn after_specialize(&self) {
        let lock = self.ctx.lock().unwrap();

        let args = &lock.args;
        let args= SpecializeArgs::from(args.as_ptr());

        debug!("args = {:?}", args);

        let module = lock.modules.first().unwrap();
        
        if args.is_system_server() {
            let args = module.args_server(&args);
            module.poss(&args);
            info!("postServerSpecialize called");
        } else {
            let args = module.args_app(&args);
            module.poas(&args);
            info!("postAppSpecialize called");
        }
    }
}


#[no_mangle]
pub fn bridge_main() {
    bridge::register(ZygiskCompat::new());
}
