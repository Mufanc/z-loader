#![feature(try_blocks)]

use std::fs::File;
use std::pin::Pin;
use std::sync::Mutex;
use anyhow::Result;
use log::warn;
use ::common::zygote::SpecializeArgs;

use bridge::ApiBridge;

use crate::api::ZygiskModule;

mod api;
mod dlfcn;
mod logs;
mod abi;
mod filter;

struct ZygiskContext {
    args: Vec<u64>,
    module: Option<Pin<Box<ZygiskModule>>>
}

impl ZygiskContext {
    fn new() -> Self {
        Self {
            args: Vec::new(),
            module: None
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
        let res : Result<()> = try {
            let library = File::open("/debug_ramdisk/zloader-lsposed/liblsposed.so")?;
            let mut lock = self.ctx.lock().unwrap();
            lock.module.replace(ZygiskModule::new("LSPosed", library.into())?);
        };
        
        if let Err(err) = res {
            warn!("failed to load module: {err}");
        }
    }

    fn on_specialize(&self, args: SpecializeArgs) {
        let env = args.env();

        let mut lock = self.ctx.lock().unwrap();
        
        if let Some(module) = &lock.module {
            module.entry(env);
            
            if args.is_system_server() {
                module.prss(&module.args_server(&args));
            } else {
                module.pras(&module.args_app(&args));
            }

            lock.args.extend(args.as_slice());
        }
    }

    fn after_specialize(&self) {
        let lock = self.ctx.lock().unwrap();

        if let Some(module) = &lock.module {
            let args = &lock.args;
            let args= SpecializeArgs::from(args.as_ptr() as *mut _);

            if args.is_system_server() {
                module.poss(&module.args_server(&args));
            } else {
                module.poas(&module.args_app(&args));
            }
        }
    }
}


#[no_mangle]
pub fn bridge_main() {
    bridge::register(ZygiskCompat::new());
}
