#![feature(try_blocks)]

use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::Mutex;
use anyhow::Context;
use anyhow::Result;
use bincode::config;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use log::error;
use sendfd::RecvWithFd;
use ::common::zygote::SpecializeArgs;

use bridge::ApiBridge;

use crate::api::ZygiskModule;
use crate::common::DaemonSocketAction;

mod api;
mod dlfcn;
mod logs;
mod abi;
mod common;

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
        let res : Result<()> = try {
            let mut stream = UnixStream::connect("/debug_ramdisk/zloader-zygisk/daemon.sock").context("failed to connect daemon")?;
            
            stream.write_u8(DaemonSocketAction::ReadModules.into())?;
            
            let fds_len = stream.read_u64::<NativeEndian>()? as usize;
            let buffer_len = stream.read_u64::<NativeEndian>()? as usize;

            let mut fds: Vec<RawFd> = vec![0i32; fds_len];
            let mut buffer = vec![0u8; buffer_len];
            
            debug!("fds_len = {}, buffer_len = {}", fds_len, buffer_len);
            
            stream.recv_with_fd(&mut buffer, &mut fds)?;
            
            let ids: Vec<String> = bincode::decode_from_slice(&buffer, config::standard())?.0;
            
            let mut modules = Vec::new();

            for (id, fd) in ids.into_iter().zip(fds) {
                modules.push(ZygiskModule::new(&id, unsafe { OwnedFd::from_raw_fd(fd) })?);
            }
            
            debug!("modules: {:?}", modules);
            
            let mut lock = self.ctx.lock().unwrap();
            lock.modules.append(&mut modules);
        };
        
        if let Err(err) = res {
            error!("failed to load modules: {err}");
        }
    }

    fn on_specialize(&self, args: SpecializeArgs) {
        let env = args.env();

        let mut lock = self.ctx.lock().unwrap();
        let modules = &lock.modules;

        for module in modules {
            debug!("call `onLoad` for module: {}", module.id());
            module.entry(env);
        }

        if args.is_system_server() {
            for module in modules {
                debug!("call `preServerSpecialize` for module: {}", module.id());
                let args = module.args_server(&args);
                module.prss(&args);
            }
        } else {
            for module in modules {
                debug!("call `preAppSpecialize` for module: {}", module.id());
                let args = module.args_app(&args);
                module.pras(&args);
            }
        }

        lock.args.extend(args.as_slice());
    }

    fn after_specialize(&self) {
        let lock = self.ctx.lock().unwrap();

        let args = &lock.args;
        let args= SpecializeArgs::from(args.as_ptr() as *mut _);

        let modules = &lock.modules;
        
        if args.is_system_server() {
            for module in modules {
                debug!("call `postServerSpecialize` for module: {}", module.id());
                let args = module.args_server(&args);
                module.poss(&args);
            }
        } else {
            for module in modules {
                debug!("call `postAppSpecialize` for module: {}", module.id());
                let args = module.args_app(&args);
                module.poas(&args);
            }
        }
    }
}


#[no_mangle]
pub fn bridge_main() {
    bridge::register(ZygiskCompat::new());
}
