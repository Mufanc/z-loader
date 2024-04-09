use std::fmt::{Debug, Formatter};
use std::mem;
use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;

use anyhow::Result;
use fragile::Fragile;
use jni_sys::JNIEnv;

use bridge::SpecializeArgs;

use crate::abi::{ApiAbi, AppSpecializeArgs, ModuleAbi, ServerSpecializeArgs};
use crate::dlfcn::{dlopen_fd, dlsym};

pub struct ZygiskModule {
    id: String,
    entry: fn(*const ApiAbi, JNIEnv),
    api: Fragile<Pin<Box<ApiAbi>>>,
}

impl Debug for ZygiskModule {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "ZygiskModule {{ id = {} }}", self.id)
    }
}

macro_rules! impl_callback {
    ($name: ident, $args_type: ty) => {
        pub fn $name(&self, args: $args_type) {
            let module = self.module();
            (module.$name)(module.imp, args);
        }
    };
}

impl ZygiskModule {
    pub fn new(name: &str, fd: OwnedFd) -> Result<Pin<Box<Self>>> {
        let handle = dlopen_fd(fd.as_fd(), libc::RTLD_NOW)?;
        let entry_fn: fn(*const ApiAbi, JNIEnv) = unsafe {
            mem::transmute(dlsym(handle, "zygisk_module_entry")?)
        };
        
        Ok(Box::pin(Self {
            id: name.into(),
            entry: entry_fn,
            api: Fragile::new(Box::pin(ApiAbi::new()))
        }))
    }
    
    pub fn id(&self) -> &str {
        &self.id
    }
    
    fn api(&self) -> &ApiAbi {
        self.api.get()
    }
    
    fn module(&self) -> &ModuleAbi {
        unsafe { &*self.api().module_abi }
    }
    
    pub fn entry(&self, env: JNIEnv) {
        (self.entry)(self.api(), env);
    }

    pub fn args_app(&self, args: &SpecializeArgs) -> AppSpecializeArgs {
        AppSpecializeArgs::new(args, self.module().version)
    }

    pub fn args_server(&self, args: &SpecializeArgs) -> ServerSpecializeArgs {
        ServerSpecializeArgs::new(args, self.module().version)
    }
    
    impl_callback!(pras, &AppSpecializeArgs);
    impl_callback!(poas, &AppSpecializeArgs);
    impl_callback!(prss, &ServerSpecializeArgs);
    impl_callback!(poss, &ServerSpecializeArgs);
}
