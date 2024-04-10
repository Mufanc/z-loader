use std::marker::PhantomPinned;
use std::ptr;
use jni_sys::{jboolean, jint, jintArray, jlong, jobjectArray, jstring};
use common::zygote::SpecializeArgs;
use crate::debug;

#[macro_export]
macro_rules! compat {
    ($sdk_var: expr; $( $min: literal, $idx: literal );*) => {
        { $( if $sdk_var >= $min { $idx } else )* { unreachable!() } }
    };
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AppSpecializeArgsV1 {
    // required arguments
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    mount_external: *mut jint,
    se_info: *mut jstring,
    nice_name: *mut jstring,
    instruction_set: *mut jstring,
    app_data_dir: *mut jstring,
    
    // optional arguments
    is_child_zygote: *mut jboolean,
    is_top_app: *mut jboolean,
    pkg_data_info_list: *mut jobjectArray,
    whitelisted_data_info_list: *mut jobjectArray,
    mount_data_dirs: *mut jboolean,
    mount_storage_dirs: *mut jboolean,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AppSpecializeArgsV3 {
    // required arguments
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    rlimits: *mut jobjectArray,
    mount_external: *mut jint,
    se_info: *mut jstring,
    nice_name: *mut jstring,
    instruction_set: *mut jstring,
    app_data_dir: *mut jstring,

    // optional arguments
    fds_to_ignore: *mut jintArray,
    is_child_zygote: *mut jboolean,
    is_top_app: *mut jboolean,
    pkg_data_info_list: *mut jobjectArray,
    whitelisted_data_info_list: *mut jobjectArray,
    mount_data_dirs: *mut jboolean,
    mount_storage_dirs: *mut jboolean
}

#[repr(C)]
pub union AppSpecializeArgs {
    v1: AppSpecializeArgsV1,
    v3: AppSpecializeArgsV3,
}

impl AppSpecializeArgs {
    pub fn new(args: &SpecializeArgs, api: libc::c_long) -> Self {
        match api { 
            1 ..= 2 => {
                Self {
                    v1: AppSpecializeArgsV1 {
                        uid: args.uid,
                        gid: args.gid,
                        gids: args.gids,
                        runtime_flags: args.runtime_flags,
                        mount_external: args.mount_external,
                        se_info: args.managed_se_info,
                        nice_name: args.managed_nice_name,
                        instruction_set: args.managed_instruction_set,
                        app_data_dir: args.managed_app_data_dir,
                        is_child_zygote: args.is_child_zygote,
                        is_top_app: args.is_top_app,
                        pkg_data_info_list: args.pkg_data_info_list,
                        whitelisted_data_info_list: args.allowlisted_data_info_list,
                        mount_data_dirs: args.mount_data_dirs,
                        mount_storage_dirs: args.mount_storage_dirs,
                    }
                }
            }
            3 ..= 4 => {
                Self {
                    v3: {
                        AppSpecializeArgsV3 {
                            uid: args.uid,
                            gid: args.gid,
                            gids: args.gids,
                            runtime_flags: args.runtime_flags,
                            rlimits: args.rlimits,
                            mount_external: args.mount_external,
                            se_info: args.managed_se_info,
                            nice_name: args.managed_nice_name,
                            instruction_set: args.managed_instruction_set,
                            app_data_dir: args.managed_app_data_dir,
                            fds_to_ignore: ptr::null_mut(),
                            is_child_zygote: args.is_child_zygote,
                            is_top_app: args.is_top_app,
                            pkg_data_info_list: args.pkg_data_info_list,
                            whitelisted_data_info_list: args.allowlisted_data_info_list,
                            mount_data_dirs: args.mount_data_dirs,
                            mount_storage_dirs: args.mount_storage_dirs,
                        }
                    }
                }
            }
            _ => unreachable!()
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ServerSpecializeArgsV1 {
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    permitted_capabilities: *mut jlong,
    effective_capabilities: *mut jlong,
}

#[repr(C)]
pub union ServerSpecializeArgs {
    v1: ServerSpecializeArgsV1,
}

impl ServerSpecializeArgs {
    pub fn new(args: &SpecializeArgs, api: libc::c_long) -> Self {
        match api {
            1 ..= 4 => {
                Self {
                    v1: ServerSpecializeArgsV1 {
                        uid: args.uid,
                        gid: args.gid,
                        gids: args.gids,
                        runtime_flags: args.runtime_flags,
                        permitted_capabilities: args.permitted_capabilities,
                        effective_capabilities: args.effective_capabilities,
                    }
                }
            }
            _ => unreachable!()
        }
    }
}

type ModuleImpl = libc::c_void;

#[repr(C)]
pub struct ModuleAbi {
    pub version: libc::c_long,
    pub imp: *const ModuleImpl,
    pub pras: fn(*const ModuleImpl, *const AppSpecializeArgs),
    pub poas: fn(*const ModuleImpl, *const AppSpecializeArgs),
    pub prss: fn(*const ModuleImpl, *const ServerSpecializeArgs),
    pub poss: fn(*const ModuleImpl, *const ServerSpecializeArgs)
}

impl ModuleAbi {
    fn is_valid(&self) -> bool {
        if self.version < 1 || self.version > 4 {
            return false
        }
        
        if self.imp.is_null() {
            return false
        }
        
        self.pras as usize & self.poas as usize & self.prss as usize & self.poss as usize != 0
    }
}

#[repr(C)]
pub struct ApiAbi {
    pub module_abi: *const ModuleAbi,
    register_module: fn(*mut ApiAbi, *const ModuleAbi) -> bool,
    api: [usize; 16],
    _pin: PhantomPinned
}

impl ApiAbi {
    #[allow(clippy::transmute_null_to_fn)]
    #[allow(invalid_value)]
    pub fn new() -> Self {
        Self {
            module_abi: ptr::null(),
            register_module: ApiAbi::register,
            api: [0usize; 16],
            _pin: PhantomPinned
        }
    }
    
    fn register(api_abi: *mut ApiAbi, module_abi: *const ModuleAbi) -> bool {
        let api = match unsafe { api_abi.as_mut() } {
            Some(abi) => abi,
            None => return false,
        };
        
        let module = match unsafe { module_abi.as_ref() } {
            Some(abi) => abi,
            None => return false,
        };
        
        if !module.is_valid() {
            return false
        }
        
        api.module_abi = module;

        debug!("register module: 0x{:x} api_version={}", module_abi as usize, module.version);
        
        true
    }
}
