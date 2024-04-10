use std::{mem, ptr, slice};
use jni_sys::{jint, jintArray, jlong, JNIEnv, jobjectArray, jstring};
use crate::lazy::Lazy;
use crate::properties::getprop;

static SDK_VERSION: Lazy<i32> = Lazy::new(|| {
    getprop("ro.build.version.sdk").parse().unwrap()
});

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SpecializeArgs {
    ptr: *const u64,
    pub env: *mut JNIEnv,
    pub uid: *mut jint,
    pub gid: *mut jint,
    pub gids: *mut jintArray,
    pub runtime_flags: *mut jint,
    pub rlimits: *mut jobjectArray,
    pub permitted_capabilities: *mut jlong,
    pub effective_capabilities: *mut jlong,
    pub bounding_capabilities: *mut jlong,
    pub mount_external: *mut jint,
    pub managed_se_info: *mut jstring,
    pub managed_nice_name: *mut jstring,
    pub is_system_server: *mut bool,
    pub is_child_zygote: *mut bool,
    pub managed_instruction_set: *mut jstring,
    pub managed_app_data_dir: *mut jstring,
    pub is_top_app: *mut bool,
    pub pkg_data_info_list: *mut jobjectArray,
    pub allowlisted_data_info_list: *mut jobjectArray,
    pub mount_data_dirs: *mut bool,
    pub mount_storage_dirs: *mut bool,
    pub mount_sysprop_overrides: *mut bool,
}

impl Default for SpecializeArgs {
    fn default() -> Self {
        unsafe {
            mem::transmute([0u8; mem::size_of::<Self>()])
        }
    }
}

impl From<*mut u64> for SpecializeArgs {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn from(value: *mut u64) -> Self {
        macro_rules! arg {
            ($( $min: literal, $idx: literal );*) => {
                $(
                    if *SDK_VERSION >= $min {
                        value.offset($idx) as _
                    } else
                )* {
                    ptr::null_mut()
                }
            };
        }

        unsafe {
            Self {
                ptr: value,
                env: arg!(31, 0),
                uid: arg!(31, 1),
                gid: arg!(31, 2),
                gids: arg!(31, 3),
                runtime_flags: arg!(31, 4),
                rlimits: arg!(31, 5),
                permitted_capabilities: arg!(31, 6),
                effective_capabilities: arg!(31, 7),
                bounding_capabilities: arg!(35, 8),
                mount_external: arg!(35, 9; 31, 8),
                managed_se_info: arg!(35, 10; 31, 9),
                managed_nice_name: arg!(35, 11; 31, 10),
                is_system_server: arg!(35, 12; 31, 11),
                is_child_zygote: arg!(35, 13; 31, 12),
                managed_instruction_set: arg!(35, 14; 31, 13),
                managed_app_data_dir: arg!(35, 15; 31, 14),
                is_top_app: arg!(35, 16; 31, 15),
                pkg_data_info_list: arg!(35, 17; 31, 16),
                allowlisted_data_info_list: arg!(35, 18; 31, 17),
                mount_data_dirs: arg!(35, 19; 31, 18),
                mount_storage_dirs: arg!(35, 20; 31, 19),
                mount_sysprop_overrides: arg!(35, 21),
            }
        }
    }
}

impl SpecializeArgs {
    pub fn as_slice(&self) -> &[u64] {
        unsafe {
            match *SDK_VERSION {
                31 ..= 34 => {
                    slice::from_raw_parts(self.ptr, 20)
                }
                35 => {
                    slice::from_raw_parts(self.ptr, 22)
                }
                _ => panic!("unsupported SDK version: {}", *SDK_VERSION)
            }
        }
    }

    pub fn env(&self) -> JNIEnv {
        unsafe { *self.env }
    }

    pub fn is_system_server(&self) -> bool {
        unsafe { *self.is_system_server }
    }
}
