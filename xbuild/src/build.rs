use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use glob::glob;
use log::debug;

use crate::BuildConfigs;
use crate::ext::Also;

fn find_ar(android_ndk: &str) -> Result<String> {
    Ok(
        glob(&format!("{android_ndk}/toolchains/llvm/prebuilt/*/bin/llvm-ar"))?
            .last()
            .context("couldn't find llvm-ar")??
            .to_str().unwrap()
            .into()
    )
}

fn find_linker(android_ndk: &str, target: &str) -> Result<String> {
    Ok(
        glob(&format!("{android_ndk}/toolchains/llvm/prebuilt/*/bin/{target}*-clang"))?
            .last()
            .context(format!("couldn't find {target}-clang"))??
            .to_str().unwrap()
            .into()
    )
}

fn build_userspace(build_configs: &BuildConfigs) -> Result<()> {
    let android_ndk = env::var("NDK_ROOT").context("failed to read environment variable: NDK_ROOT")?;
    let android_ndk = android_ndk.trim_end_matches('/');

    let target_triple = build_configs.target.to_uppercase().replace('-', "_");

    let ar = &find_ar(android_ndk)?;
    let linker = &find_linker(android_ndk, &build_configs.target)?;

    let code = Command::new(env!("CARGO"))
        .current_dir(env!("PROJECT_ROOT"))
        .arg("build")
        .args(["--target", &build_configs.target])
        .also(|cmd| if build_configs.release { cmd.arg("--release"); })
        .env(format!("CARGO_TARGET_{}_AR", target_triple), ar)
        .env(format!("CARGO_TARGET_{}_LINKER", target_triple), linker)
        .env("PROFILE", build_configs.profile())
        .status().unwrap()
        .code().unwrap();

    if code != 0 {
        bail!("build loader: cargo command failed with code {code}");
    }

    Ok(())
}

fn build_ebpf(build_configs: &BuildConfigs) -> Result<()> {
    let arch = build_configs.target.split('-').next().context("failed to find target arch")?;
    let project_dir = PathBuf::from(env!("PROJECT_ROOT")).join("loader/ebpf");
    
    let mut rustflags = format!("--cfg ebpf_target_arch=\"{arch}\" ");
    
    if build_configs.release {
        rustflags.push_str("--cfg is_debug");
    }

    let code = Command::new("cargo")
        .current_dir(project_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("CARGO_CFG_BPF_TARGET_ARCH", arch)
        .arg("build")
        .args(["--target", env!("EBPF_TARGET")])
        .arg("-Z")
        .arg("build-std=core")
        .also(|cmd| if build_configs.release { cmd.arg("--release"); })
        .also(|cmd| debug!("exec: cargo {:?}", cmd.get_args()))
        .env("RUSTFLAGS", rustflags)
        .status().unwrap()
        .code().unwrap();

    if code != 0 {
        bail!("build zygote_monitor: cargo command failed with code {code}");
    }

    Ok(())
}

pub fn build_project(build_configs: &BuildConfigs) -> Result<()> {
    build_ebpf(build_configs)?;
    build_userspace(build_configs)?;
    Ok(())
}
