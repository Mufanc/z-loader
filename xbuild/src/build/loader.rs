use std::env;
use std::process::Command;

use anyhow::{bail, Context, Result};
use glob::glob;

use crate::BuildConfigs;
use crate::ext::Also;

fn find_ar(android_ndk: &str) -> Result<String> {
    Ok(
        glob(&format!("{android_ndk}/toolchains/llvm/prebuilt/*/bin/llvm-ar"))?
            .last()
            .context("couldn't find llvm-ar")??
            .to_str().unwrap()
            .to_owned()
    )
}

fn find_linker(android_ndk: &str, target: &str) -> Result<String> {
    Ok(
        glob(&format!("{android_ndk}/toolchains/llvm/prebuilt/*/bin/{target}*-clang"))?
            .last()
            .context(format!("couldn't find {target}-clang"))??
            .to_str().unwrap()
            .to_owned()
    )
}


pub fn build(build_configs: &BuildConfigs) -> Result<()> {
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
