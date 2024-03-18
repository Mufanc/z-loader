use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context};
use anyhow::Result;
use log::debug;

use crate::BuildConfigs;
use crate::ext::Also;

pub fn build(build_configs: &BuildConfigs) -> Result<()> {
    let arch = build_configs.target.split('-').next().context("failed to find target arch")?;
    let project_dir = PathBuf::from(env!("PROJECT_ROOT")).join("loader/ebpf");

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
        .env("PROFILE", build_configs.profile())
        .status().unwrap()
        .code().unwrap();

    if code != 0 {
        bail!("build zygote_monitor: cargo command failed with code {code}");
    }
    
    Ok(())
}
