use std::path::PathBuf;
use anyhow::{bail, Result};
use glob::glob;

use crate::{adb, BuildConfigs};
use crate::adb::Device;

#[allow(dead_code)]
fn target_path(build_configs: &BuildConfigs, name: &str) -> PathBuf {
    PathBuf::from(env!("PROJECT_ROOT"))
        .join("target")
        .join(&build_configs.target)
        .join(build_configs.profile())
        .join(name)
}

#[allow(unused_variables)]
pub fn run(build_configs: &BuildConfigs) -> Result<()> {
    let devices = adb::list_devices()?;

    if devices.is_empty() {
        bail!("no devices/emulators found");
    }

    if devices.len() > 1 {
        bail!("more than one device/emulator");
    }

    let device = Device::from_serial(&devices[0])?;

    let modules: Vec<_> = glob(&format!("{}/target/modules/*-LSPosed-*.zip", env!("PROJECT_ROOT")))?
        .flatten()
        .collect();
    
    assert_eq!(modules.len(), 1, "none or multiple module found");

    device.push(&modules[0], "/data/local/tmp/module.zip")?;
    device.sudo_piped("ksud module install /data/local/tmp/module.zip")?;

    Ok(())
}
