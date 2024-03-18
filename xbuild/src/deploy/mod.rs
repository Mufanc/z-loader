use std::path::PathBuf;
use anyhow::{bail, Result};

use crate::{adb, BuildConfigs};
use crate::adb::Device;

const DEPLOY_PATH: &str = "/data/local/tmp/zloader";

pub fn run(build_configs: &BuildConfigs) -> Result<()> {
    let devices = adb::list_devices()?;

    if devices.is_empty() {
        bail!("no devices/emulators found");
    }

    if devices.len() > 1 {
        bail!("more than one device/emulator");
    }

    let device = Device::from_serial(&devices[0])?;

    let zloader = PathBuf::from(env!("PROJECT_ROOT"))
        .join("target")
        .join(&build_configs.target)
        .join(build_configs.profile())
        .join("zloader");
    
    device.push(zloader, DEPLOY_PATH)?;
    device.shell(&format!("chmod +x {DEPLOY_PATH}"))?;
    device.sudo("killall zloader")?;
    device.sudo_piped(&format!("RUST_LOG=debug {DEPLOY_PATH}"))?;

    Ok(())
}
