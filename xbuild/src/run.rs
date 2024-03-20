use std::path::PathBuf;
use anyhow::{bail, Result};

use crate::{adb, BuildConfigs};
use crate::adb::Device;

fn target_path(build_configs: &BuildConfigs, name: &str) -> PathBuf {
    PathBuf::from(env!("PROJECT_ROOT"))
        .join("target")
        .join(&build_configs.target)
        .join(build_configs.profile())
        .join(name)
}

pub fn run(build_configs: &BuildConfigs) -> Result<()> {
    let devices = adb::list_devices()?;

    if devices.is_empty() {
        bail!("no devices/emulators found");
    }

    if devices.len() > 1 {
        bail!("more than one device/emulator");
    }

    let device = Device::from_serial(&devices[0])?;

    let loader = target_path(build_configs, "zloader");
    let libzygisk_so = target_path(build_configs, "libzygisk.so");

    device.push(loader, "/data/local/tmp/zloader")?;
    device.shell("chmod +x /data/local/tmp/zloader")?;

    device.shell("mkdir -p /debug_ramdisk/zloader")?;
    device.push(libzygisk_so, "/debug_ramdisk/zloader/libzygisk.so")?;

    device.sudo("killall zloader")?;
    device.sudo_piped("RUST_LOG=debug /data/local/tmp/zloader")?;

    Ok(())
}
