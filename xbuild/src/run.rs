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
    let zygiskd = target_path(build_configs, "zygiskd");
    let libzygisk_so = target_path(build_configs, "libzygisk_compat.so");
    
    if device.shell("mount | grep /debug_ramdisk").is_err() {
        device.sudo("mount -t tmpfs tmpfs /debug_ramdisk")?;
    }

    device.push(loader, "/data/local/tmp/zloader")?;
    device.push(zygiskd, "/data/local/tmp/zygiskd")?;
    device.push(libzygisk_so, "/data/local/tmp/libzygisk_compat.so")?;
    
    device.sudo("killall zloader || true")?;

    device.sudo("mkdir -p /debug_ramdisk/zloader-zygisk")?;
    device.sudo("cp /data/local/tmp/zloader /debug_ramdisk/zloader-zygisk")?;
    device.sudo("cp /data/local/tmp/libzygisk_compat.so /debug_ramdisk/zloader-zygisk")?;
    device.sudo("cp /data/local/tmp/zygiskd /debug_ramdisk/zloader-zygisk")?;
    
    device.sudo("echo 'killall zloader' > /debug_ramdisk/zloader-zygisk/run.sh")?;
    device.sudo("echo './zloader /debug_ramdisk/zloader-zygisk/libzygisk_compat.so &' > /debug_ramdisk/zloader-zygisk/run.sh")?;
    device.sudo("echo 'cd /data/adb/modules/zygisk_lsposed' >> /debug_ramdisk/zloader-zygisk/run.sh")?;
    device.sudo("echo '/debug_ramdisk/zloader-zygisk/zygiskd --tmpdir /debug_ramdisk/zloader-zygisk' >> /debug_ramdisk/zloader-zygisk/run.sh")?;

    device.sudo("chcon -R u:object_r:system_file:s0 /debug_ramdisk/zloader-zygisk")?;
    device.sudo("chmod +x /debug_ramdisk/zloader-zygisk/zloader")?;
    device.sudo("chmod +x /debug_ramdisk/zloader-zygisk/run.sh")?;

    // device.sudo("killall z-loader || true")?;
    // device.sudo_piped("RUST_LOG=debug /data/local/tmp/z-loader /debug_ramdisk/zloader-zygisk/libzygisk_compat.so")?;

    Ok(())
}
