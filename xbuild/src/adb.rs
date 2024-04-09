use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use mozdevice::Host;
use shell_quote::{Bash, QuoteExt};

pub struct ExecResult {
    pub code: i32,
    pub stdout: String
}

pub fn list_devices() -> Result<Vec<String>> {
    let devices: Vec<_> = Host::default().devices()?;

    Ok(devices.into_iter().map(|info| info.serial).collect())
}

pub fn adb(args: &[&str]) -> Result<ExecResult> {
    let output = Command::new("adb")
        .args(args)
        .output()?;
    
    let code = output.status.code().context("failed to get status code")?;
    
    if code != 0 {
        bail!("failed to run adb with args: {args:?}\n{}", String::from_utf8(output.stderr)?);
    }

    Ok(ExecResult {
        code,
        stdout: String::from_utf8(output.stdout)?
    })
}

pub fn adb_piped(args: &[&str]) -> Result<()> {
    let status = Command::new("adb")
        .args(args)
        .status()?;
    
    if let Some(0) = status.code() {
        return Ok(())
    }

    bail!("failed to run adb with args: {args:?}");
}

// pub fn shell(command: &str) -> Result<ExecResult> {
//     adb(&["shell", command])
// }
// 
// pub fn shell_piped(command: &str) -> Result<()> {
//     adb_piped(&["shell", command])
// }

pub struct Device {
    pub serial: String,
    su: &'static str
}

impl Device {
    pub fn from_serial(serial: &str) -> Result<Self> {
        let mut instance = Self { serial: serial.into(), su: "" };
        instance.initialize()?;

        Ok(instance)
    }

    fn initialize(&mut self) -> Result<()> {
        let is_avd = self.shell("which su")?.stdout.starts_with("/system/xbin");
        self.su = if is_avd { "su 0 sh -c" } else { "su -c"};

        Ok(())
    }

    fn prepend_serial<'a>(&'a self, args: &[&'a str]) -> Vec<&'a str> {
        let mut new_args = vec!["-s", &self.serial];

        new_args.extend(args);
        new_args
    }

    #[allow(dead_code)]
    pub fn push<P : AsRef<Path>, Q : AsRef<Path>>(&self, from: P, to: Q) -> Result<()> {
        let from = from.as_ref().to_str().unwrap();
        let to = to.as_ref().to_str().unwrap();

        adb_piped(&self.prepend_serial(&["push", from, to]))
    }

    #[allow(dead_code)]
    pub fn shell(&self, command: &str) -> Result<ExecResult> {
        adb(&self.prepend_serial(&["shell", command]))
    }

    #[allow(dead_code)]
    pub fn shell_piped(&self, command: &str) -> Result<()> {
        adb_piped(&self.prepend_serial(&["shell", command]))
    }

    #[allow(dead_code)]
    fn sudo_command(&self, command: &str) -> String {
        let mut script = String::new();
        
        script.push_str(self.su);
        script.push(' ');
        script.push_quoted(Bash, command);
        
        script
    }

    #[allow(dead_code)]
    pub fn sudo(&self, command: &str) -> Result<ExecResult> {
        self.shell(&self.sudo_command(command))
    }

    #[allow(dead_code)]
    pub fn sudo_piped(&self, command: &str) -> Result<()> {
        self.shell_piped(&self.sudo_command(command))
    }
}
