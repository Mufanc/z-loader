use clap::Parser;
use strum_macros::EnumString;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long, default_value = "avd")]
    pub device: Device,

    #[clap(long)]
    pub release: bool,

    #[clap(long)]
    pub run: bool
}

#[derive(EnumString, Debug, Copy, Clone)]
pub enum Device {
    #[strum(serialize = "avd")]
    Avd,
    
    #[strum(serialize = "phys")]
    Physical
}

impl Device {
    pub fn target(&self) -> String {
        match self {
            Device::Avd => "x86_64-linux-android",
            Device::Physical => "aarch64-linux-android"
        }.to_owned()
    }
}

pub fn parse() -> Args {
    Args::parse()
}
