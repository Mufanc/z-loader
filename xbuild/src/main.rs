use anyhow::Result;

use crate::args::Args;

mod args;
mod build;
mod ext;
mod deploy;
mod adb;

struct BuildConfigs {
    target: String,
    release: bool
}

impl From<&Args> for BuildConfigs {
    fn from(args: &Args) -> Self {
        Self {
            target: args.device.target(),
            release: args.release
        }
    }
}

impl BuildConfigs {
    fn profile(&self) -> &str {
        if self.release {
            "release"
        } else {
            "debug"
        }
    }
}

fn main() -> Result<()> {
    let args = args::parse();
    let build_configs = BuildConfigs::from(&args);
    
    build::build_project(&build_configs)?;
    
    if args.run {
        deploy::run(&build_configs)?;
    }
    
    Ok(())
}
