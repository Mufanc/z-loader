use anyhow::Result;

use crate::BuildConfigs;

mod loader;
mod ebpf;

pub fn build_project(build_configs: &BuildConfigs) -> Result<()> {
    ebpf::build(build_configs)?;
    loader::build(build_configs)?;
    
    Ok(())
}
