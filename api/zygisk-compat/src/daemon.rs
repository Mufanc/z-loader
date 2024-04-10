#![feature(try_blocks)]

use std::{env, fs, io};
use std::fs::File;
use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bincode::config;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use clap::Parser;
use log::{debug, info, LevelFilter, warn};
use memfd::{FileSeal, Memfd, MemfdOptions};
use sendfd::SendWithFd;
use tokio::runtime::Runtime;
use tokio::task;
use ::common::debug_select;
use ::common::utils::dump_tombstone_on_panic;

use crate::common::DaemonSocketAction;
use crate::selinux::chcon;

mod selinux;
mod common;

#[derive(Parser)]
struct Args {
    #[clap(long)]
    tmpdir: PathBuf
}

#[derive(Debug)]
struct Module {
    name: String,
    fd: Memfd
}

impl Module {
    fn new(name: String, fd: Memfd) -> Module {
        Self { name, fd }
    }
}

fn load_library(name: &str, lib: &PathBuf) -> Result<Memfd> {
    let options = MemfdOptions::default().allow_sealing(true);
    let mfd = options.create(name)?;

    let mut rx = BufReader::new(File::open(lib)?);
    let mut tx = &mut mfd.as_file();
    io::copy(&mut rx, &mut tx)?;

    mfd.add_seal(FileSeal::SealGrow)?;
    mfd.add_seal(FileSeal::SealShrink)?;
    mfd.add_seal(FileSeal::SealWrite)?;
    mfd.add_seal(FileSeal::SealSeal)?;

    Ok(mfd)
}

fn load_modules() -> Result<Vec<Module>> {
    let current = env::current_dir()?;
    let modules_dir = current.parent().unwrap();

    let dirs = fs::read_dir(modules_dir)?;
    let mut modules = Vec::new();

    for dir in dirs.flatten() {
        let module_id = dir.file_name().into_string().unwrap();

        let lib = dir.path().join("zygisk/arm64-v8a.so");
        let disable = dir.path().join("disable");

        if !lib.exists() || disable.exists() {
            continue
        }

        info!("loading module `{module_id}`...");

        let mfd = load_library(&module_id, &lib)?;

        modules.push(Module::new(module_id, mfd));
    }

    Ok(modules)
}

fn create_daemon_socket<P : AsRef<Path>>(skfile: P) -> Result<UnixListener> {
    fs::write("/proc/thread-self/attr/sockcreate", "u:r:zygote:s0")?;

    let _ = fs::remove_file(&skfile);
    let listener = UnixListener::bind(&skfile)?;

    chcon(skfile, "u:object_r:magisk_file:s0")?;

    Ok(listener)
}

fn init_logger() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("ZLoader-Zygisk")
    );
}

fn main() -> Result<()> {
    init_logger();
    dump_tombstone_on_panic();

    let args = Args::parse();

    fs::create_dir_all(&args.tmpdir).context("failed to create tmpdir")?;

    let modules = load_modules().context("failed to load modules")?;
    
    debug!("loaded modules: {modules:?}");

    let listener = create_daemon_socket(args.tmpdir.join("daemon.sock"))
        .context("failed to create daemon socket")?;

    let runtime = Runtime::new()?;
    let _handle = runtime.enter();

    let module_ids: Arc<Vec<_>> = Arc::new(modules.iter().map(|m| m.name.clone()).collect());
    let module_fds: Arc<Vec<_>> = Arc::new(modules.iter().map(|m| m.fd.as_raw_fd()).collect());

    for mut stream in listener.incoming().flatten() {
        let action = DaemonSocketAction::from(stream.read_u8()?);

        let ids = Arc::clone(&module_ids);
        let fds = Arc::clone(&module_fds);

        task::spawn(async move {
            match action {
                DaemonSocketAction::ReadModules => {
                    let res: Result<()> = try {
                        let ids = bincode::encode_to_vec(&ids, config::standard())?;
                        stream.write_u64::<NativeEndian>(fds.len() as u64)?;
                        stream.write_u64::<NativeEndian>(ids.len() as u64)?;
                        stream.send_with_fd(&ids, &fds)?;
                    };
                    
                    if let Err(err) = res {
                        warn!("failed to send modules: {err}");
                    }
                }
            }
        });
    }

    Ok(())
}
