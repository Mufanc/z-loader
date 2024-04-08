use std::collections::HashMap;
use std::mem;
use std::mem::size_of;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use aya::maps::RingBuf;
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::{TracePoint, UProbe};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use nix::errno::Errno;
use nix::libc::RLIM_INFINITY;
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::task;

use common::EbpfEvent;

use crate::{loader, symbols};

fn bump_rlimit() {
    if let Err(err) = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY) {
        warn!("failed to remove limit on locked memory: {}", err);
    }
}

fn load_ebpf() -> Result<Ebpf> {
    let program_data = include_bytes_aligned!(
        concat!(
            env!("PROJECT_ROOT"), 
            "/target/", 
            env!("EBPF_TARGET"),
            "/", 
            env!("PROFILE"), 
            "/zloader-ebpf"
        )
    );
    
    Ok(Ebpf::load(program_data)?)
}

fn attach_tracepoint(bpf: &mut Ebpf, category: &str, name: &str) -> Result<TracePointLinkId> {
    let program_name = &format!("handle_{category}_{name}");
    let program: &mut TracePoint = bpf.program_mut(program_name).unwrap().try_into()?;

    program.load().context(format!("failed to load program {program_name}"))?;

    program.attach(category, name)
            .context(format!("failed to attach tracepoint: {category}/{name}"))
}

pub async fn main(bridge: &str) -> Result<()> {
    let bridge = Arc::new(bridge.to_owned());

    bump_rlimit();
    
    let mut ebpf = load_ebpf().context("failed to load ebpf program")?;

    if EbpfLogger::init(&mut ebpf).is_err() {
        debug!("ebpf logs are not available on release build");
    }

    let channel = ebpf.take_map("EVENT_CHANNEL").expect("failed to take event channel");
    let mut channel = RingBuf::try_from(channel).unwrap();

    attach_tracepoint(&mut ebpf, "task", "task_rename")?;
    attach_tracepoint(&mut ebpf, "task", "task_newtask")?;
    attach_tracepoint(&mut ebpf, "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "raw_syscalls", "sys_enter")?;

    let uprobe_lib = "/system/lib64/libandroid_runtime.so";
    let func_addr = symbols::resolve_for_uprobe(uprobe_lib, "_ZN12_GLOBAL__N_116SpecializeCommonEP7_JNIEnvjjP10_jintArrayiP13_jobjectArraylliP8_jstringS7_bbS7_S7_bS5_S5_bb")?;

    let uprobe: &mut UProbe = ebpf.program_mut("handle_specialize_common").unwrap().try_into()?;
    uprobe.load()?;

    let mut attached_procs = HashMap::new();

    loop {
        let entry = channel.next();

        if entry.is_none() {
            continue
        }

        let mut resume_pid = 0;

        macro_rules! resume_later {
            ($pid: expr) => {
                resume_pid = $pid;
            };
        }

        let res: Result<()> = try {
            let buffer: [u8; size_of::<EbpfEvent>()] = (*entry.unwrap()).try_into()?;
            let event: EbpfEvent = unsafe { mem::transmute(buffer) };

            match event {
                EbpfEvent::ZygoteStarted(pid) => {
                    info!("zygote (re)started: {pid}");
                }
                EbpfEvent::ZygoteForked(pid) => {
                    info!("zygote forked: {pid}");
                }
                EbpfEvent::ZygoteCrashed(pid) => {
                    warn!("zygote crashed: {pid}");
                }
                EbpfEvent::RequireUprobeAttach(pid) => {
                    info!("uprobe attach required: {pid}");
                    resume_later!(pid);

                    let link_id = uprobe.attach(None, func_addr, uprobe_lib, Some(pid))?;
                    attached_procs.insert(pid, link_id);
                }
                EbpfEvent::RequireInject(pid, return_addr) => {
                    info!("inject required: {pid}");
                    // resume_later!(pid);

                    if let Some(link_id) = attached_procs.remove(&pid) {
                        uprobe.detach(link_id)?;
                        info!("uprobe detached: {pid}");
                    } else {
                        warn!("uprobe appears to be attached to {pid}, but there is no record in the map");
                    }

                    let bridge_cloned = Arc::clone(&bridge);

                    task::spawn(async move {
                        if let Err(err) = loader::handle_proc(pid, return_addr, &bridge_cloned) {
                            warn!("failed to inject {pid}: {err}");
                        }
                    });
                }
            }

            debug!("finish handling: {:?}", event);
        };

        if let Err(err) = res {
            warn!("error while handling event: {err}");
        }

        if resume_pid != 0 {
            if let Err(err) = kill(Pid::from_raw(resume_pid), Signal::SIGCONT) {
                if err == Errno::ESRCH {
                    continue
                }
                bail!(err);
            }
        }
    }
}
