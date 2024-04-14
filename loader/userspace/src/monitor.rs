use std::collections::{HashMap, VecDeque};
use std::ffi::c_char;
use std::mem;
use std::mem::size_of;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use aya::{Ebpf, include_bytes_aligned};
use aya::maps::RingBuf;
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::{TracePoint, UProbe};
use aya_log::EbpfLogger;
use libloading::{Library, Symbol};
use log::{debug, error, info, warn};
use nix::errno::Errno;
use nix::libc;
use nix::libc::RLIM_INFINITY;
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::io::unix::AsyncFd;
use tokio::task;

use ebpf_common::EbpfEvent;

use crate::{loader, symbols};
use crate::loader::BridgeConfig;
use crate::symbols::ArgCounter;

const BOOTLOOP_DETECT_DURATION: Duration = Duration::from_mins(5);
const BOOTLOOP_DETECT_THRESHOLD: usize = 3;

struct BootloopTracker {
    duration: Duration,
    threshold: usize,
    queue: VecDeque<Instant>
}

impl BootloopTracker {
    fn new(duration: Duration, threshold: usize) -> Self {
        Self {
            duration,
            threshold,
            queue: VecDeque::new()
        }
    }

    fn zygote_crashed(&mut self) -> bool {
        let now = Instant::now();

        while let Some(time) = self.queue.front() {
            if *time + self.duration <= now {
                self.queue.pop_front();
            } else {
                break;
            }
        }

        self.queue.push_back(now);
        self.queue.len() >= self.threshold
    }
}

fn bump_rlimit() {
    if let Err(err) = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY) {
        error!("failed to remove limit on locked memory: {}", err);
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

pub async fn main(bridge: &str, filter: Option<&str>) -> Result<()> {
    bump_rlimit();
    
    let mut ebpf = load_ebpf().context("failed to load ebpf program")?;

    if EbpfLogger::init(&mut ebpf).is_err() {
        debug!("ebpf logs are not available on release build");
    }

    let channel = ebpf.take_map("EVENT_CHANNEL").expect("failed to take event channel");
    let channel = RingBuf::try_from(channel).unwrap();

    attach_tracepoint(&mut ebpf, "task", "task_rename")?;
    attach_tracepoint(&mut ebpf, "task", "task_newtask")?;
    attach_tracepoint(&mut ebpf, "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "raw_syscalls", "sys_enter")?;

    let uprobe_lib = "/system/lib64/libandroid_runtime.so";
    let (func_name, func_addr) = symbols::resolve_for_uprobe(uprobe_lib, "_ZN12_GLOBAL__N_116SpecializeCommonEP7_JNIEnvjjP10_jintArrayiP13_jobjectArraylliP8_jstringS7_bbS7_S7_bS5_S5_bb")?;
    
    let args_count = ArgCounter::count(&func_name)?;
    info!("SpecializeCommon has {args_count} arguments");

    let uprobe: &mut UProbe = ebpf.program_mut("handle_specialize_common").unwrap().try_into()?;
    uprobe.load()?;

    let mut attached_procs = HashMap::new();
    let mut tracker = BootloopTracker::new(
        BOOTLOOP_DETECT_DURATION,
        BOOTLOOP_DETECT_THRESHOLD
    );
    
    let check_process = if let Some(filter) = filter {
        unsafe {
            let library = Box::new(Library::new(filter)?);
            let library = Box::leak(library);  // Fixme: don't leak memory
            let func: Symbol<extern "C" fn(libc::uid_t, *const c_char, *const c_char) -> bool> = library.get(b"check_process")?;
            Some(func)
        }
    } else {
        None
    };

    let mut async_channel = AsyncFd::new(channel)?;

    loop {
        let mut lock = async_channel.readable_mut().await?;
        let entry = lock.get_inner_mut().next();

        if entry.is_none() {
            drop(entry);
            lock.clear_ready();
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
                    debug!("zygote forked: {pid}");
                }
                EbpfEvent::ZygoteCrashed(pid) => {
                    warn!("zygote crashed: {pid}");
                    if tracker.zygote_crashed() {
                        error!("zygote crashed too many times, exiting...");
                        break
                    }
                }
                EbpfEvent::RequireUprobeAttach(pid) => {
                    debug!("[{pid}] uprobe attach required");
                    resume_later!(pid);

                    let link_id = uprobe.attach(None, func_addr, uprobe_lib, Some(pid))?;
                    attached_procs.insert(pid, link_id);
                }
                EbpfEvent::RequireInject(pid, return_addr) => {
                    debug!("[{pid}] inject required");
                    // resume_later!(pid);

                    if let Some(link_id) = attached_procs.remove(&pid) {
                        uprobe.detach(link_id)?;
                        debug!("[{pid}] uprobe detached");
                    } else {
                        error!("uprobe appears to be attached to {pid}, but there is no record in the map");
                    }

                    let config = BridgeConfig {
                        library: bridge.into(),
                        filter_fn: check_process.clone(),
                        args_count,
                        return_addr
                    };

                    task::spawn(async move {
                        if let Err(err) = loader::handle_proc(pid, &config) {
                            error!("failed to inject {pid}: {err}");
                        }
                    });
                }
            }

            debug!("finish handling: {:?}", event);
        };

        if let Err(err) = res {
            error!("error while handling event: {err}");
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

    Ok(())
}
