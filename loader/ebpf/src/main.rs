#![no_std]
#![no_main]

use core::cmp;

use aya_ebpf::{EbpfContext, helpers};
use aya_ebpf::macros::{map, tracepoint, uprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, TracePointContext};
use aya_log_ebpf::{debug, warn};
use seq_macro::seq;

use common::EbpfEvent;

const ZYGOTE_NAME: &[u8] = "zygote64".as_bytes();
const IS_DEBUG: bool = env!("PROFILE").as_bytes()[0] == b'd';  // Fixme: is it a good idea?


#[map]
static mut EVENT_CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[map]
static mut ZYGOTE_PID: Array<i32> = Array::with_max_entries(1, 0);

#[map]
static mut UNATTACHED_CHILDREN: HashMap<i32, i32> = HashMap::with_max_entries(512, 0);


trait AsEvent<T> {
    fn as_event(&self) -> &T;
}

impl<T> AsEvent<T> for TracePointContext {
    #[inline(always)]
    fn as_event(&self) -> &T {
        unsafe {
            &*(self.as_ptr().add(8) as *const _)
        }
    }
}


#[inline(always)]
fn strcmp16(str1: &[u8], str2: &[u8]) -> bool {
    let mut is_same = true;
    let length = cmp::min(str1.len(), str2.len());

    seq!(i in 0 .. 16 {
        if i >= length {
            return is_same;
        }

        if str1[i] != str2[i] {
            is_same = false;
        }
    });

    is_same
}


#[inline(always)]
fn emit<T: 'static>(value: T) -> bool {
    unsafe {
        let entry = EVENT_CHANNEL.reserve::<T>(0);
        let mut entry = match entry {
            Some(entry) => entry,
            None => return false
        };

        entry.write(value);
        entry.submit(0);
    }

    true
}


#[inline(always)]
fn is_root() -> bool {
    helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF == 0
}

#[inline(always)]
fn current_pid() -> i32 {
    (helpers::bpf_get_current_pid_tgid() & 0xFFFFFFFF) as i32
}

#[inline(always)]
fn stop_current() {
    unsafe {
        helpers::bpf_send_signal_thread(19 /* SIGSTOP */);
    }
}

#[inline(always)]
fn resume_current() {
    unsafe {
        helpers::bpf_send_signal_thread(18 /* SIGCONT */);
    }
}


#[repr(C)]
struct TaskRenameEvent {
    pid: i32,
    old_comm: [u8; 16],
    new_comm: [u8; 16]
}

#[tracepoint]
pub fn handle_task_task_rename(ctx: TracePointContext) -> u32 {
    if !is_root() {
        return 0
    }

    let event: &TaskRenameEvent = ctx.as_event();

    if strcmp16(&event.new_comm, ZYGOTE_NAME) {
        if IS_DEBUG {
            debug!(&ctx, "zygote (re)started: {}", event.pid);
        }

        if !emit(EbpfEvent::ZygoteStarted(event.pid)) && IS_DEBUG {
            warn!(&ctx, "failed to notify zygote start");
        }

        unsafe {
            if let Some(ptr) = ZYGOTE_PID.get_ptr_mut(0) {
                *ptr = event.pid;
            }
        }

        return 0
    }

    0
}


#[repr(C)]
struct NewTaskEvent {
    pid: i32,
    _comm: [u8; 16],
    clone_flags: u64,
    _oom_score_adj: i16
}

#[tracepoint]
pub fn handle_task_task_newtask(ctx: TracePointContext) -> u32 {
    if !is_root() {
        return 0
    }

    let current_pid = current_pid();

    if unsafe { ZYGOTE_PID.get(0) } != Some(&current_pid) {
        return 0
    }

    let event: &NewTaskEvent = ctx.as_event();
    let child_pid = event.pid;

    // skip for threads
    if event.clone_flags & 0x00010000 /* CLONE_THREAD */ != 0 {
        return 0
    }

    if IS_DEBUG {
        debug!(&ctx, "zygote forked: {} -> {} (clone_flags={:x})", current_pid, child_pid, event.clone_flags);
    }

    if !emit(EbpfEvent::ZygoteForked(event.pid)) && IS_DEBUG {
        warn!(&ctx, "failed to notify zygote fork");
    }

    unsafe {
        if UNATTACHED_CHILDREN.insert(&child_pid, &child_pid, 0).is_err() && IS_DEBUG {
            warn!(&ctx, "failed to mark process {} as unattached", child_pid);
        }
    }

    0
}


#[repr(C)]
struct RawSyscallEvent {
    id: i64,
    args: [u64; 6]
}

#[tracepoint]
pub fn handle_raw_syscalls_sys_enter(ctx: TracePointContext) -> u32 {
    let event: &RawSyscallEvent = ctx.as_event();

    if event.id != 14 /* rt_sigprocmask */ && event.args[0] != 1 /* SIG_UNBLOCK */ {
        return 0
    }
    
    if !is_root() {
        return 0
    }
    
    let current_pid = current_pid();

    unsafe {
        if UNATTACHED_CHILDREN.get(&current_pid).is_some() {
            if IS_DEBUG {
                debug!(&ctx, "post zygote fork: {}", current_pid);
            }
            
            if UNATTACHED_CHILDREN.remove(&current_pid).is_err() {
                warn!(&ctx, "failed to remove value {} from unattached map", current_pid);
            }
            
            stop_current();
            
            if !emit(EbpfEvent::UprobeAttach(current_pid)) && IS_DEBUG {
                warn!(&ctx, "failed to require uprobe attach");
                resume_current();
            }
        }
    }

    0
}


#[uprobe]
pub fn handle_specialize_common(ctx: ProbeContext) -> u32 {
    #[inline(always)]
    fn try_run(ctx: &ProbeContext) -> Option<()> {
        let current_pid = current_pid();
        
        let env: u64 = ctx.arg(0)?;
        let uid: u64 = ctx.arg(1)?;
        let gid: u64 = ctx.arg(2)?;

        if IS_DEBUG {
            debug!(ctx, "zygote specialize ({}): env=0x{:x} uid={} gid={}", current_pid, env, uid, gid);
        }

        Some(())
    }

    let _ = try_run(&ctx);

    0
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::hint::unreachable_unchecked()
    }
}
