#![no_std]
#![no_main]

use core::cmp;

use aya_ebpf::{EbpfContext, helpers};
use aya_ebpf::bindings::{BPF_ANY, BPF_EXIST};
use aya_ebpf::macros::{map, tracepoint, uprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, TracePointContext};
use aya_log_ebpf::{debug, error};
use seq_macro::seq;

use ebpf_common::EbpfEvent;

const ZYGOTE_NAME: &[u8] = b"zygote64";
const IS_DEBUG: bool = cfg!(is_debug);

#[repr(u32)]
#[derive(Eq, PartialEq)]
enum ProcessState {
    WaitForAttach,
    WaitForUmount
}

#[map]
static mut EVENT_CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[map]
static mut ZYGOTE_PID: Array<i32> = Array::with_max_entries(1, 0);

#[map]
static mut ZYGOTE_CHILDREN: HashMap<i32, ProcessState> = HashMap::with_max_entries(512, 0);


#[macro_export]
#[cfg(ebpf_target_arch = "x86_64")]
macro_rules! arch_select {
    ($x86: expr, $arm: expr) => {
        $x86
    };
}

#[macro_export]
#[cfg(ebpf_target_arch = "aarch64")]
macro_rules! arch_select {
    ($x86: expr, $arm: expr) => {
        $arm
    };
}


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

#[cfg(ebpf_target_arch = "aarch64")]
#[repr(C)]
#[repr(align(16))]
#[derive(Copy, Clone)]
struct TaskStruct {
    thread_info: ThreadInfo,
}

#[cfg(ebpf_target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
struct ThreadInfo {
    flags: aya_ebpf::cty::c_ulong
}

#[cfg(ebpf_target_arch = "aarch64")]
#[inline(always)]
fn is_32_bit() -> bool {
    let task = unsafe {
        helpers::bpf_get_current_task() as *const TaskStruct
    };

    let thread_info = unsafe {
        helpers::bpf_probe_read_kernel(&(*task).thread_info).unwrap()
    };

    let flags = thread_info.flags;
    let is32 = (flags >> 22) & 1 != 0;

    return is32;
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
            error!(&ctx, "failed to notify zygote start");
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

    // ignore threads
    if event.clone_flags & 0x00010000 /* CLONE_THREAD */ != 0 {
        return 0
    }

    if IS_DEBUG {
        debug!(&ctx, "zygote forked: {} -> {} (clone_flags={:x})", current_pid, child_pid, event.clone_flags);
    }

    if !emit(EbpfEvent::ZygoteForked(event.pid)) && IS_DEBUG {
        error!(&ctx, "failed to notify zygote fork");
    }

    unsafe {
        if ZYGOTE_CHILDREN.insert(&child_pid, &ProcessState::WaitForAttach, BPF_ANY as _).is_err() && IS_DEBUG {
            error!(&ctx, "failed to mark process {} as unattached", child_pid);
        }
    }

    0
}


#[repr(C)]
struct ProcessExitEvent {
    _comm: [u8; 16],
    pid: i32,
    _prio: i32
}

#[tracepoint]
pub fn handle_sched_sched_process_exit(ctx: TracePointContext) -> u32 {
    let event: &ProcessExitEvent = ctx.as_event();
    
    let pid = event.pid;
    
    unsafe {
        if ZYGOTE_PID.get(0) == Some(&pid) {
            if IS_DEBUG {
                debug!(&ctx, "zygote crashed ({})", pid);
            }

            if !emit(EbpfEvent::ZygoteCrashed(pid)) && IS_DEBUG {
                error!(&ctx, "failed to notify zygote crashed");
            }
        }

        let _ = ZYGOTE_CHILDREN.remove(&pid);
    }
    
    0
}


#[repr(C)]
struct SyscallEnterEvent {
    id: i64,
    args: [u64; 6]
}

#[tracepoint]
pub fn handle_raw_syscalls_sys_enter(ctx: TracePointContext) -> u32 {
    let event: &SyscallEnterEvent = ctx.as_event();

    if event.id != arch_select!(14, 135) /* rt_sigprocmask */ || event.args[0] != 1 /* SIG_UNBLOCK */ {
        return 0;
    }

    if !is_root() {
        return 0
    }

    #[cfg(ebpf_target_arch = "aarch64")]
    if is_32_bit() {
        return 0;
    }

    let current_pid = current_pid();

    unsafe {
        if ZYGOTE_CHILDREN.get(&current_pid) == Some(&ProcessState::WaitForAttach) {
            if IS_DEBUG {
                debug!(&ctx, "post zygote fork: {}", current_pid);
            }

            if ZYGOTE_CHILDREN.insert(&current_pid, &ProcessState::WaitForUmount, BPF_EXIST as _).is_err() {
                error!(&ctx, "failed to update process state");
            }

            stop_current();

            if !emit(EbpfEvent::RequireUprobeAttach(current_pid)) && IS_DEBUG {
                error!(&ctx, "failed to require uprobe attach");
                resume_current();
            }
        }
    }

    0
}


#[repr(C)]
struct SyscallExitEvent {
    id: i64,
    return_value: u64
}

#[tracepoint]
pub fn handle_raw_syscalls_sys_exit(ctx: TracePointContext) -> u32 {
    let event: &SyscallExitEvent = ctx.as_event();
    
    if event.id != arch_select!(272, 97) /* unshare */ || event.return_value != 0 {
        return 0;
    }

    if !is_root() {
        return 0
    }

    #[cfg(ebpf_target_arch = "aarch64")]
    if is_32_bit() {
        return 0;
    }

    let current_pid = current_pid();
    let current_uid = (helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

    unsafe {
        if ZYGOTE_CHILDREN.get(&current_pid) == Some(&ProcessState::WaitForUmount) {
            if IS_DEBUG {
                debug!(&ctx, "process unshare: {}", current_pid);
            }

            stop_current();

            if !emit(EbpfEvent::RequireUmount(current_pid, current_uid)) && IS_DEBUG {
                error!(&ctx, "failed to require umount");
                resume_current();
            }
            
            let _ = ZYGOTE_CHILDREN.remove(&current_pid);
        }
    }
    
    0
}


#[uprobe]
pub fn handle_specialize_common(ctx: ProbeContext) -> u32 {
    #[inline(always)]
    fn try_run(ctx: &ProbeContext) -> Option<()> {
        let current_pid = current_pid();

        let uid: u64 = ctx.arg(1)?;
        let gid: u64 = ctx.arg(2)?;

        #[cfg(ebpf_target_arch = "x86_64")]
        let lr = unsafe {
            let sp = (*ctx.regs).rsp as *const usize;
            helpers::bpf_probe_read_user(sp).ok()?
        };

        #[cfg(ebpf_target_arch = "aarch64")]
        let lr = unsafe { (*ctx.regs).regs[30] as usize };

        if IS_DEBUG {
            debug!(ctx, "zygote specialize ({}): uid={} gid={}", current_pid, uid, gid);
        }

        stop_current();

        if !emit(EbpfEvent::RequireInject(current_pid, lr)) && IS_DEBUG {
            error!(ctx, "failed to require inject");
            resume_current();
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
