use std::ffi::CString;
use std::io::IoSlice;
use std::mem;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::slice::Iter;
use std::time::Duration;
use anyhow::{anyhow, bail, Context, Result};
use jni_sys::JNINativeInterface__1_6;
use log::{debug, info, warn};
use nix::errno::Errno;
use nix::libc;

#[cfg(target_arch = "aarch64")]
use nix::libc::iovec;

use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use rsprocmaps::{Map, Pathname};
use crate::{arch_select, symbols};

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
struct Registers(user_regs_struct);

#[cfg(target_arch = "x86_64")]
impl Default for Registers {
    fn default() -> Self {
        Self(user_regs_struct {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        })
    }
}

#[cfg(target_arch = "aarch64")]
impl Default for Registers {
    fn default() -> Self {
        Self(user_regs_struct {
            regs: [0u64; 31],
            sp: 0,
            pc: 0,
            pstate: 0
        })
    }
}

impl Registers {
    fn new(regs: user_regs_struct) -> Self {
        Self(regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn arg(&self, n: usize) -> u64 {
        match n {
            0 => self.0.rdi,
            1 => self.0.rsi,
            2 => self.0.rdx,
            3 => self.0.rcx,
            4 => self.0.r8,
            5 => self.0.r9,
            _ => unreachable!(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn arg(&self, n: usize) -> u64 {
        if n < 8 {
            self.0.regs[n]
        } else {
            unreachable!()
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn retval(&self) -> u64 {
        self.0.rax
    }

    #[cfg(target_arch = "aarch64")]
    fn retval(&self) -> u64 {
        self.0.regs[0]
    }

    #[cfg(target_arch = "x86_64")]
    fn sp(&self) -> usize {
        self.0.rsp as _
    }

    #[cfg(target_arch = "aarch64")]
    fn sp(&self) -> usize {
        self.0.sp as _
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sp(&mut self, sp: usize) {
        self.0.rsp = sp as _
    }

    #[cfg(target_arch = "aarch64")]
    fn set_sp(&mut self, sp: usize) {
        self.0.sp = sp as _
    }

    #[cfg(target_arch = "x86_64")]
    fn pc(&self) -> usize {
        self.0.rip as _
    }

    #[cfg(target_arch = "aarch64")]
    fn pc(&self) -> usize {
        self.0.pc as _
    }

    #[cfg(target_arch = "x86_64")]
    fn set_pc(&mut self, pc: usize) {
        self.0.rip = pc as _
    }

    #[cfg(target_arch = "aarch64")]
    fn set_pc(&mut self, pc: usize) {
        self.0.pc = pc as _
    }

    #[cfg(target_arch = "x86_64")]
    fn set_args(&mut self, args: &[u64]) {
        for (i, arg) in args.iter().enumerate() {
            match i {
                0 => self.0.rdi = *arg,
                1 => self.0.rsi = *arg,
                2 => self.0.rdx = *arg,
                3 => self.0.rcx = *arg,
                4 => self.0.r8 = *arg,
                5 => self.0.r9 = *arg,
                _ => unreachable!()
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn set_args(&mut self, args: &[u64]) {
        if args.len() > 8 {
            unreachable!()
        }

        self.0.regs[0 .. args.len()].copy_from_slice(args);
    }
}


struct Tracee {
    pid: Pid,
    regs: Registers,
    regs_dirty: bool,
    allocated: Vec<usize>
}

impl Tracee {

    const MAGIC_ADDR: usize = 0xcafecafe;

    fn new(pid: i32) -> Self {
        Self {
            pid: Pid::from_raw(pid),
            regs: Registers::default(),
            regs_dirty: true,
            allocated: Vec::new()
        }
    }

    fn attach(&self) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(0x4206 /* PTRACE_SEIZE */, self.pid.as_raw(), 0, 0)
        })?;

        Ok(())
    }

    fn regs(&mut self) -> Result<Registers> {
        if !self.regs_dirty {
            return Ok(self.regs)
        }

        self.regs = self.regs_arch()?;
        self.regs_dirty = false;

        Ok(self.regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn regs_arch(&mut self) -> Result<Registers> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_GETREGS, self.pid.as_raw(), 0, regs.as_mut_ptr())
        })?;

        Ok(Registers::new(unsafe { regs.assume_init() }))
    }

    #[cfg(target_arch = "aarch64")]
    fn regs_arch(&self) -> Result<Registers> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();
        let iov = iovec {
            iov_base: regs.as_mut_ptr() as _,
            iov_len: mem::size_of::<user_regs_struct>()
        };

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_GETREGSET, self.pid.as_raw(), 1 /* NT_PRSTATUS */, &iov as *const _)
        })?;

        Ok(Registers::new(unsafe { regs.assume_init() }))
    }

    fn set_regs(&mut self, regs: Registers) -> Result<()> {
        self.set_regs_arch(regs)?;
        self.regs = regs;
        self.regs_dirty = false;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn set_regs_arch(&mut self, regs: Registers) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_SETREGS, self.pid.as_raw(), 0, &regs as *const _)
        })?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn set_regs_arch(&self, regs: Registers) -> Result<()> {
        let iov = iovec {
            iov_base: &regs as *const _ as *mut _,
            iov_len: mem::size_of::<user_regs_struct>()
        };

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_SETREGSET, self.pid.as_raw(), 1 /* NT_PRSTATUS */, &iov as *const _)
        })?;

        Ok(())
    }

    fn peek(&self, addr: usize) -> Result<u64> {
        Ok(ptrace::read(self.pid, addr as _)? as u64)
    }

    fn poke(&self, addr: usize, value: u64) -> Result<()> {
        unsafe {
            ptrace::write(self.pid, addr as _, value as *mut _)?
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn uprobe_arg(&mut self, n: usize) -> Result<u64> {
        let regs = self.regs()?;
        let arg = if n < 6 {
            regs.arg(n)
        } else {
            let n = n - 6;
            self.peek(regs.sp() + 8 * n + 16 /* call + push rbp */)?
        };

        Ok(arg)
    }

    #[cfg(target_arch = "aarch64")]
    fn uprobe_arg(&mut self, n: usize) -> Result<u64> {
        let regs = self.regs()?;
        let arg = if n < 8 {
            regs.arg(n)
        } else {
            let n = n - 8;
            self.peek(regs.sp() + 8 * n)?
        };

        Ok(arg)
    }

    #[cfg(target_arch = "x86_64")]
    fn uprobe_return_address(&mut self) -> Result<u64> {
        let regs = self.regs()?;
        self.peek(regs.sp() + 8 /* push rbp */)
    }

    #[cfg(target_arch = "aarch64")]
    fn uprobe_return_address(&mut self) -> Result<u64> {
        let regs = self.regs()?;
        Ok(regs.0.regs[30])
    }

    fn alloc(&mut self, data: &[u8]) -> Result<usize> {
        let mut regs = self.regs()?;

        let backup_sp = regs.sp();
        let new_sp = (regs.sp() - data.len()) & !0x7;

        let local_iov = IoSlice::new(data);
        let remote_iov = RemoteIoVec { base: new_sp, len: data.len() };
        process_vm_writev(self.pid, &[local_iov], &[remote_iov])?;

        regs.set_sp(new_sp);
        self.set_regs(regs)?;

        self.allocated.push(backup_sp);

        debug!("alloc memory on stack, sp 0x{backup_sp:x} -> 0x{new_sp:x}");

        Ok(new_sp)
    }

    fn free(&mut self) -> Result<()> {
        let backup = self.allocated.pop().context("empty stack")?;
        let mut regs = self.regs;

        regs.set_sp(backup);
        self.set_regs(regs)?;

        Ok(())
    }

    fn wait(&self) -> Result<WaitStatus> {
        loop {
            match waitpid(self.pid, Some(WaitPidFlag::__WALL)) {
                Ok(status) => {
                    if let WaitStatus::Stopped(_, Signal::SIGSEGV) = status {
                        return Ok(status)
                    }

                    if cfg!(debug_assertions) {
                        let info = ptrace::getsiginfo(self.pid)?;
                        debug!("process {} stopped by signal: {:?}", self.pid, info);
                    }

                    bail!("process {} stopped unexpectedly: {:?}", self.pid, status);
                },
                Err(err) => {
                    if err == Errno::EINTR {
                        continue
                    }

                    bail!("failed to wait process {}: {}", self.pid, err)
                }
            }
        }
    }

    fn call(&mut self, func: usize, args: &[u64], return_addr: Option<usize>) -> Result<u64> {
        if args.len() > arch_select!(6, 8) {
            bail!("too many parameters");
        }

        let backup = self.regs()?;

        let retval: Result<u64> = try {
            let mut regs= backup;

            // align to 16 bytes
            regs.set_sp(regs.sp() & !0xF);

            regs.set_pc(func);  // jump to func
            regs.set_args(args);  // pass arguments

            // set return address
            let return_addr = return_addr.unwrap_or(Self::MAGIC_ADDR);

            #[cfg(target_arch = "x86_64")]
            {
                regs.set_sp(regs.sp() - 8);
                self.poke(regs.sp(), return_addr as _)?;
            }

            #[cfg(target_arch = "aarch64")]
            {
                regs.0.regs[30] = return_addr as _;
            }

            // all ready, run!
            self.set_regs(regs)?;
            ptrace::cont(self.pid, None)?;
            self.wait()?;
            self.regs_dirty = true;

            // check return address
            regs = self.regs()?;
            let current_pc = regs.pc();

            if current_pc != return_addr {
                Err(anyhow!("wrong return address: 0x{:x}", current_pc))?;
            }

            regs.retval()
        };

        // restore regs
        self.set_regs(backup)?;

        retval
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        if let Err(err) = ptrace::detach(self.pid, None) {
           warn!("failed to detach process {}: {}", self.pid, err);
        }
    }
}


struct RemoteProcess {
    pid: i32,
    maps: Vec<Map>
}

impl RemoteProcess {
    fn from_pid(pid: i32) -> Result<Self> {
        Ok(Self {
            pid,
            maps: rsprocmaps::from_pid(pid)?.flatten().collect()
        })
    }

    fn refresh_maps(&mut self) -> Result<()> {
        self.maps = rsprocmaps::from_pid(self.pid)?.flatten().collect();
        Ok(())
    }
}


fn read_string(tracee: &Tracee, addr: usize) -> Result<String> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut ptr = addr;

    loop {
        let end = tracee.peek(ptr)?
            .to_le_bytes()
            .iter()
            .copied()
            .any(|ch| { buffer.push(ch); ch == 0 });

        if end {
            break
        }

        ptr += 8;
    }

    Ok(String::from_utf8(buffer)?)
}

fn read_jstring(tracee: &mut Tracee, jnienv: usize, jstring: usize) -> Result<String> {
    let functions = tracee.peek(jnienv)? as usize;
    let alloc = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, GetStringUTFChars))? as usize;
    let release = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, ReleaseStringUTFChars))? as usize;

    let ptr = tracee.call(alloc, &[jnienv as _, jstring as _, 0], None)? as usize;
    let string = read_string(tracee, ptr)?;

    tracee.call(release, &[jnienv as _, jstring as _, ptr as _], None)?;

    Ok(string)
}

// return true to inject, or false to skip
fn check_process(tracee: &mut Tracee) -> bool {
    let res: Result<bool> = try {
        let process_name = tracee.uprobe_arg(10)? as usize;

        if process_name != 0 {
            let jnienv = tracee.uprobe_arg(0)? as usize;
            let name = read_jstring(tracee, jnienv, process_name)?;

            info!("process name: {name}");
        }

        true  // Todo: more checks from blacklist or whitelist
    };

    res.unwrap_or_else(|err| {
        warn!("failed to check process: {err}");
        false
    })
}

fn find_module(proc: &RemoteProcess, name: &str) -> Result<(PathBuf, usize)> {
    let base = proc.maps.iter().find_map(|map| {
        if map.permissions.writable || map.permissions.executable {
            return None
        }

        if let Pathname::Path(p) = &map.pathname {
            if let Some(filename) = PathBuf::from(&p).file_name() {
                if filename.to_string_lossy() == name {
                    return Some((PathBuf::from(p), map.address_range.begin as usize))
                }
            }
        }

        None
    });

    base.context(format!("failed to find module {name} in process {}", proc.pid))
}

fn find_func_addr(proc: &RemoteProcess, lib: &str, func: &str) -> Result<usize> {
    let (lib, base) = find_module(&proc, lib)?;
    let offset = symbols::resolve(lib, func)?;

    Ok(base + offset)
}

fn call_dlopen(tracee: &mut Tracee, library: &str) -> Result<()> {
    let proc = RemoteProcess::from_pid(tracee.pid.as_raw())?;
    
    let lib_name = CString::new(library)?;
    let lib_addr = tracee.alloc(lib_name.as_bytes_with_nul())?;

    let res: Result<()> = try {
        let dlopen = find_func_addr(&proc, "libdl.so", "dlopen")?;
        let dlerror = find_func_addr(&proc, "libdl.so", "dlerror")?;

        let (_, libc_base) = find_module(&proc, "libc.so")?;

        let handle = tracee.call(dlopen, &[lib_addr as _, libc::RTLD_LAZY as _], Some(libc_base))?;
        
        if handle == 0 {
            let error = tracee.call(dlerror, &[], None)?;
            let error = read_string(tracee, error as usize)?;
            Err(anyhow!(error))?;
        }
    };
    
    if let Err(err) = res {
        warn!("dlopen failed: {err}");
    }

    tracee.free()?;  // lib_addr

    Ok(())
}

pub fn do_inject(pid: i32) -> Result<()> {
    let mut tracee = Tracee::new(pid);
    tracee.attach()?;

    if !check_process(&mut tracee) {
        return Ok(())
    }

    call_dlopen(&mut tracee, "/debug_ramdisk/zloader/libzygisk.so")?;

    // let mut args = Vec::new();
    // let return_addr = tracee.uprobe_return_address()?;
    //
    // for i in 0 .. 20 {
    //     args.push(tracee.uprobe_arg(i)?);
    // }

    Ok(())
}
