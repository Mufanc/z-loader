use std::mem;
use std::mem::MaybeUninit;
use anyhow::{anyhow, bail, Result};
use jni_sys::JNINativeInterface__1_6;
use log::{debug, info, warn};
use nix::errno::Errno;
use nix::libc;

#[cfg(target_arch = "aarch64")]
use nix::libc::iovec;

use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use crate::arch_select;

#[derive(Clone)]
struct Registers(user_regs_struct);

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
    fn sp(&self) -> u64 {
        self.0.rsp
    }

    #[cfg(target_arch = "aarch64")]
    fn sp(&self) -> u64 {
        self.0.sp
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sp(&mut self, sp: u64) {
        self.0.rsp = sp
    }

    #[cfg(target_arch = "aarch64")]
    fn set_sp(&mut self, sp: u64) {
        self.0.sp = sp
    }

    #[cfg(target_arch = "x86_64")]
    fn pc(&self) -> u64 {
        self.0.rip
    }

    #[cfg(target_arch = "aarch64")]
    fn pc(&self) -> u64 {
        self.0.pc
    }

    #[cfg(target_arch = "x86_64")]
    fn set_pc(&mut self, pc: u64) {
        self.0.rip = pc
    }

    #[cfg(target_arch = "aarch64")]
    fn set_pc(&mut self, pc: u64) {
        self.0.pc = pc
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


struct Tracee(Pid);

impl Tracee {

    const MAGIC_ADDR: u64 = 0xcafecafe;

    fn new(pid: i32) -> Self {
        Self(Pid::from_raw(pid))
    }

    fn attach(&self) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(0x4206 /* PTRACE_SEIZE */, self.0.as_raw(), 0, 0)
        })?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn regs(&self) -> Result<Registers> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_GETREGS, self.0.as_raw(), 0, regs.as_mut_ptr())
        })?;

        Ok(Registers::new(unsafe { regs.assume_init() }))
    }

    #[cfg(target_arch = "aarch64")]
    fn regs(&self) -> Result<Registers> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();
        let iov = iovec {
            iov_base: regs.as_mut_ptr() as _,
            iov_len: mem::size_of::<user_regs_struct>()
        };

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_GETREGSET, self.0.as_raw(), 1 /* NT_PRSTATUS */, &iov as *const _)
        })?;

        Ok(Registers::new(unsafe { regs.assume_init() }))
    }

    #[cfg(target_arch = "x86_64")]
    fn set_regs(&self, regs: &Registers) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_SETREGS, self.0.as_raw(), 0, regs as *const _)
        })?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn set_regs(&self, regs: &Registers) -> Result<()> {
        let iov = iovec {
            iov_base: regs as *const _ as *mut _,
            iov_len: mem::size_of::<user_regs_struct>()
        };

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_SETREGSET, self.0.as_raw(), 1 /* NT_PRSTATUS */, &iov as *const _)
        })?;

        Ok(())
    }

    fn peek(&self, addr: u64) -> Result<u64> {
        Ok(ptrace::read(self.0, addr as _)? as u64)
    }

    fn poke(&self, addr: u64, value: u64) -> Result<()> {
        unsafe {
            ptrace::write(self.0, addr as _, value as *mut _)?
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn uprobe_arg(&self, n: usize) -> Result<u64> {
        let regs = self.regs()?;
        let arg = if n < 6 {
            regs.arg(n)
        } else {
            let n = (n - 6) as u64;
            self.peek(regs.sp() + 8 * n + 16 /* call + push rbp */)?
        };

        Ok(arg)
    }

    #[cfg(target_arch = "aarch64")]
    fn uprobe_arg(&self, n: usize) -> Result<u64> {
        let regs = self.regs()?;
        let arg = if n < 8 {
            regs.arg(n)
        } else {
            let n = (n - 8) as u64;
            ptrace::read(self.0, (regs.sp() + 8 * n) as _)? as u64
        };

        Ok(arg)
    }

    fn wait_for(&self) -> Result<WaitStatus> {
        loop {
            match waitpid(self.0, Some(WaitPidFlag::__WALL)) {
                Ok(status) => {
                    if let WaitStatus::Stopped(_, Signal::SIGSEGV) = status {
                        return Ok(status)
                    }

                    if cfg!(debug_assertions) {
                        let info = ptrace::getsiginfo(self.0)?;
                        debug!("process {} stopped by signal: {:?}", self.0, info);
                    }

                    bail!("process {} stopped unexpectedly: {:?}", self.0, status);
                },
                Err(err) => {
                    if err == Errno::EINTR {
                        continue
                    }

                    bail!("failed to wait process {}: {}", self.0, err)
                }
            }
        }
    }

    fn call(&self, func: u64, args: &[u64], return_addr: Option<u64>) -> Result<u64> {
        if args.len() > arch_select!(6, 8) {
            bail!("too many parameters");
        }

        let backup = self.regs()?;

        let retval: Result<u64> = try {
            let mut regs= backup.clone();

            // align stack
            regs.set_sp(regs.sp() & !0xF);

            regs.set_pc(func);  // jump to func
            regs.set_args(&args);  // pass arguments

            // set return address
            let return_addr = return_addr.unwrap_or(Self::MAGIC_ADDR);

            #[cfg(target_arch = "x86_64")]
            {
                regs.set_sp(regs.sp() - 8);
                self.poke(regs.sp(), return_addr)?;
            }

            #[cfg(target_arch = "aarch64")]
            {
                regs.0.regs[30] = return_addr;
            }

            // all ready, run!
            self.set_regs(&regs)?;

            ptrace::cont(self.0, None)?;
            self.wait_for()?;

            // check return address
            regs = self.regs()?;
            let current_pc = regs.pc();

            if current_pc != return_addr {
                Err(anyhow!("wrong return address: 0x{:x}", current_pc))?;
            }

            regs.retval()
        };

        // restore regs
        self.set_regs(&backup)?;

        retval
    }

    fn read_string(&self, addr: u64) -> Result<String> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut ptr = addr;

        loop {
            let data = self.peek(ptr)?.to_le_bytes();

            let end = data.iter()
                .copied()
                .find(|ch| { buffer.push(*ch); *ch == 0 })
                .is_some();

            if end {
                break
            }

            ptr += 8;
        }

        Ok(String::from_utf8(buffer)?)
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        if let Err(err) = ptrace::detach(self.0, None) {
           warn!("failed to detach process {}: {}", self.0, err);
        }
    }
}

pub fn do_inject(pid: i32) -> Result<()> {
    let tracee = Tracee::new(pid);
    tracee.attach()?;

    for i in 0 ..= 19 {
        let arg = tracee.uprobe_arg(i)?;
        debug!("check_process: arg[{i:2}] = 0x{arg:x}\t({arg})");
    }

    let env = tracee.uprobe_arg(0)?;
    let process_name = tracee.uprobe_arg(10)?;

    if process_name != 0 {
        let functions = tracee.peek(env)?;
        let func_get = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, GetStringUTFChars) as u64)?;
        let func_release = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, ReleaseStringUTFChars) as u64)?;

        let ptr = tracee.call(func_get, &[env, process_name, 0], None)?;
        let name = tracee.read_string(ptr)?;

        tracee.call(func_release, &[env, process_name, ptr], None)?;

        info!("process name: {name}");
    }

    Ok(())
}