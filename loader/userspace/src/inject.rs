#[cfg(target_arch = "aarch64")]
use std::mem;

use std::mem::MaybeUninit;
use anyhow::Result;
use log::{debug, warn};
use nix::errno::Errno;
use nix::libc;

#[cfg(target_arch = "aarch64")]
use nix::libc::iovec;

use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::unistd::Pid;

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
    fn sp(&self) -> u64 {
        self.0.rsp
    }

    #[cfg(target_arch = "aarch64")]
    fn sp(&self) -> u64 {
        self.0.sp
    }
}


struct Tracee(Pid);

impl Tracee {
    fn new(pid: i32) -> Self {
        Self(Pid::from_raw(pid))
    }

    fn attach(&self) -> Result<()> {
        ptrace::attach(self.0)?;
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
    fn uprobe_arg(&self, n: usize) -> Result<u64> {
        let regs = self.regs()?;
        let arg = if n < 6 {
            regs.arg(n)
        } else {
            let n = (n - 6) as u64;
            ptrace::read(self.0, (regs.sp() + 8 * n + 16 /* call + push rbp */) as _)? as u64
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
}

impl Drop for Tracee {
    fn drop(&mut self) {
        if let Err(err) = ptrace::detach(self.0, None) {
           warn!("failed to detach process {}: {}", self.0, err);
        }
    }
}

pub fn check_process(pid: i32) -> Result<()> {
    let tracee = Tracee::new(pid);
    tracee.attach()?;
    
    for i in 0 ..= 12 {
        let arg = tracee.uprobe_arg(i)?;
        debug!("check_process: arg[{i:2}] = 0x{arg:x}\t({arg})");
    }

    Ok(())
}
