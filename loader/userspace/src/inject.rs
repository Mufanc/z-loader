use std::mem;
use std::mem::MaybeUninit;
use anyhow::Result;
use log::{debug, warn};
use nix::errno::Errno;
use nix::libc;
use nix::libc::{iovec, user_regs_struct};
use nix::sys::ptrace;
use nix::unistd::Pid;

struct Registers {
    pid: Pid,
    regs: user_regs_struct,
}

impl Registers {
    fn new(pid: Pid, regs: user_regs_struct) -> Self {
        Self { pid, regs }
    }

    #[cfg(target_arch = "x86_64")]
    fn arg(&self, n: usize) -> Result<u64> {
        Ok(match n {
            0 => self.regs.rdi,
            1 => self.regs.rsi,
            2 => self.regs.rdx,
            3 => self.regs.rcx,
            4 => self.regs.r8,
            5 => self.regs.r9,
            _ => {
                let n = (n - 6) as u64;
                ptrace::read(self.pid, (self.regs.rsp + 8 * n + 16) as _)? as u64
            },
        })
    }

    #[cfg(target_arch = "aarch64")]
    fn arg(&self, n: usize) -> Result<u64> {
        Ok(if n < 8 {
            self.regs.regs[n]
        } else {
            let n = (n - 8) as u64;
            ptrace::read(self.pid, (self.regs.sp + 8 * n) as _)? as u64
        })
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
            libc::ptrace(libc::PTRACE_GETREGS, self.0.as_raw(), 1 /* NT_PRSTATUS */, regs.as_mut_ptr())
        })?;

        Ok(Registers::new(self.0, unsafe { regs.assume_init() }))
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

        Ok(Registers::new(self.0, unsafe { regs.assume_init() }))
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

    let regs = tracee.regs()?;
    
    for i in 0 ..= 12 {
        let arg = regs.arg(i)?;
        debug!("check_process: arg[{i:2}] = 0x{arg:x}\t({arg})");
    }

    Ok(())
}
