use std::ffi::CString;
use std::io::IoSlice;
use std::mem;
use std::mem::MaybeUninit;
use std::path::PathBuf;
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
use rsprocmaps::{AddressRange, Map, Pathname};
use crate::{arch_select, symbols};
use crate::bridge::ApiBridge;
use crate::loader::args::Arg;


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

    #[cfg(target_arch = "x86_64")]
    fn return_value(&self) -> u64 {
        self.0.rax
    }

    #[cfg(target_arch = "aarch64")]
    fn return_value(&self) -> u64 {
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
}


struct Tracee {
    pid: Pid
}

impl Tracee {
    fn new(pid: i32) -> Self {
        Self { pid: Pid::from_raw(pid) }
    }

    fn attach(&self) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(0x4206 /* PTRACE_SEIZE */, self.pid.as_raw(), 0, 0)
        })?;

        Ok(())
    }

    fn cont(&self) -> Result<()> {
        ptrace::cont(self.pid, None)?;
        Ok(())
    }

    fn uprobe_compat(&self) -> Result<()> {
        let mut regs = self.regs()?;

        // UProbes on x86_64 stops process after `push %rbp` in target process
        if cfg!(target_arch = "x86_64") {
            regs.set_pc(regs.pc() - 1);  // move back
            regs.set_sp(regs.sp() + 8);  // pop %rbp
        }
        
        self.set_regs(&regs)?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn regs(&self) -> Result<Registers> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();

        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_GETREGS, self.pid.as_raw(), 0, regs.as_mut_ptr())
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
            libc::ptrace(libc::PTRACE_GETREGSET, self.pid.as_raw(), 1 /* NT_PRSTATUS */, &iov as *const _)
        })?;

        Ok(Registers::new(unsafe { regs.assume_init() }))
    }

    #[cfg(target_arch = "x86_64")]
    fn set_regs(&self, regs: &Registers) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_SETREGS, self.pid.as_raw(), 0, regs as *const _)
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
    fn arg(&self, regs: &Registers, n: usize) -> Result<u64> {
        let arg = if n < 6 {
            regs.arg(n)
        } else {
            let n = n - 6;
            self.peek(regs.sp() + 8 * n + 8 /* call */)?
        };

        Ok(arg)
    }

    #[cfg(target_arch = "aarch64")]
    fn arg(&self, regs: &Registers, n: usize) -> Result<u64> {
        let arg = if n < 8 {
            regs.arg(n)
        } else {
            let n = n - 8;
            self.peek(regs.sp() + 8 * n)?
        };

        Ok(arg)
    }

    #[cfg(target_arch = "x86_64")]
    fn return_addr(&self, regs: &Registers) -> Result<usize> {
        Ok(self.peek(regs.sp())? as _)
    }

    #[cfg(target_arch = "aarch64")]
    fn return_addr(&self, regs: &Registers) -> Result<usize> {
        Ok(regs.0.regs[30] as _)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_return_addr(&self, regs: &mut Registers, addr: usize) -> Result<()> {
        regs.set_sp(regs.sp() - 8);
        self.poke(regs.sp(), addr as _)
    }

    #[cfg(target_arch = "aarch64")]
    fn set_return_addr(&self, regs: &mut Registers, addr: usize) -> Result<()> {
        regs.0.regs[30] = addr as _;
        Ok(())
    }

    fn alloc(&self, regs: &mut Registers, data: &[u8]) -> Result<usize> {
        let new_sp = (regs.sp() - data.len()) & !0x7;

        let local_iov = IoSlice::new(data);
        let remote_iov = RemoteIoVec { base: new_sp, len: data.len() };
        process_vm_writev(self.pid, &[local_iov], &[remote_iov])?;

        regs.set_sp(new_sp);

        Ok(new_sp)
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

    // single step for debug
    #[allow(dead_code)]
    fn debug_call(&self) -> Result<()> {
        let pid = self.pid;
        
        let maps = rsprocmaps::from_pid(pid.as_raw())?;
        let maps: Vec<_> = maps.flatten().collect();

        loop {
            ptrace::step(self.pid, None)?;
            let status = waitpid(self.pid, Some(WaitPidFlag::__WALL))?;

            if let WaitStatus::Stopped(_, Signal::SIGTRAP) = status {
                let regs = self.regs()?;
                let pathname = maps.iter().find_map(|map| {
                    let AddressRange { begin, end } = map.address_range;
                    if (regs.pc() as u64) >= begin && (regs.pc() as u64) < end {
                        Some(map.pathname.clone())
                    } else {
                        None
                    }
                });

                println!("[{}] pc=0x{:x}, sp=0x{:x} {:?}", pid, regs.pc(), regs.sp(), pathname);
                continue
            }

            println!("[{}] exiting: {:?}", pid, status);
            break
        }
        
        Ok(())
    }

    fn call_common(&self, regs: &Registers, func: usize, args: &[u64], return_addr: usize, nowait: bool) -> Result<u64> {
        if args.len() > arch_select!(6, 8) {
            bail!("too many parameters");
        }

        let retval: Result<u64> = try {
            let mut regs = regs.clone();

            // align to 16 bytes
            regs.set_sp(regs.sp() & !0xF);

            regs.set_pc(func);  // jump to func
            regs.set_args(args);  // pass arguments

            self.set_return_addr(&mut regs, return_addr)?;

            // all ready, run!
            self.set_regs(&regs)?;
            
            if nowait {
                return Ok(0)
            }

            // // for nowait mode, SIGCONT will be sent on detach
            self.cont()?;
            self.wait()?;  // wait for return

            // check return address
            regs = self.regs()?;
            let current_pc = regs.pc();

            if current_pc != return_addr {
                Err(anyhow!("wrong return address: 0x{:x}", current_pc))?;
            }

            regs.return_value()
        };

        // restore regs
        self.set_regs(regs)?;

        retval
    }
    
    fn call(&self, regs: &Registers, func: usize, args: &[u64], return_addr: usize) -> Result<u64> {
        self.call_common(regs, func, args, return_addr, false)
    }

    // call function and detach
    fn call_nowait(self, regs: &Registers, func: usize, args: &[u64], return_addr: usize) -> Result<()> {
        self.call_common(regs, func, args, return_addr, true)?;
        Ok(())
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        if let Err(err) = ptrace::detach(self.pid, Some(Signal::SIGCONT)) {
           warn!("failed to detach process {}: {}", self.pid, err);
        }
    }
}


mod args {
    #[derive(Debug)]
    pub enum Arg {
        Register(u64),
        Stack(Vec<u8>)
    }

    pub trait UnsizedKind : Into<u64> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Register(self.into())
        }
    }

    impl<T : Into<u64>> UnsizedKind for T { }

    pub trait SizedKind : Into<i64> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Register(self.into() as u64)
        }
    }

    impl<T : Into<i64>> SizedKind for T { }

    pub trait SizeKind : Into<usize> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Register(self.into() as u64)
        }
    }

    impl<T : Into<usize>> SizeKind for T { }

    pub trait VecKind<'a> : Into<&'a [u8]> {
        fn into_arg(self) -> Arg {
            Arg::Stack(self.into().to_vec())
        }
    }

    impl<'a, T : Into<&'a [u8]>> VecKind<'a> for T { }
}

macro_rules! arg {
    ($arg: expr) => {
        {
            use args::*;
            match $arg {
                arg => (&arg).into_arg()
            }
        }
    };
}

macro_rules! args {
    ($( $arg : expr ),*) => {
        &[ $(arg!($arg)),* ]
    };
}


trait ToUnixString {
    fn unix(self) -> Vec<u8>;
}

impl<T : Into<Vec<u8>>> ToUnixString for T {
    fn unix(self) -> Vec<u8> {
        CString::new(self)
            .expect("the supplied str contains an internal 0 byte")
            .into_bytes_with_nul()
    }
}


struct TraceeWrapper<'a> {
    tracee: &'a Tracee,
    maps: Vec<Map>
}

impl<'a> TraceeWrapper<'a> {
    fn new(tracee: &'a Tracee) -> Result<Self> {
        Ok(Self {
            maps: rsprocmaps::from_pid(tracee.pid.as_raw())?.flatten().collect(),
            tracee
        })
    }
    
    fn pid(&self) -> Pid {
        self.tracee.pid
    }

    fn call(&self, func: usize, args: &[Arg], return_addr: Option<usize>) -> Result<u64> {
        let tracee = self.tracee;
        let backup = tracee.regs()?;

        let res: Result<u64> = try {
            let mut regs = backup.clone();
            let mut real_args = Vec::new();

            for arg in args {
                real_args.push(match arg {
                    Arg::Register(arg) => *arg,
                    Arg::Stack(data) => tracee.alloc(&mut regs, data.as_slice())? as u64
                });
            }

            let return_addr = return_addr.unwrap_or(self.find_module("libc.so")?.1);
            tracee.call(&regs, func, &real_args, return_addr)?
        };

        tracee.set_regs(&backup)?;

        res
    }
    
    fn read_string(&self, addr: usize) -> Result<String> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut ptr = addr;

        loop {
            let end = self.tracee.peek(ptr)?
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
    
    fn read_jstring(&self, jnienv: usize, jstring: usize) -> Result<String> {
        let tracee = self.tracee;
        let functions = tracee.peek(jnienv)? as usize;
        let alloc = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, GetStringUTFChars))? as usize;
        let release = tracee.peek(functions + mem::offset_of!(JNINativeInterface__1_6, ReleaseStringUTFChars))? as usize;

        let ptr = self.call(alloc, args!(jnienv, jstring, 0u64), None)? as usize;
        let result = self.read_string(ptr);
        self.call(release, args!(jnienv, jstring, ptr), None)?;

        result
    }

    fn find_module(&self, name: &str) -> Result<(PathBuf, usize)> {
        let base = self.maps.iter().find_map(|map| {
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

        let pid = self.pid();
        base.context(format!("failed to find module {name} in process {pid}"))
    }

    fn find_func_addr(&self, lib: &str, func: &str) -> Result<usize> {
        let (lib, base) = self.find_module(lib)?;
        let offset = symbols::resolve(lib, func)?;

        Ok(base + offset)
    }
}

// return true to inject, or false to skip
fn check_process(wrapper: &TraceeWrapper) -> Result<bool> {
    let tracee = &wrapper.tracee;
    let regs = tracee.regs()?;

    let process_name = tracee.arg(&regs, 10)? as usize;

    if process_name != 0 {
        let jnienv = tracee.arg(&regs, 0)? as usize;
        let name = wrapper.read_jstring(jnienv, process_name)?;

        info!("process name: {name}");
    }
    
    Ok(true)
}

// dlopen api bridge, and return address of pre & post specialize hook
fn load_bridge(wrapper: &TraceeWrapper, bridge: &ApiBridge) -> Result<(usize, usize)> {
    let libc_base = wrapper.find_module("libc.so")?.1;

    let dlopen_addr = wrapper.find_func_addr("libdl.so", "dlopen")?;
    let dlsym_addr = wrapper.find_func_addr("libdl.so", "dlsym")?;
    let dlerror_addr = wrapper.find_func_addr("libdl.so", "dlerror")?;

    fn dlerror(wrapper: &TraceeWrapper, func: usize) -> Result<()> {
        let error = wrapper.call(func, &[], None)?;
        let error = wrapper.read_string(error as _)?;

        Err(anyhow!(error))
    }

    let library = bridge.library.as_str();
    let handle = wrapper.call(dlopen_addr, args!(library.unix(), libc::RTLD_LAZY), Some(libc_base))?;
    
    if handle == 0 {
        dlerror(wrapper, dlerror_addr)?;
    }
    
    let hook_pre = bridge.specialize_hooks.0.as_str();
    let addr_pre = wrapper.call(dlsym_addr, args!(handle, hook_pre.unix()), Some(libc_base))?;
    
    if addr_pre == 0 {
        dlerror(wrapper, dlerror_addr)?;
    }
    
    let hook_post = bridge.specialize_hooks.1.as_str();
    let addr_post = wrapper.call(dlsym_addr, args!(handle, hook_post.unix()), Some(libc_base))?;
    
    if addr_post == 0 {
        dlerror(wrapper, dlerror_addr)?;
    }

    Ok((addr_pre as _, addr_post as _))
}

pub fn do_inject(pid: i32, bridge: &ApiBridge) -> Result<()> {
    let tracee = Tracee::new(pid);
    tracee.attach()?;
    
    let backup = tracee.regs()?;

    let res: Result<()> = try {
        tracee.uprobe_compat()?;

        let wrapper = TraceeWrapper::new(&tracee)?;

        if check_process(&wrapper)? {
            info!("skip process: {}", pid);
            return Ok(())
        }

        info!("injecting process: {}", pid);

        load_bridge(&wrapper, bridge)?;
    };

    // restore context if anything error
    if let Err(err) = res {
        tracee.set_regs(&backup)?;
        warn!("error occurred while tracing process {}: {}", pid, err);
    }

    Ok(())
}
