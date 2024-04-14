use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::io::IoSlice;
use std::{fs, mem, process, ptr};
use std::mem::MaybeUninit;
use std::path::PathBuf;
use anyhow::{anyhow, bail, Context, Result};
use jni_sys::JNINativeInterface__1_6;
use libloading::Symbol;
use log::{debug, error, warn};
use nix::errno::Errno;
use nix::libc;

#[cfg(target_arch = "aarch64")]
use nix::libc::iovec;

use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use rsprocmaps::{AddressRange, Map, Pathname};
use common::zygote::SpecializeArgs;
use crate::{arch_select, symbols};
use crate::loader::args::Arg;

pub type FilterFn<'a> = Symbol<'a, extern "C" fn(libc::uid_t, *const c_char, *const c_char) -> bool>;

pub struct BridgeConfig<'a> {
    pub library: String,
    pub filter_fn: Option<FilterFn<'a>>,
    pub args_count: usize,
    pub return_addr: usize,
}

#[derive(Debug, Clone)]
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
    fn set_arg(&mut self, n: usize, value: u64) {
        match n {
            0 => self.0.rdi = value,
            1 => self.0.rsi = value,
            2 => self.0.rdx = value,
            3 => self.0.rcx = value,
            4 => self.0.r8 = value,
            5 => self.0.r9 = value,
            _ => unreachable!()
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn set_arg(&mut self, n: usize, value: u64) {
        if n >= 8 {
            unreachable!()
        }

        self.0.regs[n] = value;
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

    #[allow(dead_code)]
    fn show_state(&self) {
        let res: Result<String> = try {
            let str = fs::read_to_string(format!("/proc/{}/status", self.pid))?;
            let str = str.lines()
                .find(|line| line.contains("State:"))
                .and_then(|s| s.split('\t').last());

            str.context("failed to find state")?.into()
        };

        debug!("{res:?}");
    }

    fn attach(&self) -> Result<()> {
        ptrace::attach(self.pid)?;

        loop {
            waitpid(self.pid, Some(WaitPidFlag::__WALL))?;

            if ptrace::getsiginfo(self.pid) != Err(Errno::EINVAL) {
                break
            }

            ptrace::cont(self.pid, None)?;
        }

        kill(self.pid, Signal::SIGCONT)?;
        ptrace::cont(self.pid, None)?;
        waitpid(self.pid, Some(WaitPidFlag::__WALL))?;

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

    fn set_arg(&self, regs: &mut Registers, n: usize, value: u64) -> Result<()> {
        let args_on_regs = arch_select!(6, 8);

        if n < args_on_regs {
            regs.set_arg(n, value);
        } else {
            self.poke(regs.sp() + 8 * (n - args_on_regs), value)?;
        }
        
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn set_return_addr(&self, regs: &mut Registers, addr: usize, alloc: bool) -> Result<()> {
        // x86_64 stores return address on the stack
        if alloc {
            regs.set_sp(regs.sp() - 8);
        }
        self.poke(regs.sp(), addr as _)
    }

    #[cfg(target_arch = "aarch64")]
    fn set_return_addr(&self, regs: &mut Registers, addr: usize, _alloc: bool) -> Result<()> {
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
                    
                    if let WaitStatus::Stopped(_, Signal::SIGTRAP) = status {
                        return Ok(status)
                    }

                    if cfg!(debug_assertions) {
                        if let WaitStatus::Stopped(_, Signal::SIGSTOP) = status {
                            warn!("detach for debug");
                            let _ = ptrace::detach(self.pid, Signal::SIGSTOP);
                            process::exit(0);
                        }
                        
                        let info = ptrace::getsiginfo(self.pid)?;
                        debug!("process {} stopped by signal: {:?}", self.pid, info);

                        let regs = self.regs()?;
                        let pc = regs.pc() as u64;

                        let maps = rsprocmaps::from_pid(self.pid.as_raw())?;

                        maps.flatten().any(|map| {
                            if map.address_range.begin <= pc  && pc < map.address_range.end {
                                debug!("fault addr: 0x{:x} in {:?}", pc - map.address_range.begin, map.pathname);
                                true
                            } else {
                                false
                            }
                        });
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
                let found = maps.iter().any(|map| {
                    let pc = regs.pc() as u64;
                    let AddressRange { begin, end } = map.address_range;

                    if pc < begin || pc >= end {
                        return false
                    }

                    let map_base = maps.iter().find(|m| m.pathname == map.pathname);
                    match map_base {
                        Some(map) => {
                            debug!("[{}] pc=0x{:x}, sp=0x{:x} {:?}", pid, pc - map.address_range.begin, regs.sp(), map.pathname);
                            true
                        }
                        None => false
                    }
                });

                if !found {
                    debug!("[{}] pc=0x{:x}, sp=0x{:x}", pid, regs.pc(), regs.sp());
                }

                continue
            }

            debug!("[{}] exiting: {:?}", pid, status);
            break
        }

        Ok(())
    }

    fn call(&self, regs: &Registers, func: usize, args: &[u64], return_addr: usize) -> Result<u64> {
        let retval: Result<u64> = try {
            let mut regs = regs.clone();
            
            let args_on_regs = arch_select!(6, 8);
            let remain = args.len().saturating_sub(args_on_regs);
            
            regs.set_sp(regs.sp() - remain * 8);

            // align to 16 bytes
            regs.set_sp(regs.sp() & !0xF);
            
            // pass arguments
            for (i, arg) in args.iter().copied().enumerate() {
                self.set_arg(&mut regs, i, arg)?;
            }

            regs.set_pc(func);  // jump to func

            self.set_return_addr(&mut regs, return_addr, true)?;

            // all ready, run!
            self.set_regs(&regs)?;
            ptrace::cont(self.pid, None)?;
            self.wait()?;

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
}

impl Drop for Tracee {
    fn drop(&mut self) {
        debug!("detaching process {} ...", self.pid);
        
        if let Err(err) = ptrace::detach(self.pid, None) {
           error!("failed to detach process {}: {}", self.pid, err);
        }
    }
}


mod args {
    use std::fmt::{Debug, Formatter};

    pub enum Arg {
        Numeric(u64),
        Slice(Vec<u8>)
    }

    impl Debug for Arg {
        fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                Arg::Numeric(value) => {
                    write!(fmt, "Numeric(0x{:x})", value)
                }
                Arg::Slice(value) => {
                    write!(fmt, "Slice([ data_len = {} ]))", value.len())
                }
            }
        }
    }

    pub trait UnsizedKind : Into<u64> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Numeric(self.into())
        }
    }

    impl<T : Into<u64>> UnsizedKind for T { }

    pub trait SizedKind : Into<i64> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Numeric(self.into() as u64)
        }
    }

    impl<T : Into<i64>> SizedKind for T { }

    pub trait SizeKind : Into<usize> {
        #[inline]
        fn into_arg(self) -> Arg {
            Arg::Numeric(self.into() as u64)
        }
    }

    impl<T : Into<usize>> SizeKind for T { }

    pub trait SliceKind<'a> : Into<&'a [u8]> {
        fn into_arg(self) -> Arg {
            Arg::Slice(self.into().to_vec())
        }
    }

    impl<'a, T : Into<&'a [u8]>> SliceKind<'a> for T { }
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
    maps: Vec<Map>,
    modules: HashMap<String, (PathBuf, usize)>
}

impl<'a> TraceeWrapper<'a> {
    fn new(tracee: &'a Tracee) -> Result<Self> {
        let mut instance = Self {
            tracee,
            maps: Vec::new(),
            modules: HashMap::new()
        };

        instance.update_maps()?;

        Ok(instance)
    }
    
    fn pid(&self) -> Pid {
        self.tracee.pid
    }

    fn update_maps(&mut self) -> Result<()> {
        self.maps = rsprocmaps::from_pid(self.pid().as_raw())?.flatten().collect();
        self.maps.sort_by_key(|map| map.address_range.begin);

        self.modules.clear();
        self.maps.iter().for_each(|map| {
            if let Pathname::Path(p) = &map.pathname {
                let pathname = PathBuf::from(p);
                if let Some(filename) = pathname.file_name() {
                    let filename = filename.to_string_lossy().into();

                    if self.modules.contains_key(&filename) {
                        return
                    }

                    self.modules.insert(
                        filename,
                        (pathname, map.address_range.begin as usize)
                    );
                }
            }
        });

        Ok(())
    }
    
    fn call(&self, func: usize, args: &[Arg], return_addr: Option<usize>) -> Result<u64> {
        debug!("remote call: func=0x{:x} args={:?} return_addr={:?}", func, args, return_addr);

        let tracee = self.tracee;
        let backup = tracee.regs()?;

        let res: Result<u64> = try {
            let mut regs = backup.clone();
            let mut real_args = Vec::new();

            for arg in args {
                real_args.push(match arg {
                    Arg::Numeric(arg) => *arg,
                    Arg::Slice(data) => tracee.alloc(&mut regs, data.as_slice())? as u64
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
                .any(|ch| {
                    let skip = ch == 0;
                    if !skip {
                        buffer.push(ch);
                    }
                    skip
                });

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

    fn find_module(&self, name: &str) -> Result<&(PathBuf, usize)> {
        self.modules.get(name)
            .context(format!("failed to find module {name} in process {}", self.pid()))
    }

    fn find_symbol_addr(&self, lib: &str, func: &str) -> Result<usize> {
        let (lib, base) = self.find_module(lib)?;
        let offset = symbols::resolve(lib, func)?;

        Ok(base + offset)
    }
}


// return true to inject, or false to skip
fn check_process(wrapper: &TraceeWrapper, args: &[u64], filter: Option<&FilterFn>) -> Result<bool> {
    let args = SpecializeArgs::from(args.as_ptr() as *mut _);

    let jnienv = unsafe { *(args.env as *const usize) };
    let process_name = unsafe { *(args.managed_nice_name as *const usize) };
    let app_data_dir = unsafe { *(args.managed_app_data_dir as *const usize) };

    let uid = unsafe { *(args.uid as *const libc::uid_t) };
    let package_name: Option<String> = if app_data_dir != 0 {
        let dir = wrapper.read_jstring(jnienv, app_data_dir)?;
        if let Some(index) = dir.rfind('/') {
            let package_name = &dir[index + 1 ..];
            Some(package_name.into())
        } else {
            None
        }
    } else {
        None
    };
    let process_name: Option<String> = if process_name != 0 {
        let name = wrapper.read_jstring(jnienv, process_name)?;
        Some(name)
    } else {
        None
    };
    
    if let Some(filter) = filter {
        let pkg = package_name.map(|pkg| CString::new(pkg.clone()).unwrap());
        let pkg = match &pkg {
            None => ptr::null(),
            Some(pkg) => pkg.as_ptr()
        };
        
        let name = process_name.map(|name| CString::new(name.clone()).unwrap());
        let name = match &name {
            None => ptr::null(),
            Some(name) => name.as_ptr()
        };
        
        return if filter(uid, pkg, name) {
            Ok(true)
        } else {
            Ok(false) 
        }
    }

    Ok(true)
}

// dlopen api bridge, and return address of pre & post specialize hook
fn remote_dlopen(wrapper: &mut TraceeWrapper, bridge: &str) -> Result<()> {
    let libc_base = wrapper.find_module("libc.so")?.1;

    let dlopen_addr = wrapper.find_symbol_addr("libdl.so", "dlopen")?;
    let dlerror_addr = wrapper.find_symbol_addr("libdl.so", "dlerror")?;

    fn dlerror(wrapper: &TraceeWrapper, func: usize) -> Result<()> {
        let error = wrapper.call(func, &[], None)?;
        let error = wrapper.read_string(error as _)?;

        Err(anyhow!(error))
    }

    let handle = wrapper.call(dlopen_addr, args!(bridge.unix(), libc::RTLD_LAZY), Some(libc_base))?;

    if handle == 0 {
        dlerror(wrapper, dlerror_addr)?;
    }

    // update maps after dlopen
    wrapper.update_maps()?;

    Ok(())
}

fn unmap_uprobes(wrapper: &TraceeWrapper) -> Result<()> {
    let uprobes_range = wrapper.maps.iter().find_map(|map| {
        if let Pathname::OtherPseudo(pseudo) = &map.pathname {
            if pseudo == "[uprobes]" {
                return Some((map.address_range.begin, map.address_range.end))
            }
        }
        None
    });

    if let Some((begin, end)) = uprobes_range {
        let munmap_addr = wrapper.find_symbol_addr("libc.so", "munmap")?;
        let res = wrapper.call(munmap_addr, args!(begin, end - begin), None)?;
        
        if res == 0 {
            debug!("unmapped uprobes: {begin:x}-{end:x}");
        } else {
            error!("failed to unmap uprobes: {begin:x}-{end:x}");
        }
    }
    
    Ok(())
}

fn load_bridge(tracee: &Tracee, config: &BridgeConfig) -> Result<()> {
    let mut regs = tracee.regs()?;

    if cfg!(target_arch = "x86_64") {
        // revert `push %rbp`
        regs.set_pc(regs.pc() - 1);   
        regs.set_sp(regs.sp() + 8);  
    }
    
    tracee.set_regs(&regs)?;

    // check process
    let mut wrapper = TraceeWrapper::new(tracee)?;
    
    unmap_uprobes(&wrapper)?;

    // retrieve args
    let mut args = Vec::new();

    for i in 0 .. config.args_count {
        args.push(tracee.arg(&regs, i)?);
    }
    
    if !check_process(&wrapper, &args, config.filter_fn.as_ref())? {
        debug!("skip process: {}", tracee.pid);
        return Ok(())
    }
    
    if cfg!(target_arch = "aarch64") {
        // revert `paciasp`
        regs.set_pc(regs.pc() - 4);
    }
    
    tracee.set_regs(&regs)?;

    let args_data = unsafe {
        std::slice::from_raw_parts(args.as_ptr() as *const u8, args.len() * 8)
    };

    // do inject
    debug!("injecting process: {}", tracee.pid);

    remote_dlopen(&mut wrapper, &config.library)?;

    let library = PathBuf::from(&config.library);
    let library = library.file_name().unwrap().to_str().unwrap();

    let callback_before = wrapper.find_symbol_addr(library, "ZLB_CALLBACK_PRE")?;
    let callback_before = tracee.peek(callback_before)? as usize;

    let trampoline = wrapper.find_symbol_addr(library, "ZLB_TRAMPOLINE")?;
    let trampoline = tracee.peek(trampoline)? as usize;

    let real_return_addr = wrapper.find_symbol_addr(library, "ZLB_RETURN_ADDRESS")?;
    tracee.poke(real_return_addr, config.return_addr as u64)?;

    // call pre specialize hook
    wrapper.call(callback_before, args!(args_data, args.len()), None)?;

    // skip return address (*)
    if cfg!(target_arch = "x86_64") {
        regs.set_sp(regs.sp() + 0x8);
    }

    // update args
    for (i, arg) in args.iter().enumerate() {
        tracee.set_arg(&mut regs, i, *arg)?;
    }

    // (*) restore sp
    if cfg!(target_arch = "x86_64") {
        regs.set_sp(regs.sp() - 0x8);
    }

    // call SpecializeCommon
    tracee.set_return_addr(&mut regs, trampoline, false)?;
    tracee.set_regs(&regs)?;

    Ok(())
}


pub fn handle_proc(pid: i32, config: &BridgeConfig) -> Result<()> {
    let tracee = Tracee::new(pid);
    tracee.attach()?;

    let backup = tracee.regs()?;

    let res: Result<()> = try {
        load_bridge(&tracee, config)?;
    };

    // restore context if anything error
    if let Err(err) = res {
        tracee.set_regs(&backup)?;
        error!("error occurred while tracing process {}: {}", pid, err);
    }

    Ok(())
}
