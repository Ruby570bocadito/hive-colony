// Platform-specific shared memory arena management.
// Creates and maps the shared memory region used by all agents.
// Prefers memfd_create on Linux (anonymous, no filesystem footprint),
// falls back to shm_open with a randomized name.

use std::io;
use crate::shared_arena;

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::ptr;

    use crate::shared_arena;

    pub struct SharedArenaMapping {
        pub ptr: *mut u8,
        pub size: usize,
        fd: i32,
        owned: bool,
        #[allow(dead_code)]
        arena_name: String,
    }

    unsafe impl Send for SharedArenaMapping {}
    unsafe impl Sync for SharedArenaMapping {}

    impl SharedArenaMapping {
        /// Create or open the shared memory arena.
        /// If `arena_name` is Some, use shm_open with that name.
        /// If None, use memfd_create for anonymous memory (no filesystem path).
        pub fn create_or_open(arena_name: Option<&str>) -> io::Result<Self> {
            let size = shared_arena::arena_size();

            let (fd, owned, name) = if let Some(name) = arena_name {
                let cname = CString::new(name).unwrap();
                let fd = unsafe {
                    libc::shm_open(
                        cname.as_ptr(),
                        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                        0o600,
                    )
                };
                let (fd, owned) = if fd == -1 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EEXIST) {
                        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0o600) };
                        if fd == -1 {
                            return Err(io::Error::last_os_error());
                        }
                        (fd, false)
                    } else {
                        return Err(err);
                    }
                } else {
                    (fd, true)
                };
                (fd, owned, name.to_string())
            } else {
                let cname = CString::new("colmena_arena").unwrap();
                let fd = unsafe {
                    libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC)
                };
                if fd == -1 {
                    return Err(io::Error::last_os_error());
                }
                (fd, true, "(anonymous)".to_string())
            };

            // Set size
            if owned {
                let rc = unsafe { libc::ftruncate64(fd, size as i64) };
                if rc == -1 {
                    let _ = unsafe { libc::close(fd) };
                    return Err(io::Error::last_os_error());
                }
            }

            // Map
            let ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };

            if ptr == libc::MAP_FAILED {
                let _ = unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            // Lock into RAM to avoid paging (anti-forensics)
            unsafe {
                libc::mlock(ptr, size);
            }

            Ok(Self {
                ptr: ptr as *mut u8,
                size,
                fd,
                owned,
                arena_name: name,
            })
        }

        /// Access the arena pointer
        pub fn as_ptr(&self) -> *mut u8 {
            self.ptr
        }

        /// Whether this process created (owns) the arena
        pub fn is_owned(&self) -> bool {
            self.owned
        }
    }

    impl Drop for SharedArenaMapping {
        fn drop(&mut self) {
            unsafe {
                libc::munlock(self.ptr as *const libc::c_void, self.size);
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use crate::shared_arena;
    use std::io;

    pub struct SharedArenaMapping {
        pub ptr: *mut u8,
        pub size: usize,
        pub owned: bool,
        pub arena_name: String,
    }

    unsafe impl Send for SharedArenaMapping {}
    unsafe impl Sync for SharedArenaMapping {}

    impl SharedArenaMapping {
        /// Fallback: allocate in-process-only arena (no cross-process on non-Linux in Phase 1)
        pub fn create_or_open(_arena_name: Option<&str>) -> io::Result<Self> {
            use std::alloc::{self, Layout};
            let size = shared_arena::arena_size();
            let layout = Layout::from_size_align(size, 4096)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let ptr = unsafe { alloc::alloc_zeroed(layout) };
            if ptr.is_null() {
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, "arena alloc failed"));
            }
            Ok(Self {
                ptr,
                size,
                owned: true,
                arena_name: "(heap)".to_string(),
            })
        }

        pub fn as_ptr(&self) -> *mut u8 {
            self.ptr
        }

        pub fn is_owned(&self) -> bool {
            self.owned
        }
    }

    impl Drop for SharedArenaMapping {
        fn drop(&mut self) {
            use std::alloc::{self, Layout};
            let layout = Layout::from_size_align(self.size, 4096)
                .expect("arena layout: valid size+align");
            unsafe { alloc::dealloc(self.ptr, layout); }
        }
    }
}

// Re-export platform type
pub use platform::SharedArenaMapping;

/// Try to connect to the arena.
/// First checks for the CROWNHIVE_ARENA_NAME env var,
/// then tries memfd_create (anonymous), then shm_open with generated name.
pub fn connect_to_arena() -> io::Result<SharedArenaMapping> {
    // Check if parent process passed us an arena name
    if let Ok(name) = std::env::var("__HIVE_ARENA") {
        if !name.is_empty() {
            let mapping = SharedArenaMapping::create_or_open(Some(&name))?;
            return Ok(mapping);
        }
    }

    // Try anonymous memfd first (parent-child scenario)
    if cfg!(target_os = "linux") {
        if let Ok(mapping) = SharedArenaMapping::create_or_open(None) { return Ok(mapping) }
    }

    // Generate a random name for cross-process discovery
    let random_name = shared_arena::generate_arena_name();
    SharedArenaMapping::create_or_open(Some(&random_name))
}
