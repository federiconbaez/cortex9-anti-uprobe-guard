//! Userspace simulation of uprobe breakpoints: `mprotect` + write into our
//! own `.text`. Restores the original byte afterwards.

use crate::canary::{find_jcc_abs, locate_canary};
use std::ptr;

pub struct PlantGuard {
    page: *mut libc::c_void,
    page_len: usize,
    patch_addr: *mut u8,
    original: u8,
}

impl Drop for PlantGuard {
    fn drop(&mut self) {
        unsafe {
            ptr::write(self.patch_addr, self.original);
            libc::mprotect(self.page, self.page_len, libc::PROT_READ | libc::PROT_EXEC);
        }
    }
}

fn page_of(addr: usize) -> (*mut libc::c_void, usize) {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let base = addr & !(ps - 1);
    (base as *mut libc::c_void, ps)
}

fn make_writable(page: *mut libc::c_void, len: usize) -> Result<(), String> {
    let rc = unsafe {
        libc::mprotect(
            page,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        return Err(format!(
            "mprotect RWX failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Plant `0xCC` (int3) over the first byte of `cx9_canary_branch`.
pub fn plant_int3() -> Result<PlantGuard, String> {
    let loc = locate_canary()?;
    let addr = loc.abs_addr as usize;
    let (page, page_len) = page_of(addr);
    make_writable(page, page_len)?;
    let patch_addr = addr as *mut u8;
    let original = unsafe { ptr::read(patch_addr) };
    unsafe { ptr::write(patch_addr, 0xCC) };
    Ok(PlantGuard {
        page,
        page_len,
        patch_addr,
        original,
    })
}

/// Plant a branch-only evasion: flip `je`↔`jne` (`0x74`↔`0x75`). No int3.
/// A detector that only searches for `0xCC` would miss this rewrite; a
/// byte-for-byte `.text` vs disk compare catches it.
pub fn plant_branch_flip() -> Result<PlantGuard, String> {
    let (jcc_abs, original) = find_jcc_abs(64)?;
    let addr = jcc_abs as usize;
    let (page, page_len) = page_of(addr);
    make_writable(page, page_len)?;
    let patch_addr = addr as *mut u8;
    let flipped = if original == 0x74 { 0x75 } else { 0x74 };
    unsafe { ptr::write(patch_addr, flipped) };
    Ok(PlantGuard {
        page,
        page_len,
        patch_addr,
        original,
    })
}

pub fn with_plant<F, T>(kind: PlantKind, f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let _guard = match kind {
        PlantKind::Int3 => plant_int3()?,
        PlantKind::BranchFlip => plant_branch_flip()?,
    };
    f()
}

#[derive(Debug, Clone, Copy)]
pub enum PlantKind {
    Int3,
    BranchFlip,
}
