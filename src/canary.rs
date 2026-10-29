//! A tiny never-inlined canary with a known conditional branch so the lab can
//! plant either an `int3` or a branch-only flip at a stable file-relative
//! offset without depending on DWARF.

use std::path::PathBuf;

/// Canary used as the uprobe target stand-in.
///
/// Observed encoding under `rustc` 1.85+ / `opt-level=3` on x86_64 (see `objdump -d`): a `test`/`je rel8` (`0x74`) near the top. Debug builds may
/// use `jne` (`0x75`) instead. [`find_jcc_abs`] accepts either.
#[inline(never)]
#[no_mangle]
pub extern "C" fn cx9_canary_branch(x: u32) -> u32 {
    let y = std::hint::black_box(x);
    if y == 0 {
        std::hint::black_box(1u32)
    } else {
        std::hint::black_box(y.wrapping_add(1))
    }
}

pub fn canary_addr() -> usize {
    cx9_canary_branch as *const () as usize
}

pub fn self_exe() -> Result<PathBuf, String> {
    std::fs::read_link("/proc/self/exe").map_err(|e| format!("readlink /proc/self/exe: {e}"))
}

#[derive(Debug, Clone, Copy)]
pub struct CanaryLoc {
    pub map_start: u64,
    pub map_file_offset: u64,
    pub abs_addr: u64,
    pub offset_in_map: u64,
    pub file_offset: u64,
}

pub fn locate_canary() -> Result<CanaryLoc, String> {
    let exe = self_exe()?;
    let maps = crate::maps::exec_maps_for(&exe)?;
    let addr = canary_addr() as u64;
    for m in &maps {
        if addr >= m.start && addr < m.end {
            let offset_in_map = addr - m.start;
            return Ok(CanaryLoc {
                map_start: m.start,
                map_file_offset: m.offset,
                abs_addr: addr,
                offset_in_map,
                file_offset: m.offset + offset_in_map,
            });
        }
    }
    Err(format!(
        "canary addr 0x{addr:x} not inside any exec mapping of {}",
        exe.display()
    ))
}

pub fn canary_branch_offset_in_text() -> Result<u64, String> {
    Ok(locate_canary()?.file_offset)
}

/// First short conditional jump in the canary: `je` (`0x74`) or `jne` (`0x75`).
pub fn find_jcc_abs(window: usize) -> Result<(u64, u8), String> {
    let loc = locate_canary()?;
    let ptr = loc.abs_addr as *const u8;
    let slice = unsafe { std::slice::from_raw_parts(ptr, window) };
    for (i, b) in slice.iter().enumerate() {
        if *b == 0x74 || *b == 0x75 {
            return Ok((loc.abs_addr + i as u64, *b));
        }
    }
    Err(format!(
        "no je/jne rel8 (0x74/0x75) in first {window} bytes of cx9_canary_branch \
         (compiler encoding changed; inspect with objdump -d)"
    ))
}

/// Back-compat alias used by older call sites / docs.
pub fn find_jne_abs(window: usize) -> Result<u64, String> {
    find_jcc_abs(window).map(|(a, _)| a)
}

pub fn canary_jne_offset_in_text() -> Result<u64, String> {
    let loc = locate_canary()?;
    let (jcc, _) = find_jcc_abs(64)?;
    Ok(loc.file_offset + (jcc - loc.abs_addr))
}
