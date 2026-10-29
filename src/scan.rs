//! Compare each executable mapping of the running binary against the file.

use crate::elf::ElfImage;
use crate::maps::exec_maps_for;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Diff {
    pub abs_addr: u64,
    pub file_offset: u64,
    pub expected: u8,
    pub actual: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    Tampered,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanReport {
    pub exe: String,
    pub bytes_compared: u64,
    pub diffs: Vec<Diff>,
    pub verdict: Verdict,
    /// Total mismatches; `diffs` is capped at [`MAX_DIFFS_KEPT`].
    pub diff_count: usize,
}

const MAX_DIFFS_KEPT: usize = 32;

/// Full scan of every executable mapping of `exe`.
pub fn scan_path(exe: &Path) -> Result<ScanReport, String> {
    let elf = ElfImage::open(exe)?;
    let maps = exec_maps_for(exe)?;
    let mut diffs = Vec::new();
    let mut bytes_compared = 0u64;
    let mut diff_count = 0usize;
    for m in &maps {
        let file_off = m.offset as usize;
        let len = (m.end - m.start) as usize;
        let file_backed = std::cmp::min(len, elf.bytes.len().saturating_sub(file_off));
        if file_backed == 0 {
            continue;
        }
        let file_slice = &elf.bytes[file_off..file_off + file_backed];
        // Safety: reading our own RX mapping of the ELF we just opened.
        let mem = unsafe { std::slice::from_raw_parts(m.start as *const u8, file_backed) };
        for (i, (a, e)) in mem.iter().zip(file_slice.iter()).enumerate() {
            bytes_compared += 1;
            if a != e {
                diff_count += 1;
                if diffs.len() < MAX_DIFFS_KEPT {
                    diffs.push(Diff {
                        abs_addr: m.start + i as u64,
                        file_offset: m.offset + i as u64,
                        expected: *e,
                        actual: *a,
                    });
                }
            }
        }
    }
    let verdict = if diff_count == 0 {
        Verdict::Ok
    } else {
        Verdict::Tampered
    };
    Ok(ScanReport {
        exe: exe.display().to_string(),
        bytes_compared,
        diffs,
        verdict,
        diff_count,
    })
}

pub fn scan_self() -> Result<ScanReport, String> {
    let exe = crate::canary::self_exe()?;
    scan_path(&exe)
}
