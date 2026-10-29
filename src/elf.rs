//! Minimal ELF64 reader: locate the executable PT_LOAD and map file offsets
//! to virtual addresses. No external ELF crate — keeps the detector auditable.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const EI_MAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

#[derive(Debug, Clone)]
pub struct ExecSegment {
    pub file_offset: u64,
    pub virt_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
}

#[derive(Debug, Clone)]
pub struct ElfImage {
    pub path: String,
    pub etype: u16,
    pub segments: Vec<ExecSegment>,
    pub bytes: Vec<u8>,
}

impl ElfImage {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let mut hdr = [0u8; 64];
        f.read_exact(&mut hdr)
            .map_err(|e| format!("read ELF header: {e}"))?;
        if hdr[0..4] != EI_MAG {
            return Err("not an ELF".into());
        }
        if hdr[4] != ELFCLASS64 || hdr[5] != ELFDATA2LSB {
            return Err("only ELF64 little-endian supported".into());
        }
        let etype = u16::from_le_bytes([hdr[16], hdr[17]]);
        if etype != ET_EXEC && etype != ET_DYN {
            return Err(format!("unexpected e_type {etype}"));
        }
        let phoff = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
        let phentsize = u16::from_le_bytes([hdr[54], hdr[55]]) as u64;
        let phnum = u16::from_le_bytes([hdr[56], hdr[57]]) as u64;

        let mut segments = Vec::new();
        for i in 0..phnum {
            f.seek(SeekFrom::Start(phoff + i * phentsize))
                .map_err(|e| format!("seek phdr: {e}"))?;
            let mut ph = vec![0u8; phentsize as usize];
            f.read_exact(&mut ph)
                .map_err(|e| format!("read phdr: {e}"))?;
            let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
            if p_type != PT_LOAD {
                continue;
            }
            let p_flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
            // Executable code: typically PF_R|PF_X. Accept any with PF_X.
            if p_flags & PF_X == 0 {
                continue;
            }
            let _ = PF_R;
            let p_offset = u64::from_le_bytes(ph[8..16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
            if p_filesz == 0 {
                continue;
            }
            segments.push(ExecSegment {
                file_offset: p_offset,
                virt_addr: p_vaddr,
                file_size: p_filesz,
                mem_size: p_memsz,
            });
        }
        if segments.is_empty() {
            return Err("no executable PT_LOAD found".into());
        }

        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("rewind: {e}"))?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)
            .map_err(|e| format!("read ELF body: {e}"))?;

        Ok(Self {
            path: path.display().to_string(),
            etype,
            segments,
            bytes,
        })
    }

    /// File bytes that back `[vaddr, vaddr+len)` inside an executable segment.
    pub fn file_slice(&self, vaddr: u64, len: usize) -> Result<&[u8], String> {
        for seg in &self.segments {
            let start = seg.virt_addr;
            let end = seg.virt_addr + seg.file_size;
            if vaddr >= start && vaddr + len as u64 <= end {
                let off = (seg.file_offset + (vaddr - start)) as usize;
                return Ok(&self.bytes[off..off + len]);
            }
        }
        Err(format!(
            "vaddr 0x{vaddr:x}+{len} not fully inside an executable PT_LOAD"
        ))
    }
}
