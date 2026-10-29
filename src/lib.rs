//! Anti-uprobe integrity: compare the running process's executable mapping
//! against the on-disk ELF that backs it.
//!
//! Real kernel uprobes replace a userspace instruction with `int3` (`0xCC`).
//! A process that distrusts those probes can detect the rewrite by comparing
//! memory to the file. This crate does that comparison for the binary's own
//! `PT_LOAD` executable segment. Breakpoints for the laboratory are planted
//! in userspace with `mprotect` + a write, because this host may have BPF
//! disabled for unprivileged users.

pub mod canary;
pub mod elf;
pub mod maps;
pub mod plant;
pub mod scan;

pub use canary::{canary_branch_offset_in_text, canary_jne_offset_in_text, cx9_canary_branch};
pub use plant::{plant_branch_flip, plant_int3, with_plant};
pub use scan::{scan_self, Diff, ScanReport, Verdict};
