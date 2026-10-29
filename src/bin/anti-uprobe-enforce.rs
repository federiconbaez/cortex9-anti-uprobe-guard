//! Optional real-uprobe enforcement.
//!
//! Tries to register a kernel uprobe on `cx9_canary_branch` via
//! `/sys/kernel/tracing/uprobe_events`. If the kernel refuses (no CAP_SYS_ADMIN,
//! `unprivileged_bpf_disabled`, missing CONFIG_UPROBE_EVENTS, Landlock, …) the
//! process exits non-zero with a clear message — no silent skip.
//!
//! When the uprobe does attach, the detector must report `tampered` (the kernel
//! rewrote the first byte to `0xCC`).

use anti_uprobe_guard::{cx9_canary_branch, scan_self, Verdict};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let _ = cx9_canary_branch(0);
    let exe = match anti_uprobe_guard::canary::self_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ENFORCE FAIL: resolve exe: {e}");
            return ExitCode::from(1);
        }
    };
    let loc = match anti_uprobe_guard::canary::locate_canary() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ENFORCE FAIL: locate canary: {e}");
            return ExitCode::from(1);
        }
    };

    let events = Path::new("/sys/kernel/tracing/uprobe_events");
    if !events.exists() {
        // Fallback path used on some distros.
        let alt = Path::new("/sys/kernel/debug/tracing/uprobe_events");
        if !alt.exists() {
            eprintln!(
                "ENFORCE FAIL: neither /sys/kernel/tracing/uprobe_events nor \
                 /sys/kernel/debug/tracing/uprobe_events exists. \
                 Kernel likely built without CONFIG_UPROBE_EVENTS, or tracingfs \
                 is not mounted. Refusing to skip."
            );
            return ExitCode::from(1);
        }
        return run_against(alt, &exe, loc.file_offset);
    }
    run_against(events, &exe, loc.file_offset)
}

fn run_against(events: &Path, exe: &Path, file_offset: u64) -> ExitCode {
    let name = "cx9_anti_uprobe_guard";
    // Clear any previous definition (ignore errors).
    let _ = fs::OpenOptions::new()
        .append(true)
        .open(events)
        .and_then(|mut f| write!(f, "-:{name}"));

    let line = format!("p:{name} {}:0x{file_offset:x}\n", exe.display());
    match fs::OpenOptions::new().append(true).open(events) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!(
                    "ENFORCE FAIL: write uprobe_events ({}): {e}. \
                     Need CAP_SYS_ADMIN / root, and a kernel that accepts uprobes. \
                     Refusing to skip.",
                    events.display()
                );
                return ExitCode::from(1);
            }
        }
        Err(e) => {
            eprintln!(
                "ENFORCE FAIL: open {} for append: {e}. Refusing to skip.",
                events.display()
            );
            return ExitCode::from(1);
        }
    }

    // Enable the event.
    let enable_paths = [
        format!("/sys/kernel/tracing/events/uprobes/{name}/enable"),
        format!("/sys/kernel/debug/tracing/events/uprobes/{name}/enable"),
    ];
    let mut enabled = false;
    for p in &enable_paths {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(p) {
            if f.write_all(b"1").is_ok() {
                enabled = true;
                break;
            }
        }
    }
    if !enabled {
        eprintln!(
            "ENFORCE FAIL: uprobe registered but could not enable event `{name}`. \
             Refusing to skip."
        );
        let _ = cleanup(events, name);
        return ExitCode::from(1);
    }

    // The kernel installs the breakpoint lazily on the next mmap of the inode
    // OR immediately on existing VMAs. For the running process, register_for_each_vma
    // should have patched us already. Scan.
    let report = match scan_self() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ENFORCE FAIL: scan after uprobe: {e}");
            let _ = cleanup(events, name);
            return ExitCode::from(1);
        }
    };

    let ok = report.verdict == Verdict::Tampered
        && report.diffs.iter().any(|d| d.actual == 0xCC);

    let _ = cleanup(events, name);

    if ok {
        println!(
            "ENFORCE OK: real uprobe installed; detector saw {} diff(s), including 0xCC.",
            report.diff_count
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "ENFORCE FAIL: uprobe appeared to register, but detector verdict={:?} \
             diff_count={}. Possible causes: valid_vma rejected a writable mapping, \
             or the breakpoint landed outside the compared range. Refusing to call this a pass.",
            report.verdict, report.diff_count
        );
        ExitCode::from(1)
    }
}

fn cleanup(events: &Path, name: &str) -> std::io::Result<()> {
    for p in [
        format!("/sys/kernel/tracing/events/uprobes/{name}/enable"),
        format!("/sys/kernel/debug/tracing/events/uprobes/{name}/enable"),
    ] {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(&p) {
            let _ = f.write_all(b"0");
        }
    }
    let mut f = fs::OpenOptions::new().append(true).open(events)?;
    write!(f, "-:{name}")
}
