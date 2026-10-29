//! Parse `/proc/self/maps` for the executable mapping of a given inode/path.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ExecMap {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub path: String,
}

/// Return every `r-xp` / `r-x` mapping whose path equals `wanted` (after
/// resolving both sides). Pie binaries usually have one executable mapping.
pub fn exec_maps_for(wanted: &Path) -> Result<Vec<ExecMap>, String> {
    let wanted_canon = fs::canonicalize(wanted)
        .map_err(|e| format!("canonicalize {}: {e}", wanted.display()))?;
    let wanted_str = wanted_canon.to_string_lossy().into_owned();
    let text = fs::read_to_string("/proc/self/maps").map_err(|e| format!("maps: {e}"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        // 55aa-55ab r-xp 00001000 fd:01 123 /path
        let mut parts = line.split_whitespace();
        let range = parts.next().ok_or("maps: short line")?;
        let perms = parts.next().ok_or("maps: no perms")?;
        let offset_s = parts.next().ok_or("maps: no offset")?;
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts.next().unwrap_or("");
        if !perms.contains('x') || !perms.contains('r') {
            continue;
        }
        if path.is_empty() || path.starts_with('[') {
            continue;
        }
        // Compare by canonical path when possible.
        let path_ok = if let Ok(c) = fs::canonicalize(path) {
            c == wanted_canon
        } else {
            path == wanted_str || path == wanted.to_string_lossy()
        };
        if !path_ok {
            continue;
        }
        let (a, b) = range
            .split_once('-')
            .ok_or_else(|| format!("bad range {range}"))?;
        let start = u64::from_str_radix(a, 16).map_err(|e| format!("start: {e}"))?;
        let end = u64::from_str_radix(b, 16).map_err(|e| format!("end: {e}"))?;
        let offset = u64::from_str_radix(offset_s, 16).map_err(|e| format!("offset: {e}"))?;
        out.push(ExecMap {
            start,
            end,
            offset,
            path: path.to_string(),
        });
    }
    if out.is_empty() {
        return Err(format!(
            "no executable mapping for {}",
            wanted_canon.display()
        ));
    }
    Ok(out)
}
