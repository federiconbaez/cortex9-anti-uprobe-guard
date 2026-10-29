//! CLI: `scan`, `measure` (lab), `locate` (debug the canary).

use anti_uprobe_guard::plant::PlantKind;
use anti_uprobe_guard::{plant_branch_flip, plant_int3, scan_self, Verdict};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Serialize)]
struct ArmResult {
    name: &'static str,
    n: usize,
    detections: usize,
    false_alarms: usize,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct MeasureReport {
    prereg: String,
    n: usize,
    arms: Vec<ArmResult>,
    thresholds: Thresholds,
    met: bool,
    by_construction_caveat: &'static str,
}

#[derive(Serialize)]
struct Thresholds {
    tpr_int3: f64,
    tpr_branch_only: f64,
    fpr_clean: f64,
    tpr_int3_min: f64,
    tpr_branch_only_min: f64,
    fpr_clean_max: f64,
}

fn usage() -> ! {
    eprintln!(
        "usage:
  anti-uprobe-guard scan
  anti-uprobe-guard locate
  anti-uprobe-guard measure [--n N] [--out PATH]
  anti-uprobe-guard plant-demo int3|branch"
    );
    std::process::exit(2);
}

fn cmd_scan() -> ExitCode {
    match scan_self() {
        Ok(r) => {
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            if r.verdict == Verdict::Ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("scan error: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_locate() -> ExitCode {
    match anti_uprobe_guard::canary::locate_canary() {
        Ok(loc) => {
            println!(
                "canary abs=0x{:x} file_offset=0x{:x} map_start=0x{:x}",
                loc.abs_addr, loc.file_offset, loc.map_start
            );
            match anti_uprobe_guard::canary::find_jcc_abs(64) {
                Ok((addr, op)) => println!("jcc abs=0x{addr:x} (byte 0x{op:02x})"),
                Err(e) => {
                    eprintln!("jcc locate: {e}");
                    return ExitCode::from(1);
                }
            }
            // Smoke: call the canary so linker keeps it.
            let v = anti_uprobe_guard::cx9_canary_branch(7);
            println!("canary(7) -> {v}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn run_arm(name: &'static str, n: usize, kind: Option<PlantKind>) -> ArmResult {
    let mut detections = 0usize;
    let mut false_alarms = 0usize;
    let mut errors = Vec::new();
    for i in 0..n {
        let result = match kind {
            None => scan_self(),
            Some(PlantKind::Int3) => {
                let _g = match plant_int3() {
                    Ok(g) => g,
                    Err(e) => {
                        errors.push(format!("trial {i}: plant int3: {e}"));
                        continue;
                    }
                };
                scan_self()
            }
            Some(PlantKind::BranchFlip) => {
                let _g = match plant_branch_flip() {
                    Ok(g) => g,
                    Err(e) => {
                        errors.push(format!("trial {i}: plant branch: {e}"));
                        continue;
                    }
                };
                scan_self()
            }
        };
        match result {
            Ok(r) => match kind {
                None => {
                    if r.verdict != Verdict::Ok {
                        false_alarms += 1;
                    }
                }
                Some(_) => {
                    if r.verdict == Verdict::Tampered {
                        detections += 1;
                    }
                }
            },
            Err(e) => errors.push(format!("trial {i}: {e}")),
        }
    }
    ArmResult {
        name,
        n,
        detections,
        false_alarms,
        errors,
    }
}

fn cmd_measure(n: usize, out: Option<PathBuf>) -> ExitCode {
    // Touch the canary so it is definitely linked into this binary.
    let _ = anti_uprobe_guard::cx9_canary_branch(0);

    let clean = run_arm("clean", n, None);
    let int3 = run_arm("int3", n, Some(PlantKind::Int3));
    let branch = run_arm("branch_only", n, Some(PlantKind::BranchFlip));

    let tpr_int3 = int3.detections as f64 / n as f64;
    let tpr_branch = branch.detections as f64 / n as f64;
    let fpr = clean.false_alarms as f64 / n as f64;

    let met = tpr_int3 >= 1.0
        && tpr_branch >= 1.0
        && fpr <= 0.0
        && clean.errors.is_empty()
        && int3.errors.is_empty()
        && branch.errors.is_empty();

    let report = MeasureReport {
        prereg: "lab/prereg.json".into(),
        n,
        arms: vec![clean, int3, branch],
        thresholds: Thresholds {
            tpr_int3,
            tpr_branch_only: tpr_branch,
            fpr_clean: fpr,
            tpr_int3_min: 1.0,
            tpr_branch_only_min: 1.0,
            fpr_clean_max: 0.0,
        },
        met,
        by_construction_caveat:
            "100% TPR / 0% FPR are on a synthetic corpus owned by the same author as the detector \
             (clean / planted 0xCC / je↔jne). Not a blind evaluation against real eBPF uprobes.",
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    println!("{json}");
    if let Some(p) = out {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::write(&p, &json) {
            eprintln!("write {}: {e}", p.display());
            return ExitCode::from(2);
        }
    }
    if met {
        ExitCode::SUCCESS
    } else {
        eprintln!("criterio no cumplido (ver JSON)");
        ExitCode::from(1)
    }
}

fn cmd_plant_demo(which: &str) -> ExitCode {
    let _ = anti_uprobe_guard::cx9_canary_branch(1);
    let guard = match which {
        "int3" => plant_int3(),
        "branch" => plant_branch_flip(),
        _ => {
            eprintln!("plant-demo expects int3|branch");
            return ExitCode::from(2);
        }
    };
    match guard {
        Ok(_g) => match scan_self() {
            Ok(r) => {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "scan" => cmd_scan(),
        "locate" => cmd_locate(),
        "measure" => {
            let mut n = 100usize;
            let mut out = None;
            let mut i = 0;
            while i < args.len() {
                match args[i].as_str() {
                    "--n" => {
                        i += 1;
                        n = args
                            .get(i)
                            .and_then(|s| s.parse().ok())
                            .expect("--n INT");
                    }
                    "--out" => {
                        i += 1;
                        out = Some(PathBuf::from(args.get(i).expect("--out PATH")));
                    }
                    other => {
                        eprintln!("unknown measure flag: {other}");
                        usage();
                    }
                }
                i += 1;
            }
            cmd_measure(n, out)
        }
        "plant-demo" => {
            let which = args.first().map(|s| s.as_str()).unwrap_or("");
            cmd_plant_demo(which)
        }
        _ => usage(),
    }
}
