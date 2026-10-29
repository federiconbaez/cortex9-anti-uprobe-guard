use anti_uprobe_guard::plant::{plant_branch_flip, plant_int3};
use anti_uprobe_guard::{cx9_canary_branch, scan_self, Verdict};

#[test]
fn canary_is_callable() {
    assert_eq!(cx9_canary_branch(0), 1);
    assert_eq!(cx9_canary_branch(7), 8);
}

#[test]
fn clean_scan_is_ok() {
    let r = scan_self().expect("scan");
    assert_eq!(r.verdict, Verdict::Ok, "diffs={:?}", r.diffs);
    assert!(r.bytes_compared > 0);
}

#[test]
fn planted_int3_is_detected_and_restored() {
    {
        let _g = plant_int3().expect("plant int3");
        let r = scan_self().expect("scan");
        assert_eq!(r.verdict, Verdict::Tampered);
        assert!(
            r.diffs.iter().any(|d| d.actual == 0xCC),
            "expected a 0xCC diff, got {:?}",
            r.diffs
        );
    }
    let r = scan_self().expect("scan after drop");
    assert_eq!(r.verdict, Verdict::Ok, "plant was not restored: {:?}", r.diffs);
}

#[test]
fn planted_branch_flip_is_detected_and_restored() {
    {
        let _g = plant_branch_flip().expect("plant branch");
        let r = scan_self().expect("scan");
        assert_eq!(r.verdict, Verdict::Tampered);
        assert!(
            r.diffs.iter().any(|d| (d.expected == 0x75 && d.actual == 0x74) || (d.expected == 0x74 && d.actual == 0x75)),
            "expected 0x75->0x74, got {:?}",
            r.diffs
        );
    }
    let r = scan_self().expect("scan after drop");
    assert_eq!(r.verdict, Verdict::Ok, "plant was not restored: {:?}", r.diffs);
}

#[test]
fn int3_plant_does_not_leave_0xcc_after_drop() {
    let before = scan_self().unwrap();
    assert_eq!(before.verdict, Verdict::Ok);
    {
        let _g = plant_int3().unwrap();
    }
    let after = scan_self().unwrap();
    assert_eq!(after.verdict, Verdict::Ok);
    assert_eq!(after.diff_count, 0);
}
