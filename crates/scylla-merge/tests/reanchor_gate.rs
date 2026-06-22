//! DD-038 — the re-anchoring release gate (the keystone's permanent conscience).
//!
//! Runs the real `scylla-merge` path over the Tier-0 committed snapshots and scores fact
//! survival per perturbation class against ground-truth symbol names. Two gates, on purpose:
//!
//!   * `WRONG = 0` — a HARD invariant across EVERY class. A silent mis-attachment fails the
//!     build, full stop. This is the DD-005 contract, not a knob.
//!   * survival % — a RATCHETED floor on the *promised* classes (same-opt re-analysis/edit);
//!     the hard classes (recompile, cross-arch) are track-only (WRONG=0 only). Floors are
//!     committed constants — raising one is a deliberate commit, never a runtime guess.
//!
//! Run with `cargo test -p scylla-merge --test reanchor_gate -- --nocapture` to see the board.

use scylla_merge::merge_into;
use scylla_model::{FactKind, StableId, UserFact};

const SRC_FUNCS: &[&str] = &[
    "gcd", "fib", "factorial", "sum_to", "main", "lcm", "my_strlen", "my_reverse", "count_vowels",
];

const M_X64_O0: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O0.json");
const M_X64_O2: &str = include_str!("../../../prototype/snapshots/mathlib.x86-64.O2.json");
const MV2_X64_O0: &str = include_str!("../../../prototype/snapshots/mathlib_v2.x86-64.O0.json");
const MV2_X64_O2: &str = include_str!("../../../prototype/snapshots/mathlib_v2.x86-64.O2.json");
const S_X64_O0: &str = include_str!("../../../prototype/snapshots/strutil.x86-64.O0.json");
const S_X64_O2: &str = include_str!("../../../prototype/snapshots/strutil.x86-64.O2.json");
const M_A64_O0: &str = include_str!("../../../prototype/snapshots/mathlib.aarch64.O0.json");
const MV2_A64_O0: &str = include_str!("../../../prototype/snapshots/mathlib_v2.aarch64.O0.json");
const S_A64_O0: &str = include_str!("../../../prototype/snapshots/strutil.aarch64.O0.json");

#[derive(Default)]
struct Score {
    correct: usize,
    wrong: usize,
    orphaned: usize,
}

impl Score {
    fn total(&self) -> usize {
        self.correct + self.wrong + self.orphaned
    }
    fn survival(&self) -> f64 {
        if self.total() == 0 {
            return 1.0;
        }
        self.correct as f64 / self.total() as f64
    }
}

/// Annotate v1's source functions with name-tagged markers, re-anchor onto v2 via the real
/// merge, and score each marker by ground truth (does it land on the same-named function?).
fn score(v1_json: &str, v2_json: &str) -> Score {
    let mut v1 = scylla_ingest::snapshot_to_program(v1_json).unwrap();
    let v2 = scylla_ingest::snapshot_to_program(v2_json).unwrap();

    let anchors: Vec<String> = v1
        .functions
        .iter()
        .filter(|f| SRC_FUNCS.contains(&f.name.as_str()))
        .map(|f| f.name.clone())
        .collect();
    for f in v1.functions.clone() {
        if SRC_FUNCS.contains(&f.name.as_str()) {
            v1.facts.push(UserFact::new(f.id, FactKind::Rename(format!("ANCHOR::{}", f.name))));
        }
    }

    let mut merged = v2.clone();
    let _ = merge_into(&v1, &mut merged);

    let name_of = |id: StableId| merged.functions.iter().find(|f| f.id == id).map(|f| f.name.clone());

    let mut s = Score::default();
    for name in &anchors {
        let marker = format!("ANCHOR::{name}");
        match merged.facts.iter().find(|f| matches!(&f.kind, FactKind::Rename(n) if *n == marker)) {
            Some(fact) => {
                if name_of(fact.target).as_deref() == Some(name.as_str()) {
                    s.correct += 1;
                } else {
                    s.wrong += 1;
                }
            }
            None => s.orphaned += 1,
        }
    }
    s
}

struct Class {
    name: &'static str,
    v1: &'static str,
    v2: &'static str,
    /// Ratcheted survival floor (promised classes); `None` = track-only (WRONG=0 only).
    floor: Option<f64>,
}

#[test]
fn reanchoring_release_gate() {
    let classes = [
        // Floors are RATCHETED from current reality (DD-038/DD-041), not guessed. The merge runs an
        // exact-signature pass (mnemonic-fingerprint disambiguated), THEN an ARCH-INDEPENDENT anchor
        // pass (Jaccard over string-literal + import-name sets — DD-041), THEN a fuzzy cosine pass.
        // Exact + fuzzy lift BOTH edit classes to 100%. The anchor pass cracks CROSS-ARCHITECTURE:
        // x86->aarch64 mnemonic cosine is ~0, but `main`'s string/import set is identical across the
        // ISA, so it re-anchors (the floor below LOCKS that recovery in). Recompile stays track-only.
        // WRONG=0 holds by construction: exact is unique-match; anchor and fuzzy are threshold +
        // runner-up margin, and fuzzy additionally requires a reciprocal (symmetric) best match.
        Class { name: "mathlib x86  O0->v2     (edit)        ", v1: M_X64_O0, v2: MV2_X64_O0, floor: Some(1.0) },
        Class { name: "mathlib aarch64 O0->v2  (edit)        ", v1: M_A64_O0, v2: MV2_A64_O0, floor: Some(1.0) },
        Class { name: "mathlib x86  O0->O2     (recompile)   ", v1: M_X64_O0, v2: M_X64_O2, floor: None },
        Class { name: "strutil x86  O0->O2     (recompile)   ", v1: S_X64_O0, v2: S_X64_O2, floor: None },
        Class { name: "mathlib x86  O0->v2 O2  (edit+opt)    ", v1: M_X64_O0, v2: MV2_X64_O2, floor: None },
        // Cross-arch: the DD-041 anchor pass recovers the string/import-bearing function (`main`).
        // Floors ratcheted to lock that in — a regression that loses cross-arch `main` fails the build.
        Class { name: "mathlib x86 -> aarch64  (cross-arch)  ", v1: M_X64_O0, v2: M_A64_O0, floor: Some(0.20) },
        Class { name: "strutil x86 -> aarch64  (cross-arch)  ", v1: S_X64_O0, v2: S_A64_O0, floor: Some(0.25) },
    ];

    println!("\n=== DD-038 re-anchoring scoreboard ===");
    println!("{:<38}  OK WRONG ORPH  survival  floor", "class");
    let mut any_wrong = false;
    let mut floor_break: Vec<String> = Vec::new();
    for c in &classes {
        let s = score(c.v1, c.v2);
        let floor_s = c.floor.map_or("  —".to_string(), |f| format!("{:.0}%", f * 100.0));
        println!(
            "{:<38} {:3} {:5} {:4}  {:6.0}%   {}",
            c.name, s.correct, s.wrong, s.orphaned, s.survival() * 100.0, floor_s
        );
        if s.wrong > 0 {
            any_wrong = true;
        }
        if let Some(f) = c.floor {
            if s.survival() + 1e-9 < f {
                floor_break.push(format!("{}: {:.0}% < floor {:.0}%", c.name.trim(), s.survival() * 100.0, f * 100.0));
            }
        }
    }
    println!("=======================================\n");

    // HARD invariant: zero silent mis-attachment, every class (DD-005).
    assert!(!any_wrong, "DD-005 VIOLATED: a class produced WRONG > 0 — silent mis-attachment");
    // Ratcheted floors on the promised classes.
    assert!(floor_break.is_empty(), "ratcheted survival floor broken: {floor_break:?}");
}
