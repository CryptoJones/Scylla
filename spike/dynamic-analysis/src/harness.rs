//! The dynamic-analysis producer's HARNESS interface — and the ONLY implementation this de-risk
//! ships: one that EXECUTES NOTHING.
//!
//! The seam spike (SPIKE-REPORT.md) proved a runtime artifact merges into the model. This module
//! de-risks the *other* half — the producer interface a real, contained execution harness would
//! implement — WITHOUT running any sample. `RecordedHarness` replays a pre-recorded trace; the real
//! `MicroVmHarness` (run the sample inside the VM-grade, ephemeral, no-egress tier of
//! HARNESS-THREAT-MODEL.md) is DEFERRED behind the open GAPs there and is deliberately absent. The
//! point is to prove the *shape* — observe → runtime edges → DD-007 `dynamic` provenance — is sound,
//! so when the containment tier exists the producer drops in behind this trait with no model change.

use serde_json::Value;

/// One runtime observation: a call-graph edge a dynamic producer resolved (e.g. an indirect call the
/// static analysis left dangling), by function/target NAME. A real harness keys on address; the
/// merge resolves to a `StableId` (the seam spike showed this lands on existing identities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEdge {
    pub from: String,
    pub to: String,
    pub confidence: u8,
}

/// A dynamic-analysis producer: observe a sample at runtime, return what was seen. The contract says
/// nothing about HOW — a real impl runs the sample inside the containment tier of
/// HARNESS-THREAT-MODEL.md (microVM, ephemeral, no egress, observed-not-trusted). The result is
/// attacker-influenced and MUST be treated as untrusted downstream (DD-036 caps + DD-007/DD-027
/// provenance weighting), never trusted because "we observed it."
pub trait DynamicHarness {
    fn observe(&self, sample: &str) -> Vec<ObservedEdge>;
    /// A human-readable description of the containment the run happened under (for provenance/audit).
    fn containment(&self) -> &str;
}

/// The only harness this de-risk ships. It **executes nothing**: it replays a pre-recorded trace
/// (`runtime-iat.json`) standing in for what a real, contained run would emit, so the producer
/// interface and the merge-with-provenance flow can be exercised end-to-end with zero risk. The real
/// `MicroVmHarness` is deferred behind GAP-5..9 (HARNESS-THREAT-MODEL.md).
pub struct RecordedHarness {
    trace: Value,
}

impl RecordedHarness {
    pub fn from_file(path: &str) -> Self {
        let trace = serde_json::from_slice(&std::fs::read(path).expect("read recorded trace"))
            .expect("parse recorded trace");
        RecordedHarness { trace }
    }
}

impl DynamicHarness for RecordedHarness {
    fn observe(&self, _sample: &str) -> Vec<ObservedEdge> {
        // NB: `_sample` is intentionally IGNORED — nothing is executed. We replay the recorded
        // resolved-IAT trace as the stand-in for a real contained run's observations.
        self.trace["resolved_imports"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| ObservedEdge {
                        from: e["function"].as_str().unwrap_or("").to_string(),
                        to: e["import"].as_str().unwrap_or("").to_string(),
                        confidence: 90,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn containment(&self) -> &str {
        "NONE — recorded replay, executes nothing (real harness: microVM, see HARNESS-THREAT-MODEL.md)"
    }
}

/// M4 — the REAL harness. `observe` runs the sample inside the M1 containment tier via the M3 in-guest
/// observer (`harness-m3/m3-observe.sh --raw`) and reads the recorded trace back over the M2 channel
/// through the bounded validator (`crate::channel::read_trace`): execute-in-sandbox → observe → channel
/// → validate, end to end. Unlike `RecordedHarness` it EXECUTES a real program — still **benign-only**
/// (a cooperative sample) and **contained** (no egress, no host FS, capped, ephemeral). Hostile samples
/// are M5 (a ptrace/QEMU observer for uncooperative code + Firecracker + an external pen-test).
pub struct MicroVmHarness {
    /// Path to the M3 observer runner (`harness-m3/m3-observe.sh`); invoked with `--raw`.
    pub observer: String,
    /// A readable kernel for the microVM (passed as `$KERNEL`); `None` uses the script's default.
    pub kernel: Option<String>,
}

impl DynamicHarness for MicroVmHarness {
    fn observe(&self, _sample: &str) -> Vec<ObservedEdge> {
        // `_sample` is the benign sample baked into the M3 observer for this first cut; a fuller
        // harness would stage an arbitrary sample into the guest. Nothing here trusts the result —
        // it crosses the bounded, validating channel exactly like a stranger's input (DD-036).
        let mut cmd = std::process::Command::new(&self.observer);
        cmd.arg("--raw");
        if let Some(k) = &self.kernel {
            cmd.env("KERNEL", k);
        }
        match cmd.output() {
            Ok(out) => crate::channel::read_trace(out.stdout.as_slice()).unwrap_or_else(|r| {
                eprintln!("[microvm] channel QUARANTINED the trace ({r}) — zero observations trusted");
                Vec::new()
            }),
            Err(e) => {
                eprintln!("[microvm] could not run the contained observer ({e}) — zero observations");
                Vec::new()
            }
        }
    }

    fn containment(&self) -> &str {
        "microVM (M1): KVM, ephemeral, no egress (-nic none), no host FS, 256M cap + wall-clock \
         kill-switch; trace read back over the M2 channel through the bounded validator (M3 observer)"
    }
}

#[cfg(test)]
mod m4 {
    use super::*;

    // WRONG=0 discipline for the dynamic producer: a dynamic observation is NEVER stamped certain
    // (user/100). It is partial-coverage by nature (GAP-8 evasion is inherent), so DD-027 collaborate
    // can only ever let it win a disagreement against a *lower*-confidence fact, never silently
    // overwrite a confident user/static one. This asserts the stamping discipline the merge relies on.
    #[test]
    fn dynamic_observations_are_never_stamped_certain() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let h = RecordedHarness::from_file(&format!("{manifest}/runtime-iat.json"));
        let edges = h.observe("ignored — recorded replay");
        assert!(!edges.is_empty(), "the recorded trace should yield observations");
        assert!(
            edges.iter().all(|e| e.confidence < 100),
            "a dynamic observation must never claim certainty (user/100) — that is what keeps DD-027 \
             collaborate from letting partial-coverage dynamic data overwrite a confident fact"
        );
    }
}
