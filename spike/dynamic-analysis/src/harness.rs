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
