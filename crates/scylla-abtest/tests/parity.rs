//! The offline A/B parity gate: every committed baseline pair under `abtest/baselines/` — the
//! Scylla-materialized artifact (inside) and the raw engine headless snapshot (outside) of the same
//! binary — must still compare as PARITY. No engine, no docker: this replays the recorded legs, so
//! a change to the ingest/assemble/loader path that made Scylla's model drift from the engine's own
//! output fails `cargo test` here. Re-record the legs with `abtest/scripts/ab.sh`.

use std::path::{Path, PathBuf};

use scylla_port::Session;

fn baselines() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../abtest/baselines")
}

fn pairs() -> Vec<(PathBuf, PathBuf)> {
    let outside_dir = baselines().join("outside");
    let inside_dir = baselines().join("inside");
    let mut pairs = Vec::new();
    let Ok(rd) = std::fs::read_dir(&outside_dir) else {
        return pairs;
    };
    for entry in rd.flatten() {
        let out = entry.path();
        let Some(fname) = out.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(stem) = fname
            .strip_suffix(".snapshot.json.gz")
            .or_else(|| fname.strip_suffix(".snapshot.json"))
        else {
            continue;
        };
        // Committed legs are gzipped; a plain file (a local run) is accepted too.
        let inside = [format!("{stem}.scylla.gz"), format!("{stem}.scylla")]
            .into_iter()
            .map(|n| inside_dir.join(n))
            .find(|p| p.exists());
        if let Some(inside) = inside {
            pairs.push((inside, out));
        }
    }
    pairs.sort();
    pairs
}

#[test]
fn every_committed_baseline_pair_is_at_parity() {
    let pairs = pairs();
    assert!(
        !pairs.is_empty(),
        "no baseline pairs under {} — run abtest/scripts/ab.sh to record them",
        baselines().display()
    );
    let mut failures = Vec::new();
    for (inside_path, outside_path) in &pairs {
        let inside = Session::from_artifact(&scylla_abtest::read_maybe_gz(inside_path).unwrap())
            .unwrap_or_else(|e| panic!("loading {}: {e}", inside_path.display()));
        let outside = scylla_ingest::snapshot_to_program(&String::from_utf8_lossy(
            &scylla_abtest::read_maybe_gz(outside_path).unwrap(),
        ))
        .unwrap_or_else(|e| panic!("parsing {}: {e}", outside_path.display()));
        // `<bin>.scylla[.gz]` -> `<bin>` (the .elf stays part of the stem, as on disk)
        let fname = inside_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let stem = fname
            .strip_suffix(".scylla.gz")
            .or_else(|| fname.strip_suffix(".scylla"))
            .unwrap()
            .to_string();
        let mask_path = baselines()
            .join("nondeterministic")
            .join(format!("{stem}.json"));
        let mask = match std::fs::read_to_string(&mask_path) {
            Ok(t) => serde_json::from_str::<scylla_abtest::Flaky>(&t)
                .unwrap_or_else(|e| panic!("parsing {}: {e}", mask_path.display()))
                .mask(),
            Err(_) => Default::default(),
        };
        let report = scylla_abtest::compare_masked(inside.program(), &outside, &mask);
        if !report.is_parity() {
            failures.push(format!(
                "{}: only_inside={:?} only_outside={:?} fields={} projection={}",
                inside_path.file_name().unwrap().to_string_lossy(),
                report.only_inside,
                report.only_outside,
                report.field_mismatches.len(),
                report.projection_mismatches.len()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} baseline pairs DIFFER:\n  {}",
        failures.len(),
        pairs.len(),
        failures.join("\n  ")
    );
}

#[test]
fn every_inside_artifact_has_an_outside_snapshot_and_vice_versa() {
    let list = |dir: &str, suffix: &str| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(baselines().join(dir))
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let n = e.file_name().to_str()?.to_string();
                        let n = n.strip_suffix(".gz").unwrap_or(&n).to_string();
                        n.strip_suffix(suffix).map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    };
    let inside = list("inside", ".scylla");
    let outside = list("outside", ".snapshot.json");
    assert_eq!(
        inside, outside,
        "baseline legs are out of step — a binary was recorded on one leg only"
    );
}
