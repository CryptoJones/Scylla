//! DD-019 — a submit→poll **job handle** for the long-running `analyze` (materialize).
//!
//! DD-019's decision: synchronous request/response everywhere, EXCEPT a job handle
//! (submit → poll) for the one call that can't be a blocking wait — analyzing a binary (a
//! 200 MB firmware analysis can't block the caller). Streaming + fine-grained cancellation
//! are deliberately deferred. The async producer work lives here on the engine side; the
//! client port (`scylla-port`) stays a pure, synchronous model consumer (DD-009) — a head
//! submits the analyze, polls the handle, and `Session::open`s the `Program` when it lands.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use scylla_model::Program;
use tokio::task::JoinHandle;

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

/// An opaque analyze-job identifier (process-local, monotonic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JobId(pub u64);

/// Lifecycle state of a submitted analyze job — what [`AnalyzeJob::status`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    /// Still analyzing.
    Running,
    /// Finished; a `Program` is ready to [`take`](AnalyzeJob::take).
    Succeeded,
    /// Finished with an error (take the result for the message).
    Failed,
}

/// The slot the detached task writes its outcome into. `ok` is retained so `status()` stays
/// truthful even after the (one-shot) result has been taken.
enum Slot {
    Running,
    Done {
        ok: bool,
        result: Option<Result<Program, String>>,
    },
}

/// A handle to a long-running analyze submitted via [`AnalyzeJob::submit`] / [`submit_analyze`].
/// The work runs on a detached Tokio task; a consumer polls [`status`](Self::status) and
/// [`take`](Self::take)s the result once it lands, or [`join`](Self::join)s to await it.
pub struct AnalyzeJob {
    id: JobId,
    slot: Arc<Mutex<Slot>>,
    task: JoinHandle<()>,
}

impl AnalyzeJob {
    /// Submit a future producing a `Program` as a background analyze job. The error is
    /// stringified at the boundary so the outcome is self-contained. Requires a Tokio runtime.
    pub fn submit<F, E>(fut: F) -> Self
    where
        F: Future<Output = Result<Program, E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let id = JobId(NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed));
        let slot = Arc::new(Mutex::new(Slot::Running));
        let writer = Arc::clone(&slot);
        let task = tokio::spawn(async move {
            let outcome = fut.await.map_err(|e| e.to_string());
            let ok = outcome.is_ok();
            *writer.lock().unwrap() = Slot::Done {
                ok,
                result: Some(outcome),
            };
        });
        AnalyzeJob { id, slot, task }
    }

    /// This job's id.
    pub fn id(&self) -> JobId {
        self.id
    }

    /// Poll the job's lifecycle state without consuming it or its result.
    pub fn status(&self) -> JobStatus {
        match &*self.slot.lock().unwrap() {
            Slot::Running => JobStatus::Running,
            Slot::Done { ok: true, .. } => JobStatus::Succeeded,
            Slot::Done { ok: false, .. } => JobStatus::Failed,
        }
    }

    /// Take the finished result, or `None` while still running. Yields the outcome exactly
    /// once; a later call after a successful take returns `None` (use [`status`](Self::status)
    /// to re-read success/failure).
    pub fn take(&self) -> Option<Result<Program, String>> {
        match &mut *self.slot.lock().unwrap() {
            Slot::Done { result, .. } => result.take(),
            Slot::Running => None,
        }
    }

    /// Await the job to completion and return its result. Consumes the handle. A panicked or
    /// cancelled analyze task becomes an `Err` rather than propagating.
    pub async fn join(self) -> Result<Program, String> {
        if self.task.await.is_err() {
            return Err("analyze job task panicked or was cancelled".to_string());
        }
        match &mut *self.slot.lock().unwrap() {
            Slot::Done { result, .. } => result
                .take()
                .unwrap_or_else(|| Err("analyze result already taken".to_string())),
            Slot::Running => Err("analyze job finished without recording a result".to_string()),
        }
    }
}

/// Submit the long-running analyze (materialize a binary over the engine port) as a background
/// job — the DD-019 submit→poll entry point a head uses instead of blocking on
/// [`crate::materialize`]. The engine error is stringified at the boundary.
pub fn submit_analyze(endpoint: String, name: String, binary: Vec<u8>) -> AnalyzeJob {
    AnalyzeJob::submit(async move {
        crate::materialize(endpoint, &name, binary)
            .await
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog() -> Program {
        Program {
            name: "p".into(),
            language: "x86:LE:64:default".into(),
            functions: vec![],
            facts: vec![],
        }
    }

    #[tokio::test]
    async fn submit_then_join_yields_the_program() {
        let job = AnalyzeJob::submit(async { Ok::<_, String>(prog()) });
        assert!(job.join().await.is_ok());
    }

    #[tokio::test]
    async fn status_is_running_until_the_work_completes() {
        // A oneshot gates the job so it is observably Running before we release it.
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let job = AnalyzeJob::submit(async move {
            gate.await.ok();
            Ok::<_, String>(prog())
        });
        assert_eq!(job.status(), JobStatus::Running);
        assert!(job.take().is_none(), "nothing to take while running");
        release.send(()).unwrap();
        assert!(job.join().await.is_ok());
    }

    #[tokio::test]
    async fn a_failed_analyze_reports_failed_with_its_message() {
        let job = AnalyzeJob::submit(async { Err::<Program, String>("boom".to_string()) });
        // spin to completion without consuming the handle
        while job.status() == JobStatus::Running {
            tokio::task::yield_now().await;
        }
        assert_eq!(job.status(), JobStatus::Failed);
        assert!(matches!(job.take(), Some(Err(e)) if e == "boom"));
    }

    #[tokio::test]
    async fn take_yields_the_result_exactly_once() {
        let job = AnalyzeJob::submit(async { Ok::<_, String>(prog()) });
        while job.status() == JobStatus::Running {
            tokio::task::yield_now().await;
        }
        assert_eq!(job.status(), JobStatus::Succeeded);
        assert!(job.take().is_some());
        assert!(job.take().is_none(), "result is taken exactly once");
        assert_eq!(
            job.status(),
            JobStatus::Succeeded,
            "status stays truthful after take"
        );
    }

    #[tokio::test]
    async fn distinct_jobs_get_distinct_ids() {
        let a = AnalyzeJob::submit(async { Ok::<_, String>(prog()) });
        let b = AnalyzeJob::submit(async { Ok::<_, String>(prog()) });
        assert_ne!(a.id(), b.id());
    }
}
