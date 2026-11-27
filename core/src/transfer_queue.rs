//! File-panel transfer queue: the shared model behind every app's transfer list.
//!
//! The queue is pure state. Hosts (or a worker) take the next job with [`TransferQueue::start_next`],
//! copy bytes with SFTP or the SCP fallback, report [`TransferQueue::progress`], and end each job
//! with [`TransferQueue::finish`] or [`TransferQueue::fail`]. Speed is smoothed, ETA follows from it,
//! and an existing target is resolved once by the job's [`Overwrite`] rule before any byte moves.
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// At most this many jobs run at once, whatever a host asks for.
pub const MAX_PARALLEL: usize = 8;
/// A failed job may be retried this many times before it stays failed.
pub const MAX_ATTEMPTS: u32 = 5;
/// Weight of the newest sample in the smoothed speed (exponential moving average).
const SPEED_SMOOTHING: f64 = 0.3;
/// Highest "name (n).ext" tried when renaming around an existing target.
const MAX_RENAME_SUFFIX: u32 = 999;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Upload,
    Download,
}

/// What to do when the target already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Overwrite {
    /// Stop and let the user choose (the job waits in `conflict`).
    #[default]
    Ask,
    Replace,
    Skip,
    /// Replace only when the source is newer than the target.
    ReplaceIfNewer,
    /// Keep both: write to "name (1).ext".
    Rename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Running,
    Paused,
    Conflict,
    Done,
    Skipped,
    Failed,
    Cancelled,
}

impl JobState {
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Done | Self::Skipped | Self::Failed | Self::Cancelled)
    }
}

/// One file transfer as the UI shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: u64,
    pub direction: Direction,
    pub source: String,
    pub target: String,
    pub overwrite: Overwrite,
    pub state: JobState,
    pub total: u64,
    pub done: u64,
    /// Smoothed bytes per second while running.
    pub speed: f64,
    /// Seconds left at the current speed, when known.
    pub eta: Option<u64>,
    pub attempts: u32,
    pub error: Option<String>,
}

/// What the worker learns about the target before copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetInfo {
    pub exists: bool,
    /// Unix seconds, when known.
    pub target_modified: Option<i64>,
    pub source_modified: Option<i64>,
}

/// Decision for a job whose target was probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum Resolution {
    /// Copy to this target, replacing it if `replace`.
    Copy { target: String, replace: bool },
    Skip,
    /// Wait for the user (state is now `conflict`).
    Ask,
}

/// Snapshot totals for a status line.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Summary {
    pub active: usize,
    pub queued: usize,
    pub failed: usize,
    pub total: u64,
    pub done: u64,
    pub speed: f64,
}

#[derive(Debug)]
pub struct TransferQueue {
    jobs: Vec<Job>,
    next_id: u64,
    parallel: usize,
}

impl Default for TransferQueue {
    fn default() -> Self {
        Self::new(2)
    }
}

impl TransferQueue {
    /// A queue running up to `parallel` jobs at once (clamped to 1..=[`MAX_PARALLEL`]).
    pub fn new(parallel: usize) -> Self {
        Self { jobs: Vec::new(), next_id: 1, parallel: parallel.clamp(1, MAX_PARALLEL) }
    }

    pub fn jobs(&self) -> &[Job] {
        &self.jobs
    }

    pub fn get(&self, id: u64) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    fn job_mut(&mut self, id: u64) -> Result<&mut Job> {
        self.jobs.iter_mut().find(|j| j.id == id).ok_or_else(|| CoreError::NotFound(format!("transfer {id}")))
    }

    /// Queue a transfer of `total` bytes. Empty paths are refused.
    pub fn add(&mut self, direction: Direction, source: &str, target: &str, total: u64, overwrite: Overwrite) -> Result<u64> {
        if source.trim().is_empty() || target.trim().is_empty() {
            return Err(CoreError::Invalid("transfer needs a source and a target".into()));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.push(Job {
            id,
            direction,
            source: source.to_string(),
            target: target.to_string(),
            overwrite,
            state: JobState::Queued,
            total,
            done: 0,
            speed: 0.0,
            eta: None,
            attempts: 0,
            error: None,
        });
        Ok(id)
    }

    fn running(&self) -> usize {
        self.jobs.iter().filter(|j| j.state == JobState::Running).count()
    }

    /// Start the oldest queued job if a slot is free. Returns a copy for the worker.
    pub fn start_next(&mut self) -> Option<Job> {
        if self.running() >= self.parallel {
            return None;
        }
        let job = self.jobs.iter_mut().find(|j| j.state == JobState::Queued)?;
        job.state = JobState::Running;
        job.attempts += 1;
        job.error = None;
        Some(job.clone())
    }

    /// Apply the job's overwrite rule to a probed target. `taken` reports whether a candidate
    /// renamed target already exists (used only for [`Overwrite::Rename`]).
    pub fn resolve(&mut self, id: u64, info: TargetInfo, taken: impl Fn(&str) -> bool) -> Result<Resolution> {
        let job = self.job_mut(id)?;
        if !info.exists {
            return Ok(Resolution::Copy { target: job.target.clone(), replace: false });
        }
        let resolution = match job.overwrite {
            Overwrite::Replace => Resolution::Copy { target: job.target.clone(), replace: true },
            Overwrite::Skip => Resolution::Skip,
            Overwrite::ReplaceIfNewer => match (info.source_modified, info.target_modified) {
                (Some(s), Some(t)) if s > t => Resolution::Copy { target: job.target.clone(), replace: true },
                _ => Resolution::Skip,
            },
            Overwrite::Rename => {
                let target = free_name(&job.target, &taken)?;
                job.target = target.clone();
                Resolution::Copy { target, replace: false }
            }
            Overwrite::Ask => Resolution::Ask,
        };
        match resolution {
            Resolution::Skip => job.state = JobState::Skipped,
            Resolution::Ask => job.state = JobState::Conflict,
            Resolution::Copy { .. } => {}
        }
        Ok(resolution)
    }

    /// The user's answer to a conflict: the job goes back to the queue with that rule.
    pub fn answer_conflict(&mut self, id: u64, rule: Overwrite) -> Result<()> {
        if rule == Overwrite::Ask {
            return Err(CoreError::Invalid("a conflict needs a decision".into()));
        }
        let job = self.job_mut(id)?;
        if job.state != JobState::Conflict {
            return Err(CoreError::Invalid(format!("transfer {id} has no conflict")));
        }
        job.overwrite = rule;
        job.state = JobState::Queued;
        job.attempts = job.attempts.saturating_sub(1);
        Ok(())
    }

    /// Report that a running job has copied `done` bytes in total after `elapsed` since the last report.
    pub fn progress(&mut self, id: u64, done: u64, elapsed: Duration) -> Result<()> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Running {
            return Ok(());
        }
        let delta = done.saturating_sub(job.done);
        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            let sample = delta as f64 / secs;
            job.speed = if job.speed == 0.0 { sample } else { SPEED_SMOOTHING * sample + (1.0 - SPEED_SMOOTHING) * job.speed };
        }
        job.total = job.total.max(done);
        job.done = done;
        job.eta = (job.speed > 0.0).then(|| ((job.total - job.done) as f64 / job.speed).ceil() as u64);
        Ok(())
    }

    pub fn finish(&mut self, id: u64) -> Result<()> {
        let job = self.job_mut(id)?;
        job.state = JobState::Done;
        job.done = job.total.max(job.done);
        job.eta = Some(0);
        job.speed = 0.0;
        Ok(())
    }

    pub fn fail(&mut self, id: u64, error: &str) -> Result<()> {
        let job = self.job_mut(id)?;
        job.state = JobState::Failed;
        job.error = Some(error.to_string());
        job.speed = 0.0;
        job.eta = None;
        Ok(())
    }

    /// Pause a queued or running job. The worker stops copying when it sees the state change and
    /// resume restarts the file (partial bytes are never trusted).
    pub fn pause(&mut self, id: u64) -> Result<()> {
        let job = self.job_mut(id)?;
        match job.state {
            JobState::Queued | JobState::Running => {
                if job.state == JobState::Running {
                    job.attempts = job.attempts.saturating_sub(1);
                }
                job.state = JobState::Paused;
                job.speed = 0.0;
                job.eta = None;
                Ok(())
            }
            s => Err(CoreError::Invalid(format!("cannot pause a {s:?} transfer"))),
        }
    }

    pub fn resume(&mut self, id: u64) -> Result<()> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Paused {
            return Err(CoreError::Invalid(format!("transfer {id} is not paused")));
        }
        job.state = JobState::Queued;
        job.done = 0;
        Ok(())
    }

    /// Queue a failed job again, up to [`MAX_ATTEMPTS`] attempts.
    pub fn retry(&mut self, id: u64) -> Result<()> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Failed {
            return Err(CoreError::Invalid(format!("transfer {id} has not failed")));
        }
        if job.attempts >= MAX_ATTEMPTS {
            return Err(CoreError::Invalid(format!("transfer {id} failed {MAX_ATTEMPTS} times")));
        }
        job.state = JobState::Queued;
        job.done = 0;
        Ok(())
    }

    pub fn cancel(&mut self, id: u64) -> Result<()> {
        let job = self.job_mut(id)?;
        if !job.state.is_finished() {
            job.state = JobState::Cancelled;
            job.speed = 0.0;
            job.eta = None;
        }
        Ok(())
    }

    /// Drop finished jobs from the list (the "Clear finished" button). Failed jobs stay for retry.
    pub fn clear_finished(&mut self) {
        self.jobs.retain(|j| !j.state.is_finished() || j.state == JobState::Failed);
    }

    pub fn summary(&self) -> Summary {
        let open: Vec<_> = self.jobs.iter().filter(|j| !j.state.is_finished()).collect();
        Summary {
            active: self.running(),
            queued: open.iter().filter(|j| j.state == JobState::Queued).count(),
            failed: self.jobs.iter().filter(|j| j.state == JobState::Failed).count(),
            total: open.iter().map(|j| j.total).sum(),
            done: open.iter().map(|j| j.done).sum(),
            speed: open.iter().filter(|j| j.state == JobState::Running).map(|j| j.speed).sum(),
        }
    }
}

/// "dir/name.ext" → first free "dir/name (n).ext".
pub fn free_name(path: &str, taken: &impl Fn(&str) -> bool) -> Result<String> {
    let split = path.rfind(['/', '\\']).map_or(0, |i| i + 1);
    let (dir, file) = path.split_at(split);
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => file.split_at(i),
        _ => (file, ""),
    };
    (1..=MAX_RENAME_SUFFIX)
        .map(|n| format!("{dir}{stem} ({n}){ext}"))
        .find(|c| !taken(c))
        .ok_or_else(|| CoreError::Invalid(format!("no free name next to {path}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    fn exists(t: Option<i64>, s: Option<i64>) -> TargetInfo {
        TargetInfo { exists: true, target_modified: t, source_modified: s }
    }

    #[test]
    fn runs_jobs_in_order_within_the_parallel_limit() {
        let mut q = TransferQueue::new(2);
        let ids: Vec<_> = (0..3).map(|i| q.add(Direction::Upload, &format!("/l/{i}"), &format!("/r/{i}"), 10, Overwrite::Replace).unwrap()).collect();
        assert_eq!(q.start_next().unwrap().id, ids[0]);
        assert_eq!(q.start_next().unwrap().id, ids[1]);
        assert!(q.start_next().is_none(), "third waits for a free slot");
        q.finish(ids[0]).unwrap();
        assert_eq!(q.start_next().unwrap().id, ids[2]);
    }

    #[test]
    fn parallel_is_clamped() {
        assert_eq!(TransferQueue::new(0).parallel, 1);
        assert_eq!(TransferQueue::new(100).parallel, MAX_PARALLEL);
    }

    #[test]
    fn refuses_empty_paths() {
        let mut q = TransferQueue::default();
        assert!(q.add(Direction::Download, " ", "/x", 1, Overwrite::Ask).is_err());
    }

    #[test]
    fn progress_smooths_speed_and_computes_eta() {
        let mut q = TransferQueue::new(1);
        let id = q.add(Direction::Download, "/r/a", "/l/a", 1000, Overwrite::Replace).unwrap();
        q.start_next();
        q.progress(id, 100, SEC).unwrap();
        assert_eq!(q.get(id).unwrap().speed, 100.0);
        assert_eq!(q.get(id).unwrap().eta, Some(9));
        q.progress(id, 300, SEC).unwrap();
        let j = q.get(id).unwrap();
        assert!((j.speed - 130.0).abs() < 1e-9, "0.3*200 + 0.7*100");
        assert_eq!(j.eta, Some(6));
        q.finish(id).unwrap();
        assert_eq!(q.get(id).unwrap().done, 1000);
    }

    #[test]
    fn progress_beyond_total_grows_total() {
        let mut q = TransferQueue::new(1);
        let id = q.add(Direction::Download, "/r/a", "/l/a", 10, Overwrite::Replace).unwrap();
        q.start_next();
        q.progress(id, 25, SEC).unwrap();
        assert_eq!((q.get(id).unwrap().total, q.get(id).unwrap().eta), (25, Some(0)));
    }

    #[test]
    fn overwrite_rules() {
        let mut q = TransferQueue::new(8);
        let never = |_: &str| false;
        let free = TargetInfo { exists: false, target_modified: None, source_modified: None };
        let a = q.add(Direction::Upload, "/l/a", "/r/a", 1, Overwrite::Skip).unwrap();
        assert_eq!(q.resolve(a, free, never).unwrap(), Resolution::Copy { target: "/r/a".into(), replace: false });
        assert_eq!(q.resolve(a, exists(None, None), never).unwrap(), Resolution::Skip);
        assert_eq!(q.get(a).unwrap().state, JobState::Skipped);

        let b = q.add(Direction::Upload, "/l/b", "/r/b", 1, Overwrite::ReplaceIfNewer).unwrap();
        assert_eq!(q.resolve(b, exists(Some(10), Some(20)), never).unwrap(), Resolution::Copy { target: "/r/b".into(), replace: true });
        let c = q.add(Direction::Upload, "/l/c", "/r/c", 1, Overwrite::ReplaceIfNewer).unwrap();
        assert_eq!(q.resolve(c, exists(Some(20), None), never).unwrap(), Resolution::Skip, "unknown age never replaces");

        let d = q.add(Direction::Upload, "/l/d.txt", "/r/d.txt", 1, Overwrite::Rename).unwrap();
        let taken = |p: &str| p == "/r/d (1).txt";
        assert_eq!(q.resolve(d, exists(None, None), taken).unwrap(), Resolution::Copy { target: "/r/d (2).txt".into(), replace: false });
        assert_eq!(q.get(d).unwrap().target, "/r/d (2).txt");
    }

    #[test]
    fn ask_waits_for_the_user_then_requeues() {
        let mut q = TransferQueue::new(1);
        let id = q.add(Direction::Download, "/r/a", "/l/a", 1, Overwrite::Ask).unwrap();
        q.start_next();
        assert_eq!(q.resolve(id, exists(None, None), |_| false).unwrap(), Resolution::Ask);
        assert_eq!(q.get(id).unwrap().state, JobState::Conflict);
        assert!(q.answer_conflict(id, Overwrite::Ask).is_err());
        q.answer_conflict(id, Overwrite::Replace).unwrap();
        let j = q.start_next().unwrap();
        assert_eq!((j.id, j.attempts, j.overwrite), (id, 1, Overwrite::Replace));
    }

    #[test]
    fn pause_resume_restarts_the_file() {
        let mut q = TransferQueue::new(1);
        let id = q.add(Direction::Upload, "/l/a", "/r/a", 100, Overwrite::Replace).unwrap();
        q.start_next();
        q.progress(id, 50, SEC).unwrap();
        q.pause(id).unwrap();
        assert!(q.start_next().is_none(), "paused job is not picked");
        assert!(q.pause(id).is_err());
        q.resume(id).unwrap();
        let j = q.start_next().unwrap();
        assert_eq!((j.done, j.attempts), (0, 1));
    }

    #[test]
    fn retry_is_bounded() {
        let mut q = TransferQueue::new(1);
        let id = q.add(Direction::Upload, "/l/a", "/r/a", 1, Overwrite::Replace).unwrap();
        assert!(q.retry(id).is_err(), "only failed jobs retry");
        for _ in 0..MAX_ATTEMPTS {
            q.start_next().unwrap();
            q.fail(id, "connection reset").unwrap();
            let _ = q.retry(id);
        }
        assert_eq!(q.get(id).unwrap().state, JobState::Failed);
        assert!(q.retry(id).is_err());
        assert_eq!(q.get(id).unwrap().error.as_deref(), Some("connection reset"));
    }

    #[test]
    fn cancel_clear_and_summary() {
        let mut q = TransferQueue::new(2);
        let a = q.add(Direction::Upload, "/l/a", "/r/a", 100, Overwrite::Replace).unwrap();
        let b = q.add(Direction::Upload, "/l/b", "/r/b", 50, Overwrite::Replace).unwrap();
        let c = q.add(Direction::Upload, "/l/c", "/r/c", 10, Overwrite::Replace).unwrap();
        q.start_next();
        q.progress(a, 40, SEC).unwrap();
        q.cancel(b).unwrap();
        let s = q.summary();
        assert_eq!((s.active, s.queued, s.total, s.done, s.speed), (1, 1, 110, 40, 40.0));
        q.finish(a).unwrap();
        q.start_next();
        q.fail(c, "x").unwrap();
        q.clear_finished();
        assert_eq!(q.jobs().iter().map(|j| j.id).collect::<Vec<_>>(), vec![c], "failed jobs stay for retry");
        assert!(q.cancel(999).is_err());
    }

    #[test]
    fn free_name_handles_dirs_dots_and_exhaustion() {
        let none = |_: &str| false;
        assert_eq!(free_name("/a.b/file", &none).unwrap(), "/a.b/file (1)");
        assert_eq!(free_name(".bashrc", &none).unwrap(), ".bashrc (1)");
        assert_eq!(free_name("C:\\x\\a.tar.gz", &none).unwrap(), "C:\\x\\a.tar (1).gz");
        assert!(free_name("a", &|_: &str| true).is_err());
    }
}
