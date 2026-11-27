//! Bridge for the file panel's transfer queue (`bastion_core::transfer_queue`). The queue is pure
//! state: the app's worker takes jobs, copies with `FilesBrowser`, and reports back here.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bastion_core::transfer_queue::{Direction, Job, JobState, Overwrite, Resolution, TargetInfo, TransferQueue};

use crate::{FfiError, FfiResult};

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TransferJobView {
    pub id: u64,
    /// `upload` or `download`.
    pub direction: String,
    pub source: String,
    pub target: String,
    /// `ask`, `replace`, `skip`, `replace_if_newer` or `rename`.
    pub overwrite: String,
    /// `queued`, `running`, `paused`, `conflict`, `done`, `skipped`, `failed` or `cancelled`.
    pub state: String,
    pub total: u64,
    pub done: u64,
    pub speed: f64,
    pub eta: Option<u64>,
    pub attempts: u32,
    pub error: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TransferSummaryView {
    pub active: u32,
    pub queued: u32,
    pub failed: u32,
    pub total: u64,
    pub done: u64,
    pub speed: f64,
}

/// What the worker should do with a probed job.
#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct TransferResolution {
    /// `copy`, `skip` or `ask`.
    pub action: String,
    pub target: String,
    pub replace: bool,
}

fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::Upload => "upload",
        Direction::Download => "download",
    }
}

fn overwrite_name(o: Overwrite) -> &'static str {
    match o {
        Overwrite::Ask => "ask",
        Overwrite::Replace => "replace",
        Overwrite::Skip => "skip",
        Overwrite::ReplaceIfNewer => "replace_if_newer",
        Overwrite::Rename => "rename",
    }
}

fn parse_overwrite(s: &str) -> FfiResult<Overwrite> {
    Ok(match s {
        "ask" => Overwrite::Ask,
        "replace" => Overwrite::Replace,
        "skip" => Overwrite::Skip,
        "replace_if_newer" => Overwrite::ReplaceIfNewer,
        "rename" => Overwrite::Rename,
        _ => return Err(FfiError::failed(format!("unknown overwrite rule `{s}`"))),
    })
}

fn state_name(s: JobState) -> &'static str {
    match s {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Paused => "paused",
        JobState::Conflict => "conflict",
        JobState::Done => "done",
        JobState::Skipped => "skipped",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    }
}

fn view(j: &Job) -> TransferJobView {
    TransferJobView {
        id: j.id,
        direction: direction_name(j.direction).into(),
        source: j.source.clone(),
        target: j.target.clone(),
        overwrite: overwrite_name(j.overwrite).into(),
        state: state_name(j.state).into(),
        total: j.total,
        done: j.done,
        speed: j.speed,
        eta: j.eta,
        attempts: j.attempts,
        error: j.error.clone(),
    }
}

#[derive(uniffi::Object)]
pub struct TransferQueueModel {
    queue: Mutex<TransferQueue>,
}

impl TransferQueueModel {
    fn with<T>(&self, f: impl FnOnce(&mut TransferQueue) -> bastion_core::error::Result<T>) -> FfiResult<T> {
        let mut q = self.queue.lock().map_err(|_| FfiError::failed("transfer queue poisoned".into()))?;
        Ok(f(&mut q)?)
    }
}

#[uniffi::export]
impl TransferQueueModel {
    /// A queue running up to `parallel` jobs at once (clamped to 1–8).
    #[uniffi::constructor]
    pub fn new(parallel: u32) -> Arc<Self> {
        Arc::new(Self { queue: Mutex::new(TransferQueue::new(parallel as usize)) })
    }

    pub fn add(&self, upload: bool, source: String, target: String, total: u64, overwrite: String) -> FfiResult<u64> {
        let rule = parse_overwrite(&overwrite)?;
        let direction = if upload { Direction::Upload } else { Direction::Download };
        self.with(|q| q.add(direction, &source, &target, total, rule))
    }

    pub fn jobs(&self) -> Vec<TransferJobView> {
        self.queue.lock().map(|q| q.jobs().iter().map(view).collect()).unwrap_or_default()
    }

    /// The next queued job, now running, when a slot is free.
    pub fn start_next(&self) -> Option<TransferJobView> {
        self.queue.lock().ok()?.start_next().as_ref().map(view)
    }

    /// Apply the job's overwrite rule to a probed target. `taken` lists the names already in the
    /// target folder, so "keep both" can pick a free one.
    pub fn resolve(&self, id: u64, exists: bool, target_modified: Option<i64>, source_modified: Option<i64>, taken: Vec<String>) -> FfiResult<TransferResolution> {
        let taken: HashSet<String> = taken.into_iter().collect();
        let info = TargetInfo { exists, target_modified, source_modified };
        let r = self.with(|q| {
            q.resolve(id, info, |p| {
                let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
                taken.contains(name)
            })
        })?;
        Ok(match r {
            Resolution::Copy { target, replace } => TransferResolution { action: "copy".into(), target, replace },
            Resolution::Skip => TransferResolution { action: "skip".into(), target: String::new(), replace: false },
            Resolution::Ask => TransferResolution { action: "ask".into(), target: String::new(), replace: false },
        })
    }

    pub fn answer_conflict(&self, id: u64, rule: String) -> FfiResult<()> {
        let rule = parse_overwrite(&rule)?;
        self.with(|q| q.answer_conflict(id, rule))
    }

    pub fn progress(&self, id: u64, done: u64, elapsed_ms: u64) -> FfiResult<()> {
        self.with(|q| q.progress(id, done, Duration::from_millis(elapsed_ms)))
    }

    pub fn finish(&self, id: u64) -> FfiResult<()> {
        self.with(|q| q.finish(id))
    }

    pub fn fail(&self, id: u64, error: String) -> FfiResult<()> {
        self.with(|q| q.fail(id, &error))
    }

    pub fn pause(&self, id: u64) -> FfiResult<()> {
        self.with(|q| q.pause(id))
    }

    pub fn resume(&self, id: u64) -> FfiResult<()> {
        self.with(|q| q.resume(id))
    }

    pub fn retry(&self, id: u64) -> FfiResult<()> {
        self.with(|q| q.retry(id))
    }

    pub fn cancel(&self, id: u64) -> FfiResult<()> {
        self.with(|q| q.cancel(id))
    }

    pub fn clear_finished(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.clear_finished();
        }
    }

    pub fn summary(&self) -> TransferSummaryView {
        let s = self.queue.lock().map(|q| q.summary()).ok();
        s.map(|s| TransferSummaryView {
            active: s.active as u32,
            queued: s.queued as u32,
            failed: s.failed as u32,
            total: s.total,
            done: s.done,
            speed: s.speed,
        })
        .unwrap_or(TransferSummaryView { active: 0, queued: 0, failed: 0, total: 0, done: 0, speed: 0.0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_a_job_through_the_bridge() {
        let q = TransferQueueModel::new(1);
        let id = q.add(true, "/tmp/a.txt".into(), "/home/u/a.txt".into(), 10, "ask".into()).unwrap();
        let job = q.start_next().unwrap();
        assert_eq!((job.id, job.state.as_str()), (id, "running"));
        assert!(q.start_next().is_none());
        let r = q.resolve(id, false, None, None, vec![]).unwrap();
        assert_eq!((r.action.as_str(), r.target.as_str()), ("copy", "/home/u/a.txt"));
        q.progress(id, 10, 1000).unwrap();
        q.finish(id).unwrap();
        assert_eq!(q.jobs()[0].state, "done");
        q.clear_finished();
        assert!(q.jobs().is_empty());
    }

    #[test]
    fn conflict_waits_then_keep_both_renames() {
        let q = TransferQueueModel::new(2);
        let id = q.add(false, "/r/a.txt".into(), "/l/a.txt".into(), 5, "ask".into()).unwrap();
        q.start_next().unwrap();
        assert_eq!(q.resolve(id, true, None, None, vec!["a.txt".into()]).unwrap().action, "ask");
        assert_eq!(q.jobs()[0].state, "conflict");
        q.answer_conflict(id, "rename".into()).unwrap();
        q.start_next().unwrap();
        let r = q.resolve(id, true, None, None, vec!["a.txt".into(), "a (1).txt".into()]).unwrap();
        assert_eq!(r.target, "/l/a (2).txt");
    }

    #[test]
    fn pause_resume_retry_and_bad_rule() {
        let q = TransferQueueModel::new(1);
        let id = q.add(true, "a".into(), "b".into(), 1, "replace".into()).unwrap();
        q.pause(id).unwrap();
        assert_eq!(q.jobs()[0].state, "paused");
        q.resume(id).unwrap();
        q.start_next().unwrap();
        q.fail(id, "timeout".into()).unwrap();
        assert_eq!(q.summary().failed, 1);
        q.retry(id).unwrap();
        assert_eq!(q.jobs()[0].state, "queued");
        assert!(q.add(true, "a".into(), "b".into(), 1, "sometimes".into()).is_err());
    }
}
