//! Bridge for multi-host exec (`bastion_core::multiexec`): run an approved command on several SSH
//! connections, `concurrency` at a time, each dialled like a terminal (policy, broker, strict host
//! keys, audit). Unknown host keys are not prompted for here: such hosts fail and are listed.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_core::multiexec::{self, HostResult, HostState, Plan};

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

/// Longest a command may run on one host before it is reported as failed.
const HOST_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(uniffi::Record)]
pub struct ExecReviewView {
    pub sensitive: Vec<String>,
    pub needs_production_ack: bool,
}

#[derive(uniffi::Record)]
pub struct HostResultView {
    pub host: String,
    /// `waiting`, `running`, `done`, `failed` or `cancelled`.
    pub state: String,
    pub exit: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub millis: u64,
}

fn plan(library: &Library, ids: &[String], command: &str, concurrency: u32) -> FfiResult<Plan> {
    let ids = ids.iter().map(|id| parse_id(id)).collect::<FfiResult<Vec<_>>>()?;
    let hosts = library.resolve_many(&ids)?;
    Ok(Plan { command: command.trim().to_string(), hosts, concurrency })
}

/// Check a plan: why it is refused, or which hosts need the production acknowledgement.
#[uniffi::export]
pub fn review_exec(library: Arc<Library>, connection_ids: Vec<String>, command: String, concurrency: u32) -> FfiResult<ExecReviewView> {
    let r = multiexec::review(&plan(&library, &connection_ids, &command, concurrency)?)?;
    Ok(ExecReviewView { sensitive: r.sensitive, needs_production_ack: r.needs_production_ack })
}

#[derive(uniffi::Object)]
pub struct MultiExec {
    manager: Arc<SessionManager>,
    library: Arc<Library>,
    ids: Vec<String>,
    command: String,
    concurrency: u32,
    username: String,
    /// Typed logins are dropped (wiped) once credentials are locked (F05).
    login: Mutex<Option<SshLogin>>,
    /// `SessionManager::credentials_epoch` when the login was given.
    epoch: u64,
    results: Arc<Mutex<Vec<HostResult>>>,
    cancel: Arc<AtomicBool>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

#[uniffi::export]
impl MultiExec {
    /// Review the plan (refusing it as `review_exec` would); `production_ack` must be true when the
    /// review asks for it. Nothing runs until `run`.
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: Arc<SessionManager>,
        library: Arc<Library>,
        connection_ids: Vec<String>,
        command: String,
        concurrency: u32,
        username: String,
        login: SshLogin,
        production_ack: bool,
    ) -> FfiResult<Arc<Self>> {
        let p = plan(&library, &connection_ids, &command, concurrency)?;
        let r = multiexec::review(&p)?;
        if r.needs_production_ack && !production_ack {
            return Err(FfiError::failed(format!("Confirm running on sensitive hosts: {}", r.sensitive.join(", "))));
        }
        let results = p.hosts.iter().map(|h| HostResult::waiting(&h.name)).collect();
        let epoch = manager.credentials_epoch();
        Ok(Arc::new(MultiExec {
            epoch,
            manager,
            library,
            ids: connection_ids,
            command: p.command,
            concurrency,
            username,
            login: Mutex::new(Some(login)),
            results: Arc::new(Mutex::new(results)),
            cancel: Arc::new(AtomicBool::new(false)),
            workers: Mutex::new(Vec::new()),
        }))
    }

    /// Run every host (again).
    pub fn run(&self) {
        let all: Vec<usize> = (0..self.ids.len()).collect();
        self.start(all);
    }

    /// Run again the hosts that failed, were cancelled or exited non-zero.
    pub fn retry_failed(&self) {
        let set = multiexec::retry_set(&self.results.lock().unwrap_or_else(|e| e.into_inner()));
        self.start(set);
    }

    /// Stop starting hosts; the ones running finish (or time out) and are reported.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_finished(&self) -> bool {
        self.results.lock().unwrap_or_else(|e| e.into_inner()).iter().all(|r| !matches!(r.state, HostState::Waiting | HostState::Running))
    }

    pub fn results(&self) -> Vec<HostResultView> {
        self.results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|r| HostResultView {
                host: r.host.clone(),
                state: serde_json::to_value(r.state).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
                exit: r.exit,
                stdout: r.stdout.clone(),
                stderr: r.stderr.clone(),
                error: r.error.clone(),
                millis: r.millis,
            })
            .collect()
    }

    /// `json` or `csv`.
    pub fn export(&self, format: String) -> FfiResult<String> {
        Ok(multiexec::export(&self.command, &self.results.lock().unwrap_or_else(|e| e.into_inner()), &format)?)
    }
}

impl Drop for MultiExec {
    fn drop(&mut self) {
        if let Some(l) = self.login.get_mut().unwrap_or_else(|e| e.into_inner()).as_mut() {
            l.wipe();
        }
    }
}

/// A worker's copy of the login, wiped when the worker ends. Each dial's own copy is moved
/// into a zeroizing `Secret` by the prompt provider.
struct WipeOnDrop(SshLogin);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

/// The sign-in for one host: its own saved credential when it has one (with its own username, or
/// the credential's), else the run's typed login and user.
fn host_login(library: &Library, id: &str, username: &str, login: &SshLogin) -> (String, SshLogin) {
    let conn = parse_id(id).ok().and_then(|cid| library.resolve(cid).ok());
    match conn.as_ref().and_then(|c| c.settings.credential_id.map(|cred| (c, cred))) {
        Some((c, cred)) => (c.settings.username.clone().unwrap_or_default(), SshLogin::Vault { credential_id: cred.to_string() }),
        None => (username.to_string(), login.clone()),
    }
}

/// Error for a run after "Lock Credentials" with a typed login.
const LOCKED_MESSAGE: &str = "credentials were locked; start a new run and sign in again";

impl MultiExec {
    /// The login for a new run, or `None` once a typed login was invalidated by a lock.
    fn current_login(&self) -> Option<SshLogin> {
        let mut slot = self.login.lock().unwrap_or_else(|e| e.into_inner());
        let invalidated = self.manager.credentials_epoch() != self.epoch && slot.as_ref().is_some_and(SshLogin::carries_typed_secret);
        if invalidated {
            if let Some(mut l) = slot.take() {
                l.wipe();
            }
        }
        slot.clone()
    }

    fn start(&self, indexes: Vec<usize>) {
        self.cancel.store(false, Ordering::SeqCst);
        let Some(login) = self.current_login().map(WipeOnDrop) else {
            let mut rs = self.results.lock().unwrap_or_else(|e| e.into_inner());
            for &i in &indexes {
                rs[i] = HostResult::waiting(&rs[i].host.clone());
                rs[i].state = HostState::Failed;
                rs[i].error = Some(LOCKED_MESSAGE.into());
            }
            return;
        };
        {
            let mut rs = self.results.lock().unwrap_or_else(|e| e.into_inner());
            for &i in &indexes {
                rs[i] = HostResult::waiting(&rs[i].host.clone());
            }
        }
        let queue = Arc::new(Mutex::new(indexes.into_iter().collect::<VecDeque<_>>()));
        let mut workers = self.workers.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..self.concurrency {
            let (queue, results, cancel) = (queue.clone(), self.results.clone(), self.cancel.clone());
            let (manager, library, ids) = (self.manager.clone(), self.library.clone(), self.ids.clone());
            let (command, username, login) = (self.command.clone(), self.username.clone(), WipeOnDrop(login.0.clone()));
            workers.push(std::thread::spawn(move || loop {
                let Some(i) = queue.lock().ok().and_then(|mut q| q.pop_front()) else { break };
                let set = |f: &dyn Fn(&mut HostResult)| {
                    if let Ok(mut rs) = results.lock() {
                        f(&mut rs[i]);
                    }
                };
                if cancel.load(Ordering::SeqCst) {
                    set(&|r| r.state = HostState::Cancelled);
                    continue;
                }
                set(&|r| r.state = HostState::Running);
                let t0 = Instant::now();
                let (user, host_login) = host_login(&library, &ids[i], &username, &login.0);
                let outcome = manager
                    .dial_ssh(&library, &ids[i], user, host_login, None, HashMap::new(), HashMap::new())
                    .and_then(|session| {
                        RUNTIME
                            .block_on(async { tokio::time::timeout(HOST_TIMEOUT, session.exec(&command)).await })
                            .map_err(|_| FfiError::failed("timed out".into()))?
                            .map_err(FfiError::from)
                    });
                let millis = t0.elapsed().as_millis() as u64;
                set(&|r| {
                    r.millis = millis;
                    match &outcome {
                        Ok(out) => {
                            r.state = HostState::Done;
                            r.exit = out.exit_status;
                            r.stdout = multiexec::capture(&out.stdout);
                            r.stderr = multiexec::capture(&out.stderr);
                        }
                        Err(e) => {
                            r.state = HostState::Failed;
                            r.error = Some(match e {
                                FfiError::HostKeyUnknown { .. } => "host key not trusted yet: connect once and verify it first".into(),
                                e => e.to_string(),
                            });
                        }
                    }
                });
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::model::{Connection, Node, Protocol};

    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn runs_on_real_hosts_reports_each_and_retries() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED runs_on_real_hosts_reports_each_and_retries: set BASTION_SSH_TEST=1");
        }
        let dir = std::env::temp_dir().join(format!("bastion-mx-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Trust both servers up front, as the UI requires; the third host's key is unknown.
        let keys = std::process::Command::new("sh").arg("-c").arg("ssh-keyscan -p 2222 127.0.0.1 2>/dev/null; ssh-keyscan -p 2223 127.0.0.1 2>/dev/null").output().unwrap().stdout;
        std::fs::write(dir.join("known_hosts"), keys).unwrap();
        let lib = Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let mut ids = Vec::new();
        for (name, host, port) in [("sshd", "127.0.0.1", 2222), ("jump", "127.0.0.1", 2223), ("unknown", "localhost", 2222)] {
            let mut c = Connection::new(name, Protocol::Ssh, host);
            c.settings.port = Some(port);
            ids.push(c.id.to_string());
            lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        }
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let login = SshLogin::Password { password: "test-pass-123".into() };
        let mx = MultiExec::new(mgr, lib, ids, "echo mx-$((6*7)); hostname >&2; exit 3".into(), 2, "tester".into(), login, false).unwrap();
        mx.run();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !mx.is_finished() {
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
        let rs = mx.results();
        for r in &rs[..2] {
            assert_eq!((r.state.as_str(), r.exit, r.stdout.trim()), ("done", Some(3), "mx-42"), "{}", r.host);
            assert!(!r.stderr.trim().is_empty());
        }
        assert_eq!(rs[2].state, "failed");
        assert!(rs[2].error.as_deref().unwrap().contains("host key"), "{:?}", rs[2].error);
        assert!(mx.export("csv".into()).unwrap().lines().count() == 4);
        // Non-zero exits and the failure are all retried.
        mx.retry_failed();
        while !mx.is_finished() {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(mx.results().iter().filter(|r| r.state == "done").count(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    fn wait(mx: &MultiExec) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !mx.is_finished() {
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn each_host_uses_its_saved_credential_and_the_rest_the_typed_login() {
        let dir = tempfile::tempdir().unwrap();
        let lib = Library::open(dir.path().join("lib.json").display().to_string()).unwrap();
        let cred = uuid::Uuid::new_v4();
        let mut saved = Connection::new("saved", Protocol::Ssh, "10.0.0.1");
        saved.settings.credential_id = Some(cred);
        saved.settings.username = Some("ops".into());
        let plain = Connection::new("plain", Protocol::Ssh, "10.0.0.2");
        let (a, b) = (saved.id.to_string(), plain.id.to_string());
        lib.with_doc(|d| {
            d.insert(None, Node::Connection(saved))?;
            d.insert(None, Node::Connection(plain))
        })
        .unwrap();
        let typed = SshLogin::Password { password: "typed".into() };
        let (user, login) = host_login(&lib, &a, "me", &typed);
        assert_eq!(user, "ops");
        assert!(matches!(login, SshLogin::Vault { credential_id } if credential_id == cred.to_string()));
        let (user, login) = host_login(&lib, &b, "me", &typed);
        assert_eq!(user, "me");
        assert!(matches!(login, SshLogin::Password { .. }));
    }

    /// F05: after "Lock Credentials" a saved MultiExec never dials with its typed password again.
    #[test]
    fn lock_credentials_invalidates_a_typed_login() {
        let dir = tempfile::tempdir().unwrap();
        let lib = Arc::new(Library::open(dir.path().join("lib.json").display().to_string()).unwrap());
        let mut c = Connection::new("closed", Protocol::Ssh, "127.0.0.1");
        c.settings.port = Some(1);
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        let mgr = SessionManager::new(dir.path().display().to_string()).unwrap();
        let login = SshLogin::Password { password: "typed-secret".into() };
        let mx = MultiExec::new(mgr.clone(), lib, vec![id], "true".into(), 1, "tester".into(), login, false).unwrap();
        mx.run();
        wait(&mx);
        assert_ne!(mx.results()[0].error.as_deref(), Some(LOCKED_MESSAGE), "first run dials");
        mgr.lock_credentials().unwrap();
        mx.run();
        wait(&mx);
        assert_eq!(mx.results()[0].error.as_deref(), Some(LOCKED_MESSAGE));
        mx.retry_failed();
        wait(&mx);
        assert_eq!(mx.results()[0].error.as_deref(), Some(LOCKED_MESSAGE));
        assert!(mx.login.lock().unwrap().is_none(), "the typed login is gone");
    }
}
