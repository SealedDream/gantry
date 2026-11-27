//! SEC-3: a connect waits for the audit log's verdict before it fetches a secret,
//! authenticates or appends a record.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;
use crate::audit::{wait_for_background_verify, AuditLog, Category, Outcome};
use crate::broker::{Broker, LeaseLimits, SystemClock};
use crate::model::Protocol;
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;

/// Counts every secret it hands out.
struct CountingProvider(Arc<AtomicUsize>);

impl CredentialProvider for CountingProvider {
    fn id(&self) -> &'static str {
        "count"
    }
    fn status(&self) -> ProviderStatus {
        ProviderStatus::Available
    }
    fn fetch(&self, _item: &str) -> Result<Secret> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Secret::new("pw"))
    }
    fn store(&self, _item: &str, _secret: &Secret) -> Result<()> {
        Ok(())
    }
    fn delete(&self, _item: &str) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_tampered_log_refuses_the_connect_with_no_secret_and_no_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    {
        let mut log = AuditLog::open(&path).unwrap();
        for i in 0..50 {
            log.record(Category::Connection, "connection.open", Some(&format!("host-{i:06}")), Outcome::Success, BTreeMap::new()).unwrap();
        }
    }
    let mut log = AuditLog::open(&path).unwrap();
    log.confirm().unwrap();
    wait_for_background_verify(&path);

    // Change a middle record, keeping the length and the last record.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    lines[25] = lines[25].replacen("host-000025", "host-999999", 1);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let tampered = std::fs::read(&path).unwrap();

    let fetches = Arc::new(AtomicUsize::new(0));
    let broker = Arc::new(Broker::new(LeaseLimits::default(), Policy::default(), Arc::new(SystemClock)));
    let o = Orchestrator::new(
        Policy::default(),
        broker,
        vec![Arc::new(CountingProvider(fetches.clone()))],
        AuditLog::open(&path).unwrap(),
        dir.path().join("known_hosts"),
    );
    let cred = CredentialRef { provider: "count".into(), item: "x".into(), scope: None, username: "u".into(), usage: SecretUse::Password };
    // Port 1 on loopback: nothing is listening, so no authentication can happen either way.
    let mut conn = Connection::new("target", Protocol::Ssh, "127.0.0.1");
    conn.settings.port = Some(1);

    for _ in 0..2 {
        let r = o.connect_ssh(&conn, &cred).await;
        assert!(matches!(r, Err(CoreError::Corrupt(_))), "a broken chain refuses the connect: {:?}", r.err());
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 0, "no secret was released");
    assert!(o.broker().status().unwrap().is_empty(), "no lease was opened");
    assert_eq!(std::fs::read(&path).unwrap(), tampered, "nothing was appended");
}
