//! Core soak against the lab sshd (live, ignored). 20 SSH sessions running a short command with
//! output every few seconds, plus SFTP upload/download loops of 1-200 MB with a hash check.
//! Every SOAK_SAMPLE_SECS it prints process RSS, open fds, threads, exec latency and SFTP rate;
//! any error is printed as ERROR. Env: NETFAULT_HOST/PORT/PW (same as netfault_live), SOAK_SECS.
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_core::algorithms::ResolvedAlgorithms;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::vault::Secret;
use bastion_core::CoreError;
use sha2::{Digest, Sha256};

fn env(k: &str, d: &str) -> String { std::env::var(k).unwrap_or_else(|_| d.to_string()) }

fn params(host: &str, port: u16, pw: &str, kh: &Path, policy: HostKeyPolicy) -> SshParams {
    SshParams { host: host.into(), port, username: "tester".into(), auth: SshAuth::Password(Secret::new(pw)), known_hosts: kh.to_path_buf(), policy,
        connect_timeout: Duration::from_secs(30), keepalive: Some(Duration::from_secs(15)), prompter: None, algorithms: ResolvedAlgorithms::default() }
}

async fn connect(host: &str, port: u16, pw: &str, kh: &Path) -> Result<SshSession, CoreError> {
    match SshSession::connect(params(host, port, pw, kh, HostKeyPolicy::Strict)).await {
        Err(CoreError::HostKeyUnknown { fingerprint }) => SshSession::connect(params(host, port, pw, kh, HostKeyPolicy::TrustFingerprint(fingerprint))).await,
        other => other,
    }
}

fn proc_stat(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))).unwrap_or(0)
}
fn fds() -> usize { std::fs::read_dir("/proc/self/fd").map(|r| r.count()).unwrap_or(0) }

fn fill(path: &Path, mb: usize, seed: u8) -> [u8; 32] {
    use std::io::Write;
    let mut f = std::fs::File::create(path).unwrap();
    let mut h = Sha256::new();
    let block: Vec<u8> = (0..1024 * 1024).map(|i: usize| (i.wrapping_mul(31) as u8).wrapping_add(seed)).collect();
    for _ in 0..mb { f.write_all(&block).unwrap(); h.update(&block); }
    h.finalize().into()
}
fn hash_file(path: &Path) -> [u8; 32] {
    use std::io::Read;
    let mut f = std::fs::File::open(path).unwrap();
    let mut h = Sha256::new();
    let mut b = vec![0u8; 1 << 20];
    loop { let n = f.read(&mut b).unwrap(); if n == 0 { break } h.update(&b[..n]); }
    h.finalize().into()
}

#[ignore = "live soak: lab sshd, hours"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn soak() {
    let host = env("NETFAULT_HOST", "127.0.0.1");
    let port: u16 = env("NETFAULT_PORT", "2222").parse().unwrap();
    let pw = env("NETFAULT_PW", "");
    let secs: u64 = env("SOAK_SECS", "14400").parse().unwrap();
    let sample: u64 = env("SOAK_SAMPLE_SECS", "300").parse().unwrap();
    assert!(!pw.is_empty());
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let kh = Arc::new(dir.path().join("known_hosts"));
    let end = Instant::now() + Duration::from_secs(secs);
    let errors = Arc::new(AtomicU64::new(0));
    let lat: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let sftp_bytes = Arc::new(AtomicU64::new(0));
    let err = {
        let errors = errors.clone();
        move |who: &str, e: String| { errors.fetch_add(1, Relaxed); println!("ERROR who={who} {}", e.chars().take(120).collect::<String>().replace(&env("NETFAULT_PW", "-"), "<pw>")); }
    };
    // First connection learns the host key before the rest start in parallel.
    drop(connect(&host, port, &pw, &kh).await.expect("first connect"));

    let mut tasks = Vec::new();
    for i in 0..20u32 {
        let (host, pw, kh, lat, err) = (host.clone(), pw.clone(), kh.clone(), lat.clone(), err.clone());
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400 * i as u64)).await;
            let mut s = None;
            while Instant::now() < end {
                if s.is_none() {
                    match connect(&host, port, &pw, &kh).await { Ok(x) => s = Some(x), Err(e) => { err(&format!("ssh{i}-connect"), format!("{e:?}")); tokio::time::sleep(Duration::from_secs(10)).await; continue } }
                }
                let t = Instant::now();
                match tokio::time::timeout(Duration::from_secs(60), s.as_ref().unwrap().exec("for n in 1 2 3; do echo line$n; done")).await {
                    Ok(Ok(o)) if String::from_utf8_lossy(&o.stdout).contains("line3") => lat.lock().unwrap().push(t.elapsed().as_millis() as u64),
                    Ok(Ok(_)) => err(&format!("ssh{i}"), "wrong output".into()),
                    Ok(Err(e)) => { err(&format!("ssh{i}"), format!("{e:?}")); s = None }
                    Err(_) => { err(&format!("ssh{i}"), "exec hung 60s".into()); s = None }
                }
                tokio::time::sleep(Duration::from_secs(4 + (i as u64 % 5))).await;
            }
            if let Some(s) = s { let _ = s.disconnect().await; }
        }));
    }
    for j in 0..2u32 {
        let (host, pw, kh, dir, err, sftp_bytes) = (host.clone(), pw.clone(), kh.clone(), dir.clone(), err.clone(), sftp_bytes.clone());
        tasks.push(tokio::spawn(async move {
            let sizes = [1usize, 5, 20, 50, 100, 200, 10, 2];
            let mut k = j as usize;
            while Instant::now() < end {
                let mb = sizes[k % sizes.len()]; k += 1;
                let (src, dst) = (dir.path().join(format!("src{j}.bin")), dir.path().join(format!("dst{j}.bin")));
                let want = tokio::task::spawn_blocking({ let src = src.clone(); move || fill(&src, mb, j as u8) }).await.unwrap();
                let remote = format!("soak_{j}.bin");
                let r: Result<(), String> = async {
                    let s = connect(&host, port, &pw, &kh).await.map_err(|e| format!("connect {e:?}"))?;
                    let f = s.open_sftp().await.map_err(|e| format!("open {e:?}"))?;
                    f.upload(&src, &remote, true).await.map_err(|e| format!("upload {mb}MB {e:?}"))?;
                    f.download(&remote, &dst, true).await.map_err(|e| format!("download {mb}MB {e:?}"))?;
                    let got = tokio::task::spawn_blocking({ let dst = dst.clone(); move || hash_file(&dst) }).await.unwrap();
                    if got != want { return Err(format!("hash mismatch {mb}MB")); }
                    sftp_bytes.fetch_add(2 * mb as u64 * 1024 * 1024, Relaxed);
                    f.remove_file(&remote).await.map_err(|e| format!("remove {e:?}"))?;
                    let _ = s.disconnect().await;
                    Ok(())
                }.await;
                if let Err(e) = r { err(&format!("sftp{j}"), e); tokio::time::sleep(Duration::from_secs(10)).await; }
                let _ = std::fs::remove_file(&src); let _ = std::fs::remove_file(&dst);
                tokio::time::sleep(Duration::from_secs(env("SOAK_SFTP_PAUSE", "0").parse().unwrap())).await;
            }
            // Clean the lab file even after an error path.
            if let Ok(s) = connect(&host, port, &pw, &kh).await { if let Ok(f) = s.open_sftp().await { let _ = f.remove_file(&format!("soak_{j}.bin")).await; } let _ = s.disconnect().await; }
        }));
    }
    let start = Instant::now();
    let mut last_bytes = 0u64;
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(sample.min(secs))).await;
        let mut l = std::mem::take(&mut *lat.lock().unwrap());
        l.sort_unstable();
        let (p50, p95) = if l.is_empty() { (0, 0) } else { (l[l.len() / 2], l[l.len() * 95 / 100]) };
        let b = sftp_bytes.load(Relaxed);
        println!("SAMPLE t={}s rss_kb={} fds={} threads={} exec_n={} exec_p50_ms={} exec_p95_ms={} sftp_mb={} sftp_mbps={:.1} errors={}", start.elapsed().as_secs(), proc_stat("VmRSS"), fds(), proc_stat("Threads"), l.len(), p50, p95, b / 1048576, (b - last_bytes) as f64 / 1048576.0 / sample as f64, errors.load(Relaxed));
        last_bytes = b;
    }
    for t in tasks { let _ = t.await; }
    println!("SAMPLE final fds={} rss_kb={} errors={}", fds(), proc_stat("VmRSS"), errors.load(Relaxed));
    println!("SOAK_DONE errors={}", errors.load(Relaxed));
    assert_eq!(errors.load(Relaxed), 0);
}
