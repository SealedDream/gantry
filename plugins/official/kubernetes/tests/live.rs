//! Live check against a throwaway k3s cluster (never a real or shared cluster). Ignored by
//! default; run by hand:
//!
//!   BASTION_K8S_URL=https://127.0.0.1:16443 BASTION_K8S_CA=<ca.crt> \
//!   BASTION_K8S_TOKEN_FILE=<admin token> BASTION_K8S_VIEWER_TOKEN_FILE=<view-only token> \
//!   cargo test --offline --test live -- --ignored --test-threads=1
//!
//! - TLS: verified against the cluster's own CA (curl `--cacert`), as the entry's pinned trust.
//! - Changes only touch namespace `shop` (deployment `web`), which the setup created.
//! - Tokens go to curl on stdin, never in argv, and nothing here prints them.

use bastion_plugin_kubernetes::api::{calls, message, Call, Error};
use bastion_plugin_kubernetes::{Method, Response};
use std::io::Write;
use std::process::{Command, Stdio};

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

fn token(var: &str) -> String {
    std::fs::read_to_string(env(var)).unwrap().trim().to_string()
}

fn send<R>(c: &Call<R>, token: &str) -> Result<R, Error> {
    let r = &c.request;
    assert!(r.method == Method::Get || r.target.contains("/namespaces/shop/"), "changes stay in shop");
    let method = match r.method {
        Method::Get => "GET",
        Method::Delete => "DELETE",
        Method::Patch => "PATCH",
    };
    let mut child = Command::new("curl")
        .args(["-sS", "--max-time", "20", "--proto", "=https", "--cacert", &env("BASTION_K8S_CA"), "-K", "-", "-w", "\n%{http_code}"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut cfg = format!("url = \"{}{}\"\nrequest = \"{method}\"\nheader = \"Authorization: Bearer {token}\"\n", env("BASTION_K8S_URL"), r.target);
    if let Some(ct) = r.content_type() {
        cfg += &format!("header = \"Content-Type: {ct}\"\ndata = {}\n", serde_json::to_string(&String::from_utf8(r.body.clone()).unwrap()).unwrap());
    }
    child.stdin.take().unwrap().write_all(cfg.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    if !out.status.success() {
        return Err(Error::Transport(format!("curl exit {:?}", out.status.code())));
    }
    let text = out.stdout;
    let cut = text.iter().rposition(|&b| b == b'\n').unwrap();
    let status = std::str::from_utf8(&text[cut + 1..]).unwrap().trim().parse().unwrap();
    c.finish(Response { status, body: text[..cut].to_vec() })
}

fn wait<F: FnMut() -> bool>(mut f: F) -> bool {
    (0..60).any(|_| {
        let ok = f();
        if !ok {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        ok
    })
}

#[test]
#[ignore = "needs a throwaway k3s cluster"]
fn live_reads_logs_and_changes() {
    let t = token("BASTION_K8S_TOKEN_FILE");
    let ns = send(&calls::namespaces(), &t).expect("namespaces");
    assert!(ns.iter().any(|n| n.metadata.name == "shop"));
    let nodes = send(&calls::nodes(), &t).expect("nodes");
    assert!(nodes.iter().all(|n| n.ready()), "nodes ready");
    assert!(send(&calls::deployments(None).unwrap(), &t).unwrap().iter().any(|d| d.metadata.name == "coredns"));
    assert!(!send(&calls::services(None).unwrap(), &t).unwrap().is_empty());
    // metrics-server ships with k3s; it may need a minute before it answers.
    let metrics_ok = wait(|| send(&calls::pod_metrics(Some("kube-system")).unwrap(), &t).is_ok_and(|m| !m.is_empty()));

    // Scale web to 3, see 3 ready.
    send(&calls::scale("shop", "web", 3).unwrap(), &t).expect("scale");
    assert!(wait(|| send(&calls::deployments(Some("shop")).unwrap(), &t).unwrap().iter().any(|d| d.metadata.name == "web" && d.status.ready_replicas == 3)), "scaled to 3");

    // Logs of a pod (pause writes none: an empty answer is a success).
    let pods = send(&calls::pods(Some("shop")).unwrap(), &t).unwrap();
    let pod = pods.iter().find(|p| p.status.phase == "Running").expect("a running pod").metadata.name.clone();
    send(&calls::logs("shop", &pod).unwrap(), &t).expect("logs");

    // Delete a pod: the deployment replaces it.
    send(&calls::delete_pod("shop", &pod).unwrap(), &t).expect("delete");
    assert!(wait(|| {
        let now = send(&calls::pods(Some("shop")).unwrap(), &t).unwrap();
        !now.iter().any(|p| p.metadata.name == pod) && now.iter().filter(|p| p.status.phase == "Running").count() == 3
    }), "pod replaced");

    // Rollout restart stamps the template.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    send(&calls::rollout_restart("shop", "web", now).unwrap(), &t).expect("restart");
    assert!(wait(|| send(&calls::pods(Some("shop")).unwrap(), &t).unwrap().iter().all(|p| !pods.iter().any(|o| o.metadata.name == p.metadata.name))), "all pods new");

    // A view-only token: reads work, changes are forbidden by RBAC in plain words.
    let v = token("BASTION_K8S_VIEWER_TOKEN_FILE");
    assert!(send(&calls::pods(Some("shop")).unwrap(), &v).is_ok());
    let e = send(&calls::delete_pod("shop", "web-x").unwrap(), &v).unwrap_err();
    assert!(message(&e).starts_with("Forbidden by RBAC: pods \"web-x\" is forbidden"), "{}", message(&e));
    // A bad token: 401 in plain words.
    let e = send(&calls::namespaces(), "not-a-token").unwrap_err();
    assert!(message(&e).contains("expired"), "{}", message(&e));
    println!("live: {} node(s), metrics {}", nodes.len(), if metrics_ok { "yes" } else { "no" });
}
