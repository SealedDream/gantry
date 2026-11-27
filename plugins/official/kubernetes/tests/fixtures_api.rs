//! The pure library against recorded API answers (k3s v1.31 shapes).

use bastion_plugin_kubernetes::api::{calls, check_name, message, Access, Error, MAX_REPLICAS};
use bastion_plugin_kubernetes::model::{self, age, bytes, cpu_millis, epoch, rfc3339};
use bastion_plugin_kubernetes::{Method, Response};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn ok(name: &str) -> Response {
    Response { status: 200, body: fixture(name) }
}

const NOW: &str = "2026-11-23T10:00:00Z";

#[test]
fn pods_parse_with_status_restarts_node_and_age() {
    let pods = calls::pods(None).unwrap().finish(ok("pods.json")).unwrap();
    assert_eq!(pods.len(), 5);
    let now = epoch(NOW).unwrap();
    assert_eq!(pods[0].status_text(), "Running");
    assert_eq!(pods[0].restarts(), 2);
    assert_eq!(pods[0].spec.node_name, "k3s-1");
    assert_eq!(age(&pods[0].metadata.creation_timestamp, now), "3d");
    assert_eq!(pods[1].status_text(), "CrashLoopBackOff");
    assert_eq!(pods[1].restarts(), 8);
    assert_eq!(pods[1].ready(), (1, 2));
    assert_eq!(age(&pods[1].metadata.creation_timestamp, now), "5m");
    assert_eq!(pods[3].status_text(), "Pending");
    assert_eq!(age(&pods[3].metadata.creation_timestamp, now), "30s");
    assert_eq!(pods[4].status_text(), "Evicted");
}

#[test]
fn deployments_services_nodes_and_namespaces_parse() {
    let d = calls::deployments(Some("shop")).unwrap().finish(ok("deployments.json")).unwrap();
    assert_eq!((d[0].status.ready_replicas, d[0].desired()), (2, 3));
    assert_eq!((d[1].status.ready_replicas, d[1].desired()), (0, 0));
    assert_eq!(d[2].desired(), 1, "absent replicas means 1");
    let s = calls::services(None).unwrap().finish(ok("services.json")).unwrap();
    assert_eq!(s[1].ports_text(), "80:30080/TCP, 53/UDP");
    assert_eq!(s[1].spec.kind, "NodePort");
    assert_eq!(s[1].spec.cluster_ip, "10.43.12.7");
    let n = calls::nodes().finish(ok("nodes.json")).unwrap();
    assert!(n[0].ready());
    assert!(!n[1].ready());
    assert_eq!(n[0].status.node_info.kubelet_version, "v1.31.4+k3s1");
    let ns = calls::namespaces().finish(ok("namespaces.json")).unwrap();
    assert_eq!(ns.iter().map(|n| n.metadata.name.as_str()).collect::<Vec<_>>(), ["default", "kube-system", "shop"]);
}

#[test]
fn pod_metrics_sum_containers() {
    let m = calls::pod_metrics(None).unwrap().finish(ok("metrics.json")).unwrap();
    assert_eq!(m[0].totals(), (3, 12340 * 1024));
    assert_eq!(m[1].totals(), (1250, 96 * 1048576 + 1073741824));
    assert_eq!(model::cpu_text(1250), "1.25");
    assert_eq!(model::cpu_text(3), "3m");
    assert_eq!(model::mem_text(12340 * 1024), "12 Mi");
}

#[test]
fn quantities_parse() {
    assert_eq!(cpu_millis("250m"), Some(250));
    assert_eq!(cpu_millis("0.5"), Some(500));
    assert_eq!(cpu_millis("1500u"), Some(2));
    assert_eq!(cpu_millis("x"), None);
    assert_eq!(bytes("1Gi"), Some(1 << 30));
    assert_eq!(bytes("129e6"), Some(129_000_000));
    assert_eq!(bytes("1k"), Some(1000));
    assert_eq!(bytes("-1"), None);
}

#[test]
fn times_round_trip() {
    assert_eq!(epoch("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(epoch("2026-11-23T10:00:00Z"), Some(1_795_428_000));
    assert_eq!(rfc3339(1_795_428_000), "2026-11-23T10:00:00Z");
    assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(epoch("2026-11-23 10:00:00"), None);
    assert_eq!(age("garbage", 0), "");
}

#[test]
fn targets_are_scoped_and_names_checked() {
    assert_eq!(calls::pods(None).unwrap().request.target, "/api/v1/pods");
    assert_eq!(calls::pods(Some("shop")).unwrap().request.target, "/api/v1/namespaces/shop/pods");
    assert_eq!(calls::deployments(Some("shop")).unwrap().request.target, "/apis/apps/v1/namespaces/shop/deployments");
    assert_eq!(calls::pod_metrics(None).unwrap().request.target, "/apis/metrics.k8s.io/v1beta1/pods");
    assert_eq!(
        calls::logs("shop", "web-1").unwrap().request.target,
        "/api/v1/namespaces/shop/pods/web-1/log?tailLines=500&limitBytes=196608"
    );
    for bad in ["", "../x", "a/b", "A", "a?b", "a%2f", "-a", "a-", "a..b", &"a".repeat(254)] {
        assert!(check_name(bad).is_err(), "{bad:?}");
        assert!(calls::pods(Some(bad)).is_err());
        assert!(calls::delete_pod("shop", bad).is_err());
    }
    assert!(check_name("kube-system").is_ok());
    assert!(check_name("web-7c9f8d6b5-x2kqp").is_ok());
    assert!(check_name("my.svc").is_ok());
}

#[test]
fn changes_are_refused_on_a_read_only_entry() {
    let d = calls::delete_pod("shop", "web-1").unwrap();
    assert_eq!(d.request.method, Method::Delete);
    assert!(matches!(d.check(Access::ReadOnly), Err(Error::Refused(_))));
    assert!(d.check(Access::MayChange).is_ok());
    assert!(calls::pods(None).unwrap().check(Access::ReadOnly).is_ok());
}

#[test]
fn scale_and_restart_send_merge_patches() {
    let s = calls::scale("shop", "web", 5).unwrap();
    assert_eq!(s.request.method, Method::Patch);
    assert_eq!(s.request.target, "/apis/apps/v1/namespaces/shop/deployments/web/scale");
    assert_eq!(s.request.content_type(), Some("application/merge-patch+json"));
    assert_eq!(String::from_utf8(s.request.body.clone()).unwrap(), r#"{"spec":{"replicas":5}}"#);
    assert!(calls::scale("shop", "web", MAX_REPLICAS + 1).is_err());
    let r = calls::rollout_restart("shop", "web", 1_795_428_000).unwrap();
    assert_eq!(r.request.target, "/apis/apps/v1/namespaces/shop/deployments/web");
    let body: serde_json::Value = serde_json::from_slice(&r.request.body).unwrap();
    assert_eq!(body["spec"]["template"]["metadata"]["annotations"]["kubectl.kubernetes.io/restartedAt"], "2026-11-23T10:00:00Z");
}

#[test]
fn errors_read_plainly() {
    let e = calls::delete_pod("shop", "web-1").unwrap().finish(Response { status: 403, body: fixture("forbidden.json") }).unwrap_err();
    let m = message(&e);
    assert!(m.starts_with("Forbidden by RBAC: pods is forbidden"), "{m}");
    let e = calls::pods(None).unwrap().finish(Response { status: 401, body: fixture("unauthorized.json") }).unwrap_err();
    assert!(message(&e).contains("expired"));
    assert!(message(&Error::Transport("connection refused".into())).starts_with("API server not reachable"));
    let e = calls::pods(None).unwrap().finish(Response { status: 200, body: b"<html>".to_vec() }).unwrap_err();
    assert!(matches!(e, Error::Parse(_)));
}
