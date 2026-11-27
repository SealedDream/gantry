//! The Kubernetes API records the plugin reads. Every field is optional on the wire, so an
//! older or newer API server, or an object in an odd state, still parses.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct List<T> {
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct Meta {
    pub name: String,
    pub namespace: String,
    pub creation_timestamp: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Pod {
    pub metadata: Meta,
    pub spec: PodSpec,
    pub status: PodStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PodSpec {
    pub node_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PodStatus {
    pub phase: String,
    pub reason: String,
    pub container_statuses: Vec<ContainerStatus>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ContainerStatus {
    pub ready: bool,
    pub restart_count: u64,
    pub state: ContainerState,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ContainerState {
    pub waiting: Option<Reason>,
    pub terminated: Option<Reason>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Reason {
    pub reason: String,
}

impl Pod {
    pub fn restarts(&self) -> u64 {
        self.status.container_statuses.iter().map(|c| c.restart_count).sum()
    }

    /// The status `kubectl get pods` shows: a container's waiting or terminated reason
    /// (CrashLoopBackOff, ImagePullBackOff, Completed), else the pod's reason, else its phase.
    pub fn status_text(&self) -> String {
        let container = self.status.container_statuses.iter().find_map(|c| {
            c.state.waiting.as_ref().or(c.state.terminated.as_ref()).map(|r| r.reason.clone()).filter(|r| !r.is_empty())
        });
        container
            .or_else(|| Some(self.status.reason.clone()).filter(|r| !r.is_empty()))
            .unwrap_or_else(|| if self.status.phase.is_empty() { "Unknown".into() } else { self.status.phase.clone() })
    }

    pub fn ready(&self) -> (usize, usize) {
        let all = self.status.container_statuses.len();
        (self.status.container_statuses.iter().filter(|c| c.ready).count(), all)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Deployment {
    pub metadata: Meta,
    pub spec: DeploymentSpec,
    pub status: DeploymentStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentSpec {
    /// Absent means 1 (the API's default).
    pub replicas: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DeploymentStatus {
    pub ready_replicas: u64,
    pub updated_replicas: u64,
    pub available_replicas: u64,
}

impl Deployment {
    pub fn desired(&self) -> u64 {
        self.spec.replicas.unwrap_or(1)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Service {
    pub metadata: Meta,
    pub spec: ServiceSpec,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ServiceSpec {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "clusterIP")]
    pub cluster_ip: String,
    pub ports: Vec<ServicePort>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ServicePort {
    pub port: u32,
    pub protocol: String,
    pub node_port: Option<u32>,
}

impl Service {
    /// `80/TCP, 443:30443/TCP`, as kubectl shows them.
    pub fn ports_text(&self) -> String {
        self.spec
            .ports
            .iter()
            .map(|p| {
                let proto = if p.protocol.is_empty() { "TCP" } else { &p.protocol };
                match p.node_port {
                    Some(n) => format!("{}:{n}/{proto}", p.port),
                    None => format!("{}/{proto}", p.port),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Node {
    pub metadata: Meta,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NodeStatus {
    pub conditions: Vec<Condition>,
    pub node_info: NodeInfo,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Condition {
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NodeInfo {
    pub kubelet_version: String,
}

impl Node {
    pub fn ready(&self) -> bool {
        self.status.conditions.iter().any(|c| c.kind == "Ready" && c.status == "True")
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Namespace {
    pub metadata: Meta,
}

/// metrics.k8s.io `PodMetrics`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PodMetrics {
    pub metadata: Meta,
    pub containers: Vec<ContainerMetrics>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ContainerMetrics {
    pub usage: Usage,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Usage {
    pub cpu: String,
    pub memory: String,
}

impl PodMetrics {
    /// Total CPU in millicores and memory in bytes over the pod's containers.
    pub fn totals(&self) -> (u64, u64) {
        self.containers.iter().fold((0, 0), |(c, m), x| {
            (c + cpu_millis(&x.usage.cpu).unwrap_or(0), m + bytes(&x.usage.memory).unwrap_or(0))
        })
    }
}

/// The API's error answer (`kind: Status`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Status {
    pub message: String,
    pub reason: String,
}

/// A CPU quantity in millicores: `250m`, `1`, `0.5`, `123456789n`, `1500u`.
pub fn cpu_millis(q: &str) -> Option<u64> {
    let q = q.trim();
    let (num, scale) = match q.char_indices().last()? {
        (i, 'n') => (&q[..i], 1e-6),
        (i, 'u') => (&q[..i], 1e-3),
        (i, 'm') => (&q[..i], 1.0),
        _ => (q, 1000.0),
    };
    let v: f64 = num.parse().ok()?;
    (v >= 0.0 && v.is_finite()).then(|| (v * scale).round() as u64)
}

/// A memory quantity in bytes: `128974848`, `129e6`, `123Ki`, `512Mi`, `1G`.
pub fn bytes(q: &str) -> Option<u64> {
    let q = q.trim();
    const UNITS: [(&str, f64); 12] = [
        ("Ki", 1024.0),
        ("Mi", 1048576.0),
        ("Gi", 1073741824.0),
        ("Ti", 1099511627776.0),
        ("Pi", 1125899906842624.0),
        ("Ei", 1152921504606846976.0),
        ("k", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("P", 1e15),
        ("E", 1e18),
    ];
    let (num, scale) = UNITS.iter().find_map(|(u, s)| q.strip_suffix(u).map(|n| (n, *s))).unwrap_or((q, 1.0));
    let v: f64 = num.parse().ok()?;
    (v >= 0.0 && v.is_finite()).then(|| (v * scale).round() as u64)
}

/// `250m`, `1.5` cores as shown in a table.
pub fn cpu_text(millis: u64) -> String {
    if millis >= 10_000 {
        format!("{:.0}", millis as f64 / 1000.0)
    } else if millis >= 1000 {
        format!("{:.2}", millis as f64 / 1000.0)
    } else {
        format!("{millis}m")
    }
}

/// `96 Mi`, `1.5 Gi`.
pub fn mem_text(b: u64) -> String {
    let mi = b as f64 / 1048576.0;
    if mi >= 1024.0 {
        format!("{:.1} Gi", mi / 1024.0)
    } else {
        format!("{mi:.0} Mi")
    }
}

/// Seconds since the Unix epoch for an RFC 3339 UTC time (`2026-11-20T08:15:00Z`), as the API
/// writes `creationTimestamp`. Anything else is `None`.
pub fn epoch(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !ts.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| ts.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, s) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3_600 + mi * 60 + s)
}

/// Age as kubectl shows it: `45s`, `12m`, `5h`, `3d`.
pub fn age(created: &str, now: i64) -> String {
    let Some(t) = epoch(created) else { return String::new() };
    let s = (now - t).max(0);
    match s {
        0..=119 => format!("{s}s"),
        120..=7_199 => format!("{}m", s / 60),
        7_200..=172_799 => format!("{}h", s / 3_600),
        _ => format!("{}d", s / 86_400),
    }
}

/// RFC 3339 UTC for a Unix time, for the rollout-restart annotation.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3_600, rem / 60 % 60, rem % 60)
}
