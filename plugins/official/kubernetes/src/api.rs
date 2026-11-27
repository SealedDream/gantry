//! Requests to the Kubernetes API and their answers.

use crate::model::{self, Deployment, List, Namespace, Node, Pod, PodMetrics, Service};
use crate::{Method, Request, Response};
use serde::de::DeserializeOwned;

/// Lines of a pod log the Logs view reads (the tail).
pub const LOG_TAIL_LINES: u32 = 500;
/// Most bytes of a log the view keeps; the API's own `limitBytes` caps the answer first.
pub const LOG_LIMIT_BYTES: u32 = 192 * 1024;
/// Most replicas the Scale dialog sends.
pub const MAX_REPLICAS: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Refused before anything was sent: a bad name, or a change on a read-only entry.
    Refused(String),
    /// The server answered with an error status, and the Status message if it sent one.
    Status(u16, String),
    /// The answer was not the JSON expected.
    Parse(String),
    /// The core could not reach the server (route, TLS, time-out); the core's words.
    Transport(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    MayChange,
}

/// A Kubernetes object name or namespace: DNS-1123 subdomain (lowercase letters, digits, `-`
/// and `.`, starting and ending with a letter or digit, at most 253). This keeps any name from
/// the server or the user from adding a path segment, a query or an escape.
pub fn check_name(name: &str) -> Result<&str, Error> {
    let b = name.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 253
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && !name.contains("..");
    if ok {
        Ok(name)
    } else {
        Err(Error::Refused(format!("Not a Kubernetes name: {}", name.chars().take(64).collect::<String>())))
    }
}

/// One call: its request and how to read the answer.
pub struct Call<R> {
    pub request: Request,
    parse: fn(&[u8]) -> Result<R, Error>,
}

impl<R> Call<R> {
    fn new(method: Method, target: String, body: Vec<u8>, parse: fn(&[u8]) -> Result<R, Error>) -> Self {
        Call { request: Request { method, target, body }, parse }
    }

    /// Refuses a change unless the access allows it. Runs before anything is sent.
    pub fn check(&self, access: Access) -> Result<(), Error> {
        if self.request.method.changes() && access != Access::MayChange {
            return Err(Error::Refused("Changes are off for this entry. Turn on \"Allow changes\" in the connection.".into()));
        }
        Ok(())
    }

    pub fn finish(&self, resp: Response) -> Result<R, Error> {
        if !(200..300).contains(&resp.status) {
            let status: model::Status = serde_json::from_slice(&resp.body).unwrap_or_default();
            let text: String = status.message.chars().take(300).collect();
            return Err(Error::Status(resp.status, text));
        }
        (self.parse)(&resp.body)
    }
}

fn json<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(body).map_err(|e| Error::Parse(e.to_string()))
}

fn items<T: DeserializeOwned + Default>(body: &[u8]) -> Result<Vec<T>, Error> {
    json::<List<T>>(body).map(|l| l.items)
}

fn text(body: &[u8]) -> Result<String, Error> {
    Ok(String::from_utf8_lossy(body).into_owned())
}

fn nothing(_: &[u8]) -> Result<(), Error> {
    Ok(())
}

/// `/api/v1/pods` or `/api/v1/namespaces/{ns}/pods`.
fn scoped(prefix: &str, ns: Option<&str>, kind: &str) -> Result<String, Error> {
    Ok(match ns {
        Some(ns) => format!("{prefix}namespaces/{}/{kind}", check_name(ns)?),
        None => format!("{prefix}{kind}"),
    })
}

pub mod calls {
    use super::*;

    pub fn namespaces() -> Call<Vec<Namespace>> {
        Call::new(Method::Get, "/api/v1/namespaces".into(), vec![], items)
    }

    pub fn pods(ns: Option<&str>) -> Result<Call<Vec<Pod>>, Error> {
        Ok(Call::new(Method::Get, scoped("/api/v1/", ns, "pods")?, vec![], items))
    }

    pub fn deployments(ns: Option<&str>) -> Result<Call<Vec<Deployment>>, Error> {
        Ok(Call::new(Method::Get, scoped("/apis/apps/v1/", ns, "deployments")?, vec![], items))
    }

    pub fn services(ns: Option<&str>) -> Result<Call<Vec<Service>>, Error> {
        Ok(Call::new(Method::Get, scoped("/api/v1/", ns, "services")?, vec![], items))
    }

    pub fn nodes() -> Call<Vec<Node>> {
        Call::new(Method::Get, "/api/v1/nodes".into(), vec![], items)
    }

    /// metrics-server's pod usage; a 404 means it is not installed.
    pub fn pod_metrics(ns: Option<&str>) -> Result<Call<Vec<PodMetrics>>, Error> {
        Ok(Call::new(Method::Get, scoped("/apis/metrics.k8s.io/v1beta1/", ns, "pods")?, vec![], items))
    }

    /// The tail of a pod's log, all containers' default (the first container).
    pub fn logs(ns: &str, pod: &str) -> Result<Call<String>, Error> {
        let target = format!(
            "/api/v1/namespaces/{}/pods/{}/log?tailLines={LOG_TAIL_LINES}&limitBytes={LOG_LIMIT_BYTES}",
            check_name(ns)?,
            check_name(pod)?
        );
        Ok(Call::new(Method::Get, target, vec![], text))
    }

    /// Deletes a pod; its controller starts a new one.
    pub fn delete_pod(ns: &str, pod: &str) -> Result<Call<()>, Error> {
        Ok(Call::new(Method::Delete, format!("/api/v1/namespaces/{}/pods/{}", check_name(ns)?, check_name(pod)?), vec![], nothing))
    }

    /// Sets a deployment's replicas through its `scale` subresource.
    pub fn scale(ns: &str, deployment: &str, replicas: u64) -> Result<Call<()>, Error> {
        if replicas > MAX_REPLICAS {
            return Err(Error::Refused(format!("At most {MAX_REPLICAS} replicas.")));
        }
        let target = format!("/apis/apps/v1/namespaces/{}/deployments/{}/scale", check_name(ns)?, check_name(deployment)?);
        let body = serde_json::json!({ "spec": { "replicas": replicas } }).to_string().into_bytes();
        Ok(Call::new(Method::Patch, target, body, nothing))
    }

    /// `kubectl rollout restart`: stamps the pod template so the deployment rolls its pods.
    pub fn rollout_restart(ns: &str, deployment: &str, now: i64) -> Result<Call<()>, Error> {
        let target = format!("/apis/apps/v1/namespaces/{}/deployments/{}", check_name(ns)?, check_name(deployment)?);
        let body = serde_json::json!({
            "spec": { "template": { "metadata": { "annotations": { "kubectl.kubernetes.io/restartedAt": model::rfc3339(now) } } } }
        })
        .to_string()
        .into_bytes();
        Ok(Call::new(Method::Patch, target, body, nothing))
    }
}

/// What the user sees when a call fails, in plain words.
pub fn message(e: &Error) -> String {
    match e {
        Error::Status(401, _) => "Token refused or expired. Put a valid ServiceAccount token in the entry's password.".into(),
        Error::Status(403, m) if m.is_empty() => "Forbidden by RBAC: the token's role does not allow this.".into(),
        Error::Status(403, m) => format!("Forbidden by RBAC: {m}"),
        Error::Status(404, m) if m.is_empty() => "Not found.".into(),
        Error::Status(code, m) if m.is_empty() => format!("The API server answered {code}."),
        Error::Status(code, m) => format!("The API server answered {code}: {m}"),
        Error::Parse(_) => "The answer was not what a Kubernetes API server sends.".into(),
        Error::Transport(why) => format!("API server not reachable: {why}"),
        Error::Refused(why) => why.clone(),
    }
}
