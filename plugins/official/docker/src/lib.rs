//! Docker plugin, pure part (PLUG-DOCKER-01).
//!
//! The plugin runs the manifest's `[[exec]]` commands on the Docker host over SSH (plugin API 1.5)
//! and reads their `--format '{{json .}}'` output: one JSON object per line. This module parses
//! that output tolerantly (unknown keys ignored, a bad line skipped and counted) and turns a
//! failed command into one of a few clear errors, each with a `GT-` code
//! (`docs/ERROR-CODES.md`).

use serde::Deserialize;

#[cfg(feature = "plugin")]
pub mod plugin;

/// Lines read from one command's output at most; more are left out.
pub const MAX_LINES: usize = 5_000;

/// One container from `docker ps --all --no-trunc --format '{{json .}}'`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Container {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: String,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Ports")]
    pub ports: String,
}

impl Container {
    /// The first name (Docker lists several for linked containers, comma-separated).
    pub fn name(&self) -> &str {
        self.names.split(',').next().unwrap_or("").trim()
    }

    /// A 12-digit id, as `docker ps` shows it.
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(12)]
    }

    pub fn running(&self) -> bool {
        self.state == "running"
    }
}

/// One line of `docker stats --no-stream --no-trunc --format '{{json .}}'`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Stats {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "CPUPerc")]
    pub cpu: String,
    #[serde(rename = "MemUsage")]
    pub mem_usage: String,
    #[serde(rename = "MemPerc")]
    pub mem_perc: String,
}

/// One line of `docker image ls --no-trunc --format '{{json .}}'`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Image {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Repository")]
    pub repository: String,
    #[serde(rename = "Tag")]
    pub tag: String,
    #[serde(rename = "Size")]
    pub size: String,
    #[serde(rename = "CreatedSince")]
    pub created: String,
}

impl Image {
    /// `repo:tag`, or `<none>` for a dangling image.
    pub fn reference(&self) -> String {
        match (self.repository.as_str(), self.tag.as_str()) {
            ("<none>" | "", _) => "<none>".into(),
            (r, "<none>" | "") => r.into(),
            (r, t) => format!("{r}:{t}"),
        }
    }

    /// The id without `sha256:`, 12 digits.
    pub fn short_id(&self) -> &str {
        let id = self.id.strip_prefix("sha256:").unwrap_or(&self.id);
        &id[..id.len().min(12)]
    }
}

/// One line of `docker volume ls --format '{{json .}}'`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Volume {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Driver")]
    pub driver: String,
    #[serde(rename = "Mountpoint")]
    pub mountpoint: String,
}

/// One line of `docker network ls --no-trunc --format '{{json .}}'`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Network {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Driver")]
    pub driver: String,
    #[serde(rename = "Scope")]
    pub scope: String,
}

/// Parsed lines and how many lines were not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    pub items: Vec<T>,
    pub skipped: usize,
}

/// One JSON object per line; blank lines ignored, bad lines counted, at most [`MAX_LINES`].
pub fn parse_lines<T: for<'de> Deserialize<'de>>(text: &str) -> Parsed<T> {
    let mut items = Vec::new();
    let mut skipped = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()).take(MAX_LINES) {
        match serde_json::from_str::<T>(line) {
            Ok(v) => items.push(v),
            Err(_) => skipped += 1,
        }
    }
    Parsed { items, skipped }
}

/// The stats line for a container, by full id.
pub fn stats_for<'a>(stats: &'a [Stats], id: &str) -> Option<&'a Stats> {
    stats.iter().find(|s| s.id == id)
}

/// Why a command failed, as the dashboard says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerError {
    /// `docker` is not on the host (`command not found`, exit 127).
    NotInstalled,
    /// The SSH user may not use the Docker socket (not in the `docker` group).
    PermissionDenied,
    /// The Docker daemon is not running or not reachable.
    DaemonDown,
    /// Something else: Docker's own first line of stderr.
    Other(String),
}

impl DockerError {
    /// A `GT-` code for support requests (`docs/ERROR-CODES.md`).
    pub fn code(&self) -> &'static str {
        match self {
            DockerError::NotInstalled => "GT-PLUG-003",
            DockerError::PermissionDenied => "GT-PLUG-004",
            DockerError::DaemonDown => "GT-PLUG-005",
            DockerError::Other(_) => "GT-PLUG-000",
        }
    }

    /// The message, one line, with what to do.
    pub fn message(&self) -> String {
        let text = match self {
            DockerError::NotInstalled => "Docker is not installed on this host, or not on the SSH user's PATH.".to_string(),
            DockerError::PermissionDenied => "The SSH user may not use Docker. Add it to the docker group (sudo usermod -aG docker <user>), then sign in again.".to_string(),
            DockerError::DaemonDown => "The Docker daemon is not running on this host (sudo systemctl start docker).".to_string(),
            DockerError::Other(t) => t.clone(),
        };
        format!("{text} ({})", self.code())
    }
}

/// Reads a non-zero exit: the exit status and stderr.
pub fn classify(exit: Option<i32>, stderr: &str) -> DockerError {
    let l = stderr.to_ascii_lowercase();
    if exit == Some(127) || l.contains("command not found") || l.contains("docker: not found") {
        DockerError::NotInstalled
    } else if l.contains("permission denied") && (l.contains("docker.sock") || l.contains("docker daemon socket")) {
        DockerError::PermissionDenied
    } else if l.contains("cannot connect to the docker daemon") || l.contains("is the docker daemon running") {
        DockerError::DaemonDown
    } else {
        let first: String = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("docker failed").chars().filter(|c| !c.is_control()).take(200).collect();
        DockerError::Other(first)
    }
}

/// Container, image, volume and network names Docker accepts, as the core's `name` kind checks
/// them; the plugin checks first, so a bad name from the server never reaches a command.
pub fn valid_name(s: &str) -> bool {
    s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric()) && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: &str = include_str!("../tests/fixtures/ps.jsonl");
    const STATS: &str = include_str!("../tests/fixtures/stats.jsonl");
    const IMAGES: &str = include_str!("../tests/fixtures/images.jsonl");
    const VOLUMES: &str = include_str!("../tests/fixtures/volumes.jsonl");
    const NETWORKS: &str = include_str!("../tests/fixtures/networks.jsonl");

    #[test]
    fn containers_parse_from_recorded_ps_output() {
        let p = parse_lines::<Container>(PS);
        assert_eq!(p.skipped, 0);
        assert_eq!(p.items.len(), 2);
        let web = &p.items[0];
        assert_eq!((web.name(), web.image.as_str(), web.running(), web.short_id()), ("web", "nginx:1.27", true, "3f1c9a2b7d8e"));
        assert!(web.ports.contains("8080->80/tcp"));
        assert!(!p.items[1].running());
    }

    #[test]
    fn stats_images_volumes_and_networks_parse() {
        let s = parse_lines::<Stats>(STATS).items;
        assert_eq!(stats_for(&s, "3f1c9a2b7d8e4f60a1b2c3d4e5f60718293a4b5c6d7e8f9012345678abcdef01").map(|s| s.cpu.as_str()), Some("0.12%"));
        let i = parse_lines::<Image>(IMAGES).items;
        assert_eq!((i[0].reference(), i[0].short_id()), ("nginx:1.27".to_string(), "111111111111"));
        assert_eq!(i[1].reference(), "<none>");
        assert_eq!(parse_lines::<Volume>(VOLUMES).items[0].name, "pgdata");
        assert_eq!(parse_lines::<Network>(NETWORKS).items.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["bridge", "host"]);
    }

    #[test]
    fn bad_lines_are_skipped_and_counted() {
        let p = parse_lines::<Container>("{\"ID\":\"x\",\"Names\":\"a\"}\nnot json\n\n[1]\n");
        assert_eq!((p.items.len(), p.skipped), (1, 2));
    }

    #[test]
    fn failures_are_classified_with_codes() {
        assert_eq!(classify(Some(127), "bash: line 1: docker: command not found"), DockerError::NotInstalled);
        let perm = "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/containers/json\": dial unix /var/run/docker.sock: connect: permission denied";
        assert_eq!(classify(Some(1), perm), DockerError::PermissionDenied);
        assert!(classify(Some(1), perm).message().contains("docker group") && classify(Some(1), perm).message().ends_with("(GT-PLUG-004)"));
        assert_eq!(classify(Some(1), "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"), DockerError::DaemonDown);
        assert_eq!(classify(Some(1), "Error response from daemon: No such container: x\n"), DockerError::Other("Error response from daemon: No such container: x".into()));
    }

    #[test]
    fn names_from_the_server_are_checked() {
        assert!(valid_name("web") && valid_name("3f1c9a2b7d8e"));
        assert!(!valid_name("-v") && !valid_name("a b") && !valid_name("") && !valid_name("a;b"));
    }
}
