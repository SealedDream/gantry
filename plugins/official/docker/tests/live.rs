//! Live check against a real Docker host (PLUG-DOCKER-01). Ignored by default; run with
//!
//!   BASTION_DOCKER_LIVE=docker-host cargo test --test live -- --ignored
//!
//! where the value is an SSH alias whose user may use Docker. It sends the exact command lines
//! the core builds from the manifest (pinned by `core/src/plugin/manifest.rs`,
//! `the_official_docker_manifest_passes_with_changes_marked`) and parses the answers with the
//! plugin's own code. Read-only: no template that changes the host is run.

use std::process::Command;

use bastion_plugin_docker::{classify, parse_lines, Container, DockerError, Image, Network, Stats, Volume};

fn ssh(alias: &str, line: &str) -> (i32, String, String) {
    let out = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", alias, line])
        .output()
        .expect("run ssh");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
#[ignore]
fn the_declared_commands_parse_on_a_real_host() {
    let Ok(alias) = std::env::var("BASTION_DOCKER_LIVE") else { return };
    let (code, v, _) = ssh(&alias, "docker version --format '{{json .Server.Version}}'");
    assert_eq!(code, 0);
    assert!(v.trim().starts_with('"'), "{v}");
    let (code, ps, _) = ssh(&alias, "docker ps --all --no-trunc --format '{{json .}}'");
    assert_eq!(code, 0);
    let ps = parse_lines::<Container>(&ps);
    assert_eq!(ps.skipped, 0);
    assert!(!ps.items.is_empty() && ps.items.iter().all(|c| c.id.len() == 64 && !c.name().is_empty()));
    let (code, st, _) = ssh(&alias, "docker stats --no-stream --no-trunc --format '{{json .}}'");
    assert_eq!(code, 0);
    let st = parse_lines::<Stats>(&st);
    assert_eq!(st.skipped, 0);
    assert!(ps.items.iter().filter(|c| c.running()).all(|c| st.items.iter().any(|s| s.id == c.id)), "stats for every running container");
    for (line, kind) in [
        ("docker image ls --no-trunc --format '{{json .}}'", "images"),
        ("docker volume ls --format '{{json .}}'", "volumes"),
        ("docker network ls --no-trunc --format '{{json .}}'", "networks"),
    ] {
        let (code, text, _) = ssh(&alias, line);
        assert_eq!(code, 0, "{kind}");
        let skipped = match kind {
            "images" => parse_lines::<Image>(&text).skipped,
            "volumes" => parse_lines::<Volume>(&text).skipped,
            _ => parse_lines::<Network>(&text).skipped,
        };
        assert_eq!(skipped, 0, "{kind}");
    }
    let first = ps.items[0].name().to_string();
    let (code, _, _) = ssh(&alias, &format!("docker logs --timestamps --tail 5 {first}"));
    assert_eq!(code, 0);
    // A missing program, as on a host without Docker, is reported as not installed.
    let (code, _, err) = ssh(&alias, "docker-not-here version");
    assert_eq!(classify(Some(code), &err), DockerError::NotInstalled);
}
