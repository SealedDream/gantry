//! Mosh on Windows through WSL (owner 2026-11-06; same rule as Tauri `mosh_wsl.rs`, #626): there
//! is no official Windows mosh client, so when a Mosh connection is opened and no `mosh.exe` is
//! on PATH the tab runs the default WSL distro's own `mosh` as `wsl.exe -d <distro> -e mosh
//! <args…>`, an argv list, never a shell string. Mosh signs in with the distro's `ssh` (the
//! password is typed in the tab); nothing is written into WSL.

use bastion_core::localshell::LocalShellSpec;

/// Shown when WSL, its default distro, or the distro's `mosh` is missing.
pub(crate) const INSTALL_HINT: &str = "Mosh on Windows runs inside WSL: install WSL (wsl --install) and mosh in it (sudo apt install mosh), or switch the transport to SSH.";

/// Wrap core's validated mosh `spec` (program "mosh") to run inside `distro`.
pub(crate) fn wrap(distro: &str, spec: LocalShellSpec) -> LocalShellSpec {
    let args = ["-d", distro, "-e", "mosh"].iter().map(|s| s.to_string()).chain(spec.args).collect();
    LocalShellSpec { program: "wsl.exe".into(), args, cwd: None }
}

/// The default WSL distribution that is ready and has `mosh`, else the install hint.
#[cfg(windows)]
pub(crate) fn distro() -> Result<String, String> {
    use bastion_core::wsl;
    let d = wsl::distros().ok().and_then(|v| v.into_iter().find(|d| d.is_default)).ok_or(INSTALL_HINT)?;
    if !matches!(wsl::availability(&d.name).map_err(|e| e.to_string())?, wsl::Availability::Ready { .. }) {
        return Err(INSTALL_HINT.into());
    }
    if has_mosh(&d.name) { Ok(d.name) } else { Err(INSTALL_HINT.into()) }
}

/// Upper bound for `which mosh` in the distro: a stuck WSL must not hang the tab.
#[cfg(windows)]
const PROBE_STEPS: u32 = 150; // × 100 ms = 15 s

#[cfg(windows)]
fn has_mosh(distro: &str) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(mut child) = Command::new("wsl.exe").args(["-d", distro, "-e", "which", "mosh"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).creation_flags(CREATE_NO_WINDOW).spawn() else { return false };
    for _ in 0..PROBE_STEPS {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(_) => return false,
        }
    }
    let _ = child.kill();
    false
}

#[cfg(test)]
mod tests {
    use bastion_core::localshell::LocalShellSpec;

    #[test]
    fn mosh_runs_in_the_distro_as_an_argv_list() {
        let spec = LocalShellSpec { program: "mosh".into(), args: vec!["--ssh=ssh -p 2250".into(), "tester@127.0.0.1".into()], cwd: Some("C:\\x".into()) };
        let w = super::wrap("Ubuntu-24.04", spec);
        assert_eq!(w.program, "wsl.exe");
        assert_eq!(w.args, ["-d", "Ubuntu-24.04", "-e", "mosh", "--ssh=ssh -p 2250", "tester@127.0.0.1"]);
        assert_eq!(w.cwd, None);
    }
}
