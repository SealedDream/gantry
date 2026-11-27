//! WSL distributions as terminal profiles (Windows). Discovery reads the per-user `Lxss`
//! registry key first (no WSL service start) and falls back to `wsl.exe --list --verbose`,
//! whose output is UTF-16LE; a tab is a local PTY running `wsl.exe -d <distro>`.
//! Names come from another program's output and end up as process arguments, so only names
//! WSL itself accepts are kept (no leading `-`, no spaces or shell characters).

/// Maximum number of distributions listed; anything past it is ignored.
const MAX_DISTROS: usize = 64;
/// WSL distribution names are at most this long.
const MAX_NAME_LEN: usize = 64;

/// Decode `wsl.exe -l -q` output: UTF-16LE (with or without BOM) or, on some builds, UTF-8.
pub fn parse_distro_list(bytes: &[u8]) -> Vec<String> {
    let text = decode(bytes);
    let mut out: Vec<String> = Vec::new();
    for name in text.lines().map(|l| l.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}' || c == '\0')) {
        if is_valid_name(name) && !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
        if out.len() == MAX_DISTROS {
            break;
        }
    }
    out
}

/// Arguments for `wsl.exe` that open `distro` in its user's home directory.
pub fn launch_args(distro: &str) -> crate::Result<Vec<String>> {
    if !is_valid_name(distro) {
        return Err(crate::CoreError::Invalid(format!("not a WSL distribution name: `{distro}`")));
    }
    Ok(vec!["-d".into(), distro.into(), "--cd".into(), "~".into()])
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('-')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn looks_utf16le(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xFE]) || (bytes.len() >= 2 && bytes.len() % 2 == 0 && bytes[1] == 0)
}

/// Whether a distribution is running, as `wsl.exe -l -v` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistroState {
    Running,
    Stopped,
    /// Installing, converting or uninstalling: launching now would fail.
    Busy,
    /// The registry was read and `wsl.exe` was not asked.
    Unknown,
}

/// One installed distribution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Distro {
    pub name: String,
    /// 1 or 2; 0 when unknown.
    pub version: u8,
    pub is_default: bool,
    pub state: DistroState,
}

/// What opening a saved WSL connection would find.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Availability {
    /// Launchable; a stopped distribution starts on launch.
    Ready { state: DistroState },
    /// `wsl.exe` is not on this PC.
    WslMissing,
    /// WSL is there but this distribution is not (unregistered or renamed).
    Removed { installed: Vec<String> },
    /// Installing, converting or uninstalling right now.
    Busy,
}

/// Decode `wsl.exe -l -v` output (UTF-16LE or UTF-8): a header row, then
/// `[*] NAME STATE VERSION` per distribution, `*` marking the default.
pub fn parse_verbose_list(bytes: &[u8]) -> Vec<Distro> {
    let mut out: Vec<Distro> = Vec::new();
    for line in decode(bytes).lines().skip(1) {
        let line = line.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}' || c == '\0');
        let (is_default, rest) = match line.strip_prefix('*') {
            Some(r) => (true, r),
            None => (false, line),
        };
        let cols: Vec<&str> = rest.split_whitespace().collect();
        let [name, state, version] = cols[..] else { continue };
        if !is_valid_name(name) || out.iter().any(|d| d.name == name) {
            continue;
        }
        let state = match state {
            "Running" => DistroState::Running,
            "Stopped" => DistroState::Stopped,
            "Installing" | "Converting" | "Uninstalling" => DistroState::Busy,
            _ => DistroState::Unknown,
        };
        out.push(Distro { name: name.into(), version: version.parse().unwrap_or(0), is_default, state });
        if out.len() == MAX_DISTROS {
            break;
        }
    }
    sort_default_first(out)
}

/// Distributions that exist to back another product (Docker Desktop's `docker-desktop` and
/// `docker-desktop-data`) rather than to be opened; pickers hide them unless asked.
pub fn is_hidden_by_default(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("docker-desktop")
}

/// Decide what launching `name` would do, given what discovery found.
pub fn availability_in(name: &str, wsl_present: bool, installed: &[Distro]) -> Availability {
    if !wsl_present {
        return Availability::WslMissing;
    }
    match installed.iter().find(|d| d.name.eq_ignore_ascii_case(name)) {
        Some(d) if d.state == DistroState::Busy => Availability::Busy,
        Some(d) => Availability::Ready { state: d.state },
        None => Availability::Removed { installed: installed.iter().map(|d| d.name.clone()).collect() },
    }
}

fn sort_default_first(mut v: Vec<Distro>) -> Vec<Distro> {
    v.sort_by_key(|d| !d.is_default);
    v
}

fn decode(bytes: &[u8]) -> String {
    if looks_utf16le(bytes) {
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Installed distributions, default first. Empty when WSL is missing.
pub fn list_distros() -> crate::Result<Vec<String>> {
    Ok(distros()?.into_iter().map(|d| d.name).collect())
}

/// Installed distributions with version and state, default first. Registry first; when it
/// has none (or fails) `wsl.exe -l -v` decides. State comes from `wsl.exe` when it answers.
pub fn distros() -> crate::Result<Vec<Distro>> {
    let from_cli = sys::verbose_list();
    let reg = sys::registry_distros();
    Ok(match (reg, from_cli) {
        (Some(reg), cli) if !reg.is_empty() => sort_default_first(
            reg.into_iter()
                .map(|d| {
                    match cli.as_ref().and_then(|c| c.iter().find(|x| x.name == d.name)) {
                        Some(x) => Distro { state: x.state, version: if x.version == 0 { d.version } else { x.version }, ..d },
                        None => d,
                    }
                })
                .collect(),
        ),
        (_, Some(cli)) => cli,
        _ => Vec::new(),
    })
}

/// What opening a saved WSL connection to `name` would find on this PC.
pub fn availability(name: &str) -> crate::Result<Availability> {
    Ok(availability_in(name, sys::wsl_present(), &distros()?))
}

#[cfg(windows)]
mod sys {
    use super::{is_valid_name, sort_default_first, Distro, DistroState, MAX_DISTROS};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

    const LXSS: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";
    /// `State` value of a registered, usable distribution (others are mid-install or -removal).
    const STATE_INSTALLED: u32 = 1;
    /// `Flags` bit set when the distribution runs as WSL 2 (`Version` is a file-system layout, not this).
    const FLAG_VM_MODE: u32 = 0x8;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn get_sz(key: HKEY, sub: &[u16], value: &str) -> Option<String> {
        let mut buf = [0u16; 260];
        let mut len = (buf.len() * 2) as u32;
        let rc = unsafe { RegGetValueW(key, sub.as_ptr(), wide(value).as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
        (rc == ERROR_SUCCESS).then(|| String::from_utf16_lossy(&buf[..(len as usize / 2).saturating_sub(1)]))
    }

    fn get_dword(key: HKEY, sub: &[u16], value: &str) -> Option<u32> {
        let mut v = 0u32;
        let mut len = 4u32;
        let rc = unsafe { RegGetValueW(key, sub.as_ptr(), wide(value).as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut v as *mut u32).cast(), &mut len) };
        (rc == ERROR_SUCCESS).then_some(v)
    }

    /// `None` when the key is absent (WSL never set up for this user).
    pub fn registry_distros() -> Option<Vec<Distro>> {
        let mut key: HKEY = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(LXSS).as_ptr(), 0, KEY_READ, &mut key) } != ERROR_SUCCESS {
            return None;
        }
        let none = wide("");
        let default = get_sz(key, &none, "DefaultDistribution");
        let mut out = Vec::new();
        for i in 0.. {
            let mut name = [0u16; 64];
            let mut len = name.len() as u32;
            let rc = unsafe { RegEnumKeyExW(key, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
            if rc != ERROR_SUCCESS || out.len() == MAX_DISTROS {
                break;
            }
            let guid = String::from_utf16_lossy(&name[..len as usize]);
            let sub = wide(&guid);
            let Some(dname) = get_sz(key, &sub, "DistributionName") else { continue };
            if !is_valid_name(&dname) {
                continue;
            }
            let state = if get_dword(key, &sub, "State").unwrap_or(STATE_INSTALLED) == STATE_INSTALLED { DistroState::Unknown } else { DistroState::Busy };
            let version = get_dword(key, &sub, "Flags").map_or(0, |f| if f & FLAG_VM_MODE != 0 { 2 } else { 1 });
            out.push(Distro { name: dname, version, is_default: default.as_deref() == Some(guid.as_str()), state });
        }
        unsafe { RegCloseKey(key) };
        Some(sort_default_first(out))
    }

    fn wsl_exe() -> std::process::Command {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = std::process::Command::new("wsl.exe");
        c.creation_flags(CREATE_NO_WINDOW);
        c
    }

    /// `None` when `wsl.exe` is missing or failed (it exits non-zero with no distributions).
    pub fn verbose_list() -> Option<Vec<Distro>> {
        let o = wsl_exe().args(["--list", "--verbose"]).output().ok()?;
        o.status.success().then(|| super::parse_verbose_list(&o.stdout))
    }

    pub fn wsl_present() -> bool {
        let system = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
        system.join("System32").join("wsl.exe").is_file() || wsl_exe().arg("--status").output().is_ok()
    }
}

#[cfg(not(windows))]
mod sys {
    use super::Distro;
    pub fn registry_distros() -> Option<Vec<Distro>> {
        None
    }
    pub fn verbose_list() -> Option<Vec<Distro>> {
        None
    }
    pub fn wsl_present() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str, bom: bool) -> Vec<u8> {
        let mut v = if bom { vec![0xFF, 0xFE] } else { vec![] };
        v.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
        v
    }

    #[test]
    fn parses_utf16_with_and_without_bom() {
        let raw = "Ubuntu-22.04\r\ndocker-desktop\r\n\r\n";
        assert_eq!(parse_distro_list(&utf16(raw, true)), vec!["Ubuntu-22.04", "docker-desktop"]);
        assert_eq!(parse_distro_list(&utf16(raw, false)), vec!["Ubuntu-22.04", "docker-desktop"]);
        assert_eq!(parse_distro_list(b"Debian\nkali-linux\n"), vec!["Debian", "kali-linux"]);
    }

    #[test]
    fn drops_names_that_could_become_options_or_shell_text() {
        let raw = "Ubuntu\r\n--exec\r\nbad name\r\nx;rm\r\nUbuntu\r\n";
        assert_eq!(parse_distro_list(&utf16(raw, true)), vec!["Ubuntu"]);
        assert!(launch_args("--exec").is_err());
        assert_eq!(launch_args("Ubuntu").unwrap(), vec!["-d", "Ubuntu", "--cd", "~"]);
    }

    #[test]
    fn empty_output_and_garbage_give_no_distros() {
        assert!(parse_distro_list(b"").is_empty());
        assert!(parse_distro_list(&utf16("\r\n", true)).is_empty());
        let many: String = (0..100).map(|i| format!("d{i}\n")).collect();
        assert_eq!(parse_distro_list(many.as_bytes()).len(), MAX_DISTROS);
    }
    #[test]
    fn verbose_list_reads_default_state_and_version() {
        let raw = "  NAME            STATE           VERSION\r\n  docker-desktop  Stopped         2\r\n* Ubuntu-24.04    Running         1\r\n  Debian          Installing      2\r\n  --evil          Stopped         2\r\n";
        let got = parse_verbose_list(&utf16(raw, false));
        assert_eq!(got.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["Ubuntu-24.04", "docker-desktop", "Debian"]);
        assert_eq!(got[0], Distro { name: "Ubuntu-24.04".into(), version: 1, is_default: true, state: DistroState::Running });
        assert_eq!(got[1].state, DistroState::Stopped);
        assert_eq!(got[2].state, DistroState::Busy);
        assert!(parse_verbose_list(b"").is_empty());
    }

    #[test]
    fn availability_covers_missing_stopped_removed_and_busy() {
        let d = |n: &str, s| Distro { name: n.into(), version: 1, is_default: false, state: s };
        let installed = [d("Ubuntu", DistroState::Stopped), d("Debian", DistroState::Busy)];
        assert_eq!(availability_in("Ubuntu", false, &installed), Availability::WslMissing);
        assert_eq!(availability_in("ubuntu", true, &installed), Availability::Ready { state: DistroState::Stopped });
        assert_eq!(availability_in("Debian", true, &installed), Availability::Busy);
        assert_eq!(availability_in("Kali", true, &installed), Availability::Removed { installed: vec!["Ubuntu".into(), "Debian".into()] });
        assert_eq!(availability_in("Kali", true, &[]), Availability::Removed { installed: vec![] });
    }
    /// Real PC: set `BASTION_TEST_WSL_DISTRO` to an installed distribution to require it.
    #[cfg(windows)]
    #[test]
    fn live_detection_agrees_with_wsl_and_launches() {
        let t = std::time::Instant::now();
        let found = distros().unwrap();
        eprintln!("detected in {:?}: {found:?}", t.elapsed());
        assert!(found.iter().all(|d| is_valid_name(&d.name)));
        assert_eq!(availability("No-Such-Distro-xyz").unwrap(), if sys::wsl_present() { Availability::Removed { installed: found.iter().map(|d| d.name.clone()).collect() } } else { Availability::WslMissing });
        let Ok(want) = std::env::var("BASTION_TEST_WSL_DISTRO") else { return };
        let d = found.iter().find(|d| d.name == want).expect("distro detected");
        if let Ok(v) = std::env::var("BASTION_TEST_WSL_VERSION") {
            assert_eq!(d.version.to_string(), v, "WSL version");
        }
        let reg = sys::registry_distros().unwrap();
        assert_eq!(reg.iter().find(|r| r.name == want).unwrap().version, d.version, "registry Flags agree with wsl -l -v");
        assert!(matches!(availability(&want).unwrap(), Availability::Ready { .. }));
        let mut args = launch_args(&want).unwrap();
        args.extend(["--".into(), "echo".into(), "bastion-wsl-ok".into()]);
        let out = std::process::Command::new("wsl.exe").args(&args).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("bastion-wsl-ok"), "{out:?}");
    }
}
