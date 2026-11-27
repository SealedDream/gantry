//! Keyboard shortcuts shared by both frontends: the commands that can have one, their defaults,
//! validation, conflict detection and the per-user overrides in `shortcuts.json` next to the
//! library.
//!
//! Chords are platform-neutral: `primary` is ⌘ on macOS and Ctrl on Windows, so the core never
//! holds a platform's shortcut text. A chord is stored as `primary+shift+p` (modifiers in a fixed
//! order, then one key); each frontend renders it in its own notation. Command ids are the targets
//! the frontends already route (`quick-connect`, `split-right`, `tab:3`, …).
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Windows,
}

impl Platform {
    pub fn parse(s: &str) -> Result<Platform> {
        match s {
            "macos" => Ok(Platform::MacOs),
            "windows" => Ok(Platform::Windows),
            _ => Err(CoreError::Invalid(format!("unknown platform `{s}`"))),
        }
    }
}

/// Named keys besides letters, digits and the punctuation in `PUNCTUATION`.
const NAMED_KEYS: &[&str] = &[
    "return", "tab", "escape", "space", "delete", "up", "down", "left", "right", "home", "end", "pageup", "pagedown",
];
const PUNCTUATION: &str = "`-=[]\\;',./";

fn is_function_key(key: &str) -> bool {
    key.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()).is_some_and(|n| (1..=12).contains(&n))
}

fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => c.is_ascii_lowercase() || c.is_ascii_digit() || PUNCTUATION.contains(c),
        _ => NAMED_KEYS.contains(&key) || is_function_key(key),
    }
}

/// One key with modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Chord {
    pub primary: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub key: String,
}

impl Chord {
    /// Parse `primary+shift+p` (modifiers in any order, each once, key last).
    pub fn parse(s: &str) -> Result<Chord> {
        let bad = || CoreError::Invalid(format!("`{s}` is not a shortcut"));
        let s = s.trim().to_lowercase();
        // `+` separates parts, so the key is everything after the last one (never `+` itself).
        let (mods, key) = s.rsplit_once('+').unwrap_or(("", s.as_str()));
        if !is_valid_key(key) {
            return Err(bad());
        }
        let mut chord = Chord { primary: false, ctrl: false, alt: false, shift: false, key: key.to_string() };
        for m in mods.split('+').filter(|m| !m.is_empty()) {
            let flag = match m {
                "primary" => &mut chord.primary,
                "ctrl" => &mut chord.ctrl,
                "alt" => &mut chord.alt,
                "shift" => &mut chord.shift,
                _ => return Err(bad()),
            };
            if *flag {
                return Err(bad());
            }
            *flag = true;
        }
        Ok(chord)
    }

    /// The physical keys on `platform`: Ctrl is the primary modifier on Windows.
    fn on(&self, platform: Platform) -> Chord {
        match platform {
            Platform::MacOs => self.clone(),
            Platform::Windows => Chord { primary: false, ctrl: self.ctrl || self.primary, ..self.clone() },
        }
    }

    /// A shortcut must not swallow typing: it needs ⌘/Ctrl/Alt, or is a function key.
    fn check_bindable(&self) -> Result<()> {
        if self.primary || self.ctrl || self.alt || is_function_key(&self.key) {
            Ok(())
        } else {
            Err(CoreError::Invalid(format!("`{self}` needs a modifier other than Shift")))
        }
    }
}

impl fmt::Display for Chord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (on, name) in [(self.primary, "primary"), (self.ctrl, "ctrl"), (self.alt, "alt"), (self.shift, "shift")] {
            if on {
                write!(f, "{name}+")?;
            }
        }
        f.write_str(&self.key)
    }
}

/// Chords the system or standard editing owns on each platform, with what they do.
fn reserved(platform: Platform) -> &'static [(&'static str, &'static str)] {
    match platform {
        Platform::MacOs => &[
            ("primary+q", "Quit"),
            ("primary+w", "Close Window"),
            ("primary+,", "Settings"),
            ("primary+h", "Hide"),
            ("primary+m", "Minimize"),
            ("primary+c", "Copy"),
            ("primary+v", "Paste"),
            ("primary+x", "Cut"),
            ("primary+a", "Select All"),
            ("primary+z", "Undo"),
            ("primary+shift+z", "Redo"),
            ("primary+tab", "Switch Apps"),
            ("primary+`", "Switch Windows"),
            ("primary+space", "Spotlight"),
            ("primary+=", "Zoom In"),
            ("primary+-", "Zoom Out"),
            ("primary+0", "Actual Size"),
        ],
        Platform::Windows => &[
            ("alt+f4", "Close Window"),
            ("ctrl+c", "Copy"),
            ("ctrl+v", "Paste"),
            ("ctrl+x", "Cut"),
            ("ctrl+a", "Select All"),
            ("ctrl+z", "Undo"),
            ("ctrl+y", "Redo"),
            ("alt+tab", "Switch Apps"),
            ("ctrl+escape", "Start"),
        ],
    }
}

/// Sections of the Keyboard page, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    File,
    View,
    Session,
    Terminal,
    Workspace,
}

impl Group {
    pub fn id(self) -> &'static str {
        match self {
            Group::File => "file",
            Group::View => "view",
            Group::Session => "session",
            Group::Terminal => "terminal",
            Group::Workspace => "workspace",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Group::File => "File",
            Group::View => "View",
            Group::Session => "Session",
            Group::Terminal => "Terminal",
            Group::Workspace => "Workspace",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShortcutDef {
    /// The command the frontend runs (its router target).
    pub id: String,
    pub label: String,
    pub group: Group,
    /// Stored form of the default chord; empty for none.
    pub default: String,
    /// Windows default when it differs (where the macOS chord would collide once ⌘ and Ctrl
    /// are the same key).
    pub windows_default: Option<&'static str>,
    pub keywords: &'static [&'static str],
}

impl ShortcutDef {
    pub fn default_on(&self, platform: Platform) -> &str {
        match (platform, self.windows_default) {
            (Platform::Windows, Some(w)) => w,
            _ => &self.default,
        }
    }

    fn matches(&self, terms: &[String]) -> bool {
        let hay = format!("{} {} {}", self.label, self.group.label(), self.keywords.join(" ")).to_lowercase();
        terms.iter().all(|t| hay.contains(t.as_str()))
    }
}

/// Every command that can have a shortcut, in display order within its group.
pub fn definitions() -> Vec<ShortcutDef> {
    use Group::*;
    let d = |id: &str, group, label: &str, default: &str, keywords| ShortcutDef {
        id: id.into(),
        label: label.into(),
        group,
        default: default.into(),
        windows_default: None,
        keywords,
    };
    let mut defs = vec![
        d("add", File, "New Connection", "primary+n", &["add", "create"]),
        d("new-folder", File, "New Folder", "primary+shift+n", &["add", "create", "group"]),
        d("quick-connect", File, "Quick Connect", "primary+l", &["open", "address", "host"]),
        d("palette", File, "Command Palette", "primary+shift+p", &["search", "run", "commands"]),
        d("local-shell", File, "New Local Shell", "primary+alt+t", &["terminal", "console"]),
        d("focus-search", View, "Filter Connections", "primary+alt+f", &["search", "find", "tree"]),
        ShortcutDef { windows_default: Some("ctrl+alt+n"), ..d("toggle-library", View, "Show or Hide Library", "primary+ctrl+s", &["sidebar", "navigation", "tree", "panel", "collapse"]) },
        // Whole-window zoom; Windows only for now (macOS keeps ⌘= for terminal text). Saved as `appearance.zoom`.
        ShortcutDef { windows_default: Some("ctrl+="), ..d("ui-zoom-in", View, "Zoom In", "", &["zoom", "scale", "bigger", "interface"]) },
        ShortcutDef { windows_default: Some("ctrl+-"), ..d("ui-zoom-out", View, "Zoom Out", "", &["zoom", "scale", "smaller", "interface"]) },
        ShortcutDef { windows_default: Some("ctrl+0"), ..d("ui-zoom-reset", View, "Actual Size", "", &["zoom", "scale", "reset", "interface"]) },
        d("toggle-inspector", View, "Show or Hide Inspector", "primary+alt+i", &["details", "properties", "panel"]),
        d("toggle-files-panel", View, "Show or Hide File Panel", "primary+shift+b", &["sftp", "files", "transfer", "panel"]),
        d("credential-manager", View, "Credential Manager", "primary+shift+k", &["passwords", "keys", "vault"]),
        d("activity", View, "Activity", "primary+alt+a", &["history", "sessions", "log"]),
        d("audit-log", View, "Audit Log", "primary+alt+u", &["security", "events", "log"]),
        ShortcutDef { windows_default: Some("ctrl+shift+l"), ..d("lock-credentials", View, "Lock Credentials", "primary+ctrl+l", &["vault", "vaultwarden"]) },
        d("default-action", Session, "Connect", "primary+return", &["open", "default"]),
        // On Windows Ctrl+D is end-of-input for the program in a focused terminal, where splitting happens; Windows
        // Terminal's Alt+Shift+= and Alt+Shift+- reach the app there.
        ShortcutDef { windows_default: Some("alt+shift+="), ..d("split-right", Session, "Split Right", "primary+d", &["pane", "vertical"]) },
        ShortcutDef { windows_default: Some("alt+shift+-"), ..d("split-down", Session, "Split Down", "primary+shift+d", &["pane", "horizontal"]) },
        // In a focused terminal Ctrl+F, Ctrl+C and Ctrl+V belong to the program, so Windows adds Shift (as Windows
        // Terminal does). macOS copies and pastes with its Edit menu; these commands have no Mac default.
        ShortcutDef { windows_default: Some("ctrl+shift+c"), ..d("copy", Session, "Copy Selection", "", &["clipboard", "terminal"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+v"), ..d("paste", Session, "Paste", "", &["clipboard", "terminal"]) },
        d("next-tab", Session, "Show Next Tab", "ctrl+tab", &["switch", "cycle"]),
        d("previous-tab", Session, "Show Previous Tab", "ctrl+shift+tab", &["switch", "cycle"]),
        d("tab-overview", Session, "Show Tab Overview", "primary+shift+\\", &["tabs", "grid", "previews", "expose", "switch"]),
        d("all-tabs", Session, "Show All Tabs", "primary+shift+a", &["tabs", "search", "overflow", "list"]),
        d("focus-pane-left", Session, "Focus Pane Left", "primary+alt+left", &["split", "move"]),
        d("focus-pane-right", Session, "Focus Pane Right", "primary+alt+right", &["split", "move"]),
        d("focus-pane-up", Session, "Focus Pane Above", "primary+alt+up", &["split", "move"]),
        d("focus-pane-down", Session, "Focus Pane Below", "primary+alt+down", &["split", "move"]),
        d("next-pane", Session, "Focus Next Pane", "primary+]", &["split", "cycle"]),
        d("previous-pane", Session, "Focus Previous Pane", "primary+[", &["split", "cycle"]),
    ];
    defs.extend([
        // Terminal commands act on the focused terminal; text zoom is per tab and never saved. Windows: Ctrl+= / - / 0
        // zoom the whole window, so terminal text takes Ctrl+Shift. macOS: ⌘= ⌘- ⌘0 zoom the whole UI (View menu,
        // Native Mac), so terminal text takes Shift too.
        ShortcutDef { windows_default: Some("ctrl+shift+="), ..d("zoom-in", Terminal, "Bigger Text", "primary+shift+=", &["zoom", "font", "size", "larger"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+-"), ..d("zoom-out", Terminal, "Smaller Text", "primary+shift+-", &["zoom", "font", "size"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+0"), ..d("zoom-reset", Terminal, "Actual Size", "primary+shift+0", &["zoom", "font", "size", "reset"]) },
        ShortcutDef { windows_default: Some(""), ..d("clear-scrollback", Terminal, "Clear Scrollback", "primary+k", &["history", "buffer", "clear", "reset"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+f"), ..d("find", Terminal, "Find…", "primary+f", &["search", "scrollback"]) },
        ShortcutDef { windows_default: Some("f3"), ..d("find-next", Terminal, "Find Next", "primary+g", &["search"]) },
        ShortcutDef { windows_default: Some("shift+f3"), ..d("find-previous", Terminal, "Find Previous", "primary+shift+g", &["search"]) },
        // Shell-integration marks (OSC 133). Windows: Ctrl+Alt+arrows rotate the screen on many PCs, so Shift too.
        ShortcutDef { windows_default: Some("ctrl+alt+shift+up"), ..d("previous-prompt", Terminal, "Previous Prompt", "primary+up", &["mark", "scroll", "command", "osc 133"]) },
        ShortcutDef { windows_default: Some("ctrl+alt+shift+down"), ..d("next-prompt", Terminal, "Next Prompt", "primary+down", &["mark", "scroll", "command", "osc 133"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+w"), ..d("close-pane", Terminal, "Close Pane", "primary+alt+w", &["split", "close", "terminal"]) },
        ShortcutDef { windows_default: Some("ctrl+shift+."), ..d("send-break", Terminal, "Send Break", "primary+.", &["interrupt", "ctrl+c", "cancel", "stop"]) },
        d("next-tab-alt", Session, "Show Next Tab (Alternate)", "primary+shift+]", &["switch", "cycle"]),
        d("previous-tab-alt", Session, "Show Previous Tab (Alternate)", "primary+shift+[", &["switch", "cycle"]),
    ]);
    for n in 1..=9 {
        defs.push(d(&format!("tab:{n}"), Session, &format!("Show Tab {n}"), &format!("primary+{n}"), &["switch"]));
    }
    defs.push(d("save-workspace", Workspace, "Save Current Layout", "primary+shift+s", &["layout", "tabs"]));
    defs.push(d("workspace-manager", Workspace, "Manage Workspaces", "", &["layout", "open", "rename"]));
    defs
}

pub fn definition(id: &str) -> Option<ShortcutDef> {
    definitions().into_iter().find(|d| d.id == id)
}

/// Commands whose label, group or keywords contain every word of `query`.
pub fn search(query: &str) -> Vec<ShortcutDef> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    definitions().into_iter().filter(|d| d.matches(&terms)).collect()
}

/// What a chord would collide with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    /// Another command (`id`, `label`) uses it.
    Command { id: String, label: String },
    /// The system or standard editing owns it (`label` says what it does).
    Reserved { label: String },
}

/// Per-user overrides by command id; an empty value removes the default. Unknown ids are kept (a
/// newer version may have written them).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Shortcuts {
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
}

impl Shortcuts {
    /// The chord for `id` on `platform`: the override when it is still valid, else the default.
    pub fn chord(&self, id: &str, platform: Platform) -> Option<Chord> {
        let def = definition(id)?;
        let stored = match self.bindings.get(id) {
            Some(v) if v.is_empty() => return None,
            Some(v) if Chord::parse(v).is_ok_and(|c| c.check_bindable().is_ok()) => v.as_str(),
            _ => def.default_on(platform),
        };
        Chord::parse(stored).ok()
    }

    pub fn is_default(&self, id: &str) -> bool {
        !self.bindings.contains_key(id)
    }

    /// What `chord` would collide with if bound to `id` on `platform`.
    pub fn conflict(&self, id: &str, chord: &Chord, platform: Platform) -> Option<Conflict> {
        let physical = chord.on(platform);
        if let Some((_, label)) = reserved(platform).iter().find(|(r, _)| Chord::parse(r).is_ok_and(|r| r.on(platform) == physical)) {
            return Some(Conflict::Reserved { label: label.to_string() });
        }
        definitions()
            .into_iter()
            .filter(|d| d.id != id)
            .find(|d| self.chord(&d.id, platform).is_some_and(|c| c.on(platform) == physical))
            .map(|d| Conflict::Command { id: d.id, label: d.label })
    }

    /// Bind `chord` (`None` removes the shortcut). A reserved chord is refused; one used by
    /// another command is refused unless `replace`, which removes it from that command.
    pub fn set(&mut self, id: &str, chord: Option<&str>, platform: Platform, replace: bool) -> Result<()> {
        let def = definition(id).ok_or_else(|| CoreError::NotFound(format!("command `{id}`")))?;
        let Some(text) = chord else {
            self.store(&def, String::new(), platform);
            return Ok(());
        };
        let chord = Chord::parse(text)?;
        chord.check_bindable()?;
        match self.conflict(id, &chord, platform) {
            Some(Conflict::Reserved { label }) => return Err(CoreError::Invalid(format!("`{chord}` is reserved for {label}"))),
            Some(Conflict::Command { id: other, label }) if !replace => {
                return Err(CoreError::Invalid(format!("`{chord}` is already used by {label} ({other})")));
            }
            Some(Conflict::Command { id: other, .. }) => {
                let other = definition(&other).expect("conflict names a defined command");
                self.store(&other, String::new(), platform);
            }
            None => {}
        }
        self.store(&def, chord.to_string(), platform);
        Ok(())
    }

    pub fn reset(&mut self, id: &str) {
        self.bindings.remove(id);
    }

    pub fn reset_all(&mut self) {
        self.bindings.clear();
    }

    /// Pairs of command ids sharing one chord on `platform` (a hand-edited file can hold them);
    /// the frontend binds only the first of each pair.
    pub fn conflicts(&self, platform: Platform) -> Vec<(String, String)> {
        let bound: Vec<(String, Chord)> = definitions()
            .into_iter()
            .filter_map(|d| self.chord(&d.id, platform).map(|c| (d.id, c.on(platform))))
            .collect();
        let mut pairs = Vec::new();
        for (i, (a, ca)) in bound.iter().enumerate() {
            if let Some((b, _)) = bound[..i].iter().find(|(_, cb)| cb == ca) {
                pairs.push((b.clone(), a.clone()));
            }
        }
        pairs
    }

    fn store(&mut self, def: &ShortcutDef, value: String, platform: Platform) {
        if value == def.default_on(platform) {
            self.bindings.remove(&def.id);
        } else {
            self.bindings.insert(def.id.clone(), value);
        }
    }
}

pub struct ShortcutsStore {
    path: PathBuf,
}

impl ShortcutsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ShortcutsStore { path: path.into() }
    }

    /// Defaults when the file is missing; a damaged file is an error, never silently replaced.
    pub fn load(&self) -> Result<Shortcuts> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| CoreError::Invalid(format!("shortcuts.json: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Shortcuts::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, shortcuts: &Shortcuts) -> Result<()> {
        let json = serde_json::to_vec_pretty(shortcuts).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Platform::*;

    #[test]
    fn chords_parse_to_one_canonical_form() {
        assert_eq!(Chord::parse("Shift+Primary+P").unwrap().to_string(), "primary+shift+p");
        assert_eq!(Chord::parse("ctrl+shift+tab").unwrap().to_string(), "ctrl+shift+tab");
        assert_eq!(Chord::parse("primary+,").unwrap().key, ",");
        assert_eq!(Chord::parse("f5").unwrap().to_string(), "f5");
        for bad in ["", "primary+", "primary+primary+k", "cmd+k", "primary+ab", "primary+f13", "hyper+k"] {
            assert!(Chord::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults_are_valid_and_free_of_conflicts_on_both_platforms() {
        let s = Shortcuts::default();
        for d in definitions() {
            for p in [MacOs, Windows] {
                if !d.default_on(p).is_empty() {
                    let c = Chord::parse(d.default_on(p)).unwrap();
                    c.check_bindable().unwrap();
                    assert_eq!(s.conflict(&d.id, &c, p), None, "{} on {p:?}", d.id);
                }
            }
        }
        assert!(s.conflicts(MacOs).is_empty() && s.conflicts(Windows).is_empty());
    }

    #[test]
    fn set_refuses_reserved_and_taken_chords_unless_replacing() {
        let mut s = Shortcuts::default();
        assert!(s.set("quick-connect", Some("primary+q"), MacOs, true).unwrap_err().to_string().contains("Quit"));
        assert!(s.set("quick-connect", Some("shift+k"), MacOs, false).is_err(), "Shift alone would swallow typing");
        let err = s.set("quick-connect", Some("primary+d"), MacOs, false).unwrap_err().to_string();
        assert!(err.contains("Split Right"), "{err}");
        assert_eq!(s.chord("quick-connect", MacOs).unwrap().to_string(), "primary+l", "refusal changes nothing");

        s.set("quick-connect", Some("primary+d"), MacOs, true).unwrap();
        assert_eq!(s.chord("quick-connect", MacOs).unwrap().to_string(), "primary+d");
        assert_eq!(s.chord("split-right", MacOs), None, "replaced command loses its shortcut");
        assert_eq!(s.bindings.get("split-right").map(String::as_str), Some(""));
    }

    #[test]
    fn primary_and_ctrl_collide_only_on_windows() {
        let mut s = Shortcuts::default();
        let c = Chord::parse("ctrl+l").unwrap();
        assert_eq!(s.conflict("palette", &c, MacOs), None);
        assert!(matches!(s.conflict("palette", &c, Windows), Some(Conflict::Command { id, .. }) if id == "quick-connect"));
        s.set("palette", Some("ctrl+l"), MacOs, false).unwrap();
        assert_eq!(s.conflicts(Windows), vec![("quick-connect".to_string(), "palette".to_string())]);
        assert!(s.conflicts(MacOs).is_empty());
    }

    #[test]
    fn default_values_are_not_stored_and_reset_restores() {
        let mut s = Shortcuts::default();
        s.set("palette", Some("primary+alt+j"), MacOs, false).unwrap();
        assert!(!s.is_default("palette"));
        s.set("palette", Some("primary+shift+p"), MacOs, false).unwrap();
        assert!(s.is_default("palette"));
        s.set("palette", None, MacOs, false).unwrap();
        assert_eq!(s.chord("palette", MacOs), None);
        s.reset("palette");
        assert_eq!(s.chord("palette", MacOs).unwrap().to_string(), "primary+shift+p");
        s.set("workspace-manager", Some("primary+alt+j"), MacOs, false).unwrap();
        s.reset_all();
        assert_eq!(s, Shortcuts::default());
    }

    #[test]
    fn windows_defaults_avoid_chords_that_collapse_onto_ctrl() {
        let s = Shortcuts::default();
        assert_eq!(s.chord("lock-credentials", MacOs).unwrap().to_string(), "primary+ctrl+l");
        assert_eq!(s.chord("lock-credentials", Windows).unwrap().to_string(), "ctrl+shift+l");
        let mut w = Shortcuts::default();
        w.set("lock-credentials", Some("ctrl+shift+l"), Windows, false).unwrap();
        assert!(w.is_default("lock-credentials"), "the Windows default is not stored on Windows");
        // A terminal keeps plain Ctrl+letter (Ctrl+D ends the shell), so splits default to Windows Terminal's keys there.
        assert_eq!(s.chord("split-right", Windows).unwrap().to_string(), "alt+shift+=");
        assert_eq!(s.chord("split-down", Windows).unwrap().to_string(), "alt+shift+-");
        assert_eq!(s.chord("split-right", MacOs).unwrap().to_string(), "primary+d");
        assert!(s.conflicts(Windows).is_empty(), "no other Windows command uses them: {:?}", s.conflicts(Windows));
        // Terminal copy, paste and find add Shift on Windows; Ctrl+C and Ctrl+F reach the program.
        assert_eq!(s.chord("copy", Windows).unwrap().to_string(), "ctrl+shift+c");
        assert_eq!(s.chord("paste", Windows).unwrap().to_string(), "ctrl+shift+v");
        assert_eq!(s.chord("find", Windows).unwrap().to_string(), "ctrl+shift+f");
        assert_eq!(s.chord("copy", MacOs), None, "the Edit menu copies on macOS");
        // Windows: Ctrl+= / - / 0 zoom the whole window and Ctrl+Shift the terminal text; macOS zooms its UI in the View menu.
        assert_eq!(s.chord("ui-zoom-in", Windows).unwrap().to_string(), "ctrl+=");
        assert_eq!(s.chord("ui-zoom-reset", Windows).unwrap().to_string(), "ctrl+0");
        assert_eq!(s.chord("zoom-in", Windows).unwrap().to_string(), "ctrl+shift+=");
        assert_eq!(s.chord("zoom-out", Windows).unwrap().to_string(), "ctrl+shift+-");
        assert_eq!(s.chord("zoom-in", MacOs).unwrap().to_string(), "primary+shift+=", "⌘= zooms the Mac UI");
        assert_eq!(s.chord("ui-zoom-in", MacOs), None);
    }

    #[test]
    fn damaged_override_falls_back_to_default() {
        let mut s = Shortcuts::default();
        s.bindings.insert("palette".into(), "cmd+k".into());
        s.bindings.insert("future-command".into(), "primary+j".into());
        assert_eq!(s.chord("palette", MacOs).unwrap().to_string(), "primary+shift+p");
        assert_eq!(s.chord("future-command", MacOs), None);
    }

    #[test]
    fn search_matches_labels_groups_and_keywords() {
        let ids = |q: &str| search(q).into_iter().map(|d| d.id).collect::<Vec<_>>();
        assert_eq!(ids("palette"), vec!["palette"]);
        assert!(ids("split").contains(&"split-down".to_string()));
        assert!(ids("workspace").contains(&"workspace-manager".to_string()));
        assert_eq!(search("").len(), definitions().len());
    }

    #[test]
    fn store_round_trips_and_refuses_damaged_files() {
        let dir = std::env::temp_dir().join(format!("bastion-shortcuts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = ShortcutsStore::new(dir.join("shortcuts.json"));
        assert_eq!(store.load().unwrap(), Shortcuts::default());
        let mut s = Shortcuts::default();
        s.set("quick-connect", Some("primary+alt+j"), MacOs, false).unwrap();
        store.save(&s).unwrap();
        assert_eq!(store.load().unwrap().chord("quick-connect", MacOs).unwrap().to_string(), "primary+alt+j");
        std::fs::write(dir.join("shortcuts.json"), b"{not json").unwrap();
        assert!(store.load().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
