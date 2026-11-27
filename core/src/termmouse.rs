//! xterm mouse reporting: turns a click, drag or wheel on a cell into the bytes a program that
//! enabled mouse mode (DECSET 1000/1002/1003, SGR 1006) expects. Pure, so every UI shares it.
use alacritty_terminal::term::TermMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    /// Motion with no button held (any-event tracking only).
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseAction {
    Press,
    Release,
    Motion,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MouseMods {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

/// Largest 1-based coordinate the legacy X10 encoding can carry in one byte (255 - 32).
const X10_MAX_COORD: u16 = 223;

/// Whether `mode` asks for any mouse reports at all; UIs keep local selection otherwise.
pub fn reporting(mode: TermMode) -> bool {
    mode.intersects(TermMode::MOUSE_MODE)
}

/// The report for one mouse event at a 0-based `row`/`col`, or `None` when the program's mode
/// does not want it (or X10 cannot encode the position).
pub fn encode(mode: TermMode, button: MouseButton, action: MouseAction, row: u16, col: u16, mods: MouseMods) -> Option<Vec<u8>> {
    if !wanted(mode, button, action) {
        return None;
    }
    let base: u16 = match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
        MouseButton::None => 3,
        MouseButton::WheelUp => 64,
        MouseButton::WheelDown => 65,
    };
    let motion = if action == MouseAction::Motion { 32 } else { 0 };
    let modifiers = u16::from(mods.shift) * 4 + u16::from(mods.alt) * 8 + u16::from(mods.ctrl) * 16;
    let (x, y) = (col.saturating_add(1), row.saturating_add(1));
    if mode.contains(TermMode::SGR_MOUSE) {
        let final_byte = if action == MouseAction::Release { 'm' } else { 'M' };
        return Some(format!("\x1b[<{};{x};{y}{final_byte}", base + motion + modifiers).into_bytes());
    }
    // X10 cannot say which button was released, so every release is button 3.
    let code = if action == MouseAction::Release { 3 } else { base } + motion + modifiers;
    if x > X10_MAX_COORD || y > X10_MAX_COORD {
        return None;
    }
    Some(vec![0x1b, b'[', b'M', (32 + code) as u8, (32 + x) as u8, (32 + y) as u8])
}

fn wanted(mode: TermMode, button: MouseButton, action: MouseAction) -> bool {
    let wheel = matches!(button, MouseButton::WheelUp | MouseButton::WheelDown);
    match action {
        _ if !reporting(mode) => false,
        MouseAction::Release if wheel => false,
        MouseAction::Press | MouseAction::Release => button != MouseButton::None,
        MouseAction::Motion if button == MouseButton::None => mode.contains(TermMode::MOUSE_MOTION),
        MouseAction::Motion => !wheel && mode.intersects(TermMode::MOUSE_DRAG | TermMode::MOUSE_MOTION),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: MouseMods = MouseMods { shift: false, alt: false, ctrl: false };
    fn sgr(m: TermMode) -> TermMode {
        m | TermMode::SGR_MOUSE
    }

    #[test]
    fn nothing_is_reported_without_mouse_mode() {
        assert!(!reporting(TermMode::empty()));
        assert_eq!(encode(TermMode::SGR_MOUSE, MouseButton::Left, MouseAction::Press, 0, 0, NONE), None);
    }

    #[test]
    fn sgr_press_and_release_name_the_button() {
        let m = sgr(TermMode::MOUSE_REPORT_CLICK);
        assert_eq!(encode(m, MouseButton::Left, MouseAction::Press, 4, 9, NONE).unwrap(), b"\x1b[<0;10;5M");
        assert_eq!(encode(m, MouseButton::Right, MouseAction::Release, 4, 9, NONE).unwrap(), b"\x1b[<2;10;5m");
    }

    #[test]
    fn x10_release_is_button_three() {
        let m = TermMode::MOUSE_REPORT_CLICK;
        assert_eq!(encode(m, MouseButton::Left, MouseAction::Press, 0, 0, NONE).unwrap(), vec![0x1b, b'[', b'M', 32, 33, 33]);
        assert_eq!(encode(m, MouseButton::Left, MouseAction::Release, 0, 0, NONE).unwrap(), vec![0x1b, b'[', b'M', 35, 33, 33]);
    }

    #[test]
    fn x10_drops_positions_it_cannot_encode() {
        assert_eq!(encode(TermMode::MOUSE_REPORT_CLICK, MouseButton::Left, MouseAction::Press, 0, 300, NONE), None);
        assert!(encode(sgr(TermMode::MOUSE_REPORT_CLICK), MouseButton::Left, MouseAction::Press, 0, 300, NONE).is_some());
    }

    #[test]
    fn drag_needs_button_event_or_any_event_tracking() {
        assert_eq!(encode(sgr(TermMode::MOUSE_REPORT_CLICK), MouseButton::Left, MouseAction::Motion, 1, 1, NONE), None);
        assert_eq!(encode(sgr(TermMode::MOUSE_DRAG), MouseButton::Left, MouseAction::Motion, 1, 1, NONE).unwrap(), b"\x1b[<32;2;2M");
        assert_eq!(encode(sgr(TermMode::MOUSE_DRAG), MouseButton::None, MouseAction::Motion, 1, 1, NONE), None);
        assert_eq!(encode(sgr(TermMode::MOUSE_MOTION), MouseButton::None, MouseAction::Motion, 1, 1, NONE).unwrap(), b"\x1b[<35;2;2M");
    }

    #[test]
    fn wheel_reports_press_only() {
        let m = sgr(TermMode::MOUSE_REPORT_CLICK);
        assert_eq!(encode(m, MouseButton::WheelUp, MouseAction::Press, 0, 0, NONE).unwrap(), b"\x1b[<64;1;1M");
        assert_eq!(encode(m, MouseButton::WheelDown, MouseAction::Press, 0, 0, NONE).unwrap(), b"\x1b[<65;1;1M");
        assert_eq!(encode(m, MouseButton::WheelUp, MouseAction::Release, 0, 0, NONE), None);
    }

    #[test]
    fn modifiers_add_to_the_button_code() {
        let mods = MouseMods { shift: true, alt: true, ctrl: true };
        assert_eq!(encode(sgr(TermMode::MOUSE_REPORT_CLICK), MouseButton::Left, MouseAction::Press, 0, 0, mods).unwrap(), b"\x1b[<28;1;1M");
    }
}
