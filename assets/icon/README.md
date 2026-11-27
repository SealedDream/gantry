# Gantry tray icons and motion

The app icon (C Stack) lives in `docs/design/app-icon/`; generate every app icon format from there.
The old "Linked prompt" app artwork was removed (2026-11-27). This folder keeps only the tray glyphs:

| File | Use |
|---|---|
| `tray-light.svg` | 16 px menu-bar / tray icon for light bars (black). On macOS use it as the template image. |
| `tray-dark.svg` | Same for dark taskbars / trays (white). |

## Motion (chosen with the logo)

UI motion style is **Native spring**: 300 ms, `cubic-bezier(.32,.72,0,1)`, 12 px travel, dialogs
scale from 0.96. Applies to left-panel collapse/auto-hide, tab open/close, tab-group collapse,
dialog present and toast. With reduce motion on, drop movement and scaling and use a 100 ms fade.
Transitions only, so idle CPU stays at zero. Native Windows exception (WIN-SHELL-LEAK): a dialog shown
while a session tab is in view appears without its entrance, because WinUI's compositor kept memory
from every animated dialog card over a session.
