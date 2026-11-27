# Gantry design system

One product on two platforms: the core owns what must match (objects, actions, icon ids, colour
tokens, density metrics), each app owns native rendering (AppKit/SwiftUI on macOS, WinUI 3 on Windows).

## Shared definitions (core)

| What | Where | Used by |
|---|---|---|
| Object kinds, actions, availability, confirmations, default action | `core/src/actions.rs` | macOS `Commands`, menus, inspector; Windows via ABI 3 `bastion_library_menu_json` |
| Icon ids, full labels, tint roles | `core/src/icons.rs` | macOS `Icons` (SF Symbols); Windows to map to Segoe Fluent Icons |
| Colour tokens (dark/light), spacing, density metrics, inspector widths | `core/src/theme.rs` | macOS `Icons.color`, `DS`, `themeMetrics`; Windows via `bastion_theme_colors_json` |
| Persisted view state (expansion, inspector visibility, double-click) | `core/src/uistate.rs` (`ui-state.json`) | macOS `TreeStateModel` |

Shortcuts: the core (`shortcuts.rs`) owns the command list, defaults, reserved chords and conflict
rules in a neutral form (`primary` = ⌘ on macOS, Ctrl on Windows); each frontend renders and
records chords in its own notation, so no platform key strings live in the core or reach the UI
(refusals are worded by the frontend: "⌘Q is reserved for Quit."). Overrides live in
`shortcuts.json` next to `settings.json`. Registry actions themselves carry no shortcuts.

## Settings, sources, empty states (M3)

- Settings rows come from `core/src/settings.rs`: label, one-line help under it (also the tooltip), control on the trailing edge. Links (pages the frontend provides) end in a chevron. No paragraphs; a setting that cannot take effect in this build is not defined or not shown (`requires`).
- Windows with a source list (Settings, Credential Manager) put the selected page's name in the window title and its status in the subtitle; actions go in the toolbar. No second header strip under the toolbar.
- `EmptyState`: subtle SF Symbol (28 pt light, tertiary), short title, one line, a primary action (default button) and at most one secondary. Used for the empty library, no open sessions, no saved workspaces and the Credential Manager sources.

## Toolbar, palette, dialogs (M5)
- The toolbar is composed per column: library changes over the sidebar, session context and actions over the canvas, window-level commands (Settings, inspector toggle) over the inspector. The window title is hidden on macOS 15+; the workspace menu names the context. Every item fits at the default 900 pt window; fix overflow by moving items between columns, never by shrinking controls.
- Toolbar items carry no key equivalents; shortcuts live in the menu bar (File, View, Session, Workspace) and tooltips name the configured keys (`ShortcutsModel.help`). Settings › Keyboard: one grouped form, a filter field with Restore Defaults beside it, rows with the label on the leading edge and a 104 pt recorder button (keys, or "None" in secondary); a changed row gets a borderless ↩ restore; a refusal shows as one red caption line under the filter; taking a chord from another command is a confirmation dialog naming it. Menu bar items have no `.disabled` state (AppKit would match a stale one); handlers ignore what does not apply.
- Command palette: 560 pt sheet, plain search field, 26 pt rows (symbol, title, right-aligned shortcut or section), accent at 18 % for the highlight; ↑/↓, Return, Escape. Ranking is the core's (`palette.rs`), so Windows will order results the same way.
- Registry items with choices (Add to Workspace) are submenus in every menu (tree, Connect ▾, inspector ⋯): saved workspaces with a checkmark where the connection already is (disabled), a divider, New Workspace…
- Name dialogs (save layout, rename) are one field plus a one-line caption that says what will happen ("2 sessions · 1 local or Quick Connect not saved · replaces “Ops”"); destructive deletes use a confirmation dialog.

## Selection and accent

- The accent (Settings › Appearance) colours selections in the library tree, primary buttons, toggles, segmented controls and focus rings. The tree is AppKit, out of SwiftUI's `.tint`, so its rows draw the selection themselves (`AccentRowView`: the accent while the tree has focus in the key window, the system's unemphasized fill otherwise, source-list shape: 10 pt inset, 5 pt radius). SwiftUI sidebars (Settings, Credential Manager) keep the system selection.
- Property editor choices use a pop-up, flags a small switch; both sit where the text field would, so the label column and help line stay aligned.

## Colour

Surfaces and text stay native (macOS materials and label colours; WinUI theme resources), so dark,
light and high-contrast modes keep working. Colour carries meaning only:

- **Object tints** (`icon.*`): one hue per family, not per row: terminals green, remote desktops blue,
  VNC violet, web orange, file transfer teal, legacy protocols grey, infrastructure sky, folders
  muted steel. Each has a dark and a light value tuned for contrast on the native sidebar.
- **Status** (`status.connected` / `connecting` / `failed`) and **favourite**: always paired with a distinct
  shape (filled dot, dotted ring, exclamation, star), so no meaning depends on colour alone.
- **Accent**: the user's accent (Appearance) for selection and primary buttons only.

## Identity colour and type roles (UI-01)

- **Identity colour.** A connection's colour is its own `host_color`, else its nearest folder's, else red when it is marked privileged (`core/src/hostcolors.rs`). The tree tints the icon with the accent and the name with the core's text-safe tone (`fg_light` / `fg_dark`, at least 4.5:1 on the window surfaces; `cargo test hostcolors` checks it). Tabs carry a 2 pt edge line, the session bar a 2 pt strip and the word "Production" for a privileged host. With Increase Contrast or a high-contrast theme names stay in the plain label colour; only the icon is coloured.
- **Status marks.** Filled dot: connected. Dotted ring: connecting (static). Warning mark: last attempt failed. A collapsed folder shows `connected/total` and a dot. Every mark has a shape and a tooltip, never colour alone.
- **Type roles.**

| Role | Mac | Windows | Use |
|---|---|---|---|
| Section label | small system font, semibold, secondary colour | Caption, SemiBold, secondary brush | tree group headers, pane sections |
| Item name | body size, medium weight, label colour | Body, Medium | tree rows, tab names |
| Secondary text | one step smaller, secondary colour | Caption, secondary brush | counts, addresses, details |

## Iconography

SF Symbols on macOS and Segoe Fluent Icons on Windows: licensed, vector, with one stroke weight and
consistent sizing. Every protocol has its own glyph (SSH `terminal`, RDP `display`, VNC
`rectangle.inset.filled.on.rectangle`, web `globe`, …), with the full name from `icons.rs` as tooltip and
accessibility label. No lowercase protocol labels in rows. VM power state is part of the VM glyph
(play/stop/pause circle), not a separate dot.

## Density

`theme::metrics`: tree row 22 / 26 / 30 pt (Compact / Comfortable / Spacious), icon 14 / 16 / 17,
indent 14 / 16 / 18. Comfortable is the default: professional density, not consumer spacing.

## Layout rules

- Three regions: navigation tree, session canvas (dominant), inspector (260–460 pt, resizable, hideable).
- The inspector is attached to the split view, not the detail column (otherwise the toolbar inset applies twice).
- Inspector: header (icon tile, name, one secondary line), one primary action, compact icon actions,
  overflow menu from the registry; destructive actions only in the overflow. Collapsible groups with
  small headings; label/value rows.
- No cards, no gradients, no decorative glows. Radius 5–7 pt only on small surfaces (icon tile, notes field).

## Copy

Labels name the thing; tooltips explain. Confirmations come from the core (`MenuItem.confirm`) and
say what will happen ("Delete this folder and the 3 connections in it?"). Security and consent text stays.

## Platform differences

| | macOS | Windows |
|---|---|---|
| Tree | NSOutlineView, source-list style | WinUI TreeView (to be moved to the registry; see ROADMAP) |
| Menus | NSMenu (tree), SwiftUI Menu (inspector) | MenuFlyout from `bastion_library_menu_json` (to do) |
| Keys | Return opens, ⌘⌫ deletes, ←/→ (⌥ for all) | Enter opens, Del deletes, F2 renames (to do) |
