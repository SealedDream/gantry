//! A thin C ABI over `bastion_ffi::Library`, for hosts that cannot use the uniffi bindings.
//!
//! Why this exists: the released `uniffi-bindgen-cs` targets uniffi 0.31 while `core-ffi` is on
//! 0.32, and generated bindings must match the library's uniffi contract. Until a C# generator
//! supports 0.32, the WinUI shell reaches the library through this surface via P/Invoke. It adds
//! nothing to `core-ffi`'s API; it only forwards to it.
//!
//! Conventions
//! - All strings are UTF-8, NUL-terminated.
//! - Strings returned to the caller are allocated here and must be released with
//!   [`bastion_string_free`]; the library handle with [`bastion_library_free`].
//! - Fallible functions take `char **err`. It is set to NULL on success, or to a message the
//!   caller must free. Pass NULL to ignore errors.
//! - Nothing here ever unwinds across the boundary: panics become errors.
//! - Secrets go in (credentials.rs) and are not listed back. The two exceptions hand one password to the
//!   in-process RDP client and are audited: `bastion_credentials_rdp_login_json` and
//!   `bastion_credentials_release_login_json`.
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};

use bastion_ffi::{ConnectionView, FolderView, Library};
use serde_json::{json, Value};

pub mod activity;
pub mod audit_view;
pub mod bulk;
pub mod errcodes;
pub mod credentials;
pub mod credtree;
pub mod forwards;
pub mod open_sessions;
pub mod docunlock;
pub mod documents;
pub mod gateway;
pub mod history;
pub mod logexport;
pub mod multiexec;
pub mod hostcas;
pub mod hoststatus;
pub mod overview;
pub mod highlight;
pub mod pluginbroker;
pub mod plugins;
pub mod pluginentries;
pub mod pluginopen;
pub mod pluginexec;
pub mod pluginview;
pub mod policy;
pub mod ipc;
pub mod prefs;
pub mod probe;
pub mod properties;
pub mod bulk_edit;
pub mod recent_users;
pub mod restore;
pub mod session;
pub mod sshimport;
pub mod sshworkflow;
pub mod supervisor;
pub mod sftp;
pub mod terminal;
pub mod telnet_serial;
pub mod termthemes;
pub mod textgen;
pub mod transfers;
pub mod triggers;
pub mod tunnels;
pub mod ui;
pub mod update;
pub mod vaultwarden;
pub mod providers;
pub mod snippets;
pub mod vnc;
pub mod webtunnel;
pub mod workflow;
pub mod tabs;
pub mod keys;
pub mod agent;
pub mod ansible;
pub mod panes;
pub mod workspace;
pub mod wol;
pub mod dbclient;
pub mod filesconnect;
pub mod tasks;
pub mod dynfolder;
pub mod templates;
pub mod sysview;
pub mod personal;
pub use agent::*;
pub use ansible::*;
pub use activity::*;
pub use audit_view::*;
pub use bulk::*;
pub use credentials::*;
pub use overview::*;
pub use credtree::*;
pub use documents::*;
pub use forwards::*;
pub use hoststatus::*;
pub use triggers::*;
pub use ipc::*;
pub use multiexec::*;
pub use highlight::*;
pub use pluginbroker::*;
pub use policy::*;
pub use prefs::*;
pub use probe::*;
pub use properties::*;
pub use recent_users::*;
pub use session::*;
pub use sshimport::*;
pub use sshworkflow::*;
pub use history::*;
pub use open_sessions::*;
pub use docunlock::*;
pub use logexport::*;
pub use webtunnel::*;
pub use supervisor::*;
pub use sftp::*;
pub use terminal::*;
pub use termthemes::*;
pub use transfers::*;
pub use tunnels::*;
pub use ui::*;
pub use vaultwarden::*;
pub use providers::*;
pub use snippets::*;
pub use vnc::*;
pub use workflow::*;
pub use tabs::*;
pub use keys::*;
pub use panes::*;
pub use workspace::*;
pub use filesconnect::*;
pub use tasks::*;

/// Version of this C surface; bump when a signature changes or functions are added.
/// 2: terminal sessions. 3: SSH sessions (`bastion_session_*`). 4: credential vault (`bastion_credentials_*`).
/// 5: OpenSSH config scan and import. 6: property editor. 7: vault logins (`LOGIN_VAULT`, `bastion_session_set_credentials`).
/// 8: supervised SSH sessions (`bastion_supervisor_*`: reconnect, cancel, sleep/wake).
/// 9: app-side IPC listener (`bastion_ipc_*`).
/// 10: workspaces (`bastion_workspace*`). 11: split panes (`bastion_terminal_open_sibling`).
/// 12: SFTP browser on an open SSH terminal (`bastion_terminal_open_sftp`, `bastion_sftp_*`).
/// 13: VNC viewer (`bastion_vnc_*`).
/// 14: Vaultwarden (`bastion_vaultwarden_*`, `LOGIN_VAULTWARDEN`, `bastion_library_set_vaultwarden_item`, `vaultwardenItem`).
/// 15: navigation tree on the core registry (`bastion_library_menu_json`, ordered moves, rename, duplicate, sort,
/// copy text, favourites, `bastion_tree_state_*`, icon and theme tokens; `favorite`, `icon`, `iconLabel` in the tree JSON).
/// 16: settings registry and file (`bastion_setting*`), keyboard shortcuts (`bastion_shortcuts_*`), palette ranking
/// (`bastion_palette_*`), workspace split layouts, Add to Workspace, rename, duplicate and last-used
/// (`bastion_workspace_save_layout` …), Quick Connect (`bastion_library_quick_connect`), property `options`.
/// 17: inspector data: connection notes (`bastion_library_notes`, `bastion_library_set_notes`), effective values and
/// personal overrides of imported SSH hosts (`bastion_ssh_effective_json`, `bastion_ssh_override_json`, `bastion_ssh_set_override`).
/// 18: accent palette and density metrics (`bastion_theme_accents_json`, `bastion_theme_metrics_json`).
/// 19: SSH agent (`LOGIN_AGENT`), keyboard-interactive second factor (`LOGIN_PASSWORD_AND_CODE`,
/// `CONNECT_TWO_FACTOR_REQUIRED`) and per-hop jump logins (`bastion_session_connect_ssh_mfa`).
/// 20: SSH host certificate authorities (`bastion_host_cas_json`, `bastion_host_ca_add`, `bastion_host_ca_remove`).
/// 21: credential key-file import (`bastion_credentials_import_key_file`); the key is read and decrypted in the core.
/// 22: Gateway Manager (`bastion_gateways_json`, `bastion_gateway_add` / `_update` / `_remove`) and RDP/VNC/web routes
/// through a gateway (`bastion_gateway_route_json`, `bastion_gateway_route_open` and the `bastion_gateway_route_*` handle).
/// 23: managed policy, read-only (`bastion_policy_state_json`) and the protocol gate for RDP and web
/// (`bastion_policy_check_protocol`).
/// 24: updates from GitHub releases (`bastion_update_check_json`, `bastion_update_download`).
/// 25: OSC 52 copy requests (`bastion_terminal_set_clipboard_policy`, `bastion_terminal_take_clipboard_json`).
/// 26: password generator (`bastion_generate_password`, `bastion_password_strength_bits`) and `$Name$` variables
/// with the secret-leak guard (`bastion_library_variables_json`, `bastion_library_substitute`).
/// 27: `.bastion` documents (`bastion_document_*`, `bastion_library_export_document_json`,
/// `bastion_library_import_document_json`, `bastion_documents_recent_json`).
/// 28: terminal bell and clear scrollback (`bastion_terminal_take_bell`, `bastion_terminal_clear_scrollback`).
/// 29: Test Connection (`bastion_probe_start`, `bastion_probe_wait_json`, `bastion_probe_cancel`, `bastion_probe_free`).
/// 30: recent usernames per host for Connect as… (`bastion_recent_usernames_json`, `bastion_recent_username_record`, `bastion_recent_username_forget`).
/// 31: WSL details and saved local shells (`bastion_wsl_distros_detail_json`,
/// `bastion_wsl_availability_json`, `bastion_terminal_open_local`).
/// 33: SSH algorithms (`CONNECT_NO_COMMON_ALGORITHM`, `bastion_library_allow_weak_algorithms`,
/// `bastion_ssh_algorithms_preview_json`, the `ssh_algorithms` property, `forbidWeakSshAlgorithms`).
/// 34: SSH config export (`bastion_library_export_ssh_config_json`).
/// 35: tab groups (`bastion_tab_strip_apply_json`, `bastion_tab_strip_auto_group_json`, `bastion_tab_group_colors_json`),
/// workspaces saved with groups (`bastion_workspace_save_grouped_layout`; `group` and `groups` in the workspace JSON),
/// the inheritable `tab_group_color` property, and up to 256 tabs per workspace.
/// 36: connection history (`bastion_connection_history_json` and friends, in `history`).
/// 37: tunnel definitions and web tabs through a tunnel (`bastion_library_tunnels_json`,
/// `bastion_library_put_tunnel_json`, `bastion_library_web_tunnel_plan_json` …, in `webtunnel`).
/// 38: Credentials section of the tree (`bastion_credentials_tree_json`, folders, rename/move,
/// `bastion_credentials_assign`, `bastion_credentials_effective_json`, `bastion_credentials_remove_checked_json` …, in `credtree`); merged after 53.
/// 39: key manager (`bastion_keys_generate_json`, `bastion_keys_inspect_json`, `bastion_keys_convert_json`,
/// in `keys`); merged after 53.
/// 45: file panel: transfer queue (`bastion_transfers_*`), OSC 7 folder (`bastion_terminal_cwd`, `bastion_osc7_path`,
/// `bastion_follow_folder_hook`), edit locally (`bastion_edit_local_path`, `bastion_edit_watcher_*`); merged after 53, so the version stays 53.
/// 53: split panes and broadcast input (`bastion_panes_apply_json`, `bastion_panes_to_layout_json`,
/// `bastion_panes_from_layout_json`, `bastion_broadcast_review_json`, in `panes`).
/// 54: log snippet export (`bastion_log_snippet_clean`, `bastion_log_snippet_export`, `bastion_terminal_export_selection`).
/// 57: library connections as palette entries (`bastion_library_palette_connections_json`, in `prefs`).
/// 58: session logging to file with rotation and prompt redaction (`bastion_terminal_start_log`, `_stop_log`, `_is_logging`).
/// 59: remote editor with conflict detection (`bastion_sftp_edit_open`, `bastion_sftp_edit_save`); merged after 61.
/// 60: Bastion's own SSH agent (`bastion_agent_start`, `bastion_agent_socket`, `bastion_agent_free`, in `agent`):
/// a Unix socket, or a `\\.\pipe\...` named pipe on Windows.
/// 61: workspace create (name must be new) and restore plan (`bastion_workspace_create`, `bastion_workspace_restore_plan_json`).
/// 62: auto-reconnect on network change (`EVENT_NETWORK_CHANGED` for `bastion_supervisor_event`); SSH keep-alive
/// defaults to 30 s with 3 missed probes when a connection turns auto-reconnect on.
/// 63: external credential providers, read-only and uncached: 1Password via `op`, KeePass `.kdbx`, HashiCorp
/// Vault KV (`bastion_provider_open_onepassword` / `_keepass` / `_hcvault`, `bastion_provider_unlock`, `_check_item`,
/// `_items_json`, `_register`, `bastion_providers_lock_all`, `LOGIN_PROVIDER`, in `providers`).
/// 64: command snippets (`bastion_snippets_json`, `bastion_snippet_put`, `_remove`, `_send` with
/// `SNIPPET_NEEDS_CONFIRM` and an audit record, in `snippets`).
/// 65: port-forward manager (`bastion_terminal_forwards_json`, `bastion_terminal_start_forwards_json`,
/// `bastion_terminal_stop_forward`, in `forwards`; `startWithConnection` in the tunnel JSON); merged after 66.
/// 66: per-host colours (`host_color` property, `bastion_library_host_color_json`, in `properties`); merged after 65.
/// 67: Mosh transport and tmux attach (`ssh.transport`, `ssh.tmux`, `ssh.tmux_session` properties;
/// `bastion_terminal_open_mosh`; SSH terminals and reconnects attach tmux).
/// 68: host status dashboard, opt-in low-frequency TCP check parked while hidden (`host_status` property,
/// `bastion_host_status_*`, in `hoststatus`); merged after 71.
/// 69: triggers, bounded-regex highlight and notify (`bastion_triggers_*`, `bastion_terminal_set_triggers`,
/// `bastion_terminal_take_trigger_events_json`, in `triggers`); merged after 71.
/// 70: SFTP/SCP/FTPS delete (`bastion_sftp_remove`: a file, or a folder with its contents).
/// 71: Wake-on-LAN (`wol_*` properties; `bastion_library_wol_plan_json`, `bastion_library_wake`,
/// `bastion_library_wake_before_connect` with `bastion_wake_cancel_new` / `_cancel` / `_free`, in `wol`).
/// 72: saved tunnels on their own SSH connection, no shell (`bastion_tunnel_start`, `_status_json`, `_stop`,
/// `_free`, in `tunnels`).
/// 73: multi-host exec (`bastion_multiexec_review_json`, `_new`, `_run`, `_retry_failed`, `_cancel`, `_results_json`,
/// `_export`, `_free`, in `multiexec`); 72 is the saved-tunnel runtime.
/// 74: terminal scrollback size (`bastion_terminal_set_scrollback`); 72 and 73 are tunnels and multi-host exec.
/// 75: terminal Select All (`bastion_terminal_select_all`); 72 to 74 are tunnels, multi-host exec and scrollback size.
/// 76: import a connection file (`bastion_library_import_file_json`: CSV, .rdp, PuTTY .reg, Royal JSON, RDCMan .rdg);
/// 72 to 75 are tunnels, multi-host exec, scrollback size and Select All.
/// 77: per-connection sensitive lookup (`bastion_library_connection_sensitive`, in `wol`).
/// 78: database client step 1, PostgreSQL through a tunnel (`bastion_db_query_json`, in `dbclient`); after NW-C's 72-76 and Core-D's 77.
/// 79: terminal mouse reporting (`bastion_terminal_mouse_reporting`, `bastion_terminal_mouse`); NW-C.
/// 80: session restore after a crash + start page recents (`bastion_open_sessions_save`, `_mark_clean_quit`,
/// `_begin_json`, `bastion_recent_sessions_json`, in `open_sessions`); Core-D.
/// 81: document-first launch (`bastion_document_unlock_status_json`, `_export_wrapped_key`, `_unlock_wrapped_key`,
/// `_state_dir`, `bastion_documents_recent_details_json`, `bastion_document_auto_lock_due`,
/// `bastion_effective_auto_lock_minutes`, in `docunlock`; password unlock gains back-off); Core-D.
/// 82: managed document policy (`bastion_document_auto_lock_minutes`, `bastion_document_biometric_unlock_allowed`;
/// policy JSON gains `documentAutoLockMaxMinutes`, `passwordOnlyDocumentUnlock`); Core-D.
/// 83: `bastion_agent_stop` (stop without blocking, completion once no confirm callback runs);
/// `bastion_agent_free` now waits for running callbacks; returned strings are wiped on free;
/// `bastion_supervisor_new` wraps the shell's own supervisor (no fresh-credential redial); FFI review.
/// 84: tree connection JSON gains `effectiveCredentialId`, `effectiveCredentialName`, `credentialSource`,
/// `credentialFrom`, `effectiveUsername`, `inlineCredential`, as UniFFI's `ConnectionView` (additive); H09.
/// 85: `bastion_last_error_code` (stable error class after a failed call; document calls report
/// `conflict`, `corrupt`, `not_found`, `vault_locked`, `io`, …, others `other`); H10 (additive).
/// 86: portable `bastion-export` v1 (`bastion_library_export_preview_json`, `bastion_library_export_portable`); additive.
/// 87: files-only connections (`bastion_session_connect_files` for SFTP/SCP, `bastion_session_connect_ftps`); additive.
/// 88: terminal themes (`bastion_termthemes_list_json`, `_duplicate`, `_put`, `_remove`) and
/// `bastion_terminal_set_theme_in` for the user's own themes (additive).
/// 89: shared-config workflow (`bastion_ssh_workflow_settings_json`, `_set_settings`,
/// `_placeholders_json`, `_set_placeholder`, `_import_hosts`, `_changes_json`, `_apply_refresh_json`),
/// the OpenSSH refresh preview macOS has (additive).
/// 90: Ansible (`bastion_library_export_ansible_inventory_json`, `bastion_ansible_run_plan_json`); additive.
/// 91: chunked SFTP transfer with byte progress; NWAA.
/// 92: saved tasks (`bastion_tasks_json`, `_save_json`, `_remove`, `_set_favorite`, `bastion_task_hooks_json`,
/// `_set_hooks_json`, `bastion_task_review_json`, `bastion_task_run_start`, `_output_json`, `_cancel`, `_free`); additive.
/// 93: read-only Services, Processes and Event Log (`bastion_sysview_open`, `_info_json`, `_services_json`,
/// `_processes_json`, `_tail_json`, `_close`, `_free`), owner point 11; additive.
/// 94: Personal as one encrypted `.bastion` document (`bastion_personal_open`, `_free`, `_library`, `_vault`,
/// `_info_json`, `_migration_json`, `_rename`) with a DPAPI-held device key, and `bastion_credentials_rdp_login_json`
/// (NW-OF-A, owner points 7, 20, 23); additive. (93 is NW-OF-C's sysview surface.)
/// 95: logins per connection (`bastion_credentials_logins_json`, `_edit_login`, `_release_login_json`): several
/// logins, folder inheritance and same-host sharing in one ordered list (owner point W23); additive.
/// 96: login scope and identity (A1-CORE-01, owner decision D1). `bastion_credentials_logins_json` rows gain
/// `autoUse` and the source `named`; a `same-host` login is offered only inside one folder scope and route and
/// never for loopback, with `autoUse` false; `bastion_credentials_release_login_json` refuses what is no longer
/// listed; folders take the property `credential_boundary`. No new export; behaviour change, so hosts re-check.
/// 97: Connect All plan (`bastion_credentials_plan_connect_all_json`, in `bulk`) and folder overview
/// (`bastion_library_folder_overview_json`, in `overview`), the calls Native Mac makes (CABI-97); additive.
/// 101: Test Connection host-key confirmation (SEC-07). `bastion_probe_start` reads `trusted_fingerprint` and
/// `bastion_probe_wait_json` returns `needs_host_key_confirmation`; a password is no longer sent to a host whose
/// key is new until the user confirms it. No new export; behaviour change, so hosts re-check. (98 to 100 are held.)
/// 103: session history, the activity store (`bastion_activity_begin`, `_event`, `_end`, `_query_json`,
/// `_events_json`, `_purge`, `_close_orphans`, in `activity`), the calls Native Mac has through UniFFI
/// (LOG-CORE-01-WIRING); additive. Sessions opened with `bastion_session_connect*` are now recorded by the core.
/// 104: the shared login rule on three more paths (A1-CORE-01-FU3; numbered 99 and then 102 before it merged).
/// `bastion_credentials_rdp_login_json` gains `lib` and returns only the connection's own inline password or its own
/// or inherited login; `bastion_probe_start` gains `lib` (NULL allowed) and `"connection_id"` in `input_json`, reads a
/// `LOGIN_VAULT` login only for a saved connection that may use it without asking, and only when the host, port and
/// jump hosts match the saved connection; `bastion_gateway_route_open` refuses `LOGIN_VAULT`. Signature change.
/// 105: session login reuse (A1-CORE-02): `bastion_session_login_reuse_minutes` and
/// `bastion_remembered_login_usable`, in `policy`; `bastion_policy_state_json` gains `sessionLoginReuseMinutes`; additive.
/// 106: `bastion_library_session_log` (in `properties`), the inherited "Log session output" property, so hosts start
/// the log when a saved connection's terminal opens or reconnects (LOG-01); additive.
/// 107: `bastion_personal_note_shown` and `bastion_document_note_opened`, so a library shown by hand opens at the
/// next launch (LIB-01); additive.
/// 108: ask once for a library opened by path (A1-CORE-01-FU5; numbered 100 and then 104 before it merged):
/// `bastion_document_origin`, `bastion_document_answer_origin`, `bastion_known_documents_migrate`. Additive, with
/// one behaviour change: `bastion_document_open` of a library this device does not know marks the logins it names
/// as offered, not used, until the answer.
/// 109: Connect All applies the managed policy (B4-FOLDER-CONNECT-ALL-FU1): `bastion_credentials_plan_connect_all_json`
/// gains `skippedBlocked`, the connections whose type the effective policy forbids (no longer in `ready` or
/// `needsLogin`, not counted in `toConnect`), and fails with the policy error while the managed file is broken.
/// Additive field with a behaviour change, so hosts re-check.
/// 111: plugin broker exports (PLUG-02c): `bastion_plugin_policy_state_json`, `bastion_plugin_may_load` and
/// `bastion_plugin_field_save_warning`. Additive only.
/// 112: OpenSSH import forwards (SSH-IMPORT-FORWARDS): `bastion_library_ssh_forwards_json` (preview rows) and
/// `bastion_library_import_ssh_forwards` (ticked rows become auto-start tunnels). Additive. Reserved as 110, renumbered
/// after 111 merged first.
/// 114: Recently Deleted (B10): `bastion_library_trash`, `_deleted_json`, `_restore`, `_delete_permanently`,
/// `_empty_deleted`, `_purge_deleted`, `_live_connection_ids_json` and `bastion_credentials_prune_inline`. Additive; hosts that prune inline secrets
/// must use the live set from `_live_connection_ids_json` once they call `_trash`.
/// 115: the terminal find bar (W11-TERM-SEARCH): `bastion_terminal_find_json`, plain text unless `regex`, case
/// ignored unless `match_case`, returns the match's place among all matches; additive.
/// 116: Telnet and serial terminals (B7-CORE): `bastion_session_connect_telnet`, `bastion_terminal_open_serial`,
/// `bastion_terminal_reconnect` and the other `telnet_serial` exports. Additive.
/// 117: connection templates (B9): `bastion_templates_json`, `bastion_template_save_from`,
/// `bastion_template_instantiate`, `bastion_template_update`, `bastion_template_delete`. Additive.
/// 118: `bastion_library_no_preview` (in `properties`), the inherited "Hide tab preview" property, so hosts leave
/// the remote screen out of tab previews and the tab overview (B11); additive.
/// 119: `bastion_library_import_file_json` also accepts mRemoteNG `confCons.xml` (`.xml`, B14). Additive: a new
/// file type; passwords are never imported, Rlogin/RAW/other types are listed in `skipped`.
/// 120: plugins folder and catalogue (PLUG-04b part 2): `bastion_plugins_installed_json`,
/// `bastion_plugin_install_file`, `bastion_plugin_remove`, `bastion_plugins_refresh`, `bastion_plugins_updates_json`.
/// Additive.
/// 121: custom properties over the C ABI: `bastion_library_custom_properties_json`,
/// `bastion_library_set_custom_property` (as UniFFI's `custom_properties`). Additive.
/// 122: per-item icon: tree connection JSON gains `ownIcon`; `bastion_connection_icon_names_json`,
/// `bastion_library_set_icon` (UniFFI `connection_icon_names`, `Library.set_icon`, #960). Additive.
/// 123: Audit Log page: read a page of audit records newest first and verify the tamper chain (`audit_view`). Read-only, additive.
/// ABI_TBD_WEBFILL: B13 web sign-in fill: `bastion_web_autofill_offered`, `bastion_credentials_web_autofill_json`
/// (in `credentials`). Additive. The number is assigned at merge time.
/// 125: `bastion_library_host_colors_json`, every connection's host colour in one tree pass (in `properties`). Additive.
/// 126: `bastion_library_properties_for_selection_json`, `bastion_library_apply_to_selection`, bulk edit (in `bulk_edit`). Additive.
/// 127: B8 KeePass import into the vault: `bastion_credentials_keepass_preview_json`,
/// `bastion_credentials_keepass_import_json` (in `credentials`). Additive.
/// 128: B5 task hooks for Native Windows: `bastion_task_resolved_hooks_json`, `bastion_task_trust`
/// (in `tasks`). Additive.
/// 129: `bastion_vnc_resize`, the VNC desktop follows the tab (ExtendedDesktopSize, RDP-VNC-FIT, in `vnc`). Additive.
/// 130: B15 dynamic folders: `bastion_dynamic_folder_*`, `bastion_dynamic_folders_allowed` (in `dynfolder`). Additive.
/// 132: terminal shell marks and notifications: `bastion_terminal_take_events_json`, `bastion_terminal_jump_prompt`, `bastion_tags_is_production` (in `terminal`). Additive.
/// 133: `bastion_terminal_foreground_json`, a local terminal's foreground process for the per-pane close check (in `terminal`). Additive.
/// 134: `bastion_terminal_carry_over`, Reconnect keeps the old terminal text above the new prompt (in `terminal`). Additive.
/// 135: task prompt variables `$Ask:Label$`: `bastion_task_ask_labels_json`, `bastion_task_review_with_json`,
/// `bastion_task_run_start_with` (in `tasks`). Additive; the old review/start pass no answers.
/// 136: PLUG-06c code editor: `bastion_highlight_line_json`, `bastion_highlight_text_json`,
/// `bastion_completion_context_json`, `bastion_completions_rank_json` (in `highlight`). Additive.
/// 137: PLUG-VIEW-CABI plugin view sessions: `bastion_plugin_host_set_helper_path`, `bastion_plugin_view_open`,
/// `bastion_plugin_view_next_update`, `bastion_plugin_view_send_event`, `bastion_plugin_view_close`,
/// `bastion_plugin_view_free` (in `pluginview`). Additive.
/// 138: session log v2 (LOG-CORE-02): `bastion_session_log_plan_json`, `bastion_terminal_start_planned_log`,
/// `bastion_terminal_log_state_json`, `bastion_terminal_finish_log`, `bastion_purge_session_logs_json` (in `logexport`).
/// 139: PLUG-08-WIN plugin entries: `bastion_plugin_connection_types_json`, `bastion_library_add_plugin_connection`,
/// `bastion_library_plugin_entry_tls_json`, `bastion_library_set_plugin_entry_tls`, `bastion_plugin_certificate_probe`,
/// `bastion_library_plugin_entry_gateway`, `bastion_plugin_entry_view_open` with a route (in `pluginentries`). Additive.
/// 140: PLUG-OPEN-WIN plugin open requests: `bastion_plugin_open_resolve_json`, `bastion_library_plugin_open_library`,
/// `bastion_library_plugin_open_save` (in `pluginopen`). Additive.
/// 141: plugin API 1.3 sidebar tree and plugin entry fields: `bastion_plugin_entry_sidebar_open`,
/// `bastion_library_plugin_entry_fields_json`, `bastion_library_set_plugin_field`; `sidebarTree` in
/// `bastion_plugin_connection_types_json` (in `pluginentries`). Additive.
/// 142: PVE-TLS Test Connection for plugin entries: `bastion_plugin_certificate_check` (in `pluginentries`). Additive.
/// 143: UI-06 window colours from the terminal theme: `bastion_termtheme_window_tones` (in `termthemes`). Additive.
/// 144: PVE-AUTH Test Connection login step for plugin entries: `bastion_plugin_entry_test_json` (in `pluginentries`). Additive.
/// 145: START-WINDOW Recents: `bastion_documents_forget_recent`; `connectionCount` in
/// `bastion_documents_recent_details_json` (in `docunlock`). Additive.
/// 146: LOG-ERRCODES `bastion_error_code`, `bastion_log_redact` (in `errcodes`). Additive.
/// 147: PLUG-EXEC-01 plugin API 1.5 `exec` (in `pluginexec`): `bastion_plugin_exec_json`,
/// `bastion_plugin_exec_terminal_library` and the `bastion_plugin_exec_cancel_*` handle. Additive.
/// 149: Save as Connection (plugin API 1.6 `library.propose`): `bastion_library_plugin_propose_duplicates_json`,
/// `bastion_library_plugin_propose_save_json` (in `pluginopen`). Additive. Number assigned 2026-11-23.
pub const ABI_VERSION: u32 = 149;

/// Success value for `i32`-returning calls.
pub(crate) fn set_ok() -> Result<i32, String> {
    Ok(0)
}

pub(crate) fn optional_text(s: Option<String>) -> *mut c_char {
    s.filter(|s| !s.is_empty()).map(to_c).unwrap_or(null_mut())
}

/// Opaque handle for one open library. Held as an `Arc` because that is what the session calls
/// in `bastion_ffi` take; the C surface still hands out one plain pointer per open library.
pub struct BastionLibrary(pub(crate) Arc<Library>);

pub(crate) fn to_c(s: String) -> *mut c_char {
    use zeroize::Zeroize;
    // One exact-size copy (room for the NUL, so `CString` never reallocates); interior NULs
    // are dropped. The source is wiped: results may be secrets (generated passwords, keys; F09).
    let mut src = s;
    let mut bytes = Vec::with_capacity(src.len() + 1);
    bytes.extend(src.bytes().filter(|&b| b != 0));
    src.zeroize();
    // SAFETY: interior NULs were filtered out above.
    unsafe { CString::from_vec_unchecked(bytes) }.into_raw()
}

/// # Safety
/// `err` must be NULL or point to a writable `char *`.
unsafe fn set_err(err: *mut *mut c_char, msg: String) {
    if !err.is_null() {
        *err = to_c(msg);
    }
}

/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
pub(crate) unsafe fn required(p: *const c_char, what: &str) -> Result<String, String> {
    if p.is_null() {
        return Err(format!("{what} is required"));
    }
    CStr::from_ptr(p).to_str().map(str::to_string).map_err(|_| format!("{what} is not valid UTF-8"))
}

/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
pub(crate) unsafe fn optional(p: *const c_char, what: &str) -> Result<Option<String>, String> {
    if p.is_null() {
        return Ok(None);
    }
    required(p, what).map(|s| if s.is_empty() { None } else { Some(s) })
}

/// # Safety
/// `lib` must be NULL or a handle from [`bastion_library_open`] that has not been freed.
pub(crate) unsafe fn handle<'a>(lib: *const BastionLibrary) -> Result<&'a Library, String> {
    lib.as_ref().map(|l| &*l.0).ok_or_else(|| "library handle is NULL".to_string())
}

/// The library as a shared handle, for the `bastion_ffi` calls that take one.
///
/// # Safety
/// `lib` must be NULL or a handle from [`bastion_library_open`] that has not been freed.
pub(crate) unsafe fn library(lib: *const BastionLibrary) -> Result<Arc<Library>, String> {
    lib.as_ref().map(|l| l.0.clone()).ok_or_else(|| "library handle is NULL".to_string())
}

thread_local! {
    /// Code of the last error this thread reported through `err` (see [`bastion_last_error_code`]).
    static LAST_CODE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") };
    /// Code captured by [`coded`] for the call in progress.
    static PENDING_CODE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

fn intern(code: &str) -> &'static str {
    // The codes are a small fixed set; leak each distinct one once.
    static SEEN: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = seen.iter().find(|c| **c == code) {
        return c;
    }
    let c: &'static str = Box::leak(code.to_owned().into_boxed_str());
    seen.push(c);
    c
}

/// Turn a bridge error into its message and remember its stable code for
/// [`bastion_last_error_code`]. Use in place of `.map_err(|e| e.to_string())`.
pub(crate) fn coded(e: impl Into<bastion_ffi::FfiError>) -> String {
    let e = e.into();
    PENDING_CODE.with(|p| p.set(Some(intern(e.code()))));
    e.to_string()
}

/// Stable class of the last error this thread received through an `err` out-parameter:
/// `conflict`, `corrupt`, `not_found`, `vault_locked`, `io`, `offline`, `timeout`, `invalid`,
/// `policy`, … (see `CoreError::code`), or `other` when the call has no finer class. An empty
/// string after a call that succeeded. Read it right after the failing call on the same thread.
/// Static storage: never free it.
#[no_mangle]
pub extern "C" fn bastion_last_error_code() -> *const c_char {
    static CODES: Mutex<Vec<(&'static str, CString)>> = Mutex::new(Vec::new());
    let code = LAST_CODE.with(|c| c.get());
    let mut codes = CODES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, c)) = codes.iter().find(|(k, _)| *k == code) {
        return c.as_ptr();
    }
    let c = CString::new(code).unwrap_or_default();
    let ptr = c.as_ptr();
    codes.push((code, c));
    ptr
}

/// Run `f`, turning errors and panics into the `err` out-parameter and returning `fail`.
pub(crate) fn guarded<T>(err: *mut *mut c_char, fail: T, f: impl FnOnce() -> Result<T, String>) -> T {
    PENDING_CODE.with(|p| p.set(None));
    LAST_CODE.with(|c| c.set(""));
    if !err.is_null() {
        // SAFETY: documented contract of every `err` parameter.
        unsafe { *err = null_mut() };
    }
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(msg)) => {
            LAST_CODE.with(|c| c.set(PENDING_CODE.with(|p| p.take()).unwrap_or("other")));
            unsafe { set_err(err, msg) };
            fail
        }
        Err(_) => {
            LAST_CODE.with(|c| c.set("internal"));
            unsafe { set_err(err, "internal error".into()) };
            fail
        }
    }
}

fn connection_json(c: &ConnectionView) -> Value {
    // Destructured without `..` (H09): a field added to the UniFFI record fails to compile here
    // until it is projected or deliberately listed as omitted, so the ABIs cannot drift silently.
    let ConnectionView {
        id,
        name,
        protocol,
        host,
        port,
        username,
        group,
        source_status,
        imported,
        favorite,
        credential_id,
        vaultwarden_item,
        effective_credential_id,
        effective_credential_name,
        credential_source,
        credential_from,
        effective_username,
        inline_credential,
        has_tools,
        unavailable,
        own_icon,
        tags,
    } = c;
    // The core's icon for the protocol, with its full name for the tooltip (core/src/icons.rs).
    // A type this app does not know (PLUG-03a) gets a neutral glyph whose tooltip is the core's
    // fixed text; its stored type name is never looked up as an icon.
    let mut icon = bastion_ffi::icon_for(if unavailable.is_some() { "network".to_string() } else { protocol.clone() });
    if let Some(text) = unavailable {
        icon.label = text.clone();
    }
    json!({
        "id": id, "name": name, "protocol": protocol, "host": host, "port": port,
        "username": username, "group": group, "credentialId": credential_id, "vaultwardenItem": vaultwarden_item, "sourceStatus": source_status, "imported": imported,
        "favorite": favorite, "icon": icon.id, "iconLabel": icon.label,
        "effectiveCredentialId": effective_credential_id, "effectiveCredentialName": effective_credential_name,
        "credentialSource": credential_source, "credentialFrom": credential_from,
        "effectiveUsername": effective_username, "inlineCredential": inline_credential,
        "hasTools": has_tools, "unavailable": unavailable, "ownIcon": own_icon,
        "tags": tags,
    })
}

fn folder_json(f: &FolderView) -> Value {
    json!({
        "id": f.id, "name": f.name,
        "folders": f.folders.iter().map(folder_json).collect::<Vec<_>>(),
        "connections": f.connections.iter().map(connection_json).collect::<Vec<_>>(),
    })
}

/// Version of this C surface (see [`ABI_VERSION`]).
#[no_mangle]
pub extern "C" fn bastion_abi_version() -> u32 {
    ABI_VERSION
}

/// Open `path`, creating an empty library when the file does not exist yet.
/// Returns NULL and sets `*err` on failure.
///
/// # Safety
/// `path` must be a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_open(path: *const c_char, err: *mut *mut c_char) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let path = required(path, "path")?;
        let lib = Library::open(path).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionLibrary(Arc::new(lib)))))
    })
}

/// An unsaved, in-memory library holding one connection for a Quick Connect `target` (`user@host:port`,
/// `ssh://…`, `rdp://host`, `https://…`). `bastion_library_save` refuses it; connect through it like any
/// library, so host-key checks and the login prompt still apply. NULL and `*err` for a target that does not parse.
///
/// # Safety
/// `target` valid NUL-terminated; `err` NULL or writable. Free with [`bastion_library_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_library_quick_connect(target: *const c_char, err: *mut *mut c_char) -> *mut BastionLibrary {
    guarded(err, null_mut(), || {
        let lib = Library::quick_connect(required(target, "target")?).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionLibrary(Arc::new(lib)))))
    })
}

/// Release a library handle. NULL is ignored. Unsaved changes are not saved.
///
/// # Safety
/// `lib` must be NULL or a live handle, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_free(lib: *mut BastionLibrary) {
    if !lib.is_null() {
        drop(Box::from_raw(lib));
    }
}

/// The folder tree as JSON: `{id,name,folders:[…],connections:[{id,name,protocol,host,port,
/// username,group,sourceStatus,imported,…,unavailable}]}`; `port` and `username` are null when
/// unset. `unavailable` is null, or the core's fixed text "Needs a newer Bastion or a plugin"
/// for an entry whose type this app does not know (PLUG-03a, additive; no ABI change): show it
/// on the row. Such an entry cannot be connected to or edited, and `protocol` is then its
/// stored type name (untrusted, display only).
///
/// # Safety
/// `lib` must be a live handle; `err` NULL or writable. Free the result with [`bastion_string_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_library_tree_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let tree = handle(lib)?.tree();
        Ok(to_c(folder_json(&tree).to_string()))
    })
}

/// Add a folder under `parent` (NULL or empty = root). Returns the new folder id.
///
/// # Safety
/// Strings must be valid NUL-terminated (`parent` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_add_folder(lib: *const BastionLibrary, parent: *const c_char, name: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let parent = optional(parent, "parent")?;
        let name = required(name, "name")?;
        let id = handle(lib)?.add_folder(parent, name).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// Add a connection under `parent` (NULL or empty = root). `protocol` is a lowercase name such as
/// `ssh`, `rdp`, `vnc`. `port` is -1 for "protocol default"; `username` may be NULL. Returns the id.
///
/// # Safety
/// Strings must be valid NUL-terminated (`parent`, `username` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_add_connection(
    lib: *const BastionLibrary,
    parent: *const c_char,
    name: *const c_char,
    protocol: *const c_char,
    host: *const c_char,
    port: i32,
    username: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let parent = optional(parent, "parent")?;
        let name = required(name, "name")?;
        let protocol = required(protocol, "protocol")?;
        let host = required(host, "host")?;
        let username = optional(username, "username")?;
        let port = match port {
            -1 => None,
            p if (1..=65535).contains(&p) => Some(p as u16),
            p => return Err(format!("port {p} is out of range")),
        };
        let id = handle(lib)?.add_connection(parent, name, protocol, host, port, username).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// Remove a folder (with its contents) or a connection by id. Returns 0 on success, -1 on failure.
///
/// # Safety
/// `id` a valid NUL-terminated string; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_remove(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(id, "id")?;
        handle(lib)?.remove(id).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Write the library to disk (atomic, owner-only on Windows). Returns 0 on success, -1 on failure.
///
/// # Safety
/// `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_save(lib: *const BastionLibrary, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        handle(lib)?.save().map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Free a string returned by this library. NULL is ignored.
///
/// # Safety
/// `s` must be NULL or a pointer returned by this library, and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_string_free(s: *mut c_char) {
    if !s.is_null() {
        // Wiped before release: any returned string may hold a secret (F09).
        let mut bytes = CString::from_raw(s).into_bytes_with_nul();
        zeroize::Zeroize::zeroize(&mut bytes);
    }
}
