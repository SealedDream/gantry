//! The logins a connection can use, best first (owner point W23; scope and identity from
//! A1-CORE-01, `audit/fable-review/A1_CREDENTIAL_DESIGN.md`). One ordered list per connection,
//! shared by every app:
//!
//! 1. its default login (`Settings::credential_id`),
//! 2. its other saved logins (`Settings::logins`),
//! 3. the saved credential it names (`Settings::credential_name`),
//! 4. the login it inherits when it sets no default: the nearest folder that sets a credential,
//!    else the nearest folder that names one, else the type default,
//! 5. steps 1 to 3 of every other connection with the same identity, in tree order.
//!
//! Steps 1 to 4 are the connection's own and may be used without asking (`auto_use`). Step 5 is
//! only offered: the user confirms it once (owner decision D1). The exception to steps 1 to 4
//! (A1-CORE-01-FU1): a credential reference that arrived with an imported library
//! (`Settings::credential_unconfirmed`, set by `mark_received`) is only offered too, until the
//! user chooses that credential for the node (Properties, `add_login`, `set_default_login`).
//! A choice confirms the credential chosen (`Settings::credential_confirmed`), not whatever
//! else the sender wrote on the node.
//!
//! Two connections have the same identity when all of this holds:
//! - the same host text (`normalize_host`; the port is not part of it, so SSH and RDP match),
//!   and the host is not this computer (`is_local`): a loopback address is a port forward or a
//!   container, where every port is another machine;
//! - the same route: the same effective gateway and the same `ProxyJump`;
//! - the same scope: the nearest folder marked `Settings::credential_boundary`, else the
//!   top-level folder; connections directly under the root share only among themselves.
//!
//! No duplicates, no secrets, and credentials no longer in the vault are skipped. Inline secrets
//! stay private to their connection and are never offered here. `may_use` reads the same list.
//! The bridge checks it in `release_login` and before every SSH connect reads a saved login
//! (A1-CORE-01-FU2). The paths with no step where the user confirms a login, `rdp_login_for`
//! and Test Connection, read only the connection's own inline secret or an `auto_use` login
//! from this list; the gateway route of an RDP, VNC or web connection takes no saved login at
//! all, because a gateway is not an entry this list can be asked about (A1-CORE-01-FU3).
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;

use crate::model::{Connection, Document, Folder, Node, Protocol, Settings};
use crate::vault::{CredentialKind, Vault};
use crate::{CoreError, Result};

/// What the login is for: RDP takes a password itself, so it drops SSH keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginPurpose {
    Any,
    Password,
}

/// Where a candidate comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginSource {
    /// The connection's default login.
    Default,
    /// One of the connection's other saved logins.
    Connection,
    /// The saved credential the connection names (`Settings::credential_name`).
    Named,
    /// Inherited from this folder (`None`: the connection type's default).
    Inherited { folder: Option<Uuid>, name: String },
    /// Saved for another connection with the same identity (host, route and scope).
    SameHost { connection: Uuid, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCandidate {
    pub credential: Uuid,
    pub source: LoginSource,
    /// The connection's own or inherited login: connect with it without asking. `false` for a
    /// login saved for another connection, which is offered and needs the user's yes.
    pub auto_use: bool,
}

/// The host as typed, without what does not tell two hosts apart: outer spaces, IPv6 brackets
/// and a trailing dot.
fn bare_host(host: &str) -> &str {
    let h = host.trim();
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    h.trim_end_matches('.')
}

/// The host name as compared for sharing: trimmed, lowercase, IPv6 brackets and a trailing dot dropped.
pub fn normalize_host(host: &str) -> String {
    bare_host(host).to_ascii_lowercase()
}

/// `127.1`, `0x7f.0.0.1`, `2130706433`: text the system resolver reads as an IPv4 address
/// (`inet_aton`) though it is not written as one.
fn legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    let number = |part: &str| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_hexdigit() || b == b'x') {
            return None;
        }
        match (part.strip_prefix("0x"), part.strip_prefix('0')) {
            (Some(hex), _) => u32::from_str_radix(hex, 16).ok(),
            (None, Some(octal)) if !octal.is_empty() => u32::from_str_radix(octal, 8).ok(),
            _ => part.parse::<u32>().ok(),
        }
    };
    let parts: Vec<u32> = host.split('.').map(number).collect::<Option<_>>()?;
    let (last, lead) = parts.split_last()?;
    // Each leading part is one byte; the last part fills the bytes that are left.
    let room = 4usize.checked_sub(lead.len()).filter(|r| *r > 0)?;
    if lead.iter().any(|n| *n > 255) || (room < 4 && *last >= 1 << (8 * room)) {
        return None;
    }
    Some(Ipv4Addr::from(lead.iter().enumerate().fold(*last, |v, (i, n)| v | n << (24 - 8 * i))))
}

/// Whether a normalised host is this computer: `localhost`, a name under `.localhost`, the
/// IPv4 block 127.0.0.0/8, `::1`, or the unspecified address, in any spelling.
fn is_local(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    let local_v4 = |a: Ipv4Addr| a.is_loopback() || a.is_unspecified();
    // An IPv6 zone (`::1%lo0`) names the interface, not another host.
    match host.split('%').next().unwrap_or(host).parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => local_v4(a),
        Ok(IpAddr::V6(a)) => a.is_loopback() || a.is_unspecified() || a.to_ipv4().is_some_and(local_v4),
        Err(_) => legacy_ipv4(host).is_some_and(local_v4),
    }
}

fn usable(vault: &Vault, id: Uuid, purpose: LoginPurpose) -> bool {
    match vault.get(id) {
        Some(c) if c.owner.is_none() => purpose == LoginPurpose::Any || matches!(c.kind, CredentialKind::Password { .. }),
        _ => false,
    }
}

/// The one saved credential called `name`, compared like the apps' own look-up (ASCII case
/// ignored). `None` when no credential or more than one has the name: a name that fits two
/// credentials decides nothing. Inline secrets have no name to be found by.
fn by_name(vault: &Vault, name: &str) -> Option<Uuid> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let mut hits = vault.entries.values().filter(|c| c.owner.is_none() && c.name.eq_ignore_ascii_case(name));
    match (hits.next(), hits.next()) {
        (Some(c), None) => Some(c.id),
        _ => None,
    }
}

/// What a connection gets from the folders above it.
#[derive(Clone, Copy)]
struct Above<'a> {
    /// The folder its saved logins stay inside (the root for a connection directly under it).
    scope: Uuid,
    /// The gateway set by the nearest folder that sets one.
    gateway: Option<Uuid>,
    /// The nearest folder that sets a credential, with it.
    credential: Option<(Uuid, &'a Folder)>,
    /// The nearest folder that names a credential, with the name.
    credential_name: Option<(&'a str, &'a Folder)>,
}

impl<'a> Above<'a> {
    /// What the children of `f` get. `parent` is what `f` itself gets and whether its parent
    /// is the root; `None` when `f` is the root.
    fn below(parent: Option<(Above<'a>, bool)>, f: &'a Folder) -> Above<'a> {
        let d = &f.defaults;
        let up = parent.map(|(above, _)| above);
        let scope = match parent {
            // A top-level folder is always a scope of its own, and so is the root for the
            // connections directly under it; deeper, only a marked folder is.
            None | Some((_, true)) => f.id,
            Some((_, false)) if d.credential_boundary == Some(true) => f.id,
            Some((above, false)) => above.scope,
        };
        Above {
            scope,
            gateway: d.gateway_id.or(up.and_then(|u| u.gateway)),
            credential: d.credential_id.map(|c| (c, f)).or(up.and_then(|u| u.credential)),
            credential_name: d.credential_name.as_deref().map(|n| (n, f)).or(up.and_then(|u| u.credential_name)),
        }
    }
}

/// Every connection in tree order with what it gets from its folders, until `each` returns
/// true. This one walk decides scope and route for the connection asked about and for every
/// connection compared with it, so the two can never be worked out differently.
fn visit<'a>(f: &'a Folder, parent: Option<(Above<'a>, bool)>, each: &mut impl FnMut(&'a Connection, Above<'a>) -> bool) -> bool {
    let here = Above::below(parent, f);
    f.children.iter().any(|n| match n {
        Node::Connection(c) => each(c, here),
        Node::Folder(sub) => visit(sub, Some((here, parent.is_none())), each),
    })
}

/// What two connections on the same host must also share before a login saved for one is
/// offered to the other.
#[derive(PartialEq, Eq)]
struct Identity<'a> {
    scope: Uuid,
    /// The effective gateway: the connection's, else its folders', else its type default's.
    gateway: Option<Uuid>,
    /// Jump hosts from an imported SSH config, as written.
    jump: Option<&'a str>,
}

fn identity<'a>(doc: &Document, c: &'a Connection, above: Above) -> Identity<'a> {
    let type_gateway = || doc.type_defaults.get(&c.protocol).and_then(|t| t.gateway_id);
    Identity {
        scope: above.scope,
        gateway: c.settings.gateway_id.or(above.gateway).or_else(type_gateway),
        jump: c.metadata.get("ProxyJump").map(|j| j.trim()).filter(|j| !j.is_empty()),
    }
}

/// Steps 1 to 3: the logins that are the connection's own, best first.
fn own_logins(vault: &Vault, c: &Connection) -> Vec<(Uuid, LoginSource)> {
    let s = &c.settings;
    let default = s.credential_id.map(|d| (d, LoginSource::Default));
    let others = s.logins.iter().map(|l| (*l, LoginSource::Connection));
    let named = s.credential_name.as_deref().and_then(|n| by_name(vault, n)).map(|n| (n, LoginSource::Named));
    default.into_iter().chain(others).chain(named).collect()
}

/// Whether the node's credential references arrived from outside and are not all the user's
/// choice yet (`Settings::credential_unconfirmed`).
fn unconfirmed(s: &Settings) -> bool {
    s.credential_unconfirmed == Some(true)
}

/// Whether `credential`, referred to by the node with settings `s`, may be used without
/// asking: the node is the user's own, or the user has chosen this credential for it.
fn chosen(s: &Settings, credential: Uuid) -> bool {
    !unconfirmed(s) || s.credential_confirmed.contains(&credential)
}

/// The user chose `credential` for the node with settings `s`. On a node whose references
/// arrived from outside this confirms that one credential, not the node: whatever else the
/// sender wrote stays offered. The mark goes once nothing unconfirmed is left (no name, and
/// every id the node refers to was chosen).
pub(crate) fn confirm(s: &mut Settings, credential: Uuid) {
    if !unconfirmed(s) {
        return;
    }
    if !s.credential_confirmed.contains(&credential) {
        s.credential_confirmed.push(credential);
    }
    let all_chosen = s.credential_id.iter().chain(&s.logins).all(|c| s.credential_confirmed.contains(c));
    if s.credential_name.is_none() && all_chosen {
        confirm_all(s);
    }
}

/// Every reference on the node is the user's choice: drop the mark.
pub(crate) fn confirm_all(s: &mut Settings) {
    s.credential_unconfirmed = None;
    s.credential_confirmed.clear();
}

/// Step 4: the login a connection without a default inherits, and whether it may be used
/// without asking (`chosen`, for the folder or type default it comes from).
fn inherited_login(doc: &Document, vault: &Vault, c: &Connection, above: Above) -> Option<(Uuid, LoginSource, bool)> {
    if c.settings.credential_id.is_some() {
        return None;
    }
    let from = |f: &Folder| LoginSource::Inherited { folder: Some(f.id), name: f.name.clone() };
    if let Some((cred, f)) = above.credential {
        return Some((cred, from(f), chosen(&f.defaults, cred)));
    }
    if let Some((name, f)) = above.credential_name {
        return by_name(vault, name).map(|cred| (cred, from(f), chosen(&f.defaults, cred)));
    }
    let t = doc.type_defaults.get(&c.protocol)?;
    let cred = t.credential_id.or_else(|| t.credential_name.as_deref().and_then(|n| by_name(vault, n)))?;
    Some((cred, LoginSource::Inherited { folder: None, name: format!("{} default", c.protocol.as_str()) }, chosen(t, cred)))
}

/// The logins `connection` can use, best first (see the module rules).
pub fn login_candidates(doc: &Document, vault: &Vault, connection: Uuid, purpose: LoginPurpose) -> Result<Vec<LoginCandidate>> {
    let mut found = None;
    visit(&doc.root, None, &mut |c, above| {
        found = (c.id == connection).then_some((c, above));
        found.is_some()
    });
    let (me, above) = found.ok_or_else(|| CoreError::NotFound(connection.to_string()))?;
    // The same refusal as `Document::resolve`: an entry of an unknown type cannot be connected
    // to, so no login is offered for it and none is released (`may_use` comes through here).
    // A plugin entry has a login of its own; the app releases it only to that plugin's view,
    // after checking the plugin is installed (`plugintypes::plugin_entry`).
    if me.protocol == Protocol::Unsupported && !crate::properties::is_plugin_entry(me) {
        return Err(CoreError::Invalid(crate::model::NEEDS_NEWER.into()));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |credential: Uuid, source: LoginSource, auto_use: bool| {
        if usable(vault, credential, purpose) && seen.insert(credential) {
            out.push(LoginCandidate { credential, source, auto_use });
        }
    };
    // Used without asking, unless the reference arrived with a received library and the user
    // has not chosen it yet: then it is offered like a same-host login.
    for (cred, src) in own_logins(vault, me) {
        push(cred, src, chosen(&me.settings, cred));
    }
    if let Some((cred, src, auto_use)) = inherited_login(doc, vault, me, above) {
        push(cred, src, auto_use);
    }
    let host = normalize_host(&me.host);
    if !host.is_empty() && !is_local(&host) {
        let mine = identity(doc, me, above);
        // An entry of a type this app does not know offers none: nothing about it is used.
        let mut same: Vec<&Connection> = Vec::new();
        visit(&doc.root, None, &mut |other, above| {
            if other.id != connection
                && other.protocol != Protocol::Unsupported
                && bare_host(&other.host).eq_ignore_ascii_case(&host)
                && identity(doc, other, above) == mine
            {
                same.push(other);
            }
            false
        });
        for other in same {
            for (cred, _) in own_logins(vault, other) {
                push(cred, LoginSource::SameHost { connection: other.id, name: other.name.clone() }, false);
            }
        }
    }
    Ok(out)
}

/// Whether `credential` is one of the logins `connection` may use for `purpose`.
pub fn may_use(doc: &Document, vault: &Vault, connection: Uuid, credential: Uuid, purpose: LoginPurpose) -> Result<bool> {
    Ok(login_candidates(doc, vault, connection, purpose)?.iter().any(|c| c.credential == credential))
}

/// Mark every credential reference in a folder that came from outside (an import, a received
/// document) as not yet chosen by the user. A node without a reference gets no mark. Plugin
/// change flags ("Allow changes") are turned off too: only the user turns them on, locally.
pub fn mark_received(folder: &mut Folder) {
    mark_settings(&mut folder.defaults);
    for n in &mut folder.children {
        match n {
            Node::Connection(c) => {
                mark_settings(&mut c.settings);
                crate::plugintypes::clear_change_flags(c);
            }
            Node::Folder(sub) => mark_received(sub),
        }
    }
}

/// `mark_received` for one node's settings (also a type's Default Settings).
pub(crate) fn mark_settings(s: &mut Settings) {
    // Nothing the file says about confirmation counts: only the user confirms, on this device.
    let has_reference = s.credential_id.is_some() || s.credential_name.is_some() || !s.logins.is_empty();
    s.credential_unconfirmed = has_reference.then_some(true);
    s.credential_confirmed.clear();
}

fn connection_mut(f: &mut Folder, id: Uuid) -> Option<&mut Connection> {
    f.children.iter_mut().find_map(|n| match n {
        Node::Connection(c) if c.id == id => Some(c),
        Node::Folder(sub) => connection_mut(sub, id),
        _ => None,
    })
}

fn with_connection<T>(doc: &mut Document, id: Uuid, f: impl FnOnce(&mut Connection) -> T) -> Result<T> {
    connection_mut(&mut doc.root, id).map(f).ok_or_else(|| CoreError::NotFound(id.to_string()))
}

/// Add a saved credential to the connection's logins; it becomes the default when there is none.
pub fn add_login(doc: &mut Document, vault: &Vault, connection: Uuid, credential: Uuid) -> Result<()> {
    if !vault.is_assignable(credential) {
        return Err(CoreError::NotFound(format!("credential {credential}")));
    }
    with_connection(doc, connection, |c| {
        let s = &mut c.settings;
        let already = s.credential_id == Some(credential) || s.logins.contains(&credential);
        if !already && s.credential_id.is_none() {
            s.credential_id = Some(credential);
        } else if !already {
            s.logins.push(credential);
        }
        // The user chose this login (also when it was already there: "use it from now on").
        confirm(s, credential);
    })
}

/// Remove a login from the connection (the credential stays in the vault). When it was the
/// default, the first other login becomes the default. Returns whether it was there.
pub fn remove_login(doc: &mut Document, connection: Uuid, credential: Uuid) -> Result<bool> {
    with_connection(doc, connection, |c| {
        let s = &mut c.settings;
        let before = s.logins.len();
        s.logins.retain(|l| *l != credential);
        if s.credential_id == Some(credential) {
            s.credential_id = (!s.logins.is_empty()).then(|| s.logins.remove(0));
            return true;
        }
        s.logins.len() != before
    })
}

/// Make `credential` the connection's default login; the old default joins the others in its place.
pub fn set_default_login(doc: &mut Document, vault: &Vault, connection: Uuid, credential: Uuid) -> Result<()> {
    if !vault.is_assignable(credential) {
        return Err(CoreError::NotFound(format!("credential {credential}")));
    }
    with_connection(doc, connection, |c| {
        let s = &mut c.settings;
        confirm(s, credential);
        if s.credential_id == Some(credential) {
            return;
        }
        let old = s.credential_id.replace(credential);
        match (s.logins.iter().position(|l| *l == credential), old) {
            (Some(i), Some(o)) => s.logins[i] = o,
            (Some(i), None) => {
                s.logins.remove(i);
            }
            (None, Some(o)) => s.logins.insert(0, o),
            (None, None) => {}
        }
    })
}

#[cfg(test)]
#[path = "logins_tests.rs"]
mod tests;
