//! Frames, message kinds, view lists and the update rate (spec section 5, "Messages" and
//! "UI components"; T18.4, T18.25).
//!
//! Two kinds of failure are kept apart. A [`ProtocolViolation`] can only come from a broken
//! or compromised helper and kills it. A [`Failure::Invalid`] is a limit over that a plain
//! plugin bug can cause through the normal API; the view is refused and the helper keeps running.

use std::collections::{HashMap, VecDeque};

use super::{Failure, ProtocolViolation};

/// Largest frame between the core and a helper.
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;
/// Nodes in one view.
pub const MAX_VIEW_NODES: usize = 2_000;
/// Bytes of one view, as encoded.
pub const MAX_VIEW_BYTES: usize = 256 * 1024;
/// Nesting depth of one view (a root node has depth 1).
pub const MAX_VIEW_DEPTH: usize = 32;
/// View updates per second per view.
pub const MAX_UPDATES_PER_SECOND: usize = 30;

/// Check a frame's length prefix before anything is allocated for it.
pub fn check_frame_len(len: u32) -> Result<usize, ProtocolViolation> {
    if len == 0 {
        return Err(ProtocolViolation("empty frame".into()));
    }
    if len > MAX_FRAME_BYTES {
        return Err(ProtocolViolation(format!("frame of {len} bytes is over the {MAX_FRAME_BYTES}-byte cap")));
    }
    Ok(len as usize)
}

/// Which kind of helper sent a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperKind {
    /// Runs plugin code; never sends compiled code.
    View,
    /// Compiles one plugin hash; runs no plugin code and sends only its sandbox report, the
    /// compiled code and its end.
    Compile,
}

/// The message kinds a helper can send, as far as the broker's decisions need them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromHelper {
    SandboxReport,
    CompiledCode,
    CompileDone,
    Call,
    ViewUpdate,
    Log,
    Pong,
}

/// Whether `kind` may come from a helper of `helper` kind, in the state "sandbox report
/// accepted" or not. The first message must be the sandbox report; the core sends nothing else
/// until it has accepted it.
pub fn check_message(helper: HelperKind, sandbox_accepted: bool, kind: FromHelper) -> Result<(), ProtocolViolation> {
    if !sandbox_accepted {
        return if kind == FromHelper::SandboxReport { Ok(()) } else { Err(ProtocolViolation("the first message must be the sandbox report".into())) };
    }
    if kind == FromHelper::SandboxReport {
        return Err(ProtocolViolation("a second sandbox report".into()));
    }
    let ok = match helper {
        HelperKind::View => !matches!(kind, FromHelper::CompiledCode | FromHelper::CompileDone),
        HelperKind::Compile => matches!(kind, FromHelper::CompiledCode | FromHelper::CompileDone | FromHelper::Pong),
    };
    if ok {
        Ok(())
    } else if helper == HelperKind::View {
        Err(ProtocolViolation("a helper that runs plugin code sent compiled code".into()))
    } else {
        Err(ProtocolViolation("a compile helper sent a message only a view helper may send".into()))
    }
}

/// One node of a flat view list: its id and its parent's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRef {
    pub id: u32,
    pub parent: Option<u32>,
}

/// Check a view list before any renderer sees it: size, node count, duplicate ids, unknown
/// parents, cycles and depth. Iterative, so a hostile list cannot exhaust the stack.
pub fn check_view(nodes: &[NodeRef], encoded_bytes: usize) -> Result<(), Failure> {
    if encoded_bytes > MAX_VIEW_BYTES {
        return Err(Failure::Invalid(format!("the view is over {MAX_VIEW_BYTES} bytes")));
    }
    if nodes.len() > MAX_VIEW_NODES {
        return Err(Failure::Invalid(format!("the view has more than {MAX_VIEW_NODES} nodes")));
    }
    let mut parent_of: HashMap<u32, Option<u32>> = HashMap::with_capacity(nodes.len());
    for n in nodes {
        if parent_of.insert(n.id, n.parent).is_some() {
            return Err(Failure::Invalid(format!("node id {} is used twice", n.id)));
        }
    }
    for n in nodes {
        if let Some(p) = n.parent {
            if !parent_of.contains_key(&p) {
                return Err(Failure::Invalid(format!("node {} names an unknown parent", n.id)));
            }
        }
    }
    // Depth of each node, memoised; a walk longer than the node count is a cycle.
    let mut depth: HashMap<u32, usize> = HashMap::with_capacity(nodes.len());
    let mut path: Vec<u32> = Vec::new();
    for n in nodes {
        path.clear();
        let mut cur = n.id;
        let base = loop {
            if let Some(d) = depth.get(&cur) {
                break *d;
            }
            path.push(cur);
            if path.len() > nodes.len() {
                return Err(Failure::Invalid("the view's parent links form a cycle".into()));
            }
            match parent_of[&cur] {
                Some(p) => cur = p,
                None => break 0,
            }
        };
        for (i, id) in path.iter().rev().enumerate() {
            let d = base + i + 1;
            if d > MAX_VIEW_DEPTH {
                return Err(Failure::Invalid(format!("the view is nested deeper than {MAX_VIEW_DEPTH}")));
            }
            depth.insert(*id, d);
        }
    }
    Ok(())
}

/// The view after a patch: `remove` and every node under one dropped, then `upsert` replacing
/// nodes by id or added. A patch's nodes may hang under nodes it does not resend, so the core
/// checks this result with [`check_view`], not the patch alone. Iterative, bounded by the input.
pub fn patched_view(current: &[NodeRef], upsert: &[NodeRef], remove: &[u32]) -> Vec<NodeRef> {
    let mut gone: std::collections::HashSet<u32> = remove.iter().copied().collect();
    // Descendants of a removed node go too; each pass adds at least one id or stops.
    loop {
        let before = gone.len();
        for n in current {
            if n.parent.is_some_and(|p| gone.contains(&p)) {
                gone.insert(n.id);
            }
        }
        if gone.len() == before {
            break;
        }
    }
    let replaced: HashMap<u32, NodeRef> = upsert.iter().map(|n| (n.id, *n)).collect();
    let mut out: Vec<NodeRef> = current.iter().filter(|n| !gone.contains(&n.id)).map(|n| replaced.get(&n.id).copied().unwrap_or(*n)).collect();
    let known: std::collections::HashSet<u32> = out.iter().map(|n| n.id).collect();
    let mut added = std::collections::HashSet::new();
    out.extend(upsert.iter().filter(|n| !known.contains(&n.id) && added.insert(n.id)).copied());
    out
}

/// The update rate of one view. Updates past 30 a second are held back, not refused; the core
/// applies the newest held update when the window allows.
#[derive(Debug, Default)]
pub struct UpdateRate {
    times: VecDeque<u64>,
}

impl UpdateRate {
    pub fn new() -> UpdateRate {
        UpdateRate::default()
    }

    /// Whether an update arriving at `now_ms` may be applied now (`true`) or is held back.
    pub fn admit(&mut self, now_ms: u64) -> bool {
        while self.times.front().is_some_and(|t| now_ms.saturating_sub(*t) >= 1_000) {
            self.times.pop_front();
        }
        if self.times.len() >= MAX_UPDATES_PER_SECOND {
            return false;
        }
        self.times.push_back(now_ms);
        true
    }
}
