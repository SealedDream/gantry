//! Split panes of one terminal tab: a tree whose leaves carry pane ids, the operations the
//! apps apply to it (split, close, resize, equalize, move focus by direction) and the
//! conversion to and from the saved `workspace::PaneLayout`. Pure rules; the apps own the shells.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::workspace::{clamp_ratio, PaneLayout, SplitAxis, RATIO_EVEN};

/// Most panes one tab may hold (each is a shell; more would be unreadable anyway).
pub const MAX_PANES: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum PaneTree {
    Leaf { id: Uuid },
    Split {
        axis: SplitAxis,
        ratio: f32,
        first: Box<PaneTree>,
        second: Box<PaneTree>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Left,
    Right,
    Up,
    Down,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "op")]
pub enum PaneOp {
    /// Split `pane`; the new shell `new_pane` goes right of or below it and takes focus.
    #[serde(rename_all = "camelCase")]
    Split { pane: Uuid, axis: SplitAxis, new_pane: Uuid },
    /// Close `pane`; its sibling takes its space and focus.
    Close { pane: Uuid },
    /// Move the nearest divider of `axis` around `pane` by `delta` (positive = right/down).
    Resize { pane: Uuid, axis: SplitAxis, delta: f32 },
    /// Every split back to even.
    Equalize,
    /// The pane next to `pane` in `direction` (no change when there is none).
    Focus { pane: Uuid, direction: Direction },
}

/// Result of an operation. `tree` is `None` once the last pane is closed (the app closes the tab).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PaneOutcome {
    pub tree: Option<PaneTree>,
    pub focus: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Rect {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
}

impl PaneTree {
    pub fn single(id: Uuid) -> Self {
        PaneTree::Leaf { id }
    }

    /// Pane ids in reading order (left to right, top to bottom).
    pub fn panes(&self) -> Vec<Uuid> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut Vec<Uuid>) {
        match self {
            PaneTree::Leaf { id } => out.push(*id),
            PaneTree::Split { first, second, .. } => {
                first.collect(out);
                second.collect(out);
            }
        }
    }

    pub fn contains(&self, pane: &Uuid) -> bool {
        self.panes().contains(pane)
    }

    /// The saved shape, without ids.
    pub fn to_layout(&self) -> PaneLayout {
        match self {
            PaneTree::Leaf { .. } => PaneLayout::Leaf,
            PaneTree::Split { axis, ratio, first, second } => PaneLayout::Split {
                axis: *axis,
                ratio: clamp_ratio(*ratio),
                first: Box::new(first.to_layout()),
                second: Box::new(second.to_layout()),
            },
        }
    }

    /// A live tree for a saved shape; `new_id` names each pane in reading order. Shapes over
    /// `MAX_PANES` are refused (a hand-edited file can hold anything).
    pub fn from_layout(layout: &PaneLayout, mut new_id: impl FnMut() -> Uuid) -> Result<Self> {
        if layout.leaves() > MAX_PANES {
            return Err(too_many());
        }
        Ok(Self::build(&layout.clamped(), &mut new_id))
    }

    fn build(layout: &PaneLayout, new_id: &mut impl FnMut() -> Uuid) -> Self {
        match layout {
            PaneLayout::Leaf => PaneTree::Leaf { id: new_id() },
            PaneLayout::Split { axis, ratio, first, second } => PaneTree::Split {
                axis: *axis,
                ratio: *ratio,
                first: Box::new(Self::build(first, new_id)),
                second: Box::new(Self::build(second, new_id)),
            },
        }
    }

    pub fn apply(&self, op: &PaneOp) -> Result<PaneOutcome> {
        match op {
            PaneOp::Split { pane, axis, new_pane } => {
                self.require(pane)?;
                if self.contains(new_pane) {
                    return Err(CoreError::Invalid("That pane id is already in use.".into()));
                }
                if self.panes().len() >= MAX_PANES {
                    return Err(too_many());
                }
                Ok(PaneOutcome { tree: Some(self.split(pane, *axis, *new_pane)), focus: Some(*new_pane) })
            }
            PaneOp::Close { pane } => {
                self.require(pane)?;
                let order = self.panes();
                let tree = self.without(pane);
                let focus = tree.as_ref().and_then(|t| sibling_focus(&order, pane, t));
                Ok(PaneOutcome { tree, focus })
            }
            PaneOp::Resize { pane, axis, delta } => {
                self.require(pane)?;
                if !delta.is_finite() {
                    return Err(CoreError::Invalid("The resize amount must be a number.".into()));
                }
                let mut tree = self.clone();
                tree.resize(pane, *axis, *delta);
                Ok(PaneOutcome { tree: Some(tree), focus: Some(*pane) })
            }
            PaneOp::Equalize => Ok(PaneOutcome { tree: Some(self.equalized()), focus: None }),
            PaneOp::Focus { pane, direction } => {
                self.require(pane)?;
                let target = self.neighbour(pane, *direction).unwrap_or(*pane);
                Ok(PaneOutcome { tree: Some(self.clone()), focus: Some(target) })
            }
        }
    }

    fn require(&self, pane: &Uuid) -> Result<()> {
        if self.contains(pane) { Ok(()) } else { Err(CoreError::NotFound(format!("pane {pane}"))) }
    }

    fn split(&self, pane: &Uuid, axis: SplitAxis, new_pane: Uuid) -> Self {
        match self {
            PaneTree::Leaf { id } if id == pane => PaneTree::Split {
                axis,
                ratio: RATIO_EVEN,
                first: Box::new(self.clone()),
                second: Box::new(PaneTree::Leaf { id: new_pane }),
            },
            PaneTree::Leaf { .. } => self.clone(),
            PaneTree::Split { axis: a, ratio, first, second } => PaneTree::Split {
                axis: *a,
                ratio: *ratio,
                first: Box::new(first.split(pane, axis, new_pane)),
                second: Box::new(second.split(pane, axis, new_pane)),
            },
        }
    }

    fn without(&self, pane: &Uuid) -> Option<Self> {
        match self {
            PaneTree::Leaf { id } if id == pane => None,
            PaneTree::Leaf { .. } => Some(self.clone()),
            PaneTree::Split { axis, ratio, first, second } => match (first.without(pane), second.without(pane)) {
                (Some(f), Some(s)) => Some(PaneTree::Split { axis: *axis, ratio: *ratio, first: Box::new(f), second: Box::new(s) }),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            },
        }
    }

    /// Returns whether a divider was moved, so only the innermost matching split changes.
    fn resize(&mut self, pane: &Uuid, axis: SplitAxis, delta: f32) -> bool {
        let PaneTree::Split { axis: a, ratio, first, second } = self else { return false };
        if first.resize(pane, axis, delta) || second.resize(pane, axis, delta) {
            return true;
        }
        if *a == axis && (first.contains(pane) || second.contains(pane)) {
            *ratio = clamp_ratio(*ratio + delta);
            return true;
        }
        false
    }

    fn equalized(&self) -> Self {
        match self {
            PaneTree::Leaf { .. } => self.clone(),
            PaneTree::Split { axis, first, second, .. } => PaneTree::Split {
                axis: *axis,
                ratio: RATIO_EVEN,
                first: Box::new(first.equalized()),
                second: Box::new(second.equalized()),
            },
        }
    }

    fn rects(&self, r: Rect, out: &mut Vec<(Uuid, Rect)>) {
        match self {
            PaneTree::Leaf { id } => out.push((*id, r)),
            PaneTree::Split { axis, ratio, first, second } => {
                let (a, b) = match axis {
                    SplitAxis::Right => {
                        let w = r.w * ratio;
                        (Rect { w, ..r }, Rect { x: r.x + w, w: r.w - w, ..r })
                    }
                    SplitAxis::Down => {
                        let h = r.h * ratio;
                        (Rect { h, ..r }, Rect { y: r.y + h, h: r.h - h, ..r })
                    }
                };
                first.rects(a, out);
                second.rects(b, out);
            }
        }
    }

    /// The touching pane in `dir` with the most shared edge; ties go to the top/left one.
    fn neighbour(&self, pane: &Uuid, dir: Direction) -> Option<Uuid> {
        const EPS: f32 = 1e-4;
        let mut all = Vec::new();
        self.rects(Rect { x: 0.0, y: 0.0, w: 1.0, h: 1.0 }, &mut all);
        let me = all.iter().find(|(id, _)| id == pane)?.1;
        let overlap = |a0: f32, a1: f32, b0: f32, b1: f32| (a1.min(b1) - a0.max(b0)).max(0.0);
        all.iter()
            .filter(|(id, _)| id != pane)
            .filter_map(|(id, r)| {
                let touches = match dir {
                    Direction::Left => (r.x + r.w - me.x).abs() < EPS,
                    Direction::Right => (me.x + me.w - r.x).abs() < EPS,
                    Direction::Up => (r.y + r.h - me.y).abs() < EPS,
                    Direction::Down => (me.y + me.h - r.y).abs() < EPS,
                };
                let shared = match dir {
                    Direction::Left | Direction::Right => overlap(me.y, me.y + me.h, r.y, r.y + r.h),
                    Direction::Up | Direction::Down => overlap(me.x, me.x + me.w, r.x, r.x + r.w),
                };
                (touches && shared > EPS).then_some((*id, shared))
            })
            .fold(None, |best: Option<(Uuid, f32)>, cand| match best {
                Some(b) if b.1 >= cand.1 - EPS => Some(b),
                _ => Some(cand),
            })
            .map(|(id, _)| id)
    }
}

/// After a close, focus the pane that came just before it in reading order (or the first).
fn sibling_focus(order: &[Uuid], closed: &Uuid, tree: &PaneTree) -> Option<Uuid> {
    let left = tree.panes();
    let at = order.iter().position(|p| p == closed)?;
    order[..at].iter().rev().find(|p| left.contains(p)).or_else(|| left.first()).copied()
}

fn too_many() -> CoreError {
    CoreError::Invalid(format!("A tab holds at most {MAX_PANES} panes."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    fn split(t: &PaneTree, pane: u8, axis: SplitAxis, new: u8) -> PaneTree {
        t.apply(&PaneOp::Split { pane: id(pane), axis, new_pane: id(new) }).unwrap().tree.unwrap()
    }

    /// Pane 1 on the left; 2 above 3 on the right.
    fn three() -> PaneTree {
        let t = split(&PaneTree::single(id(1)), 1, SplitAxis::Right, 2);
        split(&t, 2, SplitAxis::Down, 3)
    }

    #[test]
    fn split_adds_pane_and_focuses_it() {
        let out = PaneTree::single(id(1)).apply(&PaneOp::Split { pane: id(1), axis: SplitAxis::Right, new_pane: id(2) }).unwrap();
        assert_eq!(out.focus, Some(id(2)));
        assert_eq!(out.tree.unwrap().panes(), vec![id(1), id(2)]);
    }

    #[test]
    fn split_refuses_unknown_duplicate_and_too_many() {
        let t = three();
        assert!(t.apply(&PaneOp::Split { pane: id(9), axis: SplitAxis::Down, new_pane: id(8) }).is_err());
        assert!(t.apply(&PaneOp::Split { pane: id(1), axis: SplitAxis::Down, new_pane: id(2) }).is_err());
        let mut t = PaneTree::single(id(0));
        for n in 1..MAX_PANES as u8 {
            t = split(&t, n - 1, SplitAxis::Down, n);
        }
        assert_eq!(t.panes().len(), MAX_PANES);
        assert!(t.apply(&PaneOp::Split { pane: id(0), axis: SplitAxis::Down, new_pane: id(99) }).is_err());
    }

    #[test]
    fn close_collapses_split_and_moves_focus_back() {
        let out = three().apply(&PaneOp::Close { pane: id(3) }).unwrap();
        assert_eq!(out.tree.as_ref().unwrap().panes(), vec![id(1), id(2)]);
        assert_eq!(out.focus, Some(id(2)));
        let out = three().apply(&PaneOp::Close { pane: id(1) }).unwrap();
        assert_eq!(out.focus, Some(id(2)));
        let last = PaneTree::single(id(1)).apply(&PaneOp::Close { pane: id(1) }).unwrap();
        assert_eq!(last, PaneOutcome { tree: None, focus: None });
    }

    #[test]
    fn focus_moves_by_geometry() {
        let t = three();
        let f = |p, d| t.apply(&PaneOp::Focus { pane: id(p), direction: d }).unwrap().focus.unwrap();
        assert_eq!(f(1, Direction::Right), id(2), "tie goes to the top pane");
        assert_eq!(f(3, Direction::Left), id(1));
        assert_eq!(f(2, Direction::Down), id(3));
        assert_eq!(f(3, Direction::Up), id(2));
        assert_eq!(f(1, Direction::Left), id(1), "no neighbour keeps focus");
    }

    #[test]
    fn resize_moves_innermost_matching_divider_and_clamps() {
        let t = three();
        let r = t.apply(&PaneOp::Resize { pane: id(3), axis: SplitAxis::Down, delta: 0.2 }).unwrap().tree.unwrap();
        let PaneTree::Split { ratio: outer, second, .. } = &r else { panic!() };
        assert_eq!(*outer, 0.5);
        let PaneTree::Split { ratio: inner, .. } = second.as_ref() else { panic!() };
        assert!((inner - 0.7).abs() < 1e-6);
        let r = t.apply(&PaneOp::Resize { pane: id(3), axis: SplitAxis::Right, delta: -5.0 }).unwrap().tree.unwrap();
        let PaneTree::Split { ratio, .. } = &r else { panic!() };
        assert_eq!(*ratio, crate::workspace::RATIO_MIN);
        assert!(t.apply(&PaneOp::Resize { pane: id(3), axis: SplitAxis::Right, delta: f32::NAN }).is_err());
        let eq = r.apply(&PaneOp::Equalize).unwrap().tree.unwrap();
        assert_eq!(eq, three());
    }

    #[test]
    fn layout_round_trip_and_limit() {
        let t = three();
        let layout = t.to_layout();
        let mut n = 0u8;
        let back = PaneTree::from_layout(&layout, || {
            n += 1;
            id(n)
        })
        .unwrap();
        assert_eq!(back, t);
        let mut big = PaneLayout::Leaf;
        for _ in 0..MAX_PANES {
            big = PaneLayout::Split { axis: SplitAxis::Down, ratio: 0.5, first: Box::new(big), second: Box::new(PaneLayout::Leaf) };
        }
        assert!(PaneTree::from_layout(&big, Uuid::new_v4).is_err());
    }

    #[test]
    fn json_shapes() {
        let op: PaneOp = serde_json::from_str(&format!(r#"{{"op":"split","pane":"{}","axis":"down","newPane":"{}"}}"#, id(1), id(2))).unwrap();
        assert!(matches!(op, PaneOp::Split { axis: SplitAxis::Down, .. }));
        let json = serde_json::to_value(three()).unwrap();
        assert_eq!(json["kind"], "split");
        assert_eq!(json["first"]["kind"], "leaf");
    }
}
