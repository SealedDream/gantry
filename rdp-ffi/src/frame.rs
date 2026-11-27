//! The desktop picture shared between the session task and the frontend, with the regions that
//! changed since the frontend last looked, so a 1080p session does not copy 8 MB per update.
use ironrdp_pdu::geometry::InclusiveRectangle;

/// Past this many pending rectangles their bounding box is cheaper to hand over than the list.
const MAX_PENDING_RECTS: usize = 256;

/// One changed region of the desktop, BGRA rows packed tightly (`width * 4` bytes each).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RdpDirtyRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub bgra: Vec<u8>,
}

/// What changed since `after_serial`. When `full` is set the single rect covers the whole
/// desktop (first frame, resize, or the consumer fell behind) and replaces the old picture.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RdpFrameUpdate {
    pub width: u16,
    pub height: u16,
    pub serial: u64,
    pub full: bool,
    pub rects: Vec<RdpDirtyRect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    /// Clips an inclusive IronRDP rectangle to a `width` x `height` picture.
    pub fn clipped(r: &InclusiveRectangle, width: u16, height: u16) -> Option<Rect> {
        if r.left >= width || r.top >= height || r.right < r.left || r.bottom < r.top {
            return None;
        }
        let right = r.right.min(width - 1);
        let bottom = r.bottom.min(height - 1);
        Some(Rect { x: r.left, y: r.top, width: right - r.left + 1, height: bottom - r.top + 1 })
    }
}

/// RGBA picture plus the pending damage since the serial the frontend last took.
#[derive(Debug, Default)]
pub struct Picture {
    pub width: u16,
    pub height: u16,
    pub serial: u64,
    rgba: Vec<u8>,
    pending: Vec<Rect>,
    /// Serial the pending list starts from; a consumer at any other serial gets a full frame.
    pending_since: u64,
    needs_full: bool,
}

impl Picture {
    pub fn is_empty(&self) -> bool {
        self.rgba.is_empty()
    }

    /// Replaces the whole picture (connect, reactivation, graphics reset).
    pub fn replace(&mut self, width: u16, height: u16, rgba: &[u8]) {
        self.width = width;
        self.height = height;
        self.rgba.clear();
        self.rgba.extend_from_slice(rgba);
        self.pending.clear();
        self.needs_full = true;
        self.serial += 1;
    }

    /// Copies only `regions` from `source` (a full RGBA image of the same size).
    pub fn apply(&mut self, source: &[u8], regions: &[InclusiveRectangle]) {
        let stride = usize::from(self.width) * 4;
        let mut changed = false;
        for r in regions.iter().filter_map(|r| Rect::clipped(r, self.width, self.height)) {
            let (x, w) = (usize::from(r.x) * 4, usize::from(r.width) * 4);
            for row in usize::from(r.y)..usize::from(r.y) + usize::from(r.height) {
                let at = row * stride + x;
                self.rgba[at..at + w].copy_from_slice(&source[at..at + w]);
            }
            if !self.needs_full {
                self.pending.push(r);
            }
            changed = true;
        }
        if self.pending.len() > MAX_PENDING_RECTS {
            // Video frames arrive as hundreds of small tiles: hand over their bounding box.
            let b = bounding(&self.pending);
            self.pending.clear();
            self.pending.push(b);
        }
        if changed {
            self.serial += 1;
        }
    }

    /// The whole picture as BGRA.
    pub fn bgra(&self) -> Vec<u8> {
        swizzled(&self.rgba)
    }

    /// Changes since `after_serial`, or `None` when there are none. Built for one consumer:
    /// taking an update resets the pending list.
    pub fn take_update(&mut self, after_serial: u64) -> Option<RdpFrameUpdate> {
        if self.serial == after_serial || self.rgba.is_empty() {
            return None;
        }
        let full = self.needs_full || after_serial != self.pending_since;
        let rects = if full {
            vec![RdpDirtyRect { x: 0, y: 0, width: self.width, height: self.height, bgra: self.bgra() }]
        } else {
            self.pending.iter().map(|r| self.extract(*r)).collect()
        };
        self.pending.clear();
        self.needs_full = false;
        self.pending_since = self.serial;
        Some(RdpFrameUpdate { width: self.width, height: self.height, serial: self.serial, full, rects })
    }

    fn extract(&self, r: Rect) -> RdpDirtyRect {
        let stride = usize::from(self.width) * 4;
        let (x, w) = (usize::from(r.x) * 4, usize::from(r.width) * 4);
        let mut bgra = Vec::with_capacity(w * usize::from(r.height));
        for row in usize::from(r.y)..usize::from(r.y) + usize::from(r.height) {
            let at = row * stride + x;
            bgra.extend_from_slice(&self.rgba[at..at + w]);
        }
        RdpDirtyRect { x: r.x, y: r.y, width: r.width, height: r.height, bgra: swizzled(&bgra) }
    }
}

fn bounding(rects: &[Rect]) -> Rect {
    let x = rects.iter().map(|r| r.x).min().unwrap_or(0);
    let y = rects.iter().map(|r| r.y).min().unwrap_or(0);
    let right = rects.iter().map(|r| r.x + r.width).max().unwrap_or(0);
    let bottom = rects.iter().map(|r| r.y + r.height).max().unwrap_or(0);
    Rect { x, y, width: right - x, height: bottom - y }
}

fn swizzled(rgba: &[u8]) -> Vec<u8> {
    let mut out = rgba.to_vec();
    for px in out.chunks_exact_mut(4) {
        px.swap(0, 2);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(left: u16, top: u16, right: u16, bottom: u16) -> InclusiveRectangle {
        InclusiveRectangle { left, top, right, bottom }
    }

    /// 4x2 picture whose pixel n is RGBA (n, 0, 0xff, 0xff) in `source`.
    fn source() -> Vec<u8> {
        (0..8u8).flat_map(|n| [n, 0, 0xff, 0xff]).collect()
    }

    #[test]
    fn first_update_is_full_and_swizzled_to_bgra() {
        let mut p = Picture::default();
        p.replace(4, 2, &source());
        let u = p.take_update(0).unwrap();
        assert!(u.full);
        assert_eq!(u.rects.len(), 1);
        assert_eq!(&u.rects[0].bgra[..4], &[0xff, 0, 0, 0xff]);
        assert!(p.take_update(u.serial).is_none());
    }

    #[test]
    fn later_updates_carry_only_damaged_regions() {
        let mut p = Picture::default();
        p.replace(4, 2, &[0; 32]);
        let s = p.take_update(0).unwrap().serial;
        p.apply(&source(), &[rect(1, 1, 2, 1)]);
        let u = p.take_update(s).unwrap();
        assert!(!u.full);
        assert_eq!(u.rects.len(), 1);
        let r = &u.rects[0];
        assert_eq!((r.x, r.y, r.width, r.height), (1, 1, 2, 1));
        assert_eq!(r.bgra, vec![0xff, 0, 5, 0xff, 0xff, 0, 6, 0xff]);
        // Untouched pixels keep their old value.
        assert_eq!(&p.bgra()[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn regions_are_clipped_to_the_picture() {
        assert_eq!(Rect::clipped(&rect(2, 0, 100, 100), 4, 2), Some(Rect { x: 2, y: 0, width: 2, height: 2 }));
        assert_eq!(Rect::clipped(&rect(4, 0, 5, 1), 4, 2), None);
        let mut p = Picture::default();
        p.replace(4, 2, &[0; 32]);
        p.apply(&source(), &[rect(3, 1, 900, 900)]);
        assert_eq!(&p.bgra()[28..], &[0xff, 0, 7, 0xff]);
    }

    #[test]
    fn a_consumer_that_missed_updates_gets_a_full_frame() {
        let mut p = Picture::default();
        p.replace(4, 2, &[0; 32]);
        let s = p.take_update(0).unwrap().serial;
        p.apply(&source(), &[rect(0, 0, 0, 0)]);
        assert!(p.take_update(s - 1).unwrap().full);
    }

    #[test]
    fn too_many_rects_collapse_to_their_bounding_box() {
        let mut p = Picture::default();
        p.replace(4, 2, &[0; 32]);
        let s = p.take_update(0).unwrap().serial;
        let mut many = vec![rect(1, 0, 1, 0); MAX_PENDING_RECTS];
        many.push(rect(2, 1, 2, 1));
        p.apply(&source(), &many);
        let u = p.take_update(s).unwrap();
        assert!(!u.full);
        assert_eq!(u.rects.len(), 1);
        assert_eq!((u.rects[0].x, u.rects[0].y, u.rects[0].width, u.rects[0].height), (1, 0, 2, 2));
    }

    #[test]
    fn empty_damage_does_not_bump_the_serial() {
        let mut p = Picture::default();
        p.replace(4, 2, &[0; 32]);
        let s = p.serial;
        p.apply(&source(), &[]);
        assert_eq!(p.serial, s);
    }
}
