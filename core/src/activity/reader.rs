//! Activity store: reading a monthly file from its last line to its first.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;

use super::*;

pub(super) fn contains(line: &[u8], needle: &[u8]) -> bool {
    line.windows(needle.len()).any(|w| w == needle)
}

/// Visit the lines of `file` from the last to the first, reading backwards in blocks, until
/// `visit` returns false. Empty lines and lines longer than [`MAX_LINE_BYTES`] are passed over
/// without being held in memory.
pub(super) fn for_each_line_back(file: &mut File, mut visit: impl FnMut(&[u8]) -> bool) -> Result<()> {
    let mut pos = file.metadata()?.len();
    // The tail of a line whose beginning lies in an earlier block.
    let mut carry: Vec<u8> = Vec::new();
    // Inside a line that is too long: drop bytes until its beginning has been passed.
    let mut skipping = false;
    while pos > 0 {
        let n = (READ_BLOCK as u64).min(pos) as usize;
        pos -= n as u64;
        let mut block = vec![0u8; n];
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut block)?;
        let mut end = if skipping {
            match block.iter().rposition(|b| *b == b'\n') {
                Some(i) => {
                    skipping = false;
                    i
                }
                None => continue,
            }
        } else {
            block.append(&mut carry);
            block.len()
        };
        while let Some(i) = block[..end].iter().rposition(|b| *b == b'\n') {
            let line = &block[i + 1..end];
            if !line.is_empty() && line.len() <= MAX_LINE_BYTES && !visit(line) {
                return Ok(());
            }
            end = i;
        }
        // `block[..end]` is the first line of the file, or the tail of a line that began earlier.
        if pos == 0 {
            if end > 0 && end <= MAX_LINE_BYTES {
                visit(&block[..end]);
            }
        } else if end > MAX_LINE_BYTES {
            skipping = true;
        } else {
            carry = block[..end].to_vec();
        }
    }
    Ok(())
}

