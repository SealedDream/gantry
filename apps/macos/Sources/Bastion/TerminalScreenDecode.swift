import Foundation
import BastionCore

extension Terminal {
    /// The screen through the packed FFI layout (`screenPacked`), decoded into the usual
    /// `TermScreen`. One blob crosses the bridge instead of a record and a string per cell,
    /// which kept a full-screen copy at ~15 ms and every keystroke echo a frame late.
    func fastScreen() -> TermScreen {
        let p = screenPacked()
        return TermScreen(cols: p.cols, rows: p.rows, cells: Self.decodeCells(p.cells, count: Int(p.cols) * Int(p.rows)),
                          cursorRow: p.cursorRow, cursorCol: p.cursorCol, cursorVisible: p.cursorVisible,
                          appCursor: p.appCursor, title: p.title, background: p.background,
                          generation: p.generation, alive: p.alive)
    }

    /// Bytes per cell before its text (fg u32, bg u32, flags, text length).
    private static let cellHeader = 10

    static func decodeCells(_ data: Data, count: Int) -> [TermCell] {
        var cells: [TermCell] = []
        cells.reserveCapacity(count)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var i = 0
            while i + cellHeader <= raw.count {
                let fg = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: i, as: UInt32.self))
                let bg = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: i + 4, as: UInt32.self))
                let flags = raw[i + 8]
                let n = Int(raw[i + 9])
                let start = i + cellHeader
                // A truncated buffer (never expected) ends the grid instead of reading past it.
                guard start + n <= raw.count else { break }
                let text = String(decoding: UnsafeRawBufferPointer(rebasing: raw[start..<start + n]), as: UTF8.self)
                cells.append(TermCell(text: text, fg: fg, bg: bg, bold: flags & 1 != 0, italic: flags & 2 != 0,
                                      underline: flags & 4 != 0, selected: flags & 8 != 0, matched: flags & 16 != 0))
                i = start + n
            }
        }
        // Drawing indexes cols * rows cells: pad a short grid with blanks rather than crash.
        while cells.count < count {
            cells.append(TermCell(text: " ", fg: 0, bg: 0, bold: false, italic: false, underline: false, selected: false, matched: false))
        }
        return cells
    }
}
