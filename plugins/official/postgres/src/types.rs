//! Typed cells (PLUG-08b): PostgreSQL sends text; the grid gets numbers and booleans where the
//! column's type says so and the value survives the trip, so the apps align and sort them.
//! CSV, copy and local sorting keep the server's text.

use bastion_plugin_sdk::ui::Cell;

pub const BOOL: u32 = 16;
pub const INT8: u32 = 20;
pub const INT2: u32 = 21;
pub const INT4: u32 = 23;
pub const OID: u32 = 26;
pub const FLOAT4: u32 = 700;
pub const FLOAT8: u32 = 701;
pub const NUMERIC: u32 = 1700;

/// Whether the type is a number type.
pub fn is_number(oid: u32) -> bool {
    matches!(oid, INT2 | INT4 | INT8 | OID | FLOAT4 | FLOAT8 | NUMERIC)
}

/// The cell for one value of a column of type `oid`. Text is cut to `max_chars` (with `…`).
///
/// A number becomes `Cell::Number` only when the f64 prints back as the same text, so
/// `9007199254740993` (int8 past 2^53), `1.10` (numeric scale), `NaN` and `Infinity` stay text
/// and nothing shown differs from what the server sent.
pub fn cell(oid: u32, value: Option<&str>, max_chars: usize) -> Cell {
    let Some(v) = value else { return Cell::Null };
    if oid == BOOL {
        match v {
            "t" => return Cell::Boolean(true),
            "f" => return Cell::Boolean(false),
            _ => {}
        }
    }
    if is_number(oid) {
        if let Ok(n) = v.parse::<f64>() {
            if n.is_finite() && format!("{n}") == v {
                return Cell::Number(n);
            }
        }
    }
    if v.chars().count() > max_chars {
        Cell::Text(v.chars().take(max_chars).chain("…".chars()).collect())
    } else {
        Cell::Text(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Cell` has no `PartialEq` (generated from WIT); compare the debug text.
    macro_rules! same {
        ($a:expr, $b:expr $(, $m:expr)?) => { assert_eq!(format!("{:?}", $a), format!("{:?}", $b) $(, "{}", $m)?) };
    }

    #[test]
    fn typed_cells() {
        same!(cell(INT4, Some("42"), 10), Cell::Number(42.0));
        same!(cell(INT4, Some("-7"), 10), Cell::Number(-7.0));
        same!(cell(FLOAT8, Some("1.5"), 10), Cell::Number(1.5));
        same!(cell(NUMERIC, Some("0.25"), 10), Cell::Number(0.25));
        same!(cell(BOOL, Some("t"), 10), Cell::Boolean(true));
        same!(cell(BOOL, Some("f"), 10), Cell::Boolean(false));
        same!(cell(INT4, None, 10), Cell::Null);
        same!(cell(BOOL, None, 10), Cell::Null);
        // Kept as text: they would not print back the same.
        for v in ["9007199254740993", "1.10", "NaN", "Infinity", "-Infinity", "1e400", "007"] {
            same!(cell(NUMERIC, Some(v), 40), Cell::Text(v.into()), v);
        }
        same!(cell(INT8, Some("9007199254740993"), 40), Cell::Text("9007199254740993".into()));
        // Text types are text, even when they look like numbers.
        same!(cell(25, Some("42"), 10), Cell::Text("42".into()));
        same!(cell(25, Some("abcdef"), 3), Cell::Text("abc…".into()));
        same!(cell(BOOL, Some("yes"), 10), Cell::Text("yes".into()));
    }
}
