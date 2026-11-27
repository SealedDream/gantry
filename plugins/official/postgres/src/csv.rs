//! CSV export (RFC 4180) and tab-separated copy of a result.
//!
//! A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`
//! in CSV (unless the cell is a plain number), so a spreadsheet does not run a value from the database as a formula.

fn needs_guard(cell: &str) -> bool {
    // A plain number such as -1 is data, not a formula.
    if cell.parse::<f64>().is_ok() {
        return false;
    }
    matches!(cell.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'))
}

fn csv_cell(out: &mut String, cell: &str) {
    let guarded;
    let cell = if needs_guard(cell) {
        guarded = format!("'{cell}");
        guarded.as_str()
    } else {
        cell
    };
    if cell.contains([',', '"', '\n', '\r']) {
        out.push('"');
        out.push_str(&cell.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(cell);
    }
}

/// The header and the rows as CSV, CRLF line ends. NULL is an empty cell.
pub fn csv(header: &[String], rows: &[Vec<Option<String>>]) -> String {
    let mut out = String::new();
    let line = |out: &mut String, cells: &mut dyn Iterator<Item = &str>| {
        for (i, c) in cells.enumerate() {
            if i > 0 {
                out.push(',');
            }
            csv_cell(out, c);
        }
        out.push_str("\r\n");
    };
    line(&mut out, &mut header.iter().map(String::as_str));
    for r in rows {
        line(&mut out, &mut r.iter().map(|c| c.as_deref().unwrap_or("")));
    }
    out
}

/// Rows as tab-separated text for the clipboard; tabs and line breaks in cells become spaces.
pub fn tsv(rows: &[&Vec<Option<String>>]) -> String {
    rows.iter()
        .map(|r| r.iter().map(|c| c.as_deref().unwrap_or("").replace(['\t', '\n', '\r'], " ")).collect::<Vec<_>>().join("\t"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_commas_newlines_nulls_and_formulas() {
        let header = vec!["a".to_string(), "b,c".to_string()];
        let rows = vec![vec![Some("x\"y".into()), None], vec![Some("line\nbreak".into()), Some("=HYPERLINK(\"evil\")".into())], vec![Some("-1".into()), Some("@x".into())]];
        assert_eq!(csv(&header, &rows), "a,\"b,c\"\r\n\"x\"\"y\",\r\n\"line\nbreak\",\"'=HYPERLINK(\"\"evil\"\")\"\r\n-1,'@x\r\n");
    }

    #[test]
    fn tsv_flattens_cells() {
        let r = vec![Some("a\tb".to_string()), None, Some("c\nd".to_string())];
        assert_eq!(tsv(&[&r, &r]), "a b\t\tc d\na b\t\tc d");
    }
}
