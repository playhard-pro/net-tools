//! Result export (CSV / JSON / HTML) and the save dialog.

/// Open a native save dialog and write the content.
pub fn save_file(name: &str, ext: &str, content: &str) {
    if let Some(path) = rfd::FileDialog::new()
        .set_file_name(format!("{name}.{ext}"))
        .add_filter(ext.to_uppercase(), &[ext])
        .save_file()
    {
        let _ = std::fs::write(path, content);
    }
}

/// Escape one value for CSV. Values containing a separator, a quote or a line
/// break are quoted, with embedded quotes doubled.
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Split one CSV line into fields, honouring quoted fields.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

/// Convert CSV text into a simple HTML table.
pub fn csv_to_html(csv: &str) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><style>table{border-collapse:collapse}td,th{border:1px solid #888;padding:4px 8px;font-family:monospace}</style></head><body><table>\n",
    );
    for (i, line) in csv.lines().enumerate() {
        let tag = if i == 0 { "th" } else { "td" };
        out.push_str("<tr>");
        for cell in parse_csv_line(line) {
            let cell = cell
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            out.push_str(&format!("<{tag}>{cell}</{tag}>"));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</table></body></html>\n");
    out
}
