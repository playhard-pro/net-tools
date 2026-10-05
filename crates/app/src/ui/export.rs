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

/// Convert CSV text into a simple HTML table.
pub fn csv_to_html(csv: &str) -> String {
    let mut out = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><style>table{border-collapse:collapse}td,th{border:1px solid #888;padding:4px 8px;font-family:monospace}</style></head><body><table>\n",
    );
    for (i, line) in csv.lines().enumerate() {
        let tag = if i == 0 { "th" } else { "td" };
        out.push_str("<tr>");
        for cell in line.split(',') {
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
