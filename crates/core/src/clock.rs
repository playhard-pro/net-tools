//! Wall-clock timestamps for probe results.

use time::macros::format_description;
use time::OffsetDateTime;

/// Format the current local time down to milliseconds.
///
/// The local offset is used when the platform can provide it and UTC is used
/// otherwise, so a probe is always labelled with an absolute time.
pub fn now_string() -> String {
    let format =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&format)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_has_millis() {
        let s = now_string();
        assert_eq!(s.len(), 23, "unexpected timestamp: {s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], " ");
        assert_eq!(&s[19..20], ".");
    }
}
