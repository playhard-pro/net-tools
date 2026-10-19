//! Timestamp parsing and IANA timezone conversion for the Utils tab.

use chrono::{
    DateTime, Datelike, Local, LocalResult, NaiveDate, NaiveDateTime, Offset, SecondsFormat,
    TimeZone, Utc,
};
use chrono_tz::{OffsetName, Tz};

use crate::model::TimestampUnit;

/// Formatted time in one timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneTime {
    /// Timezone name shown in the result.
    pub zone: String,
    /// Local date and time including milliseconds.
    pub date_time: String,
    /// UTC offset such as `UTC+08:00`.
    pub offset: String,
    /// Timezone abbreviation such as `CST` or `BST`.
    pub abbreviation: String,
}

/// Result of one timestamp conversion.
#[derive(Debug, Clone)]
pub struct TimestampConversion {
    pub input: String,
    /// Unit actually used for a numeric timestamp.
    pub unit: &'static str,
    pub local: ZoneTime,
    pub utc: ZoneTime,
    /// One row for each configured target zone.
    pub zones: Vec<ZoneTime>,
    pub rfc3339: String,
    pub unix_seconds: i64,
    pub unix_millis: i64,
    pub unix_micros: i64,
    pub unix_nanos: i64,
    pub weekday: String,
    pub iso_week: String,
    pub relative: String,
}

/// Parse a timestamp or date-time and convert it to the requested zones.
///
/// Numeric input is interpreted according to `unit`; `Auto` chooses a unit from
/// the magnitude. Text input may be RFC 3339 or a local date/time interpreted in
/// `source_zone`.
pub fn convert(
    input: &str,
    unit: TimestampUnit,
    source_zone: &str,
    target_zones: &[String],
) -> Result<TimestampConversion, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("enter a timestamp or date/time".to_string());
    }
    let source_tz = parse_zone(source_zone)?;
    let (utc, used_unit) = parse_timestamp(input, unit, source_tz)?;

    let local = local_zone_time(utc);
    let utc_row = utc_zone_time(utc);
    let mut zones = Vec::with_capacity(target_zones.len());
    for name in target_zones {
        let tz = parse_zone(name)?;
        zones.push(zone_time(utc, tz, name));
    }

    let unix_nanos = utc
        .timestamp_nanos_opt()
        .ok_or_else(|| "timestamp is outside the supported Unix nanosecond range".to_string())?;
    let iso = utc.iso_week();
    let relative = relative_text(Utc::now().signed_duration_since(utc).num_seconds());

    Ok(TimestampConversion {
        input: input.to_string(),
        unit: used_unit,
        local,
        utc: utc_row,
        zones,
        rfc3339: utc.to_rfc3339_opts(SecondsFormat::Millis, true),
        unix_seconds: utc.timestamp(),
        unix_millis: utc.timestamp_millis(),
        unix_micros: utc.timestamp_micros(),
        unix_nanos,
        weekday: utc.format("%A").to_string(),
        iso_week: format!("{:04}-W{:02}", iso.year(), iso.week()),
        relative,
    })
}

/// Parse an IANA timezone name.
pub fn parse_zone(name: &str) -> Result<Tz, String> {
    name.trim()
        .parse::<Tz>()
        .map_err(|_| format!("`{}` is not a known IANA timezone", name.trim()))
}

/// All IANA timezone names, sorted alphabetically.
pub fn timezone_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = chrono_tz::TZ_VARIANTS.iter().map(|tz| tz.name()).collect();
    names.sort_unstable();
    names
}

fn parse_timestamp(
    input: &str,
    unit: TimestampUnit,
    source_tz: Tz,
) -> Result<(DateTime<Utc>, &'static str), String> {
    if looks_numeric(input) {
        return parse_numeric(input, unit);
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(input) {
        return Ok((parsed.with_timezone(&Utc), "text"));
    }
    // RFC 3339 allows a space instead of `T`; accept it as well.
    if let Ok(parsed) = DateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S%.f%:z") {
        return Ok((parsed.with_timezone(&Utc), "text"));
    }
    if let Ok(parsed) = DateTime::parse_from_str(input, "%Y-%m-%d %H:%M%:z") {
        return Ok((parsed.with_timezone(&Utc), "text"));
    }

    let naive = parse_naive(input)?;
    match source_tz.from_local_datetime(&naive) {
        LocalResult::Single(value) => Ok((value.with_timezone(&Utc), "text")),
        LocalResult::Ambiguous(_, _) => Err(
            "that local time is ambiguous because of a daylight-saving transition; add an offset"
                .to_string(),
        ),
        LocalResult::None => Err(
            "that local time does not exist because of a daylight-saving transition".to_string(),
        ),
    }
}

fn parse_naive(input: &str) -> Result<NaiveDateTime, String> {
    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(value) = NaiveDateTime::parse_from_str(input, format) {
            return Ok(value);
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        return Ok(date
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always a valid time"));
    }
    Err(format!(
        "`{input}` is not a Unix timestamp, RFC 3339 value, or YYYY-MM-DD HH:MM:SS date/time"
    ))
}

fn looks_numeric(input: &str) -> bool {
    let mut digits = 0;
    let mut separators = 0;
    for (index, character) in input.chars().enumerate() {
        if character.is_ascii_digit() {
            digits += 1;
        } else if (matches!(character, '-' | '+') && index == 0) || character == '.' {
            separators += 1;
        } else {
            return false;
        }
    }
    digits > 0 && separators <= 1
}

fn parse_numeric(
    input: &str,
    unit: TimestampUnit,
) -> Result<(DateTime<Utc>, &'static str), String> {
    // Keep integer input as an integer so nanosecond timestamps do not lose
    // precision through an f64 conversion.
    let (nanos, used_unit) = if input.contains('.') {
        let value: f64 = input
            .parse()
            .map_err(|_| format!("`{input}` is not a valid numeric timestamp"))?;
        let unit = resolve_unit(unit, value.abs());
        let factor = unit_factor(unit) as f64;
        let nanos = (value * factor).round();
        if !nanos.is_finite() || nanos.abs() > i64::MAX as f64 {
            return Err("timestamp is outside the supported range".to_string());
        }
        (nanos as i128, unit)
    } else {
        let value: i128 = input
            .parse()
            .map_err(|_| format!("`{input}` is not a valid numeric timestamp"))?;
        let unit = resolve_unit(unit, value.unsigned_abs() as f64);
        let nanos = value
            .checked_mul(unit_factor(unit) as i128)
            .ok_or_else(|| "timestamp is outside the supported range".to_string())?;
        (nanos, unit)
    };

    let seconds = nanos.div_euclid(1_000_000_000);
    let subsec = nanos.rem_euclid(1_000_000_000);
    let seconds = i64::try_from(seconds)
        .map_err(|_| "timestamp is outside the supported range".to_string())?;
    let value = DateTime::<Utc>::from_timestamp(seconds, subsec as u32)
        .ok_or_else(|| "timestamp is outside the supported calendar range".to_string())?;
    Ok((value, unit_name(used_unit)))
}

fn resolve_unit(unit: TimestampUnit, magnitude: f64) -> TimestampUnit {
    match unit {
        TimestampUnit::Auto => {
            if magnitude >= 1e17 {
                TimestampUnit::Nanoseconds
            } else if magnitude >= 1e14 {
                TimestampUnit::Microseconds
            } else if magnitude >= 1e11 {
                TimestampUnit::Milliseconds
            } else {
                TimestampUnit::Seconds
            }
        }
        other => other,
    }
}

fn unit_factor(unit: TimestampUnit) -> u64 {
    match unit {
        TimestampUnit::Auto | TimestampUnit::Seconds => 1_000_000_000,
        TimestampUnit::Milliseconds => 1_000_000,
        TimestampUnit::Microseconds => 1_000,
        TimestampUnit::Nanoseconds => 1,
    }
}

fn unit_name(unit: TimestampUnit) -> &'static str {
    match unit {
        TimestampUnit::Auto | TimestampUnit::Seconds => "seconds",
        TimestampUnit::Milliseconds => "milliseconds",
        TimestampUnit::Microseconds => "microseconds",
        TimestampUnit::Nanoseconds => "nanoseconds",
    }
}

fn zone_time(utc: DateTime<Utc>, timezone: Tz, name: &str) -> ZoneTime {
    let value = utc.with_timezone(&timezone);
    let offset = value.offset().fix().local_minus_utc();
    ZoneTime {
        zone: name.to_string(),
        date_time: value.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        offset: format_offset(offset),
        abbreviation: value
            .offset()
            .abbreviation()
            .unwrap_or_default()
            .to_string(),
    }
}

fn utc_zone_time(utc: DateTime<Utc>) -> ZoneTime {
    ZoneTime {
        zone: "UTC".to_string(),
        date_time: utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        offset: "UTC+00:00".to_string(),
        abbreviation: "UTC".to_string(),
    }
}

fn local_zone_time(utc: DateTime<Utc>) -> ZoneTime {
    let value = utc.with_timezone(&Local);
    let offset = value.offset().fix().local_minus_utc();
    ZoneTime {
        zone: "Local".to_string(),
        date_time: value.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        offset: format_offset(offset),
        abbreviation: value.format("%Z").to_string(),
    }
}

fn format_offset(seconds: i32) -> String {
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.unsigned_abs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    format!("UTC{sign}{hours:02}:{minutes:02}")
}

fn relative_text(delta_seconds: i64) -> String {
    if delta_seconds.abs() < 2 {
        return "now".to_string();
    }
    let (value, unit) = if delta_seconds.abs() < 60 {
        (delta_seconds, "second")
    } else if delta_seconds.abs() < 3_600 {
        (delta_seconds / 60, "minute")
    } else if delta_seconds.abs() < 86_400 {
        (delta_seconds / 3_600, "hour")
    } else if delta_seconds.abs() < 2_592_000 {
        (delta_seconds / 86_400, "day")
    } else if delta_seconds.abs() < 31_536_000 {
        (delta_seconds / 2_592_000, "month")
    } else {
        (delta_seconds / 31_536_000, "year")
    };
    let suffix = if value < 0 { "ago" } else { "from now" };
    let value = value.abs();
    let plural = if value == 1 { "" } else { "s" };
    if suffix == "ago" {
        format!("{value} {unit}{plural} ago")
    } else {
        format!("in {value} {unit}{plural}")
    }
}

/// Current Unix time in seconds, used by the "Now" button.
pub fn now_unix_seconds() -> i64 {
    Utc::now().timestamp()
}

/// Build a readable date/time without a timezone, used for hints and tests.
pub fn format_naive(value: NaiveDateTime) -> String {
    value.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_units_are_converted() {
        let result = convert("0", TimestampUnit::Auto, "UTC", &["Asia/Shanghai".into()]).unwrap();
        assert_eq!(result.utc.date_time, "1970-01-01 00:00:00.000");
        assert_eq!(result.unit, "seconds");
        assert_eq!(result.zones[0].offset, "UTC+08:00");
        assert_eq!(result.zones[0].date_time, "1970-01-01 08:00:00.000");
    }

    #[test]
    fn auto_detects_milliseconds_and_microseconds() {
        let millis = convert("1700000000000", TimestampUnit::Auto, "UTC", &[]).unwrap();
        assert_eq!(millis.unit, "milliseconds");
        assert_eq!(millis.unix_seconds, 1_700_000_000);

        let micros = convert("1700000000000000", TimestampUnit::Auto, "UTC", &[]).unwrap();
        assert_eq!(micros.unit, "microseconds");
        assert_eq!(micros.unix_seconds, 1_700_000_000);
    }

    #[test]
    fn numeric_units_and_negative_values_work() {
        let result = convert("-1", TimestampUnit::Seconds, "UTC", &[]).unwrap();
        assert_eq!(result.unix_seconds, -1);
        assert_eq!(result.utc.date_time, "1969-12-31 23:59:59.000");
    }

    #[test]
    fn rfc3339_input_keeps_its_offset() {
        let result = convert("2024-01-02T03:04:05+08:00", TimestampUnit::Auto, "UTC", &[]).unwrap();
        assert_eq!(result.utc.date_time, "2024-01-01 19:04:05.000");
        assert_eq!(result.rfc3339, "2024-01-01T19:04:05.000Z");
    }

    #[test]
    fn naive_input_uses_the_source_zone() {
        let result = convert(
            "2024-01-02 03:04:05",
            TimestampUnit::Auto,
            "Asia/Shanghai",
            &[],
        )
        .unwrap();
        assert_eq!(result.utc.date_time, "2024-01-01 19:04:05.000");
    }

    #[test]
    fn daylight_saving_transitions_are_handled() {
        let winter = convert(
            "2024-01-02 12:00:00",
            TimestampUnit::Auto,
            "Europe/London",
            &[],
        )
        .unwrap();
        assert_eq!(winter.utc.date_time, "2024-01-02 12:00:00.000");

        let summer = convert(
            "2024-07-02 12:00:00",
            TimestampUnit::Auto,
            "Europe/London",
            &[],
        )
        .unwrap();
        assert_eq!(summer.utc.date_time, "2024-07-02 11:00:00.000");

        // New York skips 02:30 when daylight saving starts.
        let gap = convert(
            "2024-03-10 02:30:00",
            TimestampUnit::Auto,
            "America/New_York",
            &[],
        );
        assert!(gap.is_err());
    }

    #[test]
    fn invalid_zone_and_text_are_rejected() {
        assert!(convert("2024-01-01", TimestampUnit::Auto, "Not/AZone", &[]).is_err());
        assert!(convert("not a timestamp", TimestampUnit::Auto, "UTC", &[]).is_err());
    }

    #[test]
    fn timezone_list_contains_common_names() {
        let names = timezone_names();
        assert!(names.contains(&"UTC"));
        assert!(names.contains(&"Asia/Shanghai"));
        assert!(names.contains(&"Europe/London"));
    }
}
