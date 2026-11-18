//! Wall-clock time in the forms the vault and Duo exchange.
//!
//! Stored timestamps keep the exact RFC 3339 shape earlier releases wrote
//! (`+00:00`, with 0, 3, 6, or 9 fraction digits): they are compared and
//! ordered as text, and older clients read them.
use jiff::{SignedDuration, Timestamp, tz::TimeZone};

pub(crate) fn now() -> Timestamp {
    Timestamp::now()
}

/// Whole seconds since the Unix epoch, clamped at zero.
pub(crate) fn unix_seconds() -> u64 {
    u64::try_from(now().as_second()).unwrap_or(0)
}

/// The canonical stored form of `at`.
pub(crate) fn rfc3339(at: Timestamp) -> String {
    let civil = TimeZone::UTC.to_datetime(at);
    let nanos = civil.subsec_nanosecond();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!("{}{fraction}+00:00", civil.strftime("%Y-%m-%dT%H:%M:%S"))
}

/// Reads RFC 3339, or the `YYYY-MM-DD HH:MM:SS[.f] +HH:MM` form some imports use.
pub(crate) fn parse(value: &str) -> Option<Timestamp> {
    value.parse::<Timestamp>().ok().or_else(|| {
        jiff::fmt::strtime::parse("%Y-%m-%d %H:%M:%S%.f %:z", value)
            .ok()?
            .to_timestamp()
            .ok()
    })
}

/// `days` as a duration, or `None` when it cannot be represented.
pub(crate) fn days(days: u64) -> Option<SignedDuration> {
    i64::try_from(days)
        .ok()?
        .checked_mul(86_400)
        .map(SignedDuration::from_secs)
}

/// The `Date` header form Duo signs, such as `Wed, 18 Nov 2026 19:42:33 +0000`.
pub(crate) fn rfc2822(at: Timestamp) -> String {
    jiff::fmt::rfc2822::to_string(&at.to_zoned(TimeZone::UTC))
        .expect("UTC timestamps are always representable in RFC 2822")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from the `chrono` calls earlier releases used
    /// (`to_rfc3339`, `to_rfc2822`, and its two parsers).
    #[test]
    fn stored_and_signed_forms_match_earlier_releases() {
        for (seconds, nanos, stored, signed) in [
            (
                0,
                0,
                "1970-01-01T00:00:00+00:00",
                "Thu, 1 Jan 1970 00:00:00 +0000",
            ),
            (
                1_779_000_000,
                120_000_000,
                "2026-05-17T06:40:00.120+00:00",
                "Sun, 17 May 2026 06:40:00 +0000",
            ),
            (
                1_779_000_000,
                123_456_000,
                "2026-05-17T06:40:00.123456+00:00",
                "Sun, 17 May 2026 06:40:00 +0000",
            ),
            (
                4_102_444_799,
                123_456_789,
                "2099-12-31T23:59:59.123456789+00:00",
                "Thu, 31 Dec 2099 23:59:59 +0000",
            ),
            (
                1_700_000_000,
                1,
                "2023-11-14T22:13:20.000000001+00:00",
                "Tue, 14 Nov 2023 22:13:20 +0000",
            ),
        ] {
            let at = Timestamp::new(seconds, nanos).unwrap();
            assert_eq!(rfc3339(at), stored);
            assert_eq!(rfc2822(at), signed);
            assert_eq!(parse(stored), Some(at), "stored values round-trip");
        }
    }

    #[test]
    fn parsing_accepts_what_earlier_releases_accepted() {
        for (value, stored) in [
            ("2020-01-01T00:00:00Z", "2020-01-01T00:00:00+00:00"),
            ("2020-01-01T01:00:00+01:00", "2020-01-01T00:00:00+00:00"),
            ("2020-01-01t00:00:00z", "2020-01-01T00:00:00+00:00"),
            (
                "2026-11-18T19:42:33.964119200+00:00",
                "2026-11-18T19:42:33.964119200+00:00",
            ),
            (
                "2026-11-18T19:42:33.9+05:30",
                "2026-11-18T14:12:33.900+00:00",
            ),
            ("2020-01-01 00:00:00 +00:00", "2020-01-01T00:00:00+00:00"),
            (
                "2020-01-01 00:00:00.25 -07:00",
                "2020-01-01T07:00:00.250+00:00",
            ),
        ] {
            assert_eq!(
                parse(value).map(rfc3339).as_deref(),
                Some(stored),
                "{value}"
            );
        }
        for invalid in ["", "yesterday", "2020-13-01T00:00:00Z", "2020-01-01"] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
        assert_eq!(days(2), Some(SignedDuration::from_hours(48)));
        assert_eq!(days(u64::MAX), None);
    }
}
