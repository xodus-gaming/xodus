use chrono::DateTime;

/// Converts a Microsoft FILETIME (number of 100ns intervals since 1601-01-01 UTC)
/// into a [`chrono::DateTime`]
pub const fn microsoft_filetime(filetime: i64) -> DateTime<chrono::Utc> {
    // FILETIME counts 100ns intervals since 1601-01-01 UTC.
    // Unix time counts nanoseconds since 1970-01-01 UTC.

    /// Number of 100 nanoseconds between FILETIME epoch and Unix time
    const FILETIME_TO_UNIX: i64 = 116_444_736_000_000_000;

    let unix_nanos = (filetime - FILETIME_TO_UNIX) * 100;
    DateTime::from_timestamp_nanos(unix_nanos)
}
