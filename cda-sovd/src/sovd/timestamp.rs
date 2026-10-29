/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Shared timestamp formatting for the SOVD API.

use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

/// Formats a point in time as an RFC 3339 timestamp as used by the SOVD API.
///
/// The timestamp is always expressed in UTC with second precision and the `Z`
/// suffix, e.g. `2026-01-02T03:04:05Z`.
pub(crate) fn system_time_to_rfc3339(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn formats_utc_with_z_suffix_and_second_precision() {
        let time = UNIX_EPOCH + Duration::from_millis(1_767_323_045_678);
        assert_eq!(system_time_to_rfc3339(time), "2026-01-02T03:04:05Z");
    }

    #[test]
    fn formats_unix_epoch() {
        assert_eq!(system_time_to_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
