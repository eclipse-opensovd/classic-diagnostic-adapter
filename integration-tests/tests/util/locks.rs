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

//! Lock test data shared by the lock and runtime file tests. Locks
//! themselves are created with the client, see
//! [`client::locks`](crate::client::locks).

use std::time::Duration;

/// A token of another client than the default test client, which does not
/// own the locks of the test.
// must be skipped due to conflicting formatter rules between nightly and stable
#[rustfmt::skip]
pub(crate) const NON_OWNER_BEARER_TOKEN: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lcnNoaXAtdGVzdCIsImV4cCI6MjAwMDAwMDAwMH0.\
     _qb-vSkPnV_Lff2wNH4VXugc-DcvGdzJxwTmb4J48Xs";

/// A lock expiration long enough for any test.
pub(crate) fn default_timeout() -> Duration {
    Duration::from_secs(3600)
}
