/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

// Duration::from_mins is only available in rust >= 1.91.0, we want to support 1.88.0
#![cfg_attr(
    nightly,
    allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "from_mins/from_hours not available in Rust 1.88"
    )
)]

mod sovd;
mod util;
