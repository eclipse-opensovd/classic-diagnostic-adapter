/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FlatbBufConfig {
    pub verify: bool,
    pub max_depth: usize,
    pub max_tables: usize,
    pub max_apparent_size: usize,
    pub ignore_missing_null_terminator: bool,
}

impl Default for FlatbBufConfig {
    fn default() -> Self {
        FlatbBufConfig {
            verify: false,
            max_depth: 64,
            max_tables: 100_000_000,
            max_apparent_size: usize::MAX,
            ignore_missing_null_terminator: false,
        }
    }
}
