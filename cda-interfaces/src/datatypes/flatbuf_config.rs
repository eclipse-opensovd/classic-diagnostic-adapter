/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use serde::{Deserialize, Serialize};

/// `FlatBuffers` verification settings for MDD database parsing.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct FlatbBufConfig {
    /// Enable `FlatBuffers` verification on loaded MDD data.
    pub verify: bool,
    /// Maximum nesting depth allowed during `FlatBuffers` verification.
    pub max_depth: usize,
    /// Maximum number of tables allowed during `FlatBuffers` verification.
    pub max_tables: usize,
    /// Maximum apparent buffer size in bytes for `FlatBuffers` verification.
    pub max_apparent_size: usize,
    /// Skip null terminator validation in `FlatBuffers` strings.
    pub ignore_missing_null_terminator: bool,
    /// Enable decompression of MDD database files.
    pub mdd_decompress: bool,
}

impl Default for FlatbBufConfig {
    fn default() -> Self {
        FlatbBufConfig {
            verify: false,
            max_depth: 64,
            max_tables: 100_000_000,
            // Internally the toml parsing is using i64, as intermediate
            // representation, so we need to set the max_apparent_size to i64::MAX
            // to prevent out-of-range value for usize type
            // Truncation must be accepted, as the toml file doesn't support
            // larger values anyway. If this turns out to be a problem,
            // we can consider using a custom deserializer for this field
            // or remove it from the config.
            #[allow(clippy::cast_possible_truncation)]
            max_apparent_size: i64::MAX as usize,
            ignore_missing_null_terminator: false,
            mdd_decompress: false,
        }
    }
}
