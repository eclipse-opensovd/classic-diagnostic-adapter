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

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, schemars::JsonSchema, Debug)]
pub struct RuntimeUpdateConfig {
    /// Maximum upload body size in bytes for multipart file uploads.
    /// Default: 50MB. Axum's built-in limit is 2MB which is too low for MDD files.
    pub upload_body_limit_bytes: usize,
    /// Directory where the updatable database is stored.
    pub storage_dir: String,
    /// Value of the Retry-After header (in seconds) sent when the service is
    /// temporarily unavailable due to a busy transaction.
    /// Default: 1 second.
    #[serde(default = "default_retry_after_seconds")]
    pub retry_after_seconds: u64,
    /// When `true` and the `DiagnosticDatabase` storage collection is absent,
    /// seed it from `database.seed_dir` on first startup by copying all `.mdd` files.
    /// An existing collection, including an empty one, remains authoritative.
    /// Default: `false`.
    #[serde(default)]
    pub init_storage_from_database_path: bool,
}

fn default_retry_after_seconds() -> u64 {
    1
}

impl Default for RuntimeUpdateConfig {
    fn default() -> Self {
        Self {
            upload_body_limit_bytes: 50 * 1024 * 1024, // 50 MB,
            storage_dir: ".".to_owned(),
            retry_after_seconds: default_retry_after_seconds(),
            init_storage_from_database_path: false,
        }
    }
}
