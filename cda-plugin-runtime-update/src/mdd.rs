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

use std::path::Path;

use cda_interfaces::runtime_update_api::{RuntimeUpdateError, VerificationError};

pub(crate) fn ecu_name(path: &Path) -> Result<String, RuntimeUpdateError> {
    let path = path.to_str().ok_or_else(|| {
        RuntimeUpdateError::ValidationFailed("MDD path is not valid UTF-8".to_owned())
    })?;
    cda_database::mmap_and_decode_mdd(path)
        .map(|mdd| mdd.ecu_name)
        .map_err(|error| {
            RuntimeUpdateError::ValidationFailed(format!("Failed to read MDD: {error}"))
        })
}

pub(crate) fn revision(path: &Path) -> Option<String> {
    cda_database::mmap_and_decode_mdd(path.to_str()?)
        .ok()
        .and_then(|mdd| mdd.revision)
}

pub(crate) fn validate(path: &Path) -> Result<(), VerificationError> {
    let path = path
        .to_str()
        .ok_or_else(|| VerificationError("MDD path is not valid UTF-8".to_owned()))?;
    cda_database::mmap_and_decode_mdd(path)
        .map(|_mdd| ())
        .map_err(|error| VerificationError(format!("Failed to read MDD: {error}")))
}
