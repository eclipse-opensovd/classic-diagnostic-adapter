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

//! Default implementation of [`MddValidator`].
//!
//! Provides structural MDD validation for installations without an OEM-specific
//! validation policy.

use cda_interfaces::runtime_update_api::{MddValidator, VerificationError};

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultMddValidator;

impl MddValidator for DefaultMddValidator {
    fn validate(&self, path: &std::path::Path) -> Result<(), VerificationError> {
        let path_str = path
            .to_str()
            .ok_or_else(|| VerificationError(format!("Invalid UTF-8 path: {}", path.display())))?;
        cda_database::mmap_and_decode_mdd(path_str).map_err(|error| {
            VerificationError(format!("Failed to parse MDD '{}': {error}", path.display()))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::runtime_update_api::MddValidator;

    use super::DefaultMddValidator;

    #[test]
    fn validate_rejects_a_file_that_is_not_an_mdd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-an-mdd.mdd");
        std::fs::write(&path, b"definitely not a flatbuffer").expect("write");

        assert!(
            DefaultMddValidator.validate(&path).is_err(),
            "a malformed file must not pass validation"
        );
    }
}
