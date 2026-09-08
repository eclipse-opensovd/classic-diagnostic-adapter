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

//! Default MDD implementation of [`DatabaseValidator`].

use cda_interfaces::runtime_update_api::{DatabaseValidator, VerificationError};

/// Reads MDD (flatbuffer) diagnostic database files.
#[derive(Debug, Default, Clone, Copy)]
pub struct MddDatabaseValidator;

impl DatabaseValidator for MddDatabaseValidator {
    fn check_integrity(&self, path: &std::path::Path) -> Result<(), VerificationError> {
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
    use cda_interfaces::runtime_update_api::DatabaseValidator;

    use super::MddDatabaseValidator;

    #[test]
    fn check_integrity_rejects_a_file_that_is_not_an_mdd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.mdd");
        std::fs::write(&path, b"not a valid mdd file").expect("write");

        assert!(MddDatabaseValidator.check_integrity(&path).is_err());
    }

    #[test]
    fn check_integrity_rejects_a_nonexistent_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.mdd");

        assert!(MddDatabaseValidator.check_integrity(&path).is_err());
    }
}
