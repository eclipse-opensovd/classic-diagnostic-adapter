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

//! MDD implementation of [`RuntimeFileInspector`].
//!
//! Keeps the flatbuffer/MDD specifics here rather than in
//! `cda-plugin-runtime-update`, so that plugin stays format-agnostic and an OEM
//! can substitute a different database format by supplying its own inspector.

use cda_interfaces::runtime_update_api::{
    RuntimeFileInspector, RuntimeUpdateError, VerificationError,
};

/// Reads MDD (flatbuffer) diagnostic database files.
#[derive(Debug, Default, Clone, Copy)]
pub struct MddFileInspector;

impl MddFileInspector {
    /// `cda_database` addresses files by `&str`, so a non-UTF-8 path cannot be
    /// passed through at all; report it rather than lossily converting.
    fn as_utf8(path: &std::path::Path) -> Option<&str> {
        path.to_str()
    }
}

impl RuntimeFileInspector for MddFileInspector {
    fn validate(&self, path: &std::path::Path) -> Result<(), VerificationError> {
        let path_str = Self::as_utf8(path)
            .ok_or_else(|| VerificationError(format!("Invalid UTF-8 path: {}", path.display())))?;
        cda_database::mmap_and_decode_mdd(path_str).map_err(|error| {
            VerificationError(format!("Failed to parse MDD '{}': {error}", path.display()))
        })?;
        Ok(())
    }

    fn ecu_name(&self, path: &std::path::Path) -> Result<String, RuntimeUpdateError> {
        let path_str = Self::as_utf8(path).ok_or_else(|| {
            RuntimeUpdateError::ValidationFailed(format!(
                "MDD path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        cda_database::mmap_and_decode_mdd(path_str)
            .map(|mdd| mdd.ecu_name)
            .map_err(|error| {
                RuntimeUpdateError::ValidationFailed(format!("Failed to read MDD: {error}"))
            })
    }

    fn revision(&self, path: &std::path::Path) -> Option<String> {
        cda_database::mmap_and_decode_mdd(Self::as_utf8(path)?)
            .ok()
            .and_then(|mdd| mdd.revision)
    }

    fn decompress_in_place(&self, path: &std::path::Path) -> Result<(), RuntimeUpdateError> {
        let path_str = Self::as_utf8(path).ok_or_else(|| {
            RuntimeUpdateError::ValidationFailed(format!(
                "MDD path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        // The `bool` reports whether anything was rewritten; an already-decompressed
        // file is a success either way.
        cda_database::update_mdd_uncompressed(path_str)
            .map(|_rewritten| ())
            .map_err(|error| {
                RuntimeUpdateError::ValidationFailed(format!("Failed to decompress MDD: {error}"))
            })
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::runtime_update_api::RuntimeFileInspector;

    use super::MddFileInspector;

    #[test]
    fn validate_rejects_a_file_that_is_not_an_mdd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-an-mdd.mdd");
        std::fs::write(&path, b"definitely not a flatbuffer").expect("write");

        assert!(
            MddFileInspector.validate(&path).is_err(),
            "a malformed file must not pass validation"
        );
    }

    #[test]
    fn revision_reports_absent_rather_than_failing_for_unreadable_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.mdd");

        assert_eq!(
            MddFileInspector.revision(&path),
            None,
            "an unreadable file must report no revision, not error"
        );
    }

    #[test]
    fn ecu_name_fails_for_unreadable_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing.mdd");

        assert!(MddFileInspector.ecu_name(&path).is_err());
    }
}
