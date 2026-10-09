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

//! Path sanitization utilities for safe filesystem operations.
//!
//! When the `sanitize-paths` feature is enabled, all collection names and keys are validated
//! before being used as filesystem path components. This prevents directory traversal attacks
//! where malicious input containing `..` or `/` could escape the storage root.
//!
//! Without the feature, validation is a no-op -- suitable for deployments where all callers
//! are trusted internal code.

use cda_interfaces::storage_api::StorageError;

/// Validate that a string is safe to use as a single filesystem path component.
///
/// When the `sanitize-paths` feature is enabled, this rejects:
/// - Empty strings
/// - `"."` or `".."`
/// - Strings containing path separators (`/` or `\`)
/// - Strings containing null bytes
///
/// Without the feature, this always succeeds (no-op).
///
/// # Errors
///
/// Returns [`StorageError::Other`] if the segment is invalid.
#[cfg(feature = "sanitize-paths")]
pub(crate) fn sanitize_path_segment(segment: &str) -> Result<(), StorageError> {
    if segment.is_empty() {
        return Err(StorageError::Other(
            "Path segment must not be empty".to_string(),
        ));
    }

    if segment == "." || segment == ".." {
        return Err(StorageError::Other(format!(
            "Path segment must not be a relative reference: {segment:?}"
        )));
    }

    if segment.contains('/') || segment.contains('\\') {
        return Err(StorageError::Other(format!(
            "Path segment must not contain separators: {segment:?}"
        )));
    }

    if segment.contains('\0') {
        return Err(StorageError::Other(format!(
            "Path segment must not contain null bytes: {segment:?}"
        )));
    }

    Ok(())
}

/// No-op path validation when the `sanitize-paths` feature is disabled.
#[cfg(not(feature = "sanitize-paths"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Signature must match the feature-enabled variant"
)]
pub(crate) fn sanitize_path_segment(_segment: &str) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_segments_accepted() {
        assert!(sanitize_path_segment("my_collection").is_ok());
        assert!(sanitize_path_segment("key-name").is_ok());
        assert!(sanitize_path_segment("data.json").is_ok());
        assert!(sanitize_path_segment("a").is_ok());
        assert!(sanitize_path_segment("123").is_ok());
    }

    #[cfg(feature = "sanitize-paths")]
    mod with_feature {
        use super::*;

        #[test]
        fn empty_string_rejected() {
            let result = sanitize_path_segment("");
            assert!(result.is_err());
        }

        #[test]
        fn dot_rejected() {
            let result = sanitize_path_segment(".");
            assert!(result.is_err());
        }

        #[test]
        fn dot_dot_rejected() {
            let result = sanitize_path_segment("..");
            assert!(result.is_err());
        }

        #[test]
        fn forward_slash_rejected() {
            let result = sanitize_path_segment("foo/bar");
            assert!(result.is_err());
        }

        #[test]
        fn backslash_rejected() {
            let result = sanitize_path_segment("foo\\bar");
            assert!(result.is_err());
        }

        #[test]
        fn null_byte_rejected() {
            let result = sanitize_path_segment("foo\0bar");
            assert!(result.is_err());
        }

        #[test]
        fn dot_prefix_allowed() {
            // ".hidden" is a valid single path component (not "." or "..")
            assert!(sanitize_path_segment(".hidden").is_ok());
        }

        #[test]
        fn triple_dot_allowed() {
            // "..." is unusual but not a traversal vector
            assert!(sanitize_path_segment("...").is_ok());
        }
    }
}
