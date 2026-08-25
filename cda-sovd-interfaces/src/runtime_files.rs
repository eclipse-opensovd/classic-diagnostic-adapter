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

//! ISO 17978-3 bulk-data wire shapes for the runtime-files endpoints.
//!
//! These live here rather than in `cda-interfaces` because they are the HTTP
//! representation, not the update plugin's vocabulary: `mimetype`, the duplicate
//! `name`, the `x-sovd2uds-*` field names and the schema envelope are all things a
//! plugin would otherwise have to produce without ever using. The plugin reports
//! [`RuntimeFile`](cda_interfaces::runtime_update_api::RuntimeFile); `cda-sovd`
//! converts.

use serde::{Deserialize, Serialize};

/// Hash algorithm for bulk-data integrity checks (ISO 17978-3).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
}

/// A single item in a bulk-data creation response (Table 303 shape).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataCreated {
    /// Bulk-data identifier created by the SOVD server to identify the bulk-data.
    pub id: String,
}

/// Response body for deleting all bulk-data in a category (ISO 17978-3 Table 306).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataDeleted {
    pub deleted_ids: Vec<String>,
    // spec requires an errors array to be present, however with transaction semantics
    // this will always be an empty array
    pub errors: Vec<BulkDataDeletionError>,
}

/// A bulk-data item that could not be deleted and its reason.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataDeletionError {
    pub id: String,
    pub error: serde_json::Value,
}

/// Generic list wrapper used for bulk-data responses.
#[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
pub struct BulkDataItems<T> {
    pub items: Vec<T>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

impl<T> Default for BulkDataItems<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            schema: None,
        }
    }
}

/// A bulk-data descriptor as defined by ISO 17978-3, Table 298.
#[derive(Serialize, Deserialize, Debug, Clone, schemars::JsonSchema)]
pub struct BulkDataDescriptor {
    pub id: String,
    pub mimetype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<HashAlgorithm>,
    #[serde(
        rename = "x-sovd2uds-OrigPath",
        skip_serializing_if = "Option::is_none"
    )]
    pub origin_path: Option<String>,
    #[serde(
        rename = "x-sovd2uds-revision",
        skip_serializing_if = "Option::is_none"
    )]
    pub revision: Option<String>,
}

/// Response body for bulk-data list endpoints (`BulkDataDescriptor` follows Table 298 shape).
pub type BulkDataList = BulkDataItems<BulkDataDescriptor>;

/// Response body for bulk-data creation (Table 303 shape).
pub type BulkDataCreatedList = BulkDataItems<BulkDataCreated>;

/// Query parameters for runtime file list endpoints.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct RuntimeFilesQuery {
    #[serde(rename = "include-schema", default)]
    pub include_schema: bool,
    #[serde(rename = "x-sovd2uds-include-hash")]
    pub include_hash: Option<HashAlgorithm>,
    #[serde(rename = "x-sovd2uds-include-file-size", default)]
    pub include_file_size: bool,
    #[serde(rename = "x-sovd2uds-include-revision", default)]
    pub include_revision: bool,
    /// Accepted for ISO 17978-3 compatibility but not currently applied.
    #[serde(rename = "created-after")]
    pub created_after: Option<String>,
    /// Accepted for ISO 17978-3 compatibility but not currently applied.
    #[serde(rename = "created-before")]
    pub created_before: Option<String>,
}

impl From<cda_interfaces::runtime_update_api::HashAlgorithm> for HashAlgorithm {
    fn from(algorithm: cda_interfaces::runtime_update_api::HashAlgorithm) -> Self {
        match algorithm {
            cda_interfaces::runtime_update_api::HashAlgorithm::Sha256 => Self::Sha256,
        }
    }
}

impl From<cda_interfaces::runtime_update_api::RuntimeFile> for BulkDataDescriptor {
    /// Renders a domain file as its ISO 17978-3 bulk-data representation.
    ///
    /// The fields the plugin does not model are supplied here: `mimetype` is fixed
    /// for runtime files, and `name` repeats the id because the identifier *is* the
    /// file name. `origin_path` has no domain counterpart and is left unset.
    fn from(file: cda_interfaces::runtime_update_api::RuntimeFile) -> Self {
        let (hash, hash_algorithm) = file.hash.map_or((None, None), |hash| {
            (Some(hash.value), Some(hash.algorithm.into()))
        });
        Self {
            id: file.id.clone(),
            mimetype: "application/octet-stream".to_owned(),
            name: Some(file.id),
            size: file.size,
            hash,
            hash_algorithm,
            origin_path: None,
            revision: file.revision,
        }
    }
}

impl RuntimeFilesQuery {
    /// The metadata this request asks the plugin to compute.
    ///
    /// `include-schema` is not part of it: the schema envelope is rendered by the
    /// HTTP layer, and the plugin has no notion of it. `created-after`/
    /// `created-before` are accepted for ISO compatibility but not applied.
    #[must_use]
    pub fn list_options(&self) -> cda_interfaces::runtime_update_api::FileListOptions {
        cda_interfaces::runtime_update_api::FileListOptions {
            include_size: self.include_file_size,
            include_hash: self.include_hash.map(|algorithm| match algorithm {
                HashAlgorithm::Sha256 => cda_interfaces::runtime_update_api::HashAlgorithm::Sha256,
            }),
            include_revision: self.include_revision,
        }
    }
}

/// Builds a bulk-data list response from domain files.
#[must_use]
pub fn bulk_data_list(files: Vec<cda_interfaces::runtime_update_api::RuntimeFile>) -> BulkDataList {
    BulkDataList {
        items: files.into_iter().map(BulkDataDescriptor::from).collect(),
        schema: None,
    }
}

/// Builds a creation response from the identifiers the plugin created.
#[must_use]
pub fn bulk_data_created(ids: Vec<String>) -> BulkDataCreatedList {
    BulkDataCreatedList {
        items: ids.into_iter().map(|id| BulkDataCreated { id }).collect(),
        schema: None,
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::runtime_update_api::{FileHash, RuntimeFile};

    use super::{BulkDataDescriptor, HashAlgorithm};

    /// Pins the ISO 17978-3 field names. Moved here from the update plugin when the
    /// plugin stopped producing wire types: the shape is this crate's concern.
    #[test]
    fn a_bare_file_renders_the_iso_required_fields_only() {
        let descriptor = BulkDataDescriptor::from(RuntimeFile {
            id: "plain.mdd".to_owned(),
            size: None,
            hash: None,
            revision: None,
        });

        assert_eq!(
            serde_json::to_string(&descriptor).unwrap(),
            r#"{"id":"plain.mdd","mimetype":"application/octet-stream","name":"plain.mdd"}"#
        );
    }

    #[test]
    fn optional_metadata_uses_the_vendor_extension_names() {
        let descriptor = BulkDataDescriptor::from(RuntimeFile {
            id: "full.mdd".to_owned(),
            size: Some(42),
            hash: Some(FileHash {
                algorithm: cda_interfaces::runtime_update_api::HashAlgorithm::Sha256,
                value: "abc".to_owned(),
            }),
            revision: Some("1.2.3".to_owned()),
        });

        let json = serde_json::to_string(&descriptor).unwrap();
        assert!(json.contains(r#""x-sovd2uds-revision":"1.2.3""#), "{json}");
        assert!(json.contains(r#""hash":"abc""#), "{json}");
        assert!(json.contains(r#""hash_algorithm":"sha256""#), "{json}");
        assert_eq!(descriptor.hash_algorithm, Some(HashAlgorithm::Sha256));
    }
}
