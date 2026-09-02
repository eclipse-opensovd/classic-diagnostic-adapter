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

use crate::{DiagServiceError, HashMap};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum ChunkType {
    DiagnosticDescription,
    CodeFile,
    CodeFilePartial,
    EmbeddedFile,
    VendorSpecific,
}

#[derive(Debug, Clone)]
pub struct ChunkMetaData {
    pub type_: ChunkType,
    pub name: String,
    pub uncompressed_size: u64,
    pub content_type: Option<String>,
}

pub struct Chunk {
    pub payload: Option<bytes::Bytes>,
    pub meta_data: ChunkMetaData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MddError {
    Io(String),
    InvalidFormat(String),
    Parsing(String),
    MissingData(String),
    InvalidParameter(String),
}
impl std::fmt::Display for MddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MddError::Io(msg) => write!(f, "I/O error: {msg}"),
            MddError::InvalidFormat(msg) => write!(f, "Invalid format: {msg}"),
            MddError::Parsing(msg) => write!(f, "Parsing error: {msg}"),
            MddError::MissingData(msg) => write!(f, "Missing data: {msg}"),
            MddError::InvalidParameter(msg) => write!(f, "Invalid parameter: {msg}"),
        }
    }
}

pub trait FileManager: Clone + Send + Sync + 'static {
    fn list(&self) -> impl Future<Output = HashMap<String, ChunkMetaData>> + Send;

    /// Retrieves the data of a file along with its metadata by its ID.
    /// # Errors
    /// If the file with the given ID does not exist, it returns an `MddError::InvalidParameter`.
    /// Also returns the errors from `load_data` if the chunk data cannot be read or
    /// parsed correctly.
    fn get(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<(ChunkMetaData, Vec<u8>), MddError>> + Send;
}

/// Files embedded in an ECU's database, served by the bulk-data endpoints.
///
/// Separate from [`FileManager`] only because that trait requires `Clone`,
/// which `EcuManager` does not provide.
pub trait EmbeddedFiles: Send + Sync {
    fn list(&self) -> impl Future<Output = HashMap<String, ChunkMetaData>> + Send;

    /// # Errors
    /// If the file with the given ID does not exist, it returns an `MddError::InvalidParameter`.
    /// Also returns the errors from `load_data` if the chunk data cannot be read or
    /// parsed correctly.
    fn get(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<(ChunkMetaData, Vec<u8>), MddError>> + Send;
}

/// Manager-level access to [`EmbeddedFiles`], resolving `ecu_name` to the live ECU
/// handle rather than a value captured at route-build time.
pub trait EmbeddedFilesProvider {
    /// # Errors
    /// Returns [`DiagServiceError::NotFound`] if `ecu_name` does not exist.
    fn embedded_files_list(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<HashMap<String, ChunkMetaData>, DiagServiceError>> + Send;

    /// # Errors
    /// Returns [`DiagServiceError::NotFound`] if `ecu_name` does not exist, or if no
    /// embedded file with `id` exists in its database.
    fn embedded_file(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> impl Future<Output = Result<(ChunkMetaData, Vec<u8>), DiagServiceError>> + Send;
}

#[cfg(feature = "test-utils")]
pub mod mock {
    use super::{ChunkMetaData, FileManager, MddError};
    use crate::HashMap;

    mockall::mock! {
        pub FileManager {}

        impl Clone for FileManager {
            fn clone(&self) -> Self;
        }

        impl FileManager for FileManager {
            fn list(&self) -> impl Future<Output = HashMap<String, ChunkMetaData>> + Send;

            fn get(
                &self,
                id: &str,
            ) -> impl Future<Output = Result<(ChunkMetaData, Vec<u8>), MddError>> + Send;
        }
    }
}
