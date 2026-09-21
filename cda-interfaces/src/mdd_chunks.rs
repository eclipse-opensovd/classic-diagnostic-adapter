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

use std::sync::Arc;

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
    /// Position of the chunk in the MDD file's chunk list, which is how its
    /// payload is read back later. Type and name cannot serve: an MDD may
    /// carry several chunks sharing both, and unnamed ones all share the
    /// empty name.
    pub index: usize,
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

/// Files embedded in an ECU's database, served by the bulk-data endpoints.
pub trait EmbeddedFiles: Send + Sync {
    fn list(&self) -> impl Future<Output = HashMap<String, ChunkMetaData>> + Send;

    /// # Errors
    /// Returns `MddError::InvalidParameter` if no file with the given ID exists,
    /// and the errors of the underlying chunk read if the payload cannot be
    /// read or parsed.
    fn get(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<(ChunkMetaData, bytes::Bytes), MddError>> + Send;
}

/// An ECU database that carries an [`EmbeddedFiles`] store.
///
/// Serving MDD blobs is orthogonal to diagnostics, and only the bulk-data endpoints need
/// it. Implementations that never serve files are not obliged to.
///
/// The store comes out as an owned handle so a caller can drop the guard it
/// resolved the ECU under before reading a payload, rather than holding the
/// ECU locked across a file read.
pub trait EmbeddedFileAccess {
    type Files: EmbeddedFiles;

    fn embedded_files(&self) -> Arc<Self::Files>;
}

/// Manager-level access to [`EmbeddedFiles`], resolving `ecu_name` to the live ECU
/// handle rather than a value captured at route-build time.
pub trait EmbeddedFilesProvider {
    type Files: EmbeddedFiles;

    /// The store comes out as an owned handle so the ECU guard it was resolved
    /// under can be dropped before a payload is read, rather than holding the
    /// ECU locked across a memory map and a decompression.
    ///
    /// # Errors
    /// Returns [`DiagServiceError::NotFound`] if `ecu_name` does not exist.
    fn embedded_files(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<Arc<Self::Files>, DiagServiceError>> + Send;
}
