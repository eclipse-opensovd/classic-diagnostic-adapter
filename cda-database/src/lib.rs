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

pub mod datatypes;
pub(crate) mod flatbuf;
pub(crate) mod mdd_data;
pub(crate) mod proto;

use cda_interfaces::datatypes::DatabaseNamingConvention;
pub use mdd_data::{
    ProtoLoadConfig, files::FileManager, load_chunk, load_ecudata, load_proto_data,
    update_mdd_uncompressed,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct DatabaseConfig {
    pub path: String,
    pub naming_convention: DatabaseNamingConvention,
    /// If true, the application will exit if no database could be loaded.
    pub exit_no_database_loaded: bool,
    /// If true, when variant detection fails to find a matching variant,
    /// the ECU will fall back to the base variant instead of reporting an error.
    pub fallback_to_base_variant: bool,
    /// When `true`, com-param and protocol lookups ignore the protocol filter
    /// and match by parameter name alone.
    ///
    /// This is useful for databases that contain only a single protocol but
    /// where the protocol short-name recorded in the database does not match
    /// the one used at runtime. Enabling this flag allows the lookup to succeed
    /// by falling back to a protocol-agnostic match.
    ///
    /// Only valid when the database contains exactly one distinct protocol;
    /// attempting a lookup with this flag set against a multi-protocol database
    /// returns `DiagServiceError::InvalidDatabase`.
    pub ignore_protocol: bool,
}
