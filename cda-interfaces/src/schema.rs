/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use crate::{DiagComm, DiagServiceError};

pub struct SchemaDescription {
    /// A unique name for the schema.
    ///
    /// Duplicates are not prevented, but can cause
    /// issues when generating openapi from the
    /// schema.
    name: String,
    /// A descriptive title that should be human readable
    ///
    /// Can be used to provide more context about the schema.
    title: String,
    /// The json schema definition this description is for.
    schema: Option<schemars::Schema>,
}

impl SchemaDescription {
    pub fn new(name: String, title: String, schema: Option<schemars::Schema>) -> Self {
        Self {
            name,
            title,
            schema,
        }
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn schema(&self) -> Option<&schemars::Schema> {
        self.schema.as_ref()
    }
    pub fn into_schema(self) -> Option<schemars::Schema> {
        self.schema
    }
}

pub trait EcuSchemaProvider {
    fn schema_for_request(&self, service: &DiagComm)
    -> Result<SchemaDescription, DiagServiceError>;

    fn schema_for_responses(
        &self,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError>;
}

pub trait SchemaProvider {
    fn schema_for_request(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;

    fn schema_for_responses(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;
}
