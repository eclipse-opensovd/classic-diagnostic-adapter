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
    #[must_use]
    pub fn new(name: String, title: String, schema: Option<schemars::Schema>) -> Self {
        Self {
            name,
            title,
            schema,
        }
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn schema(&self) -> Option<&schemars::Schema> {
        self.schema.as_ref()
    }
    #[must_use]
    pub fn into_schema(self) -> Option<schemars::Schema> {
        self.schema
    }

    /// Set the `format` of binary (byte field) string values to the one of
    /// `encoding`. Byte fields are marked with the base64 format `byte` by
    /// the schema generation.
    #[must_use]
    pub fn with_binary_encoding(mut self, encoding: crate::BinaryEncoding) -> Self {
        fn replace(value: &mut serde_json::Value, from: &str, to: &str) {
            match value {
                serde_json::Value::Object(map) => {
                    let is_binary_string = map.get("type").and_then(|t| t.as_str())
                        == Some("string")
                        && map.get("format").and_then(|f| f.as_str()) == Some(from);
                    if is_binary_string {
                        map.insert("format".to_owned(), to.into());
                    }
                    for v in map.values_mut() {
                        replace(v, from, to);
                    }
                }
                serde_json::Value::Array(values) => {
                    for v in values.iter_mut() {
                        replace(v, from, to);
                    }
                }
                _ => {}
            }
        }

        let from = crate::BinaryEncoding::Base64.json_schema_format();
        let to = encoding.json_schema_format();
        if from != to
            && let Some(schema) = self.schema.as_mut()
        {
            let mut value = std::mem::take(schema).to_value();
            replace(&mut value, from, to);
            if let Ok(updated) = schemars::Schema::try_from(value) {
                *schema = updated;
            }
        }
        self
    }

    #[must_use]
    pub fn get_param_properties(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        let properties = self.schema()?;

        let properties = properties.as_object()?;
        let response_properties = schema_find_recursive(properties, "properties")?.as_object()?;
        schema_find_recursive(response_properties, "properties")?.as_object()
    }
}

fn schema_find_recursive<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Value> {
    for (k, v) in obj {
        if k == key {
            return Some(v);
        }
        if let Some(nested_obj) = v.as_object()
            && let Some(found) = schema_find_recursive(nested_obj, key)
        {
            return Some(found);
        }
    }
    None
}

pub trait EcuSchemas {
    fn schema_for_request(
        &self,
        service: &DiagComm,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;

    fn schema_for_responses(
        &self,
        service: &DiagComm,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;

    /// Get the request schema for a service defined in a functional group's diag layer.
    ///
    /// This is equivalent to [`schema_for_request`](EcuSchemas::schema_for_request)
    /// but looks up the service in the given functional group instead of the variant.
    fn schema_for_fg_request(
        &self,
        service: &DiagComm,
        functional_group_name: &str,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;
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

    /// Get the request schema for an operation defined in a functional group.
    ///
    /// The implementation resolves the functional description database internally;
    /// the caller only needs to provide the functional group name and service.
    fn schema_for_fg_request(
        &self,
        service: &DiagComm,
        functional_group_name: &str,
    ) -> impl Future<Output = Result<SchemaDescription, DiagServiceError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_binary_encoding() {
        let schema = schemars::json_schema!({
            "type": "object",
            "properties": {
                "raw": { "type": "string", "format": "byte" },
                "list": { "type": "array", "items": [{ "type": "string", "format": "byte" }] },
                "date": { "type": "string", "format": "date" }
            }
        });
        let desc = SchemaDescription::new("n".to_owned(), "t".to_owned(), Some(schema.clone()));

        let hex = desc
            .with_binary_encoding(crate::BinaryEncoding::Hex)
            .into_schema()
            .unwrap()
            .to_value();
        let format = |pointer: &str| hex.pointer(pointer).and_then(|v| v.as_str());
        assert_eq!(format("/properties/raw/format"), Some("binary"));
        assert_eq!(format("/properties/list/items/0/format"), Some("binary"));
        assert_eq!(format("/properties/date/format"), Some("date"));

        let desc = SchemaDescription::new("n".to_owned(), "t".to_owned(), Some(schema.clone()));
        assert_eq!(
            desc.with_binary_encoding(crate::BinaryEncoding::Base64)
                .into_schema(),
            Some(schema)
        );
    }
}
