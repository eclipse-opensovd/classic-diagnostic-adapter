/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! Builders for the online capability description of SOVD data and configuration
//! resources.
//!
//! Produces the [`PathItem`]s that describe a data/configuration service's API
//! surface (GET for reading, optionally PUT for writing) and embeds
//! request/response parameter schemas obtained from the diagnostic layer.
//!
//! The [`build_docs_response`] helper is shared by both the `/data/{service}/docs`
//! and `/configurations/{service}/docs` endpoint handlers.

use aide::openapi::{Operation, PathItem};
use axum::{Json, http::StatusCode, response::IntoResponse as _};
use cda_interfaces::{DiagComm, DiagCommType, SchemaProvider, UdsEcu};
use indexmap::IndexMap;
use schemars::Schema;
use sovd_interfaces::docs;

use super::{error_schema, json_request_body, json_response, responses};

/// Metadata needed to construct the online capability description for a single
/// SOVD data resource.
pub struct DataDocsMeta {
    /// Human-readable name of the data service.
    pub name: String,
    /// JSON Schema describing the data returned by GET (the `data` property in
    /// the response). `None` if the schema could not be determined.
    pub read_response_schema: Option<Schema>,
    /// If `Some`, the data service supports PUT (a corresponding
    /// `WriteDataByIdentifier` / 0x2E service exists in the diagnostic
    /// description). The schema describes the request parameters for writing.
    /// If `None`, only GET is available.
    pub write_request_schema: Option<Schema>,
}

/// Shared helper that retrieves schemas from the diagnostic layer and builds
/// the self-contained `OpenAPI` 3.1 response for both `/data/{service}/docs` and
/// `/configurations/{service}/docs`.
///
/// The caller is responsible for verifying that the service exists before
/// calling this function.
///
/// # Arguments
/// * `uds` - UDS gateway providing schema lookups
/// * `ecu_name` - Name of the ECU component
/// * `service` - Short name of the data/configuration service
/// * `resource_type` - Path segment identifying the resource kind (e.g. `"data"`
///   or `"configurations"`)
pub async fn build_docs_response<T: UdsEcu + SchemaProvider + Clone>(
    uds: &T,
    ecu_name: &str,
    service: &str,
    resource_type: &str,
) -> axum::response::Response {
    // Get the read (GET) response schema (ReadDataByIdentifier / 0x22)
    let read_service = DiagComm {
        name: service.to_owned(),
        type_: DiagCommType::Data,
        lookup_name: None,
        subfunction_id: None,
    };

    let read_response_schema = uds
        .schema_for_responses(ecu_name, &read_service)
        .await
        .ok()
        .and_then(cda_interfaces::SchemaDescription::into_schema);

    // Check if a corresponding WriteDataByIdentifier (0x2E) service exists
    // by attempting to resolve its request schema
    let write_service = DiagComm {
        name: service.to_owned(),
        type_: DiagCommType::Configurations,
        lookup_name: None,
        subfunction_id: None,
    };

    let write_request_schema = uds
        .schema_for_request(ecu_name, &write_service)
        .await
        .ok()
        .and_then(cda_interfaces::SchemaDescription::into_schema);

    let meta = DataDocsMeta {
        name: service.to_owned(),
        read_response_schema,
        write_request_schema,
    };

    let title_prefix = match resource_type {
        "configurations" => "Configuration",
        _ => "Data",
    };

    let base_path = format!("/components/{ecu_name}/{resource_type}/{service}");
    let path_items = build_path_items(&base_path, &meta);
    let doc = super::build_openapi_doc(&format!("{title_prefix}: {service}"), path_items);

    (StatusCode::OK, Json(doc)).into_response()
}

/// Build the `PathItem` entries for a single data service.
///
/// Returns an ordered map with a single entry:
/// - `{base_path}` - GET (read) and optionally PUT (write)
///
/// PUT is only included when `meta.write_request_schema` is `Some`, indicating
/// that a `WriteDataByIdentifier` (0x2E) service exists for this data identifier.
pub fn build_path_items(base_path: &str, meta: &DataDocsMeta) -> IndexMap<String, PathItem> {
    let mut paths = IndexMap::new();

    let path_item = PathItem {
        get: Some(build_get_operation(meta)),
        put: meta
            .write_request_schema
            .as_ref()
            .map(|_| build_put_operation(meta)),
        extensions: path_item_extensions(),
        ..Default::default()
    };
    paths.insert(base_path.to_owned(), path_item);

    paths
}

/// GET operation for reading a data service value.
fn build_get_operation(meta: &DataDocsMeta) -> Operation {
    let response_schema = build_get_response_schema(meta);

    let mut get_op = Operation {
        summary: Some(format!("Read data: {}", meta.name)),
        ..Default::default()
    };
    get_op.responses = Some(responses(vec![
        (
            200,
            json_response("Data read successfully.", response_schema),
        ),
        (
            404,
            json_response("Data service not found.", error_schema()),
        ),
    ]));
    get_op
}

/// PUT operation for writing a data service value.
fn build_put_operation(meta: &DataDocsMeta) -> Operation {
    let request_schema = build_put_request_schema(meta);

    let mut put_op = Operation {
        summary: Some(format!("Write data: {}", meta.name)),
        ..Default::default()
    };
    put_op.request_body = Some(json_request_body(request_schema));
    put_op.responses = Some(responses(vec![
        (
            200,
            json_response(
                "Data written successfully.",
                build_put_response_schema(meta),
            ),
        ),
        (
            400,
            json_response("Invalid request payload.", error_schema()),
        ),
        (
            404,
            json_response("Data service not found.", error_schema()),
        ),
    ]));
    put_op
}

/// Build the JSON Schema for the GET response body.
///
/// Matches the `ObjectDataItem` structure: `{ id, data: { ... }, errors: [] }`.
fn build_get_response_schema(meta: &DataDocsMeta) -> Schema {
    let data_schema = meta
        .read_response_schema
        .as_ref()
        .map_or(serde_json::json!({ "type": "object" }), |s| {
            serde_json::Value::from(s.clone())
        });

    schemars::json_schema!({
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Identifier of the data service."
            },
            "data": data_schema,
            "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "message": { "type": "string" },
                        "error_code": { "type": "string" }
                    }
                },
                "description": "Errors that occurred while reading individual parameters."
            }
        },
        "required": ["id", "data"]
    })
}

/// Build the JSON Schema for the PUT request body.
///
/// Matches the `DataRequestPayload` structure: `{ data: { ... } }`.
fn build_put_request_schema(meta: &DataDocsMeta) -> Schema {
    let data_schema = meta
        .write_request_schema
        .as_ref()
        .map_or(serde_json::json!({ "type": "object" }), |s| {
            serde_json::Value::from(s.clone())
        });

    schemars::json_schema!({
        "type": "object",
        "properties": {
            "data": data_schema
        },
        "required": ["data"]
    })
}

/// Build the JSON Schema for the PUT response body.
///
/// After a successful write the server echoes back the written data in the same
/// `ObjectDataItem` format as GET.
fn build_put_response_schema(meta: &DataDocsMeta) -> Schema {
    // Re-use the GET response schema structure; the written values are echoed back.
    build_get_response_schema(meta)
}

/// Collect the SOVD extension properties for the `PathItem` object
/// (ISO 17978-3 Table 169).
///
/// Emits `x-sovd-proximity-proof-required` which is always `false` for classic
/// UDS data services.
fn path_item_extensions() -> IndexMap<String, serde_json::Value> {
    let mut ext = IndexMap::new();
    ext.insert(
        docs::X_SOVD_PROXIMITY_PROOF_REQUIRED.to_owned(),
        serde_json::Value::Bool(false),
    );
    ext
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema() -> Schema {
        schemars::json_schema!({
            "type": "object",
            "properties": {
                "temperature": { "type": "integer", "description": "Sensor temperature" }
            }
        })
    }

    #[test]
    fn build_path_items_read_only_has_get_but_no_put() {
        let meta = DataDocsMeta {
            name: "Sensor".to_owned(),
            read_response_schema: Some(sample_schema()),
            write_request_schema: None,
        };
        let paths = build_path_items("/components/ecu1/data/Sensor", &meta);

        assert_eq!(paths.len(), 1);
        let item = paths.get("/components/ecu1/data/Sensor").unwrap();
        assert!(item.get.is_some(), "GET operation should be present");
        assert!(
            item.put.is_none(),
            "PUT operation should not be present for read-only data"
        );
    }

    #[test]
    fn build_path_items_read_write_has_both_get_and_put() {
        let meta = DataDocsMeta {
            name: "Config".to_owned(),
            read_response_schema: Some(sample_schema()),
            write_request_schema: Some(sample_schema()),
        };
        let paths = build_path_items("/components/ecu1/configurations/Config", &meta);

        assert_eq!(paths.len(), 1);
        let item = paths.get("/components/ecu1/configurations/Config").unwrap();
        assert!(item.get.is_some(), "GET operation should be present");
        assert!(
            item.put.is_some(),
            "PUT operation should be present for writable data"
        );
    }

    #[test]
    fn build_path_items_no_schemas_produces_valid_get_only() {
        let meta = DataDocsMeta {
            name: "Empty".to_owned(),
            read_response_schema: None,
            write_request_schema: None,
        };
        let paths = build_path_items("/components/ecu1/data/Empty", &meta);

        let item = paths.get("/components/ecu1/data/Empty").unwrap();
        assert!(
            item.get.is_some(),
            "GET should still be generated with fallback schema"
        );
        assert!(
            item.put.is_none(),
            "PUT should not be present without write schema"
        );

        // Verify GET has a valid response
        let get_op = item.get.as_ref().unwrap();
        assert!(get_op.responses.is_some());
    }

    #[test]
    fn path_item_has_proximity_proof_extension() {
        let meta = DataDocsMeta {
            name: "X".to_owned(),
            read_response_schema: None,
            write_request_schema: None,
        };
        let paths = build_path_items("/components/ecu1/data/X", &meta);
        let item = paths.get("/components/ecu1/data/X").unwrap();

        assert_eq!(
            item.extensions.get(docs::X_SOVD_PROXIMITY_PROOF_REQUIRED),
            Some(&serde_json::Value::Bool(false)),
            "PathItem should have x-sovd-proximity-proof-required: false"
        );
    }
}
