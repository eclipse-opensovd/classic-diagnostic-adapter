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

//! Builders for the online capability description of SOVD operation resources.
//!
//! Produces the [`PathItem`]s that describe an operation's execution surface
//! (`/executions`, `/executions/{execution-id}`) and embeds request/response
//! parameter schemas obtained from the diagnostic layer.

use aide::openapi::{Operation, PathItem};
use indexmap::IndexMap;
use schemars::Schema;

use super::{
    empty_response, error_schema, json_request_body, json_response, operation_with_extensions,
    responses,
};

/// Metadata needed to construct the online capability description for a single
/// SOVD operation resource.
pub struct OperationDocsMeta {
    /// Human-readable name of the operation.
    pub name: String,
    /// Whether the operation executes asynchronously (has Stop / `RequestResults`).
    pub is_async: bool,
    /// JSON Schema describing the operation's request parameters (the value of
    /// the `parameters` attribute in the POST request body). `None` if the
    /// operation takes no parameters.
    pub request_params_schema: Option<Schema>,
    /// JSON Schema describing the operation's response parameters. `None` if
    /// the operation produces no response data.
    pub response_params_schema: Option<Schema>,
}

/// Build the `PathItem` entries for a single operation's execution endpoints.
///
/// Returns an ordered map with two entries:
/// - `{base_path}/executions` - POST (start), GET (list)
/// - `{base_path}/executions/{execution-id}` - GET (status), PUT (capabilities), DELETE (terminate)
///
/// The second entry is only present for asynchronous operations.
pub fn build_path_items(base_path: &str, meta: &OperationDocsMeta) -> IndexMap<String, PathItem> {
    let mut paths = IndexMap::new();

    let executions_path_item = PathItem {
        post: Some(build_post_operation(meta)),
        get: Some(build_list_executions_operation(meta)),
        ..Default::default()
    };
    paths.insert(format!("{base_path}/executions"), executions_path_item);

    if meta.is_async {
        paths.insert(
            format!("{base_path}/executions/{{execution-id}}"),
            build_execution_id_path_item(meta),
        );
    }

    paths
}

/// POST operation for starting an execution (7.14.6).
fn build_post_operation(meta: &OperationDocsMeta) -> Operation {
    let post_request_schema = build_post_request_schema(meta);
    let mut post_op = operation_with_extensions(
        &format!("Start execution of {}", meta.name),
        sovd_extensions(meta),
    );
    post_op.request_body = Some(json_request_body(post_request_schema));

    if meta.is_async {
        post_op.responses = Some(responses(vec![
            (
                202,
                json_response(
                    "Execution started asynchronously. Poll the returned execution resource for \
                     status.",
                    schemars::json_schema!({
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "description": "Execution identifier" },
                            "status": {
                                "type": "string",
                                "enum": ["running", "completed", "failed", "stopped"]
                            }
                        },
                        "required": ["id"]
                    }),
                ),
            ),
            (
                409,
                json_response(
                    "Operation already executing or resource conflict.",
                    error_schema(),
                ),
            ),
        ]));
    } else {
        let sync_response_schema = build_sync_response_schema(meta);
        post_op.responses = Some(responses(vec![
            (
                200,
                json_response("Operation completed synchronously.", sync_response_schema),
            ),
            (
                409,
                json_response("Operation not available.", error_schema()),
            ),
        ]));
    }

    post_op
}

/// GET operation for listing executions of an operation (7.14.4).
fn build_list_executions_operation(meta: &OperationDocsMeta) -> Operation {
    let mut list_op = Operation {
        summary: Some(format!("List executions of {}", meta.name)),
        ..Default::default()
    };
    list_op.responses = Some(responses(vec![(
        200,
        json_response(
            "List of current execution identifiers.",
            schemars::json_schema!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" }
                            },
                            "required": ["id"]
                        }
                    }
                }
            }),
        ),
    )]));
    list_op
}

/// Build the `PathItem` for `/executions/{execution-id}` (async operations only).
///
/// Contains GET (status, 7.14.7), PUT (capabilities, 7.14.9) and DELETE (terminate, 7.14.8).
fn build_execution_id_path_item(meta: &OperationDocsMeta) -> PathItem {
    PathItem {
        get: Some(build_get_status_operation(meta)),
        put: Some(build_put_capability_operation(meta)),
        delete: Some(build_delete_terminate_operation(meta)),
        ..Default::default()
    }
}

/// GET - poll execution status (7.14.7).
fn build_get_status_operation(meta: &OperationDocsMeta) -> Operation {
    let mut status_schema = schemars::json_schema!({
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["running", "completed", "failed", "stopped"],
                "description": "Current execution status."
            },
            "capability": {
                "type": "string",
                "description": "Capability currently being executed."
            },
            "progress": {
                "type": "integer",
                "description": "Execution progress in percent (0-100)."
            },
            "error": {
                "type": "array",
                "items": { "type": "object" },
                "description": "Errors that occurred during execution."
            }
        },
        "required": ["status", "capability"]
    });
    embed_response_params(&mut status_schema, meta);

    let mut get_status = Operation {
        summary: Some(format!("Read the status of an execution of {}", meta.name)),
        ..Default::default()
    };
    get_status.responses = Some(responses(vec![
        (
            200,
            json_response("Current execution status.", status_schema),
        ),
        (404, json_response("Execution not found.", error_schema())),
    ]));
    get_status
}

/// PUT - stop / freeze / reset / execute capabilities (7.14.9).
fn build_put_capability_operation(meta: &OperationDocsMeta) -> Operation {
    let mut put_capability = Operation {
        summary: Some(format!(
            "Execute a capability (stop, freeze, reset, execute) on {}",
            meta.name
        )),
        ..Default::default()
    };
    put_capability.request_body = Some(json_request_body(schemars::json_schema!({
        "type": "object",
        "properties": {
            "capability": {
                "type": "string",
                "enum": ["execute", "stop", "freeze", "reset"],
                "description": "Capability to be executed."
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds."
            },
            "parameters": { "type": "object" },
            "proximity_response": { "type": "string" }
        },
        "required": ["capability"]
    })));
    put_capability.responses = Some(responses(vec![
        (
            202,
            json_response(
                "Capability execution triggered.",
                schemars::json_schema!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "status": { "type": "string" }
                    }
                }),
            ),
        ),
        (404, json_response("Execution not found.", error_schema())),
    ]));
    put_capability
}

/// DELETE - terminate execution (7.14.8).
fn build_delete_terminate_operation(meta: &OperationDocsMeta) -> Operation {
    let mut delete_terminate = Operation {
        summary: Some(format!("Terminate execution of {}", meta.name)),
        ..Default::default()
    };
    delete_terminate.responses = Some(responses(vec![
        (204, empty_response("Execution terminated and removed.")),
        (404, json_response("Execution not found.", error_schema())),
    ]));
    delete_terminate
}

/// Build the JSON Schema for the POST request body of an operation execution.
fn build_post_request_schema(meta: &OperationDocsMeta) -> Schema {
    let mut properties = serde_json::Map::new();

    properties.insert(
        "timeout".to_owned(),
        serde_json::json!({
            "type": "integer",
            "description": "Seconds after which the server should terminate the operation."
        }),
    );

    if let Some(params_schema) = &meta.request_params_schema {
        properties.insert(
            "parameters".to_owned(),
            serde_json::Value::from(params_schema.clone()),
        );
    } else {
        properties.insert(
            "parameters".to_owned(),
            serde_json::json!({ "type": "object" }),
        );
    }

    properties.insert(
        "proximity_response".to_owned(),
        serde_json::json!({
            "type": "string",
            "description": "Response to a co-location proximity challenge."
        }),
    );

    schemars::json_schema!({
        "type": "object",
        "properties": properties
    })
}

/// Collect the SOVD-specific extension properties for the Operation object
/// (ISO 17978-3 Table 24).
fn sovd_extensions(meta: &OperationDocsMeta) -> IndexMap<String, serde_json::Value> {
    let mut ext = IndexMap::new();
    if meta.is_async {
        ext.insert(
            "x-sovd-asynchronous-execution".to_owned(),
            serde_json::Value::Bool(true),
        );
    }
    // proximity_proof_required is always false for classic UDS routines.
    ext.insert(
        "x-sovd-proximity-proof-required".to_owned(),
        serde_json::Value::Bool(false),
    );
    ext
}

/// Embed the operation's response parameter schema as a `"parameters"` property
/// inside an existing JSON Schema object (mutates in place).
fn embed_response_params(schema: &mut Schema, meta: &OperationDocsMeta) {
    if let Some(resp_schema) = &meta.response_params_schema
        && let Some(obj) = schema.as_object_mut()
        && let Some(props) = obj.get_mut("properties")
        && let Some(props_obj) = props.as_object_mut()
    {
        props_obj.insert(
            "parameters".to_owned(),
            serde_json::Value::from(resp_schema.clone()),
        );
    }
}

/// Build the response schema for a synchronous operation (200 from POST).
fn build_sync_response_schema(meta: &OperationDocsMeta) -> Schema {
    let mut schema = schemars::json_schema!({
        "type": "object",
        "properties": {
            "parameters": { "type": "object" }
        }
    });
    embed_response_params(&mut schema, meta);
    schema
}
