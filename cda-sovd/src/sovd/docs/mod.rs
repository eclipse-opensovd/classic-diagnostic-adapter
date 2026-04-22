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

//! Reusable utilities for building self-contained `OpenAPI` 3.1 documents
//! that serve as SOVD online capability descriptions (ISO 17978-3 Section 7.5).
//!
//! Each SOVD resource type (operations, data, faults, ...) constructs its own
//! [`PathItem`]s and passes them to [`build_openapi_doc`] to produce a valid,
//! self-contained `OpenAPI` specification returned by `GET .../docs`.

pub mod operations;

use aide::openapi::{
    Info, MediaType, OpenApi, Operation, PathItem, Paths, ReferenceOr, RequestBody, Response,
    Responses, SchemaObject, StatusCode,
};
use indexmap::IndexMap;
use schemars::Schema;

/// Build a minimal, self-contained `OpenAPI` 3.1 document.
///
/// `title` - used as `info.title` (e.g. `"Operation: CalibrateSensors"`).
/// `paths` - the set of path items that describe the resource's API surface.
pub fn build_openapi_doc(title: &str, paths: IndexMap<String, PathItem>) -> OpenApi {
    OpenApi {
        info: Info {
            title: title.to_owned(),
            version: "1.0.0".to_owned(),
            ..Default::default()
        },
        paths: Some(Paths {
            paths: paths
                .into_iter()
                .map(|(k, v)| (k, ReferenceOr::Item(v)))
                .collect(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Wrap a [`schemars::Schema`] into an aide [`SchemaObject`].
pub fn schema_object(schema: Schema) -> SchemaObject {
    SchemaObject {
        json_schema: schema,
        external_docs: None,
        example: None,
    }
}

/// Build a JSON media type entry from a [`schemars::Schema`].
pub fn json_media_type(schema: Schema) -> MediaType {
    MediaType {
        schema: Some(schema_object(schema)),
        ..Default::default()
    }
}

/// Create a JSON request body from a [`schemars::Schema`].
pub fn json_request_body(schema: Schema) -> ReferenceOr<RequestBody> {
    ReferenceOr::Item(RequestBody {
        content: IndexMap::from([("application/json".to_owned(), json_media_type(schema))]),
        ..Default::default()
    })
}

/// Create a response entry with a JSON body.
pub fn json_response(description: &str, schema: Schema) -> ReferenceOr<Response> {
    ReferenceOr::Item(Response {
        description: description.to_owned(),
        content: IndexMap::from([("application/json".to_owned(), json_media_type(schema))]),
        ..Default::default()
    })
}

/// Create a response entry without a body.
pub fn empty_response(description: &str) -> ReferenceOr<Response> {
    ReferenceOr::Item(Response {
        description: description.to_owned(),
        ..Default::default()
    })
}

/// Build a [`Responses`] map from `(status_code, response)` pairs.
pub fn responses(entries: Vec<(u16, ReferenceOr<Response>)>) -> Responses {
    Responses {
        responses: entries
            .into_iter()
            .map(|(code, resp)| (StatusCode::Code(code), resp))
            .collect(),
        ..Default::default()
    }
}

/// Build an [`Operation`] with optional SOVD extension properties.
pub fn operation_with_extensions(
    summary: &str,
    extensions: IndexMap<String, serde_json::Value>,
) -> Operation {
    Operation {
        summary: Some(summary.to_owned()),
        extensions,
        ..Default::default()
    }
}

/// Minimal SOVD error response schema (spec 5.8).
pub fn error_schema() -> Schema {
    schemars::json_schema!({
        "type": "object",
        "properties": {
            "error_code": { "type": "string" },
            "message": { "type": "string" }
        }
    })
}
