/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! OpenAPI specification generation.
//!
//! The spec is built by aide from the routes and the [`schemars::JsonSchema`]
//! derives on the API types. This module supplies the top-level metadata
//! (title, contact, license, tags, server URL) via [`api_docs`] and a few
//! reusable [`TransformOperation`] helpers for documenting the simulator's
//! shared response shapes (4xx errors, JSON-or-octet request bodies).

use aide::{
    openapi::{Contact, License, Server, Tag},
    transform::{TransformOpenApi, TransformOperation},
};
use axum::Json;

use crate::api::types::ErrorResponse;

pub(crate) mod aide_helper {
    /// Helper macro to generate path params that have an OpenAPI schema.
    ///
    /// # Usage
    /// ## With single field
    /// The macro requires at least 3 arguments:
    ///  - Name of the struct that should be generated
    ///  - Name of the path parameter
    ///  - Type of the path parameter
    ///
    /// `gen_path_param!(IdPathParam, id, String)`
    /// ## With multiple fields
    /// Alternatively it can be called with multiple pairs of
    /// (name, type) to generate a struct with multiple fields.
    ///
    /// `gen_path_param!(MultiFieldParam, id, String, name, String)`
    macro_rules! gen_path_param {
        ($struct_name:ident $value_name:ident $type:ty) => {
            #[derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
            pub(crate) struct $struct_name {
                pub $value_name: $type,
            }

            impl std::ops::Deref for $struct_name {
                type Target = $type;

                fn deref(&self) -> &Self::Target {
                    &self.$value_name
                }
            }
        };
        ($struct_name:ident $($value_name:ident $type:ty)+) => {
            #[derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
            pub(crate) struct $struct_name {
                $(
                pub $value_name: $type,
                )*
            }

            impl $struct_name {
            $(
                #[allow(dead_code)]
                pub(crate) fn $value_name(&self) -> &$type {
                    &self.$value_name
                }
            )*
            }
        };
    }

    pub(crate) use gen_path_param;
}

/// Top-level OpenAPI metadata: title, summary, contact, license, tags, and
/// the `server_url` the simulator is bound to.
pub(crate) fn api_docs(api: TransformOpenApi, server_url: String) -> TransformOpenApi {
    api.title("CDA Simulator - MDD-based ECU Simulator")
        .summary("A simulator that emulates any ECU defined by an MDD file.")
        .description(
            "## Overview\n\nThis API allows you to:\n- View simulator information and \
             statistics\n- List available services and their parameters (all from MDD)\n- \
             Override parameter values for testing\n- Monitor and control the simulated ECU\n\n## \
             Value Format\n\nAll values use **physical units**. Conversions are applied \
             automatically based on the MDD's computational methods (CompuMethod).",
        )
        .contact(Contact {
            name: Some("Eclipse OpenSOVD".to_owned()),
            url: Some("https://github.com/eclipse-opensovd/classic-diagnostic-adapter/".to_owned()),
            email: Some("opensovd-dev@eclipse.org".to_owned()),
            ..Default::default()
        })
        .license(License {
            name: "Apache 2.0".to_owned(),
            identifier: Some("Apache-2.0".to_owned()),
            ..Default::default()
        })
        .tag(Tag {
            name: "Simulator".to_owned(),
            description: Some("Simulator information and control".to_owned()),
            ..Default::default()
        })
        .tag(Tag {
            name: "Services".to_owned(),
            description: Some("MDD service definitions and parameters".to_owned()),
            ..Default::default()
        })
        .tag(Tag {
            name: "Overrides".to_owned(),
            description: Some("Parameter value overrides".to_owned()),
            ..Default::default()
        })
        .server(Server {
            url: server_url,
            ..Default::default()
        })
}

/// 404 response: service or parameter not found.
pub(crate) fn error_not_found(op: TransformOperation) -> TransformOperation {
    op.response_with::<404, Json<ErrorResponse>, _>(|res| {
        res.description("Service or parameter not found.")
    })
}

/// 400 response: malformed request body.
pub(crate) fn error_bad_request(op: TransformOperation) -> TransformOperation {
    op.response_with::<400, Json<ErrorResponse>, _>(|res| {
        res.description("The request body was invalid or could not be parsed.")
    })
}

/// Document the request body as JSON with the schema of `T`.
///
/// For handlers that take `axum::body::Bytes` to do their own JSON parsing
/// (e.g. `PUT /services/{name}/parameters/{param}`, which parses the tagged
/// [`SetParameterValue`] union by hand to stay lenient about content type).
pub(crate) fn request_json<T: schemars::JsonSchema>(
    mut op: TransformOperation,
) -> TransformOperation {
    // remove automatically created request_body (axum's Bytes extractor
    // makes aide record a `string` body, which would shadow our JSON schema)
    op.inner_mut().request_body = None;
    op.input::<Json<T>>()
}
