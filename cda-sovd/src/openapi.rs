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

use aide::{
    openapi::{Contact, License, MediaType, SchemaObject, Server, Tag},
    transform::{TransformOpenApi, TransformOperation},
};
use axum::Json;
use schemars::JsonSchema;
use sovd_interfaces::error::ApiErrorResponse;

use crate::sovd;

pub(crate) mod aide_helper {
    /// Helper macro to generate path params that have an openapi
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
                $value_name: $type,
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
                $value_name: $type,
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

pub(crate) fn api_docs(api: TransformOpenApi) -> TransformOpenApi {
    api.title("Eclipse OpenSOVD - Classic Diagnostic Adapter")
        .summary(
            "In the SOVD (Service-Oriented Vehicle Diagnostics) context, a Classic Diagnostic \
             Adapter serves as a compatibility bridge between traditional (legacy) diagnostic \
             interfaces and the modern SOVD-based diagnostic architecture used in next-generation \
             vehicles.",
        )
        // .description(include_str!("../../README.md"))
        .contact(Contact {
            name: Some("Classic Diagnostic Adapter".to_owned()),
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
            name: "OpenSOVD CDA".to_owned(),
            description: Some("Classic Diagnostic Adapter written in Rust".to_owned()),
            ..Default::default()
        })
        .server(Server {
            url: "http://localhost:20002".to_owned(),
            ..Default::default()
        })
}

pub(crate) fn request_json_and_octet<T: JsonSchema>(
    mut op: TransformOperation,
) -> TransformOperation {
    // remove automatically created request_body
    op.inner_mut().request_body = None;
    op = op.input::<Json<T>>();
    op = add_octet_request(op);
    op
}

pub(crate) fn request_octet(mut op: TransformOperation) -> TransformOperation {
    // remove automatically created request_body
    op.inner_mut().request_body = None;
    add_octet_request(op)
}

fn add_octet_request(mut op: TransformOperation) -> TransformOperation {
    if let Some(body) = op.inner_mut().request_body.as_mut()
        && let Some(i) = body.as_item_mut()
    {
        i.content.insert(
            "application/octet-stream".to_owned(),
            MediaType {
                schema: Some(SchemaObject {
                    json_schema: schemars::json_schema!({
                        "description": "Raw bytes",
                        "type": ["string"]
                    }),
                    example: None,
                    external_docs: None,
                }),
                ..Default::default()
            },
        );
    }
    op
}

pub(crate) fn ecu_service_response(op: TransformOperation) -> TransformOperation {
    op.response_with::<200, Json<sovd_interfaces::ObjectDataItem>, _>(|res| {
        let mut res =
            res.description("ECU Response as JSON")
                .example(sovd_interfaces::ObjectDataItem {
                    id: "example_service".to_string(),
                    data: [
                        ("ecu_state".to_owned(), serde_json::json!("active")),
                        ("version".to_owned(), serde_json::json!("1.0.0")),
                        ("manufacturer".to_owned(), serde_json::json!("Example Corp")),
                    ]
                    .into_iter()
                    .collect(),
                    schema: None,
                });
        res.inner().content.insert(
            "application/octet-stream".to_owned(),
            MediaType {
                example: Some(serde_json::json!([0xabu8, 0xcd, 0xef, 0x00])),
                ..Default::default()
            },
        );
        res
    })
}

pub(crate) fn lock_not_found(op: TransformOperation) -> TransformOperation {
    op.response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Given lock does not exist.")
    })
}

pub(crate) fn lock_not_owned(op: TransformOperation) -> TransformOperation {
    op.response_with::<403, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Lock is not owned.")
    })
}

pub(crate) fn error_forbidden(op: TransformOperation) -> TransformOperation {
    op.response_with::<403, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description(
            "Forbidden: The SOVD client does not have the right to access the resource.",
        )
        .example(ApiErrorResponse {
            message: "Forbidden".to_string(),
            error_code: sovd_interfaces::error::ErrorCode::InsufficientAccessRights,
            vendor_code: None,
            parameters: None,
            error_source: None,
        })
    })
}

pub(crate) fn error_not_found(op: TransformOperation) -> TransformOperation {
    op.response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Not Found: The requested resource does not exist.")
            .example(ApiErrorResponse {
                message: "Not found".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::NotFound),
                parameters: None,
                error_source: None,
            })
    })
}

pub(crate) fn error_bad_gateway(op: TransformOperation) -> TransformOperation {
    op.response_with::<502, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Bad Gateway: ECU responded with an NRC")
            .example(ApiErrorResponse {
                message: "NRC".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::ErrorResponse,
                vendor_code: None,
                parameters: None,
                error_source: Some("ECU".to_string()),
            })
    })
}

pub(crate) fn error_internal_server(op: TransformOperation) -> TransformOperation {
    op.response_with::<500, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Internal Server Error: An internal error occurred in the SOVD server.")
            .example(ApiErrorResponse {
                message: "Internal Server Error".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::SovdServerFailure,
                vendor_code: None,
                parameters: None,
                error_source: None,
            })
    })
}

pub(crate) fn error_conflict(op: TransformOperation) -> TransformOperation {
    op.response_with::<409, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Conflict: The preconditions to execute the method are not fulfilled.")
            .example(ApiErrorResponse {
                message: "Conflict".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::PreconditionsNotFulfilled,
                vendor_code: None,
                parameters: None,
                error_source: None,
            })
    })
}

pub(crate) fn error_bad_request(op: TransformOperation) -> TransformOperation {
    op.response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Bad Request: The request was invalid or cannot be otherwise served.")
            .example(ApiErrorResponse {
                message: "Bad Request".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                parameters: None,
                error_source: None,
            })
    })
}

pub(crate) fn comparam_execution_errors(op: TransformOperation) -> TransformOperation {
    op.response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Id does not exist or execution failed")
            .example(ApiErrorResponse {
                message: "Bad Request".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                parameters: None,
                error_source: None,
            })
    })
    .response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Id does not exist")
            .example(ApiErrorResponse {
                message: "Not Found".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::NotFound),
                parameters: None,
                error_source: None,
            })
    })
}
