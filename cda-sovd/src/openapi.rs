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

use aide::{
    openapi::{Contact, License, MediaType, SchemaObject, Server, Tag},
    transform::{TransformOpenApi, TransformOperation, TransformPathItem},
};
use axum::Json;
use schemars::JsonSchema;
use sovd_interfaces::error::ApiErrorResponse;

use crate::sovd::{self, error::VendorErrorCode};

pub(crate) fn lock_details_example() -> sovd_interfaces::locking::id::get::Response {
    sovd_interfaces::locking::id::get::Response {
        lock_expiration: "2025-01-01T00:00:00Z".to_owned(),
        x_sovd2uds_broken_by: None,
        x_sovd2uds_broken_at: None,
        x_sovd2uds_current_holder: None,
        schema: None,
    }
}

pub(crate) fn lock_created_example() -> sovd_interfaces::locking::post_put::Response {
    sovd_interfaces::locking::post_put::Response {
        id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
        lock_expiration: None,
        owned: Some(true),
        x_sovd2uds_broken_by: None,
        x_sovd2uds_broken_at: None,
        x_sovd2uds_current_holder: None,
        schema: None,
    }
}

pub(crate) fn lock_list_example() -> sovd_interfaces::locking::get::Response {
    sovd_interfaces::locking::get::Response {
        items: vec![sovd_interfaces::locking::Lock {
            id: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            lock_expiration: Some("2025-01-01T00:00:00Z".to_owned()),
            owned: Some(true),
            x_sovd2uds_broken_by: None,
            x_sovd2uds_broken_at: None,
            x_sovd2uds_current_holder: None,
            schema: None,
        }],
        schema: None,
    }
}

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

// Allowing pass by value here for the config, to prevent life-time issues with the
// borrowed config in the closure.
pub(crate) fn api_docs(api: TransformOpenApi, server_url: String) -> TransformOpenApi {
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
            url: server_url,
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
    op.response_with::<200, Json<sovd_interfaces::ObjectDataItem<VendorErrorCode>>, _>(|res| {
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
                    errors: vec![],
                    schema: None,
                });
        res.inner().content.insert(
            "application/octet-stream".to_owned(),
            MediaType {
                example: Some(serde_json::json!([0xABu8, 0xCD, 0xEF, 0x00])),
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
            schema: None,
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
                schema: None,
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
                schema: None,
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
                schema: None,
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
                schema: None,
            })
    })
}

/// Documents lock and update-guard failures shared by diagnostic routes.
pub(crate) fn lock_responses(op: TransformOperation) -> TransformOperation {
    op.response_with::<409, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description(
            "Conflict: A required lock is missing or broken, or an operation conflicts with the \
             current state.",
        )
    })
    .response_with::<423, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Locked: Another client holds an incompatible lock.")
    })
    .response_with::<503, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Service Unavailable: Lock state cannot currently be evaluated.")
    })
}

/// Documents defunct-lock rejection on every diagnostic operation.
pub(crate) fn defunct_lock_path(mut path: TransformPathItem) -> TransformPathItem {
    {
        let item = path.inner_mut();
        for operation in [
            item.get.as_mut(),
            item.put.as_mut(),
            item.post.as_mut(),
            item.delete.as_mut(),
            item.options.as_mut(),
            item.head.as_mut(),
            item.patch.as_mut(),
            item.trace.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            let _ = TransformOperation::new(operation).response_with::<409, Json<
                ApiErrorResponse<sovd::error::VendorErrorCode>,
            >, _>(|response| {
                response.description(
                    "Conflict: A lock previously held by this client was broken by preemption.",
                )
            });
        }
    }
    path
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
                schema: None,
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
                schema: None,
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
                schema: None,
            })
    })
}

#[cfg(test)]
mod tests {
    use aide::{
        openapi::{Operation, StatusCode},
        transform::TransformOperation,
    };

    #[test]
    fn lock_responses_document_shared_json_error_schema() {
        let mut operation = Operation::default();
        let _ = super::lock_responses(TransformOperation::new(&mut operation));
        let responses = operation.responses.expect("lock responses");

        for status in [409, 423, 503] {
            let response = responses
                .responses
                .get(&StatusCode::Code(status))
                .and_then(aide::openapi::ReferenceOr::as_item)
                .expect("documented lock response");
            let schema = response
                .content
                .get("application/json")
                .and_then(|content| content.schema.as_ref())
                .expect("JSON error schema");
            let serialized = serde_json::to_value(schema).expect("serializable schema");
            assert_eq!(
                serialized.get("$ref"),
                Some(&serde_json::json!("#/components/schemas/ApiErrorResponse"))
            );
        }
    }
}
