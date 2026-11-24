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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{SchemaProvider, UdsEcu, file_manager::FileManager, util::std_ext::lock_read};
use cda_plugin_security::Secured;
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::{
    common::operations::OperationIdItem,
    components::ecu::operations::{
        AsyncPostResponse, OperationQuery, service::executions as sovd_executions,
    },
};
use uuid::Uuid;

use crate::{
    openapi,
    sovd::{
        WebserverEcuState,
        binary_encoding::BinaryEncodingParam,
        create_schema,
        error::{ApiError, ErrorWrapper, VendorErrorCode},
        locks::require_ecu_access,
    },
};

pub(crate) mod id;
mod reset;
mod response;
#[cfg(test)]
mod tests;
mod write;

pub(crate) use write::{
    OperationWriteContext, WriteHandlerOptions, WriteHandlerRequest,
    ecu_operation_write_handler_with_activity,
};

openapi::aide_helper::gen_path_param!(OperationServicePathParam service String);

pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
    WithRejection(Query(query), _): WithRejection<Query<sovd_executions::Query>, ApiError>,
    State(WebserverEcuState {
        ecu_name,
        locks,
        service_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(
        read,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let schema = if query.include_schema {
        Some(create_schema!(sovd_interfaces::Items<OperationIdItem>))
    } else {
        None
    };
    let ids: Vec<OperationIdItem> = lock_read(&service_executions)
        .get(&service)
        .map(|op_map| {
            op_map
                .iter()
                .filter(|(_, v)| v.is_created)
                .map(|(k, _)| OperationIdItem { id: k.to_string() })
                .collect()
        })
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(sovd_interfaces::Items { items: ids, schema }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("List all active service operation executions")
        .response_with::<200, Json<sovd_interfaces::Items<String>>, _>(|res| {
            res.description("List of active execution ids.")
        })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Axum extractors cannot be combined without a new custom extractor"
)]
pub(crate) async fn post<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
    WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
    BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        service_executions,
        communication_access,
        ..
    }): State<WebserverEcuState<T, U>>,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    require_ecu_access!(
        write,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let ctx = OperationWriteContext::new(service_executions, communication_access);
    ecu_operation_write_handler_with_activity::<T>(
        WriteHandlerRequest {
            service,
            headers,
            body,
        },
        &ecu_name,
        &uds,
        ctx,
        security_plugin,
        WriteHandlerOptions {
            include_schema: query.include_schema,
            suppress_service: query.suppress_service,
            base_path: format!("http://{host}{uri}"),
            binary_encoding,
        },
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    openapi::request_json_and_octet::<sovd_executions::Request>(op)
        .description("Start a new operation execution (Start subfunction)")
        .response_with::<200, Json<sovd_executions::Response<VendorErrorCode>>, _>(|res| {
            let mut res = res
                .description("Execution started, synchronous result.")
                .example(sovd_executions::Response {
                    parameters: Some(serde_json::json!({
                        "example_param": "example_value",
                    })),
                    error: None,
                    schema: None,
                });
            res.inner().content.insert(
                "application/octet-stream".to_owned(),
                aide::openapi::MediaType {
                    example: Some(serde_json::json!([0xABu8, 0xCD, 0xEF, 0x00])),
                    ..Default::default()
                },
            );
            res
        })
        .response_with::<
            202,
            Json<
                AsyncPostResponse<
                    serde_json::Map<String, serde_json::Value>,
                    VendorErrorCode,
                >,
            >,
            _,
        >(|res| {
            res.description(
                "Execution started asynchronously. Use the returned id for GET/DELETE on \
                 /executions/{id}.",
            )
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_not_found)
        .with(openapi::error_forbidden)
        .with(openapi::error_conflict)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_gateway)
}

fn parse_exec_uuid(id: &str, include_schema: bool) -> Result<Uuid, ErrorWrapper> {
    Uuid::parse_str(id).map_err(|e| ErrorWrapper {
        error: ApiError::BadRequest(format!("{e:?}")),
        include_schema,
    })
}
