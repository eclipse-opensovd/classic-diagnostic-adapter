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

use aide::{UseApi, openapi::OpenApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use cda_interfaces::{
    DiagComm, DiagCommType, DynamicPlugin, SchemaProvider, UdsEcu, file_manager::FileManager,
    subfunction_ids,
};
use cda_plugin_security::Secured;

use crate::{
    openapi,
    sovd::{
        WebserverEcuState,
        docs::{self, operations::OperationDocsMeta},
        error::ApiError,
        locks::require_ecu_access,
    },
};

openapi::aide_helper::gen_path_param!(OperationNamePathParam service String);

pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(OperationNamePathParam { service }): Path<OperationNamePathParam>,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(read, security_plugin, &ecu_name, &locks, false);
    let security_plugin: DynamicPlugin = security_plugin;

    let ops_info = match uds
        .get_components_operations_info(&ecu_name, &security_plugin)
        .await
    {
        Ok(info) => info,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let Some(op_info) = ops_info
        .iter()
        .find(|o| o.id.eq_ignore_ascii_case(&service))
    else {
        return ApiError::NotFound(Some(format!("Operation '{service}' not found")))
            .into_response();
    };

    let is_async = op_info.has_stop || op_info.has_request_results;

    let diag_service = DiagComm {
        name: service.clone(),
        type_: DiagCommType::Operations,
        lookup_name: None,
        subfunction_id: Some(subfunction_ids::routine::START),
    };

    let request_params_schema = uds
        .schema_for_request(&ecu_name, &diag_service)
        .await
        .ok()
        .and_then(|s| s.with_all_binary_encodings().into_schema());

    let response_params_schema = uds
        .schema_for_responses(&ecu_name, &diag_service)
        .await
        .ok()
        .and_then(|s| s.with_all_binary_encodings().into_schema());

    let meta = OperationDocsMeta {
        name: service.clone(),
        is_async,
        request_params_schema,
        response_params_schema,
    };

    let base_path = format!("/components/{ecu_name}/operations/{service}");
    let path_items = docs::operations::build_path_items(&base_path, &meta);
    let doc = docs::build_openapi_doc(&format!("Operation: {service}"), path_items);

    (StatusCode::OK, Json(doc)).into_response()
}

pub(crate) fn docs_transform(op: TransformOperation) -> TransformOperation {
    op.description(
        "Online capability description for a specific operation on this ECU component (ISO \
         17978-3 Section 7.5). Returns a self-contained OpenAPI specification.",
    )
    .response_with::<200, Json<OpenApi>, _>(|res| {
        res.description("Self-contained OpenAPI 3.1 specification for this operation.")
    })
    .with(openapi::error_not_found)
}
