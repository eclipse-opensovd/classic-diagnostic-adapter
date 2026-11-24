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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{DynamicPlugin, SchemaProvider, UdsEcu, file_manager::FileManager};
use cda_plugin_security::Secured;
use sovd_interfaces::components::ecu::operations::OperationCollectionItem;

use crate::sovd::{
    WebserverEcuState, create_schema,
    error::{ApiError, ErrorWrapper},
    locks::require_ecu_access,
};

pub(crate) mod comparams;
pub(crate) mod service;
#[cfg(test)]
mod tests;

pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
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
    let security_plugin: DynamicPlugin = security_plugin;
    match uds
        .get_components_operations_info(&ecu_name, &security_plugin)
        .await
    {
        Ok(items) => {
            let schema = if query.include_schema {
                Some(create_schema!(
                    sovd_interfaces::Items<OperationCollectionItem>
                ))
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(sovd_interfaces::Items {
                    items: items
                        .into_iter()
                        .map(|info| OperationCollectionItem {
                            id: info.id,
                            name: info.name,
                            proximity_proof_required: false,
                            asynchronous_execution: info.has_stop || info.has_request_results,
                        })
                        .collect(),
                    schema,
                }),
            )
                .into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all available operations for this ECU component")
        .response_with::<200, Json<sovd_interfaces::Items<OperationCollectionItem>>, _>(|res| {
            res.description("List of operations available on this ECU.")
        })
}
