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

use aide::UseApi;
use axum::{
    Extension, Json,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::components::ecu::operations::OperationCollectionItem;

use crate::{
    dynamic_router::{DataResources, OperationResources},
    sovd::{create_schema, data_list_response, error::ApiError},
};

pub(crate) mod bulk_data;
pub(crate) mod data;
pub(crate) mod operations;

pub(crate) async fn get(
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    Extension(operations): Extension<OperationResources>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    let base_path = format!("http://{host}/vehicle/v15/apps/sovd2uds");
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::apps::sovd2uds::get::Response
        ))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_interfaces::apps::sovd2uds::get::Response {
            id: "sovd2uds".to_owned(),
            name: "sovd2uds".to_owned(),
            bulk_data: format!("{base_path}/bulk-data"),
            data: format!("{base_path}/data"),
            operations: (!operations.list(OPERATIONS_PATH).await.is_empty())
                .then(|| format!("{base_path}/operations")),
            schema,
        }),
    )
        .into_response()
}

/// The data collection of the `sovd2uds` app.
pub(crate) const DATA_PATH: &str = "/vehicle/v15/apps/sovd2uds/data";

/// Lists the data resources registered in [`DATA_PATH`].
pub(crate) async fn data_get(
    Extension(data_resources): Extension<DataResources>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    data_list_response(data_resources.list(DATA_PATH).await, query.include_schema)
}

/// The bulk-data collection of the `sovd2uds` app.
pub(crate) const BULK_DATA_PATH: &str = "/vehicle/v15/apps/sovd2uds/bulk-data";

/// The operations collection of the `sovd2uds` app.
pub(crate) const OPERATIONS_PATH: &str = "/vehicle/v15/apps/sovd2uds/operations";

/// Lists the operations registered in [`OPERATIONS_PATH`].
pub(crate) async fn operations_get(
    Extension(operations): Extension<OperationResources>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    let items = operations
        .list(OPERATIONS_PATH)
        .await
        .into_iter()
        .map(|(id, asynchronous)| OperationCollectionItem {
            name: id.clone(),
            id,
            proximity_proof_required: false,
            asynchronous_execution: asynchronous,
        })
        .collect();
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::Items<OperationCollectionItem>
        ))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_interfaces::Items { items, schema }),
    )
        .into_response()
}
