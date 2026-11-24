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

use crate::{
    dynamic_router::DataResources,
    sovd::{create_schema, data_list_response, error::ApiError},
};

pub(crate) async fn get(
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    let base_path = format!("http://{host}/vehicle/v15");
    let schema = if query.include_schema {
        Some(create_schema!(sovd_interfaces::vehicle::get::Response))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_interfaces::vehicle::get::Response {
            id: String::new(),
            name: String::new(),
            components: format!("{base_path}/components"),
            apps: format!("{base_path}/apps"),
            functions: format!("{base_path}/functions"),
            locks: format!("{base_path}/locks"),
            data: format!("{base_path}/data"),
            schema,
        }),
    )
        .into_response()
}

/// The data collection of the vehicle.
pub(crate) const DATA_PATH: &str = "/vehicle/v15/data";

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
