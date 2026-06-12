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

use aide::UseApi;
use axum::{
    extract::{OriginalUri, Query},
    response::Response,
};
use axum_extra::extract::WithRejection;
use opensovd_axum_extra::ExtractHost;

use crate::sovd::{error::ApiError, resource_response};

pub(crate) mod flash_files;
pub(crate) mod runtimefiles;

pub(crate) async fn get(
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    OriginalUri(uri): OriginalUri,
) -> Response {
    resource_response(
        &host,
        &uri,
        vec![("flashfiles", None)],
        query.include_schema,
    )
}
