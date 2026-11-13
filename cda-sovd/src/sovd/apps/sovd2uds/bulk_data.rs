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
    Extension,
    extract::{OriginalUri, Query},
    response::Response,
};
use axum_extra::extract::WithRejection;
use opensovd_axum_extra::ExtractHost;

use crate::{
    dynamic_router::BulkDataCategories,
    sovd::{error::ApiError, resource_response},
};

/// The `flashfiles` category.
pub(crate) const FLASHFILES_PATH: &str = "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles";

pub(crate) mod flash_files;
pub(crate) mod runtimefiles;

/// Lists the categories registered in [`BULK_DATA_PATH`](super::BULK_DATA_PATH).
///
/// The `runtimefiles-*` categories only exist with a runtime update plugin, so they are
/// registered together with its routes.
pub(crate) async fn get(
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    Extension(resources): Extension<BulkDataCategories>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let categories = resources.list(super::BULK_DATA_PATH).await;
    resource_response(
        &host,
        &uri,
        categories.iter().map(|id| (id.as_str(), None)).collect(),
        query.include_schema,
    )
}
