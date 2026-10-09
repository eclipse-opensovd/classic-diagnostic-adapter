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

//! `GET {host}[/{manufacturer}]/version-info` (ISO 17978-3 §5.6, Tables 36-38).

use aide::{
    axum::{ApiRouter, routing},
    transform::TransformOperation,
};
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use http::StatusCode;
use serde::Serialize;
use sovd_interfaces::version_info::{SovdInfo, get};

use crate::{
    api_config::{API_PATH_PREFIX, SOVD_STANDARD_VERSION, SovdApiConfig},
    dynamic_router::DynamicRouter,
    sovd::{create_schema, error::ApiError},
};

/// Paths serving the version info: without and with the manufacturer prefix.
/// The path does not contain a version segment, so it is stable across API versions.
const VERSION_INFO_PATHS: [&str; 2] = ["/version-info", "/vehicle/version-info"];

/// Adds the `version-info` resource, listing one entry per served version segment.
/// `base_uri` is a relative URI reference, so it is valid for every host the server
/// is reached on.
pub async fn add_version_info_endpoint<V>(
    dynamic_router: &DynamicRouter,
    api_config: &SovdApiConfig,
    vendor_info: Option<V>,
) where
    V: Serialize + schemars::JsonSchema + Clone + Send + Sync + 'static,
{
    let response = build_response(api_config, vendor_info.as_ref());
    let docs_example = response.clone();
    let router = VERSION_INFO_PATHS
        .into_iter()
        .fold(ApiRouter::new(), |router, path| {
            let docs_example = docs_example.clone();
            router.api_route(
                path,
                routing::get_with(get::<V>, move |op| docs_get(op, docs_example.clone())),
            )
        })
        .with_state(response);
    dynamic_router.add_routes(router).await;
}

fn build_response<V: Clone>(
    api_config: &SovdApiConfig,
    vendor_info: Option<&V>,
) -> get::Response<V> {
    get::Response {
        sovd_info: api_config
            .version_segments()
            .into_iter()
            .map(|segment| SovdInfo {
                version: SOVD_STANDARD_VERSION.to_owned(),
                base_uri: format!("{API_PATH_PREFIX}/{segment}"),
                vendor_info: vendor_info.cloned(),
            })
            .collect(),
        schema: None,
    }
}

async fn get<V>(
    State(mut response): State<get::Response<V>>,
    WithRejection(Query(query), _): WithRejection<Query<get::Query>, ApiError>,
) -> Response
where
    V: Serialize + schemars::JsonSchema + Clone + Send + Sync + 'static,
{
    if query.include_schema {
        response.schema = Some(create_schema!(get::Response<V>));
    }
    (StatusCode::OK, Json(response)).into_response()
}

fn docs_get<V>(op: TransformOperation, example: get::Response<V>) -> TransformOperation
where
    V: Serialize + schemars::JsonSchema,
{
    op.description("Get the SOVD versions and base URIs offered by the server")
        .response_with::<200, Json<get::Response<V>>, _>(|res| res.example(example))
}

#[cfg(test)]
mod tests {
    use sovd_interfaces::version_info::VendorInfo;

    use super::*;

    #[test]
    fn lists_one_base_uri_per_segment() {
        let response = build_response(
            &SovdApiConfig::default(),
            Some(&VendorInfo {
                version: "0.1.0".to_owned(),
                name: "CDA".to_owned(),
            }),
        );
        let vendor_info = serde_json::json!({ "version": "0.1.0", "name": "CDA" });
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "sovd_info": [
                    { "version": "1.1.0", "base_uri": "/vehicle/v15", "vendor_info": vendor_info },
                    { "version": "1.1.0", "base_uri": "/vehicle/v1", "vendor_info": vendor_info },
                ]
            })
        );
    }
}
