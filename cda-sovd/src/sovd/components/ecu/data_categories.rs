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

use std::collections::BTreeSet;

use aide::UseApi;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_plugin_security::Secured;
use http::StatusCode;
use sovd_interfaces::components::ecu::data_categories as sovd_data_categories;

use super::{ApiError, DynamicPlugin, ErrorWrapper, FileManager, UdsEcu, WebserverEcuState};
use crate::sovd::create_schema;

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_data_categories::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
) -> Response {
    let schema = if query.include_schema {
        Some(create_schema!(sovd_data_categories::get::Response))
    } else {
        None
    };
    match uds
        .get_components_data_info(&ecu_name, &(security_plugin as DynamicPlugin))
        .await
    {
        Ok(items) => {
            let categories: BTreeSet<String> =
                items.into_iter().map(|item| item.category).collect();
            let response = sovd_data_categories::get::Response {
                items: categories
                    .into_iter()
                    .map(|category| sovd_data_categories::DataCategoryInformation {
                        item: category,
                        category_translation_id: None,
                    })
                    .collect(),
                schema,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(
    op: aide::transform::TransformOperation,
) -> aide::transform::TransformOperation {
    op.description(
        "Get all data categories currently in use by this ECU component's /data resources \
         (ISO 17978-3 Section 7.9.2.1).",
    )
    .response_with::<200, Json<sovd_data_categories::get::Response>, _>(|res| {
        res.description("Response with all data categories.").example(
            sovd_data_categories::get::Response {
                items: vec![sovd_data_categories::DataCategoryInformation {
                    item: "identData".to_string(),
                    category_translation_id: None,
                }],
                schema: None,
            },
        )
    })
    .response_with::<400, Json<sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode>>, _>(
        |res| {
            res.description("Error while fetching data from ECU.")
                .example(sovd_interfaces::error::ApiErrorResponse {
                    message: "Failed to fetch ECU data".to_string(),
                    error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                    vendor_code: Some(crate::sovd::error::VendorErrorCode::BadRequest),
                    parameters: None,
                    error_source: Some("ECU".to_string()),
                    schema: None,
                })
        },
    )
}

#[cfg(test)]
mod tests {
    use aide::UseApi;
    use axum::extract::State;
    use cda_interfaces::{
        datatypes::ComponentDataInfo, file_manager::mock::MockFileManager, mock::MockUdsEcu,
    };
    use cda_plugin_security::{Secured, mock::TestSecurityPlugin};

    use super::*;
    use crate::sovd::tests::create_test_webserver_state;

    async fn call_get(mock_uds: MockUdsEcu) -> Response {
        let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
            "TestECU".to_owned(),
            mock_uds,
            MockFileManager::new(),
        );

        get::<MockUdsEcu, MockFileManager>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                Query(sovd_data_categories::get::Query {
                    include_schema: false,
                }),
                std::marker::PhantomData,
            ),
            State(state),
        )
        .await
    }

    #[tokio::test]
    async fn returns_deduplicated_sorted_categories() {
        let mut mock_uds = MockUdsEcu::new();
        mock_uds
            .expect_get_components_data_info()
            .returning(|_, _| {
                Ok(vec![
                    ComponentDataInfo {
                        category: "currentData".to_owned(),
                        id: "Foo".to_owned(),
                        name: "Foo".to_owned(),
                    },
                    ComponentDataInfo {
                        category: "identData".to_owned(),
                        id: "Bar".to_owned(),
                        name: "Bar".to_owned(),
                    },
                    ComponentDataInfo {
                        category: "currentData".to_owned(),
                        id: "Baz".to_owned(),
                        name: "Baz".to_owned(),
                    },
                ])
            });

        let response = call_get(mock_uds).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = doc.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2, "categories must be deduplicated");
        assert_eq!(
            items.first().expect("Expected item 0")["item"],
            "currentData"
        );
        assert_eq!(items.get(1).expect("Expected item 1")["item"], "identData");
    }

    #[tokio::test]
    async fn returns_empty_when_no_data_items() {
        let mut mock_uds = MockUdsEcu::new();
        mock_uds
            .expect_get_components_data_info()
            .returning(|_, _| Ok(vec![]));

        let response = call_get(mock_uds).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(doc.get("items").unwrap().as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn returns_error_when_lookup_fails() {
        use cda_interfaces::DiagServiceError;

        let mut mock_uds = MockUdsEcu::new();
        mock_uds
            .expect_get_components_data_info()
            .returning(|_, _| Err(DiagServiceError::NotFound("ECU not found".to_owned())));

        let response = call_get(mock_uds).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
