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

use aide::UseApi;
use cda_plugin_security::Secured;
use sovd_interfaces::error::ApiErrorResponse;

use super::{
    ApiError, DynamicPlugin, ErrorWrapper, FileManager, IntoResponse, Json, Query, Response, State,
    StatusCode, TransformOperation, UdsEcu, WebserverEcuState, WithRejection,
};
use crate::sovd::{self, create_schema};

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::components::ecu::data::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
) -> Response {
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::components::ecu::data::get::Response
        ))
    } else {
        None
    };
    match uds
        .get_components_data_info(&ecu_name, &(security_plugin as DynamicPlugin))
        .await
    {
        Ok(mut items) => {
            let sovd_component_data = sovd_interfaces::components::ecu::data::get::Response {
                items: items
                    .drain(0..)
                    .map(crate::sovd::IntoSovd::into_sovd)
                    .collect(),
                schema,
            };
            (StatusCode::OK, Json(sovd_component_data)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all ECU data.")
        .response_with::<200, Json<sovd_interfaces::components::ecu::data::get::Response>, _>(
            |res| {
                res.description("Response with all data.").example(
                    sovd_interfaces::components::ecu::data::get::Response {
                        items: vec![sovd_interfaces::components::ecu::ComponentDataInfo {
                            category: "example_category".to_string(),
                            id: "example_id".to_string(),
                            name: "example_name".to_string(),
                        }],
                        schema: None,
                    },
                )
            },
        )
        .response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
            res.description("Error while fetching data from ECU.")
                .example(sovd_interfaces::error::ApiErrorResponse {
                    message: "Failed to fetch ECU data".to_string(),
                    error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                    vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                    parameters: None,
                    error_source: Some("ECU".to_string()),
                    schema: None,
                })
        })
}

pub(crate) mod diag_service {
    use aide::{
        UseApi,
        transform::{TransformOperation, TransformParameter},
    };
    use axum::{
        Json,
        body::Bytes,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        DiagComm, DiagCommType, HashMap, HashMapExtensions, SchemaProvider, UdsEcu,
        file_manager::FileManager,
    };
    use cda_plugin_security::Secured;
    use http::{HeaderMap, StatusCode};

    use crate::{
        openapi,
        sovd::{
            IntoSovd, WebserverEcuState,
            components::ecu::{DiagServicePathParam, data_request},
            create_schema,
            error::{ApiError, ErrorWrapper},
        },
    };

    // [[ dimpl~sovd-api-component-data-sdgsd, GET /data/{service} SDG handler ]]
    async fn get_sdgs_handler<T: UdsEcu + Clone>(
        service: String,
        ecu_name: &str,
        gateway: &T,
        include_schema: bool,
    ) -> Response {
        let service_ops = vec![
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Data,
                lookup_name: None,
                subfunction_id: None,
            },
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Data,
                lookup_name: None,
                subfunction_id: None,
            },
            DiagComm {
                name: service,
                type_: DiagCommType::Data,
                lookup_name: None,
                subfunction_id: None,
            },
        ];
        let schema = if include_schema {
            Some(create_schema!(
                sovd_interfaces::components::ecu::ServicesSdgs
            ))
        } else {
            None
        };
        let mut resp = sovd_interfaces::components::ecu::ServicesSdgs {
            items: HashMap::new(),
            schema,
        };
        for service in service_ops {
            match gateway.get_sdgs(ecu_name, Some(&service)).await {
                Ok(sdgs) => {
                    if sdgs.is_empty() {
                        continue;
                    }
                    resp.items.insert(
                        format!("{}_{:?}", service.name, service.action()).to_lowercase(),
                        sovd_interfaces::components::ecu::ServiceSdgs {
                            sdgs: sdgs.into_sovd(),
                        },
                    );
                }
                Err(e) => {
                    return ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response();
                }
            }
        }
        (StatusCode::OK, Json(resp)).into_response()
    }

    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Send + Sync + Clone, U: FileManager>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam {
            service: diag_service,
        }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::components::ComponentQuery>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        if query.include_sdgs {
            get_sdgs_handler::<T>(diag_service, &ecu_name, &uds, include_schema).await
        } else {
            if diag_service.contains('/') {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Invalid path".to_owned()),
                    include_schema,
                }
                .into_response();
            }
            data_request::<T>(
                DiagComm {
                    name: diag_service,
                    type_: DiagCommType::Data,
                    lookup_name: None,
                    subfunction_id: None,
                },
                &ecu_name,
                &uds,
                headers,
                None,
                security_plugin,
                include_schema,
            )
            .await
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get a specific diagnostic service.")
            .parameter("x-sovd2uds-includesdgs", |op: TransformParameter<bool>| {
                op.description("Set to true to include sdgs.")
            })
            .with(openapi::ecu_service_response)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }

    pub(crate) async fn put<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam { service }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::components::ecu::data::service::put::Query>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
        body: Bytes,
    ) -> Response {
        let include_schema = query.include_schema;
        if service.contains('/') {
            return ErrorWrapper {
                error: ApiError::BadRequest("Invalid path".to_owned()),
                include_schema,
            }
            .into_response();
        }
        data_request::<T>(
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Configurations,
                lookup_name: None,
                subfunction_id: None,
            },
            &ecu_name,
            &uds,
            headers,
            Some(body),
            security_plugin,
            include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            sovd_interfaces::components::ecu::data::DataRequestPayload
        >(op)
            .description("Update data for a specific data service")
            .with(openapi::ecu_service_response)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }

    /// `GET /data/{service}/docs` - online capability description for a data service.
    pub(crate) mod docs_endpoint {
        use aide::{UseApi, openapi::OpenApi, transform::TransformOperation};
        use axum::{
            Json,
            extract::{Path, State},
            response::{IntoResponse as _, Response},
        };
        use cda_interfaces::{DynamicPlugin, SchemaProvider, UdsEcu, file_manager::FileManager};
        use cda_plugin_security::Secured;

        use crate::{
            openapi,
            sovd::{WebserverEcuState, docs, error::ApiError},
        };

        openapi::aide_helper::gen_path_param!(DataDocsPathParam service String);

        pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(DataDocsPathParam { service }): Path<DataDocsPathParam>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
        ) -> Response {
            let security_plugin: DynamicPlugin = security_plugin;

            // Verify the data service exists
            let data_info = match uds
                .get_components_data_info(&ecu_name, &security_plugin)
                .await
            {
                Ok(info) => info,
                Err(e) => return ApiError::from(e).into_response(),
            };

            if !data_info
                .iter()
                .any(|d| d.id.eq_ignore_ascii_case(&service))
            {
                return ApiError::NotFound(Some(format!("Data service '{service}' not found")))
                    .into_response();
            }

            docs::data::build_docs_response(&uds, &ecu_name, &service, "data").await
        }

        pub(crate) fn docs_transform(op: TransformOperation) -> TransformOperation {
            op.description(
                "Online capability description for a specific data service on this ECU component \
                 (ISO 17978-3 Section 7.5). Returns a self-contained OpenAPI specification \
                 describing the available methods (GET and optionally PUT) with their data types.",
            )
            .response_with::<200, Json<OpenApi>, _>(|res| {
                res.description("Self-contained OpenAPI 3.1 specification for this data service.")
            })
            .with(openapi::error_not_found)
        }

        #[cfg(test)]
        mod tests {
            use aide::UseApi;
            use axum::{extract::State, http::StatusCode};
            use cda_interfaces::{
                DiagServiceError, datatypes::ComponentDataInfo,
                file_manager::mock::MockFileManager, mock::MockUdsEcu,
            };
            use cda_plugin_security::{Secured, mock::TestSecurityPlugin};

            use super::*;
            use crate::sovd::tests::create_test_webserver_state;

            #[tokio::test]
            async fn returns_200_with_openapi_doc_when_service_exists() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_data_info()
                    .withf(|ecu, _| ecu == "TestECU")
                    .times(1)
                    .returning(|_, _| {
                        Ok(vec![ComponentDataInfo {
                            category: "sensor".to_owned(),
                            id: "EngineTemp".to_owned(),
                            name: "Engine Temperature".to_owned(),
                        }])
                    });

                let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
                    "TestECU".to_owned(),
                    mock_uds,
                    MockFileManager::new(),
                );

                let response = get::<MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(DataDocsPathParam {
                        service: "EngineTemp".to_owned(),
                    }),
                    State(state),
                )
                .await;

                assert_eq!(response.status(), StatusCode::OK);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(
                    doc.get("info").is_some(),
                    "Response should be a valid OpenAPI doc"
                );
                assert!(doc.get("paths").is_some(), "Response should contain paths");
            }

            #[tokio::test]
            async fn returns_404_when_service_not_found() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_data_info()
                    .returning(|_, _| {
                        Ok(vec![ComponentDataInfo {
                            category: "sensor".to_owned(),
                            id: "EngineTemp".to_owned(),
                            name: "Engine Temperature".to_owned(),
                        }])
                    });

                let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
                    "TestECU".to_owned(),
                    mock_uds,
                    MockFileManager::new(),
                );

                let response = get::<MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(DataDocsPathParam {
                        service: "NonExistent".to_owned(),
                    }),
                    State(state),
                )
                .await;

                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }

            #[tokio::test]
            async fn returns_error_when_data_info_lookup_fails() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_data_info()
                    .returning(|_, _| Err(DiagServiceError::NotFound("ECU not found".to_owned())));

                let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
                    "TestECU".to_owned(),
                    mock_uds,
                    MockFileManager::new(),
                );

                let response = get::<MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(DataDocsPathParam {
                        service: "Anything".to_owned(),
                    }),
                    State(state),
                )
                .await;

                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }
        }
    }
}
