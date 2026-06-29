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
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DynamicPlugin, UdsEcu, datatypes::ComponentConfigurationsInfo, file_manager::FileManager,
};
use cda_plugin_security::Secured;
use http::StatusCode;
use sovd_interfaces::components::ecu::configurations as sovd_configurations;

use crate::sovd::{
    IntoSovd, WebserverEcuState, create_schema,
    error::{ApiError, ErrorWrapper},
};

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_configurations::ConfigurationsQuery>,
        ApiError,
    >,
) -> Response {
    let schema = if query.include_schema {
        Some(create_schema!(sovd_configurations::get::Response))
    } else {
        None
    };
    match uds
        .get_components_configuration_info(&ecu_name, &(security_plugin as DynamicPlugin))
        .await
    {
        Ok(mut items) => {
            let sovd_component_configuration = sovd_configurations::get::Response {
                items: items
                    .drain(0..)
                    .map(crate::sovd::IntoSovd::into_sovd)
                    .collect::<Vec<sovd_configurations::ComponentItem>>(),
                schema,
            };
            (StatusCode::OK, Json(sovd_component_configuration)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: ApiError::from(e),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all configuration services for the component")
        .response_with::<200, Json<sovd_configurations::get::Response>, _>(|res| {
            res.example(sovd_configurations::get::Response {
                items: vec![sovd_configurations::ComponentItem {
                    id: "example_id".into(),
                    name: "example_name".into(),
                    configurations_type: "example_type".into(),
                    service_abstract: vec!["example_service".into()],
                }],
                schema: None,
            })
        })
}

impl IntoSovd for ComponentConfigurationsInfo {
    type SovdType = sovd_configurations::ComponentItem;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            id: self.id,
            name: self.name,
            configurations_type: self.configurations_type,
            service_abstract: self
                .service_abstract
                .iter()
                .map(|service_abstract| {
                    service_abstract
                        .iter()
                        .fold(String::new(), |mut acc, byte| {
                            use std::fmt::Write;
                            if let Err(e) = write!(&mut acc, "{byte:02X}") {
                                tracing::error!(error = ?e, "Error writing service abstract");
                            }
                            acc
                        })
                })
                .collect(),
        }
    }
}

pub(crate) mod diag_service {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        body::Bytes,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        DiagComm, DiagCommType, SchemaProvider, UdsEcu, file_manager::FileManager,
    };
    use cda_plugin_security::Secured;
    use http::HeaderMap;
    use sovd_interfaces::components::ecu::configurations as sovd_configurations;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            components::ecu::{DiagServicePathParam, data_request},
            error::{ApiError, ErrorWrapper},
        },
    };

    pub(crate) async fn put<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam { service }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_configurations::ConfigurationsQuery>,
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
            .description("Update data for a specific configuration service")
            .with(openapi::ecu_service_response)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }

    /// `GET /configurations/{service}/docs` - online capability description for a
    /// configuration service.
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

        openapi::aide_helper::gen_path_param!(ConfigDocsPathParam service String);

        pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(ConfigDocsPathParam { service }): Path<ConfigDocsPathParam>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
        ) -> Response {
            let security_plugin: DynamicPlugin = security_plugin;

            // Verify the configuration service exists
            let config_info = match uds
                .get_components_configuration_info(&ecu_name, &security_plugin)
                .await
            {
                Ok(info) => info,
                Err(e) => return ApiError::from(e).into_response(),
            };

            if !config_info
                .iter()
                .any(|c| c.id.eq_ignore_ascii_case(&service))
            {
                return ApiError::NotFound(Some(format!(
                    "Configuration service '{service}' not found"
                )))
                .into_response();
            }

            docs::data::build_docs_response(&uds, &ecu_name, &service, "configurations").await
        }

        pub(crate) fn docs_transform(op: TransformOperation) -> TransformOperation {
            op.description(
                "Online capability description for a specific configuration service on this ECU \
                 component (ISO 17978-3 Section 7.5). Returns a self-contained OpenAPI \
                 specification describing the available methods (GET and PUT) with their data \
                 types.",
            )
            .response_with::<200, Json<OpenApi>, _>(|res| {
                res.description(
                    "Self-contained OpenAPI 3.1 specification for this configuration service.",
                )
            })
            .with(openapi::error_not_found)
        }

        #[cfg(test)]
        mod tests {
            use aide::UseApi;
            use axum::{extract::State, http::StatusCode};
            use cda_interfaces::{
                DiagServiceError, datatypes::ComponentConfigurationsInfo,
                file_manager::mock::MockFileManager, mock::MockUdsEcu,
            };
            use cda_plugin_security::{Secured, mock::TestSecurityPlugin};

            use super::*;
            use crate::sovd::tests::create_test_webserver_state;

            #[tokio::test]
            async fn returns_200_with_openapi_doc_when_config_exists() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_configuration_info()
                    .withf(|ecu, _| ecu == "TestECU")
                    .times(1)
                    .returning(|_, _| {
                        Ok(vec![ComponentConfigurationsInfo {
                            id: "VarCoding1".to_owned(),
                            name: "Variant Coding 1".to_owned(),
                            configurations_type: "varcoding".to_owned(),
                            service_abstract: vec![vec![0x22, 0x01, 0x00]],
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
                    Path(ConfigDocsPathParam {
                        service: "VarCoding1".to_owned(),
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
            async fn returns_404_when_config_not_found() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_configuration_info()
                    .returning(|_, _| {
                        Ok(vec![ComponentConfigurationsInfo {
                            id: "VarCoding1".to_owned(),
                            name: "Variant Coding 1".to_owned(),
                            configurations_type: "varcoding".to_owned(),
                            service_abstract: vec![],
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
                    Path(ConfigDocsPathParam {
                        service: "NonExistent".to_owned(),
                    }),
                    State(state),
                )
                .await;

                assert_eq!(response.status(), StatusCode::NOT_FOUND);
            }

            #[tokio::test]
            async fn returns_error_when_config_info_lookup_fails() {
                let mut mock_uds = MockUdsEcu::new();
                mock_uds
                    .expect_get_components_configuration_info()
                    .returning(|_, _| {
                        Err(DiagServiceError::NotFound(
                            "Functional class not found".to_owned(),
                        ))
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
                    Path(ConfigDocsPathParam {
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
