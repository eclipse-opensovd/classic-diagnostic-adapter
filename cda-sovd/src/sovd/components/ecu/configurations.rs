/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DynamicPlugin, UdsEcu, datatypes::ComponentConfigurationsInfo,
    diagservices::DiagServiceResponse, file_manager::FileManager,
};
use cda_plugin_security::Secured;
use http::StatusCode;
use sovd_interfaces::components::ecu::configurations as sovd_configurations;

use crate::sovd::{
    IntoSovd, WebserverEcuState, create_schema,
    error::{ApiError, ErrorWrapper},
};

pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
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
        DiagComm, DiagCommType, SchemaProvider, UdsEcu, diagservices::DiagServiceResponse,
        file_manager::FileManager,
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

    pub(crate) async fn put<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager,
    >(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam {
            diag_service: service,
        }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_configurations::ConfigurationsQuery>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
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
}
