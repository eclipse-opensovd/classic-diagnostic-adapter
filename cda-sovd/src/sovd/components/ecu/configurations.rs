/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    UdsEcu, datatypes::ComponentConfigurationsInfo, diagservices::DiagServiceResponse,
    file_manager::FileManager,
};
use http::StatusCode;
use sovd_interfaces::components::ecu::configurations as sovd_configurations;

use crate::sovd::{
    IntoSovd, WebserverEcuState,
    error::{ApiError, ErrorWrapper},
};

pub(crate) async fn get<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    match uds.get_components_configuration_info(&ecu_name).await {
        Ok(mut items) => {
            let sovd_component_configuration = sovd_configurations::get::Response {
                items: items
                    .drain(0..)
                    .map(|c| c.into_sovd())
                    .collect::<Vec<sovd_configurations::ComponentItem>>(),
            };
            (StatusCode::OK, Json(sovd_component_configuration)).into_response()
        }
        Err(e) => ErrorWrapper(ApiError::from(e)).into_response(),
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
                        .map(|byte| format!("{byte:02X}"))
                        .collect()
                })
                .collect(),
        }
    }
}

pub(crate) mod diag_service {
    use aide::transform::TransformOperation;
    use axum::{
        body::Bytes,
        extract::{Path, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        DiagComm, DiagCommAction, DiagCommType, SchemaProvider, UdsEcu,
        diagservices::DiagServiceResponse, file_manager::FileManager,
    };
    use http::HeaderMap;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            components::ecu::{DiagServicePathParam, data_request},
            error::{ApiError, ErrorWrapper},
        },
    };

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        headers: HeaderMap,
        Path(DiagServicePathParam {
            diag_service: service,
        }): Path<DiagServicePathParam>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Bytes,
    ) -> Response {
        if service.contains('/') {
            return ErrorWrapper(ApiError::BadRequest("Invalid path".to_owned())).into_response();
        }
        data_request::<T>(
            DiagComm {
                name: service.clone(),
                action: DiagCommAction::Write,
                type_: DiagCommType::Configurations,
                lookup_name: None,
            },
            &ecu_name,
            &uds,
            headers,
            Some(body),
            false,
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
