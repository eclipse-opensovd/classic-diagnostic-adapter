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
    use axum::{
        body::Bytes,
        extract::{Path, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        DiagComm, DiagCommAction, DiagCommType, UdsEcu, diagservices::DiagServiceResponse,
        file_manager::FileManager,
    };
    use http::HeaderMap;

    use crate::sovd::{
        WebserverEcuState,
        components::ecu::data_request,
        error::{ApiError, ErrorWrapper},
    };

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        headers: HeaderMap,
        Path(service): Path<String>,
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
            body,
        )
        .await
    }
}
