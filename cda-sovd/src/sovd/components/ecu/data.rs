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

use super::*;

pub(crate) async fn get<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    match uds.get_components_data_info(&ecu_name).await {
        Ok(mut items) => {
            let sovd_component_data = sovd_interfaces::components::ecu::data::get::Response {
                items: items.drain(0..).map(|info| info.into_sovd()).collect(),
            };
            (StatusCode::OK, Json(sovd_component_data)).into_response()
        }
        Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    }
}

pub(crate) mod diag_service {
    use axum::{
        Json,
        body::Bytes,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        DiagComm, DiagCommAction, DiagCommType, UdsEcu, diagservices::DiagServiceResponse,
        file_manager::FileManager,
    };
    use hashbrown::HashMap;
    use http::{HeaderMap, StatusCode};
    use sovd_interfaces::components::ecu::data::service::get::DiagServiceQuery;

    use crate::sovd::{
        IntoSovd, WebserverEcuState,
        components::ecu::data_request,
        error::{ApiError, ErrorWrapper},
    };

    async fn get_sdgs_handler<T: UdsEcu + Send + Sync + Clone>(
        service: String,
        ecu_name: &str,
        gateway: &T,
    ) -> Response {
        let service_ops = vec![
            DiagComm {
                name: service.clone(),
                action: DiagCommAction::Read,
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            DiagComm {
                name: service.clone(),
                action: DiagCommAction::Write,
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            DiagComm {
                name: service,
                action: DiagCommAction::Start,
                type_: DiagCommType::Data,
                lookup_name: None,
            },
        ];
        let mut resp = sovd_interfaces::components::ecu::ServicesSdgs {
            items: HashMap::new(),
        };
        for service in service_ops {
            match gateway.get_sdgs(ecu_name, Some(&service)).await {
                Ok(sdgs) => {
                    if sdgs.is_empty() {
                        continue;
                    }
                    resp.items.insert(
                        format!("{}_{:?}", service.name, service.action).to_lowercase(),
                        sovd_interfaces::components::ecu::ServiceSdgs {
                            sdgs: sdgs.into_sovd(),
                        },
                    );
                }
                Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
            }
        }
        (StatusCode::OK, Json(resp)).into_response()
    }

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        headers: HeaderMap,
        Path(diag_service): Path<String>,
        Query(query): Query<DiagServiceQuery>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Bytes,
    ) -> Response {
        if Some(true) == query.include_sdgs {
            get_sdgs_handler::<T>(diag_service, &ecu_name, &uds).await
        } else {
            if diag_service.contains('/') {
                return ErrorWrapper(ApiError::BadRequest("Invalid path".to_owned()))
                    .into_response();
            }
            data_request::<T>(
                DiagComm {
                    name: diag_service,
                    action: DiagCommAction::Read,
                    type_: DiagCommType::Data,
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
