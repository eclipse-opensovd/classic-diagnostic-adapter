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

pub(in crate::sovd) mod single_ecu {
    use axum::{
        Json,
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};

    use crate::sovd::{
        SovdComponentData, WebserverEcuState,
        error::{ApiError, ErrorWrapper},
    };

    pub(in crate::sovd) async fn get_ecu_single_job_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds.get_components_single_ecu_jobs_info(&ecu_name).await {
            Ok(mut items) => {
                let sovd_component_data = SovdComponentData {
                    items: items.drain(0..).map(std::convert::Into::into).collect(),
                };
                (StatusCode::OK, Json(sovd_component_data)).into_response()
            }
            Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
        }
    }

    pub(in crate::sovd) async fn get_ecu_single_jobs_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(job_name): Path<String>,
        State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        uds.get_single_ecu_job(&ecu_name, &job_name)
            .await
            .map_or_else(
                |e| ErrorWrapper(e.into()).into_response(),
                |job| (StatusCode::OK, Json(job)).into_response(),
            )
    }
}
