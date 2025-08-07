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
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};
use http::StatusCode;
use serde::Deserialize;

use crate::sovd::{
    IntoSovd, WebserverEcuState,
    error::{ApiError, ErrorWrapper},
};

pub(crate) mod configurations;
pub(crate) mod data;
pub(crate) mod genericservice;
pub(crate) mod modes;
pub(crate) mod operations;
pub(crate) mod x_single_ecu_jobs;
pub(crate) mod x_sovd2uds_bulk_data;
pub(crate) mod x_sovd2uds_download;

#[derive(Deserialize)]
pub(crate) struct ComponentQuery {
    #[serde(rename = "x-include-sdgs")]
    pub include_sdgs: Option<bool>,
}

pub(crate) async fn get<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    Query(query): Query<ComponentQuery>,
) -> Response {
    let base_path = format!("http://localhost:20002/vehicle/v15/components/{ecu_name}");
    let variant = match uds.get_variant(&ecu_name).await {
        Ok(v) => v,
        Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    };

    let mut sdgs = None;
    if Some(true) == query.include_sdgs {
        sdgs = match uds
            .get_sdgs(&ecu_name, None)
            .await
            .map_err(ApiError::BadRequest)
        {
            Ok(v) => Some(v),
            Err(e) => return ErrorWrapper(e).into_response(),
        }
    }
    (
        StatusCode::OK,
        Json(sovd_interfaces::components::ecu::get::Response {
            id: ecu_name.to_lowercase(),
            name: ecu_name.clone(),
            variant,
            locks: format!("{base_path}/locks"),
            operations: format!("{base_path}/operations"),
            data: format!("{base_path}/data"),
            sdgs: sdgs.map(|sdgs| sdgs.into_sovd()),
            single_ecu_jobs: format!("{base_path}/x-single-ecu-jobs"),
        }),
    )
        .into_response()
}
pub(crate) async fn post<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

pub(crate) async fn put<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

async fn update<T: UdsEcu + Send + Sync + Clone>(ecu_name: &str, uds: T) -> Response {
    match uds.detect_variant(ecu_name).await {
        Ok(()) => (StatusCode::CREATED, ()).into_response(),
        Err(e) => ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComplexComParamValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComplexComParamValue;

    fn into_sovd(self) -> Self::SovdType {
        self.into_iter()
            .map(|(key, value)| (key, value.into_sovd()))
            .collect()
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComParamValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComParamValue;

    fn into_sovd(self) -> Self::SovdType {
        match self {
            Self::Simple(simple) => Self::SovdType::Simple(simple.into_sovd()),
            Self::Complex(complex) => Self::SovdType::Complex(complex.into_sovd()),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComParamSimpleValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComParamSimpleValue;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            value: self.value.clone(),
            unit: self.unit.map(|u| {
                sovd_interfaces::components::ecu::operations::comparams::Unit {
                    factor_to_si_unit: u.factor_to_si_unit,
                    offset_to_si_unit: u.offset_to_si_unit,
                }
            }),
        }
    }
}
