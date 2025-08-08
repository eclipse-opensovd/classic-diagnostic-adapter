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
    body::Bytes,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    DiagComm, UdsEcu,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;

use crate::sovd::{
    IntoSovd, WebserverEcuState,
    error::{ApiError, ErrorWrapper, api_error_from_diag_response},
    get_payload_data,
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
            configurations: format!("{base_path}/configurations"),
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

async fn data_request<T: UdsEcu + Send + Sync + Clone>(
    service: DiagComm,
    ecu_name: &str,
    gateway: &T,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let data = match get_payload_data::<sovd_interfaces::components::ecu::data::DataRequestPayload>(
        &headers, &body,
    ) {
        Ok(value) => value,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    let (response_mime, map_to_json) = match headers.get(header::ACCEPT) {
        Some(v)
            if v == mime::APPLICATION_JSON.essence_str() || v == mime::STAR_STAR.essence_str() =>
        {
            (Some(v), true)
        }
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => (Some(v), false),
        Some(unsupported) => {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Unsupported Accept: {unsupported:?}"
            )))
            .into_response();
        }
        _ => (None, true),
    };

    let response = match gateway
        .send(ecu_name, service.clone(), data, map_to_json)
        .await
        .map_err(std::convert::Into::into)
    {
        Err(e) => return ErrorWrapper(e).into_response(),
        Ok(v) => v,
    };

    if let DiagServiceResponseType::Negative = response.response_type() {
        return api_error_from_diag_response(response).into_response();
    }

    match response_mime {
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => {
            let data = response.get_raw().to_vec();
            (StatusCode::OK, Bytes::from_owner(data)).into_response()
        }
        _ => {
            let mapped_data = match response
                .into_json()
                .map_err(|e| ApiError::InternalServerError(Some(format!("{e:?}"))))
            {
                Err(e) => {
                    return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                        "Failed to serialize response: {e:?}"
                    ))))
                    .into_response();
                }
                Ok(v) => v,
            };

            if mapped_data.is_null() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (
                    StatusCode::OK,
                    Json(sovd_interfaces::DataItem {
                        id: service.name.to_lowercase(),
                        data: mapped_data,
                    }),
                )
                    .into_response()
            }
        }
    }
}
