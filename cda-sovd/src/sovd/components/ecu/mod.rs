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

use aide::{axum::IntoApiResponse, transform::TransformOperation};
use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DiagComm, SchemaProvider, UdsEcu,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use http::{HeaderMap, StatusCode};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState,
        components::{field_parse_errors_to_json, get_content_type_and_accept},
        create_response_schema,
        error::{ApiError, ErrorWrapper, api_error_from_diag_response},
        get_payload_data,
    },
};

pub(crate) mod configurations;
pub(crate) mod data;
pub(crate) mod faults;
pub(crate) mod genericservice;
pub(crate) mod modes;
pub(crate) mod operations;
pub(crate) mod x_single_ecu_jobs;
pub(crate) mod x_sovd2uds_bulk_data;
pub(crate) mod x_sovd2uds_download;

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ComponentQuery {
    #[serde(rename = "x-include-sdgs")]
    pub include_sdgs: Option<bool>,
}

pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    WithRejection(Query(query), _): WithRejection<Query<ComponentQuery>, ApiError>,
) -> impl IntoApiResponse {
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
            faults: format!("{base_path}/faults"),
        }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get ECU details")
        .response_with::<200, Json<sovd_interfaces::components::ecu::Ecu>, _>(|res| {
            res.example(sovd_interfaces::components::ecu::Ecu {
                id: "my_ecu".to_string(),
                name: "My ECU".to_string(),
                variant: "Variant1".to_string(),
                locks: "http://localhost:20002/vehicle/v15/components/my_ecu/locks".to_string(),
                operations: "http://localhost:20002/vehicle/v15/components/my_ecu/operations"
                    .to_string(),
                data: "http://localhost:20002/vehicle/v15/components/my_ecu/data".to_string(),
                configurations:
                    "http://localhost:20002/vehicle/v15/components/my_ecu/configurations"
                        .to_string(),
                sdgs: None,
                single_ecu_jobs:
                    "http://localhost:20002/vehicle/v15/components/my_ecu/x-single-ecu-jobs"
                        .to_string(),
                faults: "http://localhost:20002/vehicle/v15/components/my_ecu/faults".to_string(),
            })
            .description("Response with ECU information (i.e. detected variant) and service URLs")
        })
}

pub(crate) async fn post<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
    op.description("Trigger ECU variant detection")
        .response_with::<201, (), _>(|res| res.description("ECU variant detection triggered."))
}

async fn update<T: UdsEcu + Clone>(ecu_name: &str, uds: T) -> Response {
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

openapi::aide_helper::gen_path_param!(DiagServicePathParam diag_service String);

async fn data_request<T: UdsEcu + SchemaProvider + Clone>(
    service: DiagComm,
    ecu_name: &str,
    gateway: &T,
    headers: HeaderMap,
    body: Option<Bytes>,
    include_schema: bool,
) -> Response {
    let (content_type, accept) = match get_content_type_and_accept(&headers) {
        Ok(v) => v,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    let data = if let Some(body) = body {
        match get_payload_data::<sovd_interfaces::components::ecu::data::DataRequestPayload>(
            content_type.as_ref(),
            &headers,
            &body,
        ) {
            Ok(value) => value,
            Err(e) => return ErrorWrapper(e).into_response(),
        }
    } else {
        None
    };

    let map_to_json = match (accept.type_(), accept.subtype()) {
        (mime::APPLICATION, mime::JSON) => true,
        (mime::APPLICATION, mime::OCTET_STREAM) => false,
        unsupported => {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Unsupported Accept: {unsupported:?}"
            )))
            .into_response();
        }
    };

    if !map_to_json && include_schema {
        return ErrorWrapper(ApiError::BadRequest(
            "Cannot use include-schema with non-JSON response".to_string(),
        ))
        .into_response();
    }

    let schema = if include_schema {
        match gateway
            .schema_for_responses(ecu_name, &service)
            .await
            .map(|desc| desc.into_schema())
        {
            Ok(Some(data_schema)) => Some(create_response_schema!(
                sovd_interfaces::ObjectDataItem<VendorErrorCode>,
                "data",
                data_schema
            )),
            Err(e) => return ErrorWrapper(e.into()).into_response(),
            _ => None,
        }
    } else {
        None
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

    if response.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    if map_to_json {
        let (mapped_data, errors) = match response.into_json() {
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(mapped_data),
                errors,
            }) => (mapped_data, errors),
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Null,
                errors,
            }) => {
                if errors.is_empty() {
                    return StatusCode::NO_CONTENT.into_response();
                }
                (serde_json::Map::new(), errors)
            }
            Ok(v) => {
                return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                    "Expected JSON object but got: {}",
                    v.data
                ))))
                .into_response();
            }
            Err(e) => {
                return ErrorWrapper(ApiError::InternalServerError(Some(format!("{e:?}"))))
                    .into_response();
            }
        };
        (
            StatusCode::OK,
            Json(sovd_interfaces::ObjectDataItem {
                id: service.name.to_lowercase(),
                data: mapped_data,
                errors: field_parse_errors_to_json(errors, "data"),
                schema,
            }),
        )
            .into_response()
    } else {
        let data = response.get_raw().to_vec();
        (StatusCode::OK, Bytes::from_owner(data)).into_response()
    }
}
