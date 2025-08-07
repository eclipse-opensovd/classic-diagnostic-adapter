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

use axum::body::Bytes;
use cda_interfaces::diagservices::DiagServiceResponseType;
use http::header;

use super::*;
use crate::sovd::{error::api_error_from_diag_response, get_payload_data};

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
    use axum::extract::Path;
    use cda_interfaces::{DiagComm, DiagCommAction, DiagCommType};
    use hashbrown::HashMap;
    use http::HeaderMap;
    use sovd_interfaces::components::ecu::data::service::get::DiagServiceQuery;

    use super::*;
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
            data_request::<T>(Op::Read, diag_service, &ecu_name, &uds, headers, body).await
        }
    }

    pub(crate) async fn post<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        headers: HeaderMap,
        Path(service): Path<String>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Bytes,
    ) -> Response {
        data_request::<T>(Op::Write, service, &ecu_name, &uds, headers, body).await
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
        data_request::<T>(Op::Update, service, &ecu_name, &uds, headers, body).await
    }

    async fn data_request<T: UdsEcu + Send + Sync + Clone>(
        op: Op,
        service_name: String,
        ecu_name: &str,
        gateway: &T,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if service_name.contains('/') {
            return ErrorWrapper(ApiError::BadRequest("Invalid path".to_owned())).into_response();
        }
        let service = match op {
            Op::Read => DiagComm {
                name: service_name.clone(),
                action: DiagCommAction::Read,
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            Op::Write | Op::Update => DiagComm {
                name: service_name.clone(),
                action: DiagCommAction::Write,
                type_: DiagCommType::Configurations,
                lookup_name: None,
            },
        };

        let data = match get_payload_data::<
            sovd_interfaces::components::ecu::data::DataRequestPayload,
        >(&headers, &body)
        {
            Ok(value) => value,
            Err(e) => return ErrorWrapper(e).into_response(),
        };

        let (response_mime, map_to_json) = match headers.get(header::ACCEPT) {
            Some(v)
                if v == mime::APPLICATION_JSON.essence_str()
                    || v == mime::STAR_STAR.essence_str() =>
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
            .send(ecu_name, service, data, map_to_json)
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
                            id: service_name.to_lowercase(),
                            data: mapped_data,
                        }),
                    )
                        .into_response()
                }
            }
        }
    }
}

pub(crate) enum Op {
    Read,
    Write,
    Update,
}
