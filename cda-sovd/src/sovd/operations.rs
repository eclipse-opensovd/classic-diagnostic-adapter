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

pub(in crate::sovd) mod comparams {
    use std::sync::Arc;

    use axum::{
        Json,
        extract::{OriginalUri, Path, State},
        http::{StatusCode, header},
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::{Host, WithRejection};
    use cda_interfaces::{
        UdsEcu,
        datatypes::{Capability, ComParamValue, ExecutionStatus},
        diagservices::DiagServiceResponse,
        file_manager::FileManager,
    };
    use hashbrown::HashMap;
    use indexmap::IndexMap;
    use serde::{Deserialize, Serialize};
    use tokio::sync::RwLock;
    use uuid::Uuid;

    use crate::sovd::{
        WebserverEcuState,
        error::{ApiError, ErrorWrapper},
    };

    #[derive(Clone)]
    pub(in crate::sovd) struct Execution {
        capability: Capability,
        status: ExecutionStatus,
        comparam_override: ComParamMap,
    }
    type ComParamMap = HashMap<String, ComParamValue>;

    #[derive(Serialize)]
    struct ComparamListResponse {
        capability: Capability,
        // todo: probably out of scope for now:
        // use trait items here to allow for other execution types than comparam
        parameters: ComParamMap,
        status: ExecutionStatus,
    }

    // todo: which ones are optional or not
    // the spec is confusing me with O C and M for convention..
    #[derive(Deserialize)]
    #[allow(dead_code)]
    pub(crate) struct CreateUpdateExecutionRequest {
        capability: Option<Capability>,
        timeout: Option<u32>,
        parameters: Option<ComParamMap>,
        proximity_response: Option<String>,
    }

    #[derive(Serialize)]
    struct CreateExecutionResponse {
        id: String,
        status: ExecutionStatus,
    }

    #[derive(Serialize)]
    struct ExecutionItem {
        id: String,
    }
    #[derive(Serialize)]
    struct GetExecutionsResponse {
        items: Vec<ExecutionItem>,
    }

    pub(in crate::sovd) async fn get_executions_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState {
            comparam_executions,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        comparams_handler_read(comparam_executions).await
    }

    pub(in crate::sovd) async fn post_executions_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState {
            comparam_executions,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        Host(host): Host,
        OriginalUri(uri): OriginalUri,
        request_body: Option<Json<CreateUpdateExecutionRequest>>,
    ) -> Response {
        let path = format!("http://{host}{uri}");
        let body = if let Some(Json(body)) = request_body {
            Some(body)
        } else {
            None
        };
        comparams_handler_write(comparam_executions, path, body).await
    }

    pub(in crate::sovd) async fn comparams_handler_read(
        executions: Arc<RwLock<IndexMap<Uuid, Execution>>>,
    ) -> Response {
        (
            StatusCode::OK,
            Json(GetExecutionsResponse {
                items: executions
                    .read()
                    .await
                    .keys()
                    .map(|id| ExecutionItem { id: id.to_string() })
                    .collect::<Vec<_>>(),
            }),
        )
            .into_response()
    }
    pub(in crate::sovd) async fn comparams_handler_write(
        executions: Arc<RwLock<IndexMap<Uuid, Execution>>>,
        base_path: String,
        request: Option<CreateUpdateExecutionRequest>,
    ) -> Response {
        // todo: not in scope for now: request can take body with
        // { timeout: INT, parameters: { ... }, proximity_response: STRING }
        let mut executions = executions.write().await;
        let id = Uuid::new_v4();
        let mut comparam_override = ComParamMap::new();

        if let Some(CreateUpdateExecutionRequest {
            parameters: Some(parameters),
            ..
        }) = request
        {
            for (k, v) in parameters {
                comparam_override.insert(k, v);
            }
        }

        let create_execution_response = CreateExecutionResponse {
            id: id.to_string(),
            status: ExecutionStatus::Running,
        };
        executions.insert(
            id,
            Execution {
                capability: Capability::Execute,
                status: create_execution_response.status.clone(),
                comparam_override,
            },
        );
        (
            StatusCode::ACCEPTED,
            [(header::LOCATION, format!("{base_path}/{id}"))],
            Json(create_execution_response),
        )
            .into_response()
    }

    pub(in crate::sovd) async fn get_execution_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(id): Path<String>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            comparam_executions,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let id = match Uuid::parse_str(&id) {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(ApiError::BadRequest(format!("{e:?}"))).into_response(),
        };
        let mut executions: Vec<Execution> = Vec::new();

        let (idx, execution) = match comparam_executions
            .read()
            .await
            .get_full(&id)
            .ok_or_else(|| ApiError::NotFound(Some(format!("Execution with id {id} not found"))))
        {
            Ok((idx, _, v)) => (idx, v.clone()),
            Err(e) => return ErrorWrapper(e).into_response(),
        };
        let capability = execution.capability.clone();
        let status = execution.status.clone();

        // put in all executions with lower index than this one
        for (_, v) in &comparam_executions.read().await.as_slice()[..idx] {
            executions.push(v.clone());
        }
        executions.push(execution);

        let mut parameters = match uds.get_comparams(&ecu_name).await {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
        };

        for (k, v) in executions.into_iter().flat_map(|e| e.comparam_override) {
            parameters.insert(k, v);
        }

        (
            StatusCode::OK,
            Json(ComparamListResponse {
                capability,
                parameters,
                status,
            }),
        )
            .into_response()
    }

    pub(in crate::sovd) async fn delete_execution_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(id): Path<String>,
        State(WebserverEcuState {
            comparam_executions,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let id = match Uuid::parse_str(&id) {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(ApiError::BadRequest(format!("{e:?}"))).into_response(),
        };
        let mut executions = comparam_executions.write().await;
        if executions.shift_remove(&id).is_none() {
            return ErrorWrapper(ApiError::NotFound(Some(format!(
                "Execution with id {id} not found"
            ))))
            .into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    }

    pub(in crate::sovd) async fn update_execution_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(id): Path<String>,
        State(WebserverEcuState {
            comparam_executions,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        Host(host): Host,
        OriginalUri(uri): OriginalUri,
        WithRejection(Json(request), _): WithRejection<
            Json<CreateUpdateExecutionRequest>,
            ApiError,
        >,
    ) -> Response {
        let id = match Uuid::parse_str(&id) {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(ApiError::BadRequest(format!("{e:?}"))).into_response(),
        };
        let path = format!("http://{host}{uri}");
        // todo: (out of scope for now) handle timout and capability

        // todo: validate that the passed in CP is actually a valid CP for the ECU
        // let mut comparams = match uds.get_comparams(&ecu_name).await {
        //     Ok(v) => v,
        //     Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
        // };

        let mut executions_lock = comparam_executions.write().await;
        let execution: &mut Execution = match executions_lock
            .get_mut(&id)
            .ok_or_else(|| ApiError::NotFound(Some(format!("Execution with id {id} not found"))))
        {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(e).into_response(),
        };

        if let Some(comparam_values) = request.parameters {
            for (k, v) in comparam_values {
                execution.comparam_override.insert(k, v);
            }
        }

        (
            StatusCode::ACCEPTED,
            [(header::LOCATION, path)],
            Json(CreateExecutionResponse {
                id: id.to_string(),
                status: execution.status.clone(),
            }),
        )
            .into_response()
    }
}

pub(in crate::sovd) mod executions {
    use std::str::FromStr;

    use axum::{
        Json,
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse as _, Response},
    };
    use cda_interfaces::{
        DiagComm, DiagCommAction, DiagCommType, UdsEcu,
        diagservices::{DiagServiceResponse, DiagServiceResponseType},
        file_manager::FileManager,
    };
    use hashbrown::HashMap;
    use http::header;
    use serde::{Deserialize, Serialize};

    use crate::sovd::{
        self, Op, SovdExecutionRequestBody, WebserverEcuState, api_error_from_diag_response,
        error::{ApiError, ErrorWrapper},
    };

    #[derive(Serialize)]
    struct ExecutionResponse {
        parameters: serde_json::Value,
    }

    #[derive(Serialize)]
    struct ExecutionsResponse {
        items: Vec<String>, // todo: should be a list of execution ids
    }

    #[derive(Deserialize)]
    struct ExecutionRequest {
        parameters: HashMap<String, serde_json::Value>,
    }

    pub(in crate::sovd) async fn get_ecu_operation_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(service): Path<String>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        ecu_operation_handler::<T>(Op::Read, service, &ecu_name, &uds, headers, body).await
    }

    pub(in crate::sovd) async fn post_ecu_operation_handler<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(service): Path<String>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        ecu_operation_handler::<T>(Op::Write, service, &ecu_name, &uds, headers, body).await
    }

    async fn ecu_operation_handler<T: UdsEcu + Send + Sync + Clone>(
        op: Op,
        service: String,
        ecu_name: &str,
        uds: &T,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        match op {
            Op::Read => (
                StatusCode::OK,
                Json(ExecutionsResponse { items: Vec::new() }),
            )
                .into_response(),
            Op::Write => {
                if service == "reset" {
                    return ecu_reset_handler::<T>(service, ecu_name, uds, body).await;
                }
                let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
                    return ErrorWrapper(ApiError::BadRequest("Missing Content-Type".to_owned()))
                        .into_response();
                };

                let diag_service = DiagComm {
                    name: service.clone(),
                    action: DiagCommAction::Start,
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                };

                let data = match sovd::get_payload_data::<SovdExecutionRequestBody>(&headers, &body)
                {
                    Ok(v) => v,
                    Err(e) => return ErrorWrapper(e).into_response(),
                };

                let accept_header = headers.get(header::ACCEPT).map_or(content_type, |v| {
                    if v == mime::STAR_STAR.essence_str() {
                        content_type
                    } else {
                        v
                    }
                });
                let response_mime = match accept_header.to_str() {
                    Ok(v) => v
                        .split(';')
                        .next()
                        .map(str::trim)
                        .ok_or_else(|| format!("invalid or empty accept header {accept_header:?}"))
                        .and_then(|s| {
                            mime::Mime::from_str(s)
                                .map_err(|_| format!("failed to parse mime type {accept_header:?}"))
                        }),
                    Err(_) => Err(format!(
                        "Neither accept header or content type is set or not a valid string: \
                         {accept_header:?}"
                    )),
                };

                let response_mime = match response_mime {
                    Ok(mime) => mime,
                    Err(err) => {
                        return ErrorWrapper(ApiError::BadRequest(err)).into_response();
                    }
                };

                if response_mime != mime::APPLICATION_OCTET_STREAM
                    && response_mime != mime::APPLICATION_JSON
                {
                    return ErrorWrapper(ApiError::BadRequest(format!(
                        "Unsupported Accept header: {accept_header:?}"
                    )))
                    .into_response();
                }

                let map_to_json = response_mime == mime::APPLICATION_JSON;
                let response = match uds.send(ecu_name, diag_service, data, map_to_json).await {
                    Ok(v) => v,
                    Err(e) => return ErrorWrapper(e.into()).into_response(),
                };

                if let DiagServiceResponseType::Negative = response.response_type() {
                    return api_error_from_diag_response(response).into_response();
                }

                if map_to_json {
                    let mapped_data = match response.into_json() {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                                "{e:?}"
                            ))))
                            .into_response();
                        }
                    };
                    (
                        StatusCode::OK,
                        Json(ExecutionResponse {
                            parameters: mapped_data,
                        }),
                    )
                        .into_response()
                } else {
                    let data = response.get_raw().to_vec();
                    (StatusCode::OK, Bytes::from_owner(data)).into_response()
                }
            }
            Op::Update => unreachable!("No put handler registered"),
        }
    }

    async fn ecu_reset_handler<T: UdsEcu + Send + Sync + Clone>(
        service: String,
        ecu_name: &str,
        uds: &T,
        body: Bytes,
    ) -> Response {
        // todo: in the future we have to handle possible parameters for the reset service
        let request_parameters = match serde_json::from_slice::<ExecutionRequest>(&body) {
            Ok(v) => v.parameters,
            Err(e) => {
                return ErrorWrapper(ApiError::BadRequest(format!("Invalid request body: {e}")))
                    .into_response();
            }
        };

        let Some(value) = request_parameters.get("value") else {
            return ErrorWrapper(ApiError::BadRequest(
                "Missing 'value' parameter in request body".to_owned(),
            ))
            .into_response();
        };

        let Some(value_str) = value.as_str() else {
            return ErrorWrapper(ApiError::BadRequest(
                "The 'value' parameter must be a string".to_owned(),
            ))
            .into_response();
        };

        let allowed_values = match uds.get_ecu_reset_services(ecu_name).await {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(e.into()).into_response(),
        };

        if !allowed_values
            .iter()
            .any(|v| v.eq_ignore_ascii_case(value_str))
        {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Invalid value for reset service: {value_str}. Allowed values: [{}]",
                allowed_values.join(", ")
            )))
            .into_response();
        }

        let diag_service = DiagComm {
            name: service.clone(),
            action: DiagCommAction::Start,
            type_: DiagCommType::Modes, // ecureset is in modes
            lookup_name: Some(value_str.to_owned()),
        };

        let response = match uds.send(ecu_name, diag_service, None, true).await {
            Ok(v) => v,
            Err(e) => return ErrorWrapper(e.into()).into_response(),
        };

        match response.response_type() {
            DiagServiceResponseType::Negative => {
                api_error_from_diag_response(response).into_response()
            }
            DiagServiceResponseType::Positive => {
                if response.is_empty() {
                    StatusCode::NO_CONTENT.into_response()
                } else {
                    let response_data = match response.into_json() {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper(ApiError::InternalServerError(Some(format!(
                                "{e:?}"
                            ))))
                            .into_response();
                        }
                    };
                    (
                        StatusCode::OK,
                        Json(ExecutionResponse {
                            parameters: response_data,
                        }),
                    )
                        .into_response()
                }
            }
        }
    }
}
