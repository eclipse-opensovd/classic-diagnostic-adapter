/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

use std::sync::{Arc, RwLock};

use axum::{
    Json,
    body::Bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use cda_interfaces::{
    BinaryEncoding, DiagComm, DiagCommType, DiagServiceError, DynamicPlugin, SchemaProvider,
    UdsEcu,
    communication_control::CommunicationAccess,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
    subfunction_ids,
};
use cda_plugin_security::SecurityPlugin;
use sovd_interfaces::components::ecu::operations::{
    AsyncPostResponse, ExecutionStatus, service::executions as sovd_executions,
};
use uuid::Uuid;

use super::{
    reset::ecu_reset_handler,
    response::{get_subschema, is_present_value, parse_json_response_params_stored},
};
use crate::sovd::{
    self, ExecutionReservation, ServiceExecution, StoredParameters, acquire_and_reserve_execution,
    api_error_from_diag_response,
    components::get_content_type_and_accept,
    create_response_schema, create_schema,
    error::{ApiError, ErrorWrapper, VendorErrorCode},
    field_parse_errors_to_json,
};

/// Options forwarded from the HTTP layer into `ecu_operation_write_handler`.
pub(crate) struct WriteHandlerOptions {
    pub include_schema: bool,
    pub suppress_service: bool,
    pub base_path: String,
    pub binary_encoding: BinaryEncoding,
}

/// Request data forwarded from the HTTP layer into `ecu_operation_write_handler`.
pub(crate) struct WriteHandlerRequest {
    pub service: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

fn validate_and_parse_write_request(
    headers: &HeaderMap,
    body: &Bytes,
    binary_encoding: BinaryEncoding,
) -> Result<(Option<cda_interfaces::diagservices::UdsPayloadData>, bool), ApiError> {
    let (Some(content_type), accept) = get_content_type_and_accept(headers)? else {
        return Err(ApiError::BadRequest("Missing Content-Type".to_owned()));
    };
    let data = sovd::get_payload_data::<sovd_executions::Request>(
        Some(&content_type),
        headers,
        body,
        binary_encoding,
    )?;
    if accept != mime::APPLICATION_OCTET_STREAM && accept != mime::APPLICATION_JSON {
        return Err(ApiError::BadRequest(format!(
            "Unsupported Accept header: {accept:?}"
        )));
    }
    Ok((data, accept == mime::APPLICATION_JSON))
}

/// Context for ECU operation write handlers, grouping execution-related state.
pub(crate) struct OperationWriteContext {
    service_executions:
        Arc<RwLock<cda_interfaces::HashMap<String, indexmap::IndexMap<Uuid, ServiceExecution>>>>,
    communication_access: Arc<dyn CommunicationAccess>,
}

impl OperationWriteContext {
    pub(crate) fn new(
        service_executions: Arc<
            RwLock<cda_interfaces::HashMap<String, indexmap::IndexMap<Uuid, ServiceExecution>>>,
        >,
        communication_access: Arc<dyn CommunicationAccess>,
    ) -> Self {
        Self {
            service_executions,
            communication_access,
        }
    }
}

pub(crate) async fn ecu_operation_write_handler_with_activity<
    T: UdsEcu + SchemaProvider + Clone,
>(
    req: WriteHandlerRequest,
    ecu_name: &str,
    uds: &T,
    ctx: OperationWriteContext,
    security_plugin: Box<dyn SecurityPlugin>,
    opts: WriteHandlerOptions,
) -> Response {
    let OperationWriteContext {
        service_executions,
        communication_access,
    } = ctx;
    let WriteHandlerRequest {
        service,
        headers,
        body,
    } = req;
    let WriteHandlerOptions {
        include_schema,
        suppress_service,
        base_path,
        binary_encoding,
    } = opts;
    let err_response = |error: ApiError| -> Response {
        ErrorWrapper {
            error,
            include_schema,
        }
        .into_response()
    };
    if service == "reset" {
        return ecu_reset_handler::<T>(
            service,
            ecu_name,
            uds,
            body,
            security_plugin,
            include_schema,
            binary_encoding,
        )
        .await;
    }

    // Reserve an execution slot atomically: checks for a running
    // conflict and, if none, inserts a placeholder so that a second
    // concurrent POST for the same operation sees 409 Conflict.
    // The lease is the active-execution marker for update arbitration. It is
    // published with the reservation and retained until the entry is removed.
    let reservation = match acquire_and_reserve_execution(
        &*communication_access,
        Arc::clone(&service_executions),
        &service,
        &service,
        include_schema,
    ) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let security_plugin: DynamicPlugin = security_plugin;
    let ResolvedOperation {
        is_async,
        operation: diag_service,
    } = if suppress_service {
        ResolvedOperation {
            is_async: true,
            operation: DiagComm {
                name: service.clone(),
                type_: DiagCommType::Operations,
                lookup_name: None,
                subfunction_id: Some(subfunction_ids::routine::START),
            },
        }
    } else {
        match resolve_operation(uds, ecu_name, &service, &security_plugin).await {
            Ok(v) => v,
            Err(e) => {
                return err_response(e);
            }
        }
    };

    let (data, map_to_json) =
        match validate_and_parse_write_request(&headers, &body, binary_encoding) {
            Ok(v) => v,
            Err(e) => {
                return err_response(e);
            }
        };

    let response = if suppress_service {
        None
    } else {
        match send_start_request(
            uds,
            ecu_name,
            diag_service.clone(),
            &security_plugin,
            data,
            map_to_json,
            include_schema,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return *e;
            }
        }
    };
    finish_write_request(FinishWriteRequestArgs {
        is_async,
        response,
        map_to_json,
        include_schema,
        base_path,
        reservation,
        ecu_name,
        uds,
        diag_service,
        binary_encoding,
    })
    .await
}

/// Arguments for [`finish_write_request`].
struct FinishWriteRequestArgs<'a, T: UdsEcu + SchemaProvider + Clone> {
    is_async: bool,
    response: Option<T::Response>,
    map_to_json: bool,
    include_schema: bool,
    base_path: String,
    reservation: ExecutionReservation<ServiceExecution>,
    ecu_name: &'a str,
    uds: &'a T,
    diag_service: DiagComm,
    binary_encoding: BinaryEncoding,
}

/// Dispatch the tail of a write request to the async or sync
/// post-processing path.
async fn finish_write_request<T: UdsEcu + SchemaProvider + Clone>(
    args: FinishWriteRequestArgs<'_, T>,
) -> Response {
    let FinishWriteRequestArgs {
        is_async,
        response,
        map_to_json,
        include_schema,
        base_path,
        reservation,
        ecu_name,
        uds,
        diag_service,
        binary_encoding,
    } = args;
    if is_async {
        handle_async_post::<T>(
            response,
            include_schema,
            &base_path,
            reservation,
            binary_encoding,
        )
    } else {
        drop(reservation);
        handle_sync_post::<T>(
            response,
            map_to_json,
            include_schema,
            ecu_name,
            uds,
            &diag_service,
            binary_encoding,
        )
        .await
    }
}

struct ResolvedOperation {
    is_async: bool,
    operation: DiagComm,
}

/// Resolves an operation-id to its underlying UDS service type and addressing scheme:
/// a `RoutineControl` group addressed through its Start subfunction, or an IO Control
/// (and any other non-routine operation) addressed by its exact diagnostic service name.
///
/// Each type is checked directly rather than inferring IO Control from the absence of a
/// `RoutineControl` service, so an operation-id that matches neither fails immediately
/// with `NotFound` instead of falling through into a doomed `send()` attempt.
async fn resolve_operation<T: UdsEcu>(
    uds: &T,
    ecu_name: &str,
    service: &str,
    security_plugin: &DynamicPlugin,
) -> Result<ResolvedOperation, ApiError> {
    match uds
        .get_routine_subfunctions(ecu_name, service, security_plugin)
        .await
    {
        Ok(sf) => {
            return Ok(ResolvedOperation {
                is_async: sf.has_stop || sf.has_request_results,
                operation: DiagComm {
                    name: service.to_owned(),
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                    subfunction_id: Some(subfunction_ids::routine::START),
                },
            });
        }
        Err(DiagServiceError::NotFound(_)) => {}
        Err(error) => return Err(ApiError::from(error)),
    }

    match uds
        .get_io_control_service(ecu_name, service, security_plugin)
        .await
    {
        Ok(operation) => Ok(ResolvedOperation {
            is_async: false,
            operation,
        }),
        Err(DiagServiceError::NotFound(_)) => Err(ApiError::from(DiagServiceError::NotFound(
            format!("Operation '{service}' not found"),
        ))),
        Err(error) => Err(ApiError::from(error)),
    }
}

/// Sends the Start subfunction request and returns the positive response, or
/// `Err(Response)` if the UDS call failed, returned a negative response, or
/// was cancelled because the owning lock is closing.
async fn send_start_request<T: UdsEcu>(
    uds: &T,
    ecu_name: &str,
    diag_service: DiagComm,
    security_plugin: &DynamicPlugin,
    data: Option<cda_interfaces::diagservices::UdsPayloadData>,
    map_to_json: bool,
    include_schema: bool,
) -> Result<Option<T::Response>, Box<Response>> {
    let response = match uds
        .send(ecu_name, diag_service, security_plugin, data, map_to_json)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(
                ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response(),
            ));
        }
    };
    if let DiagServiceResponseType::Negative = response.response_type() {
        return Err(Box::new(
            api_error_from_diag_response(&response, include_schema).into_response(),
        ));
    }
    Ok(Some(response))
}

/// Handles the async (Stop/RequestResults) POST path: finalises the
/// previously reserved execution with the Start-response parameters,
/// then returns them with the execution id and status.
fn handle_async_post<T: UdsEcu>(
    response: Option<T::Response>,
    include_schema: bool,
    base_path: &str,
    reservation: ExecutionReservation<ServiceExecution>,
    binary_encoding: BinaryEncoding,
) -> Response {
    let (parameters, stored_parameters, errors) = match response {
        Some(r) if !r.is_empty() => parse_json_response_params_stored(&r, "Start", binary_encoding),
        _ => (serde_json::Map::new(), StoredParameters::default(), vec![]),
    };
    let exec_id = reservation.commit_async(|exec| {
        exec.parameters = stored_parameters;
    });
    let schema = if include_schema {
        Some(create_schema!(
            AsyncPostResponse<serde_json::Map<String, serde_json::Value>, VendorErrorCode>
        ))
    } else {
        None
    };
    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, format!("{base_path}/{exec_id}"))],
        Json(AsyncPostResponse {
            id: exec_id.to_string(),
            status: Some(ExecutionStatus::Running),
            parameters,
            errors,
            schema,
        }),
    )
        .into_response()
}

/// Handles the synchronous (no Stop/RequestResults) POST path: returns 200 OK
/// with the mapped response parameters, or raw bytes if the accept header
/// requested octet-stream.
async fn handle_sync_post<T: UdsEcu + SchemaProvider>(
    response: Option<T::Response>,
    map_to_json: bool,
    include_schema: bool,
    ecu_name: &str,
    uds: &T,
    diag_service: &DiagComm,
    binary_encoding: BinaryEncoding,
) -> Response {
    let schema = if map_to_json && include_schema {
        let subschema = get_subschema(ecu_name, uds, diag_service, binary_encoding).await;
        Some(create_response_schema!(
            sovd_executions::Response<VendorErrorCode>,
            "parameters",
            subschema
        ))
    } else {
        None
    };

    if map_to_json {
        // Spec Table 189: `parameters` is `AnyValue`, so non-object results are valid.
        let (mapped_data, parse_errors) =
            match response.and_then(|r| (!r.is_empty()).then(|| r.into_json(binary_encoding))) {
                None => (serde_json::Value::Null, vec![]),
                Some(Ok(DiagServiceJsonResponse { data, errors })) => (data, errors),
                Some(Err(e)) => {
                    return ErrorWrapper {
                        error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                        include_schema,
                    }
                    .into_response();
                }
            };
        // Spec Table 183: `error` is singular (first parse error wins).
        let error = field_parse_errors_to_json(parse_errors, "parameters")
            .into_iter()
            .next();
        let parameters = is_present_value(&mapped_data).then_some(mapped_data);
        (
            StatusCode::OK,
            Json(sovd_executions::Response {
                parameters,
                error,
                schema,
            }),
        )
            .into_response()
    } else {
        let data = response.map_or(vec![], |r| r.get_raw().to_vec());
        (StatusCode::OK, Bytes::from_owner(data)).into_response()
    }
}
