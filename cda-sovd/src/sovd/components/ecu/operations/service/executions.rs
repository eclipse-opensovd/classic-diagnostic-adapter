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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    BinaryEncoding, DiagComm, DiagCommType, DiagServiceError, DynamicPlugin, SchemaProvider,
    UdsEcu,
    communication_control::CommunicationAccess,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
    subfunction_ids,
    util::std_ext::{lock_read, lock_write},
};
use cda_plugin_security::{Secured, SecurityPlugin};
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::{
    common::operations::OperationIdItem,
    components::ecu::operations::{
        AsyncGetByIdResponse, AsyncPostResponse, ExecutionStatus, OperationDeleteQuery,
        OperationQuery, service::executions as sovd_executions,
    },
};
use uuid::Uuid;

use crate::{
    openapi,
    sovd::{
        self, ExecutionReservation, ServiceExecution, StoredParameters, WebserverEcuState,
        acquire_and_reserve_execution, api_error_from_diag_response,
        binary_encoding::BinaryEncodingParam,
        components::get_content_type_and_accept,
        create_response_schema, create_schema,
        error::{ApiError, ErrorWrapper, VendorErrorCode},
        field_parse_errors_to_json, guard_execution,
        locks::require_ecu_access,
    },
};

pub(crate) mod id;
#[cfg(test)]
mod tests;

openapi::aide_helper::gen_path_param!(OperationServicePathParam service String);

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

pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
    WithRejection(Query(query), _): WithRejection<Query<sovd_executions::Query>, ApiError>,
    State(WebserverEcuState {
        ecu_name,
        locks,
        service_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(
        read,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let schema = if query.include_schema {
        Some(create_schema!(sovd_interfaces::Items<OperationIdItem>))
    } else {
        None
    };
    let ids: Vec<OperationIdItem> = lock_read(&service_executions)
        .get(&service)
        .map(|op_map| {
            op_map
                .iter()
                .filter(|(_, v)| v.is_created)
                .map(|(k, _)| OperationIdItem { id: k.to_string() })
                .collect()
        })
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(sovd_interfaces::Items { items: ids, schema }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("List all active service operation executions")
        .response_with::<200, Json<sovd_interfaces::Items<String>>, _>(|res| {
            res.description("List of active execution ids.")
        })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Axum extractors cannot be combined without a new custom extractor"
)]
pub(crate) async fn post<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
    WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
    BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        service_executions,
        communication_access,
        ..
    }): State<WebserverEcuState<T, U>>,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    require_ecu_access!(
        write,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let ctx = OperationWriteContext::new(service_executions, communication_access);
    ecu_operation_write_handler_with_activity::<T>(
        WriteHandlerRequest {
            service,
            headers,
            body,
        },
        &ecu_name,
        &uds,
        ctx,
        security_plugin,
        WriteHandlerOptions {
            include_schema: query.include_schema,
            suppress_service: query.suppress_service,
            base_path: format!("http://{host}{uri}"),
            binary_encoding,
        },
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    openapi::request_json_and_octet::<sovd_executions::Request>(op)
        .description("Start a new operation execution (Start subfunction)")
        .response_with::<200, Json<sovd_executions::Response<VendorErrorCode>>, _>(|res| {
            let mut res = res
                .description("Execution started, synchronous result.")
                .example(sovd_executions::Response {
                    parameters: Some(serde_json::json!({
                        "example_param": "example_value",
                    })),
                    error: None,
                    schema: None,
                });
            res.inner().content.insert(
                "application/octet-stream".to_owned(),
                aide::openapi::MediaType {
                    example: Some(serde_json::json!([0xABu8, 0xCD, 0xEF, 0x00])),
                    ..Default::default()
                },
            );
            res
        })
        .response_with::<
            202,
            Json<
                AsyncPostResponse<
                    serde_json::Map<String, serde_json::Value>,
                    VendorErrorCode,
                >,
            >,
            _,
        >(|res| {
            res.description(
                "Execution started asynchronously. Use the returned id for GET/DELETE on \
                 /executions/{id}.",
            )
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_not_found)
        .with(openapi::error_forbidden)
        .with(openapi::error_conflict)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_gateway)
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

/// `null` and an empty object both mean "no output parameters"; the
/// response then omits `parameters` instead of sending an empty value.
fn is_present_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

fn err_invalid_content(detail: String) -> sovd_interfaces::error::DataError<VendorErrorCode> {
    sovd_interfaces::error::DataError {
        path: "/parameters".to_owned(),
        error: sovd_interfaces::error::ApiErrorResponse {
            message: detail,
            error_code: sovd_interfaces::error::ErrorCode::InvalidResponseContent,
            vendor_code: None,
            parameters: None,
            error_source: None,
            schema: None,
        },
    }
}

/// Parses a positive, non-empty UDS response into `(parameters, errors)`.
///
/// - `Object` -> parameters map + any field-parse errors
/// - `Null`  -> empty parameters, no errors (ECU signalled no output)
/// - anything else, or a parse failure -> empty parameters, one soft `DataError`
fn parse_json_response_params<R: DiagServiceResponse>(
    response: R,
    context: &str,
    binary_encoding: BinaryEncoding,
) -> (
    serde_json::Map<String, serde_json::Value>,
    Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
) {
    match response.into_json(binary_encoding) {
        Ok(DiagServiceJsonResponse {
            data: serde_json::Value::Object(m),
            errors,
        }) => (m, field_parse_errors_to_json(errors, "parameters")),
        Ok(DiagServiceJsonResponse {
            data: serde_json::Value::Null,
            ..
        }) => (serde_json::Map::new(), vec![]),
        Ok(v) => (
            serde_json::Map::new(),
            vec![err_invalid_content(format!(
                "Expected JSON object but got: {}",
                v.data
            ))],
        ),
        Err(e) => (
            serde_json::Map::new(),
            vec![err_invalid_content(format!(
                "Failed to parse {context} response: {e:?}"
            ))],
        ),
    }
}

type ResponseParameters = serde_json::Map<String, serde_json::Value>;

/// Like [`parse_json_response_params`] for `binary_encoding`, additionally
/// returns the stored parameters, which map the kept response on demand
/// in the encoding of a later request.
fn parse_json_response_params_stored<R: DiagServiceResponse>(
    response: &R,
    context: &'static str,
    binary_encoding: BinaryEncoding,
) -> (
    ResponseParameters,
    StoredParameters<ResponseParameters>,
    Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
) {
    let (parameters, errors) =
        parse_json_response_params(response.clone(), context, binary_encoding);
    let stored_response = response.clone();
    let stored = StoredParameters::from_fn(move |encoding| {
        parse_json_response_params(stored_response.clone(), context, encoding).0
    });
    (parameters, stored, errors)
}

fn parse_exec_uuid(id: &str, include_schema: bool) -> Result<Uuid, ErrorWrapper> {
    Uuid::parse_str(id).map_err(|e| ErrorWrapper {
        error: ApiError::BadRequest(format!("{e:?}")),
        include_schema,
    })
}

/// Builds the `200 OK` `AsyncGetByIdResponse` body used by both the
/// `RequestResults` success path and the `suppress_service` fallback path.
/// An empty `parameters` map is serialised as `null` per the SOVD spec.
fn get_by_id_response(
    status: ExecutionStatus,
    parameters: serde_json::Map<String, serde_json::Value>,
    error: Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
    include_schema: bool,
) -> Response {
    use sovd_interfaces::components::ecu::operations::GetByIdCapability;
    let schema = if include_schema {
        Some(create_schema!(AsyncGetByIdResponse<VendorErrorCode>))
    } else {
        None
    };
    let parameters = if parameters.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(parameters))
    };
    (
        StatusCode::OK,
        Json(AsyncGetByIdResponse::<VendorErrorCode> {
            status,
            capability: GetByIdCapability::Execute,
            parameters,
            progress: None,
            error,
            schema,
        }),
    )
        .into_response()
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

#[allow(
    clippy::too_many_lines,
    reason = "Current implementation has little potential to extract smaller functions"
)]
async fn ecu_reset_handler<T: UdsEcu + SchemaProvider + Clone>(
    service: String,
    ecu_name: &str,
    uds: &T,
    body: Bytes,
    security_plugin: Box<dyn SecurityPlugin>,
    include_schema: bool,
    binary_encoding: BinaryEncoding,
) -> Response {
    // todo: in the future we have to handle possible parameters for the reset service
    let Some(request_parameters) = serde_json::from_slice::<sovd_executions::Request>(&body)
        .ok()
        .and_then(|v| v.parameters)
    else {
        return ErrorWrapper {
            error: ApiError::BadRequest("Invalid request body".to_string()),
            include_schema,
        }
        .into_response();
    };

    let Some(value) = request_parameters.get("value") else {
        return ErrorWrapper {
            error: ApiError::BadRequest("Missing 'value' parameter in request body".to_owned()),
            include_schema,
        }
        .into_response();
    };

    let Some(value_str) = value.as_str() else {
        return ErrorWrapper {
            error: ApiError::BadRequest("The 'value' parameter must be a string".to_owned()),
            include_schema,
        }
        .into_response();
    };

    let allowed_values = uds.get_ecu_reset_services(ecu_name).await;
    let allowed_values = match allowed_values {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    if !allowed_values
        .iter()
        .any(|v| v.eq_ignore_ascii_case(value_str))
    {
        return ErrorWrapper {
            error: ApiError::BadRequest(format!(
                "Invalid value for reset service: {value_str}. Allowed values: [{}]",
                allowed_values.join(", ")
            )),
            include_schema,
        }
        .into_response();
    }

    let diag_service = DiagComm {
        name: service.clone(),
        type_: DiagCommType::Modes, // ecureset is in modes
        lookup_name: Some(value_str.to_owned()),
        subfunction_id: None,
    };

    let schema = if include_schema {
        let subschema = get_subschema(ecu_name, uds, &diag_service, binary_encoding).await;
        Some(create_response_schema!(
            sovd_executions::Response<VendorErrorCode>,
            "parameters",
            subschema
        ))
    } else {
        None
    };

    let security_plugin: DynamicPlugin = security_plugin;
    let send_result = uds
        .send(ecu_name, diag_service, &security_plugin, None, true)
        .await;
    let response = match send_result {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    match response.response_type() {
        DiagServiceResponseType::Negative => {
            api_error_from_diag_response(&response, include_schema).into_response()
        }
        DiagServiceResponseType::Positive => {
            if response.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                let (response_data, parse_errors) = match response.into_json(binary_encoding) {
                    Ok(DiagServiceJsonResponse {
                        data: serde_json::Value::Null,
                        errors,
                    }) if errors.is_empty() => {
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    Ok(DiagServiceJsonResponse { data, errors }) => (data, errors),
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                            include_schema,
                        }
                        .into_response();
                    }
                };
                let error = field_parse_errors_to_json(parse_errors, "parameters")
                    .into_iter()
                    .next();
                let parameters = is_present_value(&response_data).then_some(response_data);
                (
                    StatusCode::OK,
                    Json(sovd_executions::Response {
                        parameters,
                        error,
                        schema,
                    }),
                )
                    .into_response()
            }
        }
    }
}

async fn get_subschema<T: SchemaProvider>(
    ecu_name: &str,
    uds: &T,
    diag_service: &DiagComm,
    binary_encoding: BinaryEncoding,
) -> Option<schemars::Schema> {
    match uds
        .schema_for_responses(ecu_name, diag_service)
        .await
        .map(|s| s.with_binary_encoding(binary_encoding).into_schema())
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                error = ?e,
                diag_service = ?diag_service,
                "Failed to get schema for diag service"
            );
            None
        }
    }
}
