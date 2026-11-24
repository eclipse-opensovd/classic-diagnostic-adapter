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

use super::*;
use crate::sovd::locks::require_ecu_access;

#[cfg(test)]
mod tests;

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct ServiceAndIdPathParam {
    pub service: String,
    pub id: String,
}

/// Process a successful UDS `RequestResults` response: parse it, update stored
/// execution state, and return the `200 OK` response body.
fn get_operations_response<T: UdsEcu>(
    response: &T::Response,
    service: &str,
    exec_id: Uuid,
    service_executions: &std::sync::RwLock<
        cda_interfaces::HashMap<String, indexmap::IndexMap<Uuid, ServiceExecution>>,
    >,
    include_schema: bool,
    binary_encoding: BinaryEncoding,
) -> Response {
    if let DiagServiceResponseType::Negative = response.response_type() {
        tracing::warn!(
            exec_id = %exec_id,
            "RequestResults subfunction returned negative response"
        );
        return api_error_from_diag_response(response, include_schema).into_response();
    }

    // Mapped before the lock is taken, so the conversion happens outside the
    // critical section rather than under the write lock.
    let (parameters, stored_parameters, error_list) = if response.is_empty() {
        (serde_json::Map::new(), StoredParameters::default(), vec![])
    } else {
        parse_json_response_params_stored::<T::Response>(
            response,
            "RequestResults",
            binary_encoding,
        )
    };

    if let Some(stored_mut) = lock_write(service_executions)
        .get_mut(service)
        .and_then(|m| m.get_mut(&exec_id))
    {
        stored_mut.parameters = stored_parameters;
        stored_mut.complete();
    }

    get_by_id_response(
        ExecutionStatus::Completed,
        parameters,
        error_list,
        include_schema,
    )
}

pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(ServiceAndIdPathParam { service, id }): Path<ServiceAndIdPathParam>,
    WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
    BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        service_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    let include_schema = query.include_schema;
    require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
    let exec_id = match parse_exec_uuid(&id, include_schema) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let stored = match guard_execution(
        &service_executions,
        &service,
        exec_id,
        include_schema,
        &format!("Execution {exec_id} is already in progress"),
    ) {
        Ok(guard) => guard,
        Err(error) => return error.into_response(),
    };

    // suppress_service: skip the UDS send, return stored state directly
    if query.suppress_service {
        return get_by_id_response(
            stored.snapshot().status.clone(),
            stored.snapshot().parameters.in_encoding(binary_encoding),
            vec![],
            include_schema,
        );
    }

    // Try to send RequestResults (subfunction 0x03)
    let diag_service = DiagComm {
        name: service.clone(),
        type_: DiagCommType::Operations,
        lookup_name: None,
        subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
    };
    let uds_result = uds
        .send(
            &ecu_name,
            diag_service,
            &(security_plugin as DynamicPlugin),
            None,
            true,
        )
        .await;

    match uds_result {
        Err(e) => {
            tracing::warn!(
                error = ?e,
                service = %service,
                exec_id = %exec_id,
                "RequestResults subfunction failed"
            );
            ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response()
        }
        Ok(response) => get_operations_response::<T>(
            &response,
            &service,
            exec_id,
            &service_executions,
            include_schema,
            binary_encoding,
        ),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get the result of an async operation execution (RequestResults subfunction)")
        .response_with::<200, Json<AsyncGetByIdResponse<VendorErrorCode>>, _>(|res| {
            res.description("Execution result retrieved successfully.")
        })
        .with(openapi::error_not_found)
        .with(openapi::error_bad_request)
        .with(openapi::error_bad_gateway)
}

#[allow(
    clippy::too_many_lines,
    reason = "Keeping validation, execution guarding, UDS Stop, and guard cleanup together makes \
              cleanup on every response path visible. Splitting the flow would obscure that state \
              invariant"
)]
pub(crate) async fn delete<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(ServiceAndIdPathParam { service, id }): Path<ServiceAndIdPathParam>,
    WithRejection(Query(query), _): WithRejection<Query<OperationDeleteQuery>, ApiError>,
    BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        service_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    let include_schema = query.include_schema;
    require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
    let exec_id = match parse_exec_uuid(&id, include_schema) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let _request_guard = match guard_execution(
        &service_executions,
        &service,
        exec_id,
        include_schema,
        &format!("Execution {exec_id} is already being stopped"),
    ) {
        Ok(guard) => guard,
        Err(error) => return error.into_response(),
    };

    // suppress_service: skip sending Stop to the ECU, just remove and return 204
    if query.suppress_service {
        tracing::info!(
            service = %service,
            exec_id = %exec_id,
            "Stop skipped (suppress_service=true), removing execution"
        );
        if let Some(op_map) = lock_write(&service_executions).get_mut(&service) {
            op_map.shift_remove(&exec_id);
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    let diag_service = DiagComm {
        name: service.clone(),
        type_: DiagCommType::Operations,
        lookup_name: None,
        subfunction_id: Some(subfunction_ids::routine::STOP),
    };
    let uds_result = uds
        .send(
            &ecu_name,
            diag_service,
            &(security_plugin as DynamicPlugin),
            None,
            true,
        )
        .await;

    match uds_result {
        Ok(r) if matches!(r.response_type(), DiagServiceResponseType::Positive) => {
            if let Some(op_map) = lock_write(&service_executions).get_mut(&service) {
                op_map.shift_remove(&exec_id);
            }
            if r.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                let (parameters, error_list) =
                    parse_json_response_params::<T::Response>(r, "Stop", binary_encoding);
                get_by_id_response(
                    ExecutionStatus::Stopped,
                    parameters,
                    error_list,
                    include_schema,
                )
            }
        }
        result => {
            if let Err(e) = &result {
                tracing::warn!(
                    error = ?e,
                    service = %service,
                    exec_id = %exec_id,
                    "Stop subfunction failed"
                );
            } else {
                tracing::warn!(
                    service = %service,
                    exec_id = %exec_id,
                    "Stop subfunction returned negative response"
                );
            }
            if query.force {
                if let Some(op_map) = lock_write(&service_executions).get_mut(&service) {
                    op_map.shift_remove(&exec_id);
                }
                return StatusCode::NO_CONTENT.into_response();
            }

            match result {
                Err(e) => ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response(),
                Ok(r) => api_error_from_diag_response(&r, include_schema).into_response(),
            }
        }
    }
}

pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
    op.description(
        "Stop an async operation execution (Stop subfunction). Use ?x-sovd2uds-force=true to \
         remove even on ECU error.",
    )
    .response_with::<204, (), _>(|res| {
        res.description("Execution stopped and removed (no response data from ECU).")
    })
    .response_with::<200, Json<AsyncGetByIdResponse<VendorErrorCode>>, _>(|res| {
        res.description(
            "Execution stopped and removed. The ECU returned response data (non-spec extension).",
        )
    })
    .with(openapi::error_not_found)
    .with(openapi::error_bad_request)
    .with(openapi::error_bad_gateway)
    .with(openapi::error_forbidden)
}
