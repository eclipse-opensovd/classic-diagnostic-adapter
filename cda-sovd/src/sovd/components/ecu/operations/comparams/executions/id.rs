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
use crate::{openapi, sovd::components::IdPathParam};

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(id): Path<IdPathParam>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_comparams::executions::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        comparam_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    let include_schema = query.include_schema;
    require_ecu_access!(read, security_plugin, &ecu_name, &locks, include_schema);
    let id = match parse_exec_uuid(&id, include_schema) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let mut executions: Vec<sovd_comparams::Execution> = Vec::new();

    let (idx, execution) = match comparam_executions
        .read()
        .await
        .get_full(&id)
        .ok_or_else(|| ApiError::NotFound(Some(format!("Execution with id {id} not found"))))
    {
        Ok((idx, _, exec)) => (idx, exec.snapshot()),
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema,
            }
            .into_response();
        }
    };
    let capability = execution.capability.clone();
    let status = execution.status.clone();

    // put in all executions with lower index than this one
    for (_, v) in &comparam_executions.read().await.as_slice()[..idx] {
        executions.push(v.snapshot());
    }
    executions.push(execution);

    let mut parameters = match uds.get_comparams(&ecu_name).await {
        Ok(v) => v.into_sovd(),
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    for (k, v) in executions.into_iter().flat_map(|e| e.comparam_override) {
        parameters.insert(k, v);
    }

    let schema = if include_schema {
        Some(create_schema!(
            sovd_comparams::executions::id::get::Response
        ))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(sovd_comparams::executions::id::get::Response {
            capability,
            parameters,
            status,
            schema,
        }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get a specific comparam execution")
        .response_with::<200, Json<sovd_comparams::executions::id::get::Response>, _>(|res| {
            res.description("Response with comparam execution details.")
                .example(sovd_comparams::executions::id::get::Response {
                    capability: sovd_comparams::executions::Capability::Execute,
                    parameters: HashMap::new(),
                    status: ExecutionStatus::Running,
                    schema: None,
                })
        })
        .with(openapi::comparam_execution_errors)
}

pub(crate) async fn delete<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(id): Path<IdPathParam>,
    State(WebserverEcuState {
        ecu_name,
        locks,
        comparam_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(write, security_plugin, &ecu_name, &locks, false);
    let id = match parse_exec_uuid(&id, false) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let removed = {
        let mut executions = comparam_executions.write().await;
        executions.shift_remove(&id).is_some()
    };
    if !removed {
        return ErrorWrapper {
            error: ApiError::NotFound(Some(format!("Execution with id {id} not found"))),
            include_schema: false,
        }
        .into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
    op.description("Delete a specific comparam execution")
        .response_with::<204, (), _>(|res| {
            res.description("Comparam execution deleted successfully.")
        })
        .with(openapi::comparam_execution_errors)
}

pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(id): Path<IdPathParam>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_comparams::executions::update::Query>,
        ApiError,
    >,
    State(WebserverEcuState {
        ecu_name,
        locks,
        comparam_executions,
        ..
    }): State<WebserverEcuState<T, U>>,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
    WithRejection(Json(request), _): WithRejection<
        Json<sovd_comparams::executions::update::Request>,
        ApiError,
    >,
) -> Response {
    let include_schema = query.include_schema;
    require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
    let id = match parse_exec_uuid(&id, include_schema) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let path = format!("http://{host}{uri}");
    // todo: (out of scope for now) handle timout and capability

    // todo: validate that the passed in CP is actually a valid CP for the ECU
    // let mut comparams = match uds.get_comparams(&ecu_name).await {
    //     Ok(v) => v,
    //     Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
    // };

    let mut executions_lock = comparam_executions.write().await;
    let execution: &mut ComparamExecution = match executions_lock
        .get_mut(&id)
        .ok_or_else(|| ApiError::NotFound(Some(format!("Execution with id {id} not found"))))
    {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema,
            }
            .into_response();
        }
    };

    if let Some(comparam_values) = request.parameters {
        for (k, v) in comparam_values {
            execution.comparam_override.insert(k, v);
        }
    }

    let schema = if include_schema {
        Some(create_schema!(sovd_comparams::executions::update::Response))
    } else {
        None
    };

    (
        StatusCode::ACCEPTED,
        [(header::LOCATION, path)],
        Json(sovd_comparams::executions::update::Response {
            id: id.to_string(),
            status: execution.status.clone(),
            schema,
        }),
    )
        .into_response()
}

pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
    op.description("Update a specific comparam execution")
        .response_with::<202, Json<sovd_comparams::executions::update::Response>, _>(|res| {
            res.description("Comparam execution updated successfully.")
                .example(sovd_comparams::executions::update::Response {
                    id: "example_id".to_string(),
                    status: ExecutionStatus::Running,
                    schema: None,
                })
        })
        .with(openapi::comparam_execution_errors)
}
