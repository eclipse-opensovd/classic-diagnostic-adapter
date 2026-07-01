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

//! API endpoint handlers with per-handler OpenAPI documentation.

use std::sync::Arc;

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use super::{openapi, types::*};
use crate::{mdd::ParameterValue, simulator::SimulatorState};

// Typed path params - each derives `JsonSchema` so aide turns them into
// proper path-parameter entries in the OpenAPI spec.
super::openapi::aide_helper::gen_path_param!(ServicePathParam name String);
super::openapi::aide_helper::gen_path_param!(ServiceParamPathParam name String param String);

/// GET / - Get simulator information
pub async fn get_info(State(state): State<Arc<SimulatorState>>) -> Json<SimulatorInfo> {
    Json(SimulatorInfo::from_state(&state))
}

pub fn docs_get_info(op: TransformOperation) -> TransformOperation {
    op.id("getInfo")
        .tag("Simulator")
        .summary("Get simulator information")
        .description("Returns the simulator's identity, loaded MDD, active variant, and counts.")
        .response_with::<200, Json<SimulatorInfo>, _>(|res| {
            res.description("Simulator information")
        })
}

/// GET /stats - Get statistics
pub async fn get_stats(State(state): State<Arc<SimulatorState>>) -> Json<StatsResponse> {
    Json(StatsResponse::from(state.get_stats().await))
}

pub fn docs_get_stats(op: TransformOperation) -> TransformOperation {
    op.id("getStats")
        .tag("Simulator")
        .summary("Get request/response statistics")
        .response_with::<200, Json<StatsResponse>, _>(|res| res.description("Statistics"))
}

/// DELETE /stats - Reset statistics
pub async fn reset_stats(State(state): State<Arc<SimulatorState>>) -> StatusCode {
    state.reset_stats().await;
    StatusCode::NO_CONTENT
}

pub fn docs_reset_stats(op: TransformOperation) -> TransformOperation {
    op.id("resetStats")
        .tag("Simulator")
        .summary("Reset statistics")
        .response_with::<204, (), _>(|res| res.description("Statistics reset"))
}

/// GET /variant - Get current variant info
pub async fn get_variant(State(state): State<Arc<SimulatorState>>) -> Json<VariantInfo> {
    Json(VariantInfo {
        name: state.variant.name.clone(),
        is_base: state.variant.is_base,
        is_active: true,
    })
}

pub fn docs_get_variant(op: TransformOperation) -> TransformOperation {
    op.id("getVariant")
        .tag("Simulator")
        .summary("Get current variant info")
        .response_with::<200, Json<VariantInfo>, _>(|res| res.description("Current variant"))
}

/// GET /services - List all services
pub async fn list_services(State(state): State<Arc<SimulatorState>>) -> Json<Vec<ServiceInfo>> {
    let services: Vec<ServiceInfo> = state
        .services
        .values()
        .map(ServiceInfo::from_definition)
        .collect();
    Json(services)
}

pub fn docs_list_services(op: TransformOperation) -> TransformOperation {
    op.id("listServices")
        .tag("Services")
        .summary("List all services from MDD")
        .response_with::<200, Json<Vec<ServiceInfo>>, _>(|res| res.description("List of services"))
}

/// GET /services/:name - Get service details
pub async fn get_service(
    State(state): State<Arc<SimulatorState>>,
    Path(ServicePathParam { name }): Path<ServicePathParam>,
) -> Result<Json<ServiceDetailInfo>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.get_service_by_name(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("Service not found: {name}"))),
        )
    })?;

    let overrides = state.get_all_overrides().await;

    let parameters: Vec<ParameterInfo> = service
        .response_params
        .iter()
        .map(|param| {
            let override_value = overrides.get(&(service.name.clone(), param.name.clone()));
            ParameterInfo::from_parameter(param, override_value)
        })
        .collect();

    Ok(Json(ServiceDetailInfo {
        service: ServiceInfo::from_definition(service),
        parameters,
    }))
}

pub fn docs_get_service(op: TransformOperation) -> TransformOperation {
    op.id("getService")
        .tag("Services")
        .summary("Get service details with parameters")
        .response_with::<200, Json<ServiceDetailInfo>, _>(|res| res.description("Service details"))
        .with(openapi::error_not_found)
}

/// GET /services/:name/parameters - List parameters for a service
pub async fn list_parameters(
    State(state): State<Arc<SimulatorState>>,
    Path(ServicePathParam { name }): Path<ServicePathParam>,
) -> Result<Json<Vec<ParameterInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.get_service_by_name(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("Service not found: {name}"))),
        )
    })?;

    let overrides = state.get_all_overrides().await;

    let parameters: Vec<ParameterInfo> = service
        .response_params
        .iter()
        .map(|param| {
            let override_value = overrides.get(&(service.name.clone(), param.name.clone()));
            ParameterInfo::from_parameter(param, override_value)
        })
        .collect();

    Ok(Json(parameters))
}

pub fn docs_list_parameters(op: TransformOperation) -> TransformOperation {
    op.id("listParameters")
        .tag("Services")
        .summary("List parameters for a service")
        .response_with::<200, Json<Vec<ParameterInfo>>, _>(|res| {
            res.description("List of parameters")
        })
        .with(openapi::error_not_found)
}

/// GET /services/:name/parameters/:param - Get parameter details
pub async fn get_parameter(
    State(state): State<Arc<SimulatorState>>,
    Path(ServiceParamPathParam { name, param }): Path<ServiceParamPathParam>,
) -> Result<Json<ParameterInfo>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.get_service_by_name(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("Service not found: {name}"))),
        )
    })?;

    let param_def = service
        .response_params
        .iter()
        .find(|p| p.name == param)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::new(format!("Parameter not found: {param}"))),
            )
        })?;

    let override_value = state.get_override(&name, &param).await;

    Ok(Json(ParameterInfo::from_parameter(
        param_def,
        override_value.as_ref(),
    )))
}

pub fn docs_get_parameter(op: TransformOperation) -> TransformOperation {
    op.id("getParameter")
        .tag("Services")
        .summary("Get parameter details")
        .response_with::<200, Json<ParameterInfo>, _>(|res| res.description("Parameter details"))
        .with(openapi::error_not_found)
}

/// PUT /services/:name/parameters/:param - Set parameter override
pub async fn set_parameter(
    State(state): State<Arc<SimulatorState>>,
    Path(ServiceParamPathParam { name, param }): Path<ServiceParamPathParam>,
    body: axum::body::Bytes,
) -> Result<Json<ParameterInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Verify service exists
    let service = state.get_service_by_name(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("Service not found: {name}"))),
        )
    })?;

    // Verify parameter exists
    let param_def = service
        .response_params
        .iter()
        .find(|p| p.name == param)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::new(format!("Parameter not found: {param}"))),
            )
        })?;

    // Parse the body as the tagged union; a parse failure is a 400.
    let parsed: SetParameterValue = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!("Invalid request body: {e}"))),
        )
    })?;

    let stored = match &parsed {
        SetParameterValue::Number { value } => {
            tracing::info!(
                service = %name,
                parameter = %param,
                value = *value,
                "Parameter override set (number)"
            );
            ParameterValue::Float(*value)
        }
        SetParameterValue::Int { value } => {
            tracing::info!(
                service = %name,
                parameter = %param,
                value = *value,
                "Parameter override set (int)"
            );
            ParameterValue::Int(*value)
        }
        SetParameterValue::String { value } => {
            let byte_length = param_def.byte_length() as usize;
            let mut bytes = value.as_bytes().to_vec();
            bytes.truncate(byte_length);
            bytes.resize(byte_length, 0);
            tracing::info!(
                service = %name,
                parameter = %param,
                value = %value,
                byte_length,
                "Parameter override set (string)"
            );
            ParameterValue::Bytes(bytes)
        }
        SetParameterValue::Bytes { value } => {
            let byte_length = param_def.byte_length() as usize;
            let bytes = hex::decode(value.trim_start_matches("0x").trim_start_matches("0X"))
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::new(format!("invalid hex in `value`: {e}"))),
                    )
                })?;
            let mut padded = bytes;
            padded.truncate(byte_length);
            padded.resize(byte_length, 0);
            tracing::info!(
                service = %name,
                parameter = %param,
                value = %value,
                byte_length,
                "Parameter override set (bytes)"
            );
            ParameterValue::Bytes(padded)
        }
    };

    state.set_override(&name, &param, stored).await;

    let override_value = state.get_override(&name, &param).await;
    Ok(Json(ParameterInfo::from_parameter(
        param_def,
        override_value.as_ref(),
    )))
}

pub fn docs_set_parameter(op: TransformOperation) -> TransformOperation {
    openapi::request_json::<SetParameterValue>(op)
        .id("setParameter")
        .tag("Overrides")
        .summary("Set parameter override (physical value)")
        .description(
            "Overrides the parameter's physical value for the next response. `{\"type\": \
             \"number\", \"value\": 1.0}` is the canonical shape; `{\"type\": \"int\" | \
             \"string\" | \"bytes\", \"value\": ...}` are also supported.",
        )
        .response_with::<200, Json<ParameterInfo>, _>(|res| res.description("Updated parameter"))
        .with(openapi::error_bad_request)
        .with(openapi::error_not_found)
}

/// DELETE /services/:name/parameters/:param - Remove parameter override
pub async fn delete_parameter_override(
    State(state): State<Arc<SimulatorState>>,
    Path(ServiceParamPathParam { name, param }): Path<ServiceParamPathParam>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Verify service and parameter exist
    let service = state.get_service_by_name(&name).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(format!("Service not found: {name}"))),
        )
    })?;

    let _param = service
        .response_params
        .iter()
        .find(|p| p.name == param)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse::new(format!("Parameter not found: {param}"))),
            )
        })?;

    let removed = state.remove_override(&name, &param).await;

    if removed {
        tracing::info!(
            service = %name,
            parameter = %param,
            "Parameter override removed"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("No override was set for this parameter")),
        ))
    }
}

pub fn docs_delete_parameter_override(op: TransformOperation) -> TransformOperation {
    op.id("deleteParameterOverride")
        .tag("Overrides")
        .summary("Remove parameter override")
        .response_with::<204, (), _>(|res| res.description("Override removed"))
        .response_with::<404, Json<ErrorResponse>, _>(|res| {
            res.description(
                "Service or parameter not found, or no override was set for this parameter.",
            )
        })
}

/// GET /overrides - List all overrides
pub async fn list_overrides(State(state): State<Arc<SimulatorState>>) -> Json<OverrideList> {
    let overrides = state.get_all_overrides().await;

    let override_list: Vec<OverrideInfo> = overrides
        .into_iter()
        .map(|((service, parameter), value)| OverrideInfo {
            service,
            parameter,
            value,
        })
        .collect();

    Json(OverrideList {
        count: override_list.len(),
        overrides: override_list,
    })
}

pub fn docs_list_overrides(op: TransformOperation) -> TransformOperation {
    op.id("listOverrides")
        .tag("Overrides")
        .summary("List all active overrides")
        .response_with::<200, Json<OverrideList>, _>(|res| res.description("List of overrides"))
}

/// DELETE /overrides - Clear all overrides
pub async fn clear_overrides(State(state): State<Arc<SimulatorState>>) -> StatusCode {
    state.clear_overrides().await;
    tracing::info!("All overrides cleared");
    StatusCode::NO_CONTENT
}

pub fn docs_clear_overrides(op: TransformOperation) -> TransformOperation {
    op.id("clearOverrides")
        .tag("Overrides")
        .summary("Clear all overrides")
        .response_with::<204, (), _>(|res| res.description("All overrides cleared"))
}
