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

//! The vendor routes and their handlers.
//!
//! [`DiagnosticServices::uds`] hands back [`Uds`] - `dyn UdsEcu`, the same
//! interface CDA\'s own SOVD handlers hold. A plugin therefore has the
//! possibilities of an internal service: both service addressing modes,
//! sessions, security access, tester present, flash transfer, DTCs, database
//! queries, functional groups and variant state. It names no transport type, so
//! it survives transport refactors; an integration naming
//! `UdsManager<..., ...>` directly is what breaks.
//!
//! Three rules the handlers below follow:
//!
//! - Hold [`DiagnosticServices`] in handler state, *not* the `Arc<Uds>` it
//!   returns. A runtime database update replaces the whole component
//!   generation; re-reading per request is what follows it. A handle cached at
//!   startup would keep answering from components that were shut down.
//! - A route that changes state takes the caller\'s lock first, through
//!   [`LockAccess`]. Skipping that races the standard component routes, which
//!   enforce exactly this. Broadcasting to a functional group needs the
//!   functional-group lock; an ECU lock does not cover the other members.
//! - Never make an access decision from a claim read here. Extract the
//!   per-request security plugin with [`Secured`] and pass it on, because a
//!   replacement plugin may apply checks that a shortcut would skip.

use std::sync::Arc;

use aide::axum::{ApiRouter, IntoApiResponse};
use axum::{
    Extension, Json,
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
};
use cda_interfaces::{DiagServiceError, HashMap, diagservices::DiagServiceResponse};
use cda_plugin_security::Secured;
use opensovd_cda_lib::{
    AppError,
    extensions::{DiagnosticServices, ExtensionContext, HttpRoutes, LockAccess, OemRouteHandle},
};
use serde::Serialize;

/// Namespace this vendor owns.
///
/// Any path may be registered, including one that overrides a standard SOVD
/// route. `/vehicle/<version>/x-<vendor>` is the recommended choice and what to
/// use unless you mean to override something: it is the ISO extension space, so
/// nothing CDA adds later can collide with it. Registering elsewhere is logged
/// at warn level rather than refused.
const OEM_NAMESPACE: &str = "/vehicle/v15/x-example-oem";

/// `DynamicallyDefineDataIdentifier`, addressed by request prefix: the
/// subfunction is part of the request, so there is no single database short
/// name to look up.
const SID_DYNAMICALLY_DEFINE_DATA_IDENTIFIER: u8 = 0x2C;
/// `defineByIdentifier` subfunction.
const SUBFUNCTION_DEFINE_BY_IDENTIFIER: u8 = 0x01;
/// `ReadDataByPeriodicIdentifier`, addressed by SID plus database short name.
const SID_READ_DATA_BY_PERIODIC_IDENTIFIER: u8 = 0x2A;

#[derive(Clone)]
pub struct OemState {
    diagnostics: Arc<dyn DiagnosticServices>,
    locks: Arc<dyn LockAccess>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ErrorResponse {
    pub error: String,
}

fn error_response(status: StatusCode, error: String) -> axum::response::Response {
    (status, Json(ErrorResponse { error })).into_response()
}

fn failed(error: &DiagServiceError) -> axum::response::Response {
    error_response(StatusCode::BAD_GATEWAY, error.to_string())
}

/// Maps a response to JSON, reporting per-field mapping errors alongside the
/// data rather than discarding a partially mapped response.
fn rendered(response: impl DiagServiceResponse) -> axum::response::Response {
    let service = response.service_name();
    match response.into_json() {
        Ok(mapped) => {
            let failed_fields: Vec<&str> = mapped
                .errors
                .iter()
                .map(|error| error.path.as_str())
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "service": service,
                    "data": mapped.data,
                    "failed_fields": failed_fields,
                })),
            )
                .into_response()
        }
        Err(error) => failed(&error),
    }
}

/// `DynamicallyDefineDataIdentifier` - addressed by raw request prefix.
async fn dynamic_define_data(
    Extension(state): Extension<OemState>,
    Path(ecu): Path<String>,
    Secured(security): Secured,
    Json(params): Json<HashMap<String, serde_json::Value>>,
) -> impl IntoApiResponse {
    let security: cda_interfaces::DynamicPlugin = security;

    // Defining a dynamic identifier changes ECU state, so it belongs under the
    // caller\'s lock.
    if let Err(error) = state.locks.require_ecu_lock(&ecu, &security).await {
        return error_response(StatusCode::FORBIDDEN, error.to_string());
    }

    match state
        .diagnostics
        .uds()
        .await
        .send_by_sid(
            &ecu,
            &[
                SID_DYNAMICALLY_DEFINE_DATA_IDENTIFIER,
                SUBFUNCTION_DEFINE_BY_IDENTIFIER,
            ],
            &security,
            params,
            true,
        )
        .await
    {
        Ok(response) => rendered(response),
        Err(error) => failed(&error),
    }
}

/// `ReadDataByPeriodicIdentifier` - addressed by SID plus the database short
/// name taken from the path.
///
/// This returns the first response synchronously. A real integration would keep
/// the periodic responses flowing, publishing them to a websocket or an MQTT
/// topic from a spawned task; that is the reason to own the route rather than
/// use a standard one.
async fn periodic_read(
    Extension(state): Extension<OemState>,
    Path((ecu, service)): Path<(String, String)>,
    Secured(security): Secured,
    Json(params): Json<HashMap<String, serde_json::Value>>,
) -> impl IntoApiResponse {
    let security: cda_interfaces::DynamicPlugin = security;

    match state
        .diagnostics
        .uds()
        .await
        .send_by_sid_and_name(
            &ecu,
            SID_READ_DATA_BY_PERIODIC_IDENTIFIER,
            &service,
            &security,
            params,
            true,
        )
        .await
    {
        Ok(response) => rendered(response),
        Err(error) => failed(&error),
    }
}

/// Clears DTCs across a functional group.
///
/// Shows the two things a "send one service" facade could not do: reaching the
/// DTC half of the UDS surface at all, and broadcasting to a functional group --
/// which is why this takes the *functional-group* lock, not an ECU lock.
async fn clear_group_faults(
    Extension(state): Extension<OemState>,
    Path(group): Path<String>,
    Secured(security): Secured,
) -> impl IntoApiResponse {
    let security: cda_interfaces::DynamicPlugin = security;

    if let Err(error) = state
        .locks
        .require_functional_group_lock(&group, &security)
        .await
    {
        return error_response(StatusCode::FORBIDDEN, error.to_string());
    }

    let uds = state.diagnostics.uds().await;
    // `gateway_only = false`: every member of the group, not just its gateways.
    let ecus = uds.ecus_for_functional_group(&group, false).await;

    let mut cleared = Vec::new();
    for ecu in ecus {
        // `None` clears every fault code rather than one.
        match uds.delete_dtcs(&ecu, &security, None).await {
            Ok(_) => cleared.push(ecu),
            Err(error) => return failed(&error),
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "cleared": cleared })),
    )
        .into_response()
}

/// Fans a DTC read across every present ECU and returns one document.
///
/// The kind of aggregation a tester wants and SOVD does not offer: one call
/// instead of an ECU enumeration followed by a request per ECU. A failing ECU is
/// reported in place rather than failing the whole snapshot, since a partial
/// vehicle picture is more useful than none.
async fn vehicle_snapshot(
    Extension(state): Extension<OemState>,
    Secured(security): Secured,
) -> impl IntoApiResponse {
    let security: cda_interfaces::DynamicPlugin = security;
    let uds = state.diagnostics.uds().await;

    // Reflects the currently loaded database, so this follows a runtime update.
    let ecus = uds.get_physical_ecus().await;

    let mut per_ecu = serde_json::Map::new();
    for ecu in ecus {
        let entry = match uds
            .ecu_dtc_by_mask(&ecu, &security, None, None, None, None)
            .await
        {
            Ok(dtcs) => serde_json::json!({ "dtc_count": dtcs.len() }),
            Err(error) => serde_json::json!({ "error": error.to_string() }),
        };
        per_ecu.insert(ecu, entry);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "components": per_ecu })),
    )
        .into_response()
}

/// Registers this vendor\'s routes.
///
/// # Errors
/// Returns [`AppError`] if the namespace is rejected.
pub async fn register(context: ExtensionContext) -> Result<(), AppError> {
    let state = OemState {
        diagnostics: context.diagnostics(),
        locks: context.locks(),
    };

    let routes: HttpRoutes = ApiRouter::new()
        .route(
            "/components/{ecu}/dynamic-define-data",
            put(dynamic_define_data),
        )
        .route(
            "/components/{ecu}/periodic-read/{service}",
            put(periodic_read),
        )
        .route(
            "/functional-groups/{group}/clear-faults",
            put(clear_group_faults),
        )
        .route("/vehicle-snapshot", get(vehicle_snapshot))
        .layer(Extension(state));

    // The handle is what a real integration keeps in order to unmount its routes
    // later; dropping it leaves them mounted for good.
    let _handle: OemRouteHandle = context.routes().register(OEM_NAMESPACE, routes).await;
    Ok(())
}
