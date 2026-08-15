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

//! End-to-end coverage of the versioned OEM extension surface.
//!
//! `custom_routes.rs` drives `cda_sovd::launch_webserver` and the raw
//! `DynamicRouter` - the low-level flow the extension facade exists to replace. These
//! tests go through `Setup::with_extension` instead, so they cover what an OEM
//! integration actually uses: route registration under the reserved namespace,
//! the diagnostics capability against a real loaded vehicle, health registration,
//! and the property that makes the whole design work - that an OEM handle keeps
//! working after a runtime database update swaps the components underneath it.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aide::axum::{ApiRouter, IntoApiResponse};
use async_trait::async_trait;
use axum::{Extension, Json, routing::get};
use cda_interfaces::runtime_update_api::ExecutionMode;
use http::{Method, StatusCode};
use opensovd_cda_lib::{
    AppError,
    extensions::{DiagnosticServices, ExtensionContext},
};

use crate::{
    sovd::runtimefiles::{execute_mode, setup_with_lock, stage_full_database, teardown_lock},
    util::{
        TestingError,
        http::{auth_header, response_to_t, send_cda_request},
        runtime::{
            mark_cda_started, mark_cda_stopped, setup_integration_test,
            skip_without_in_process_cda, start_cda_with_setup, stop_cda, wait_for_cda_online,
        },
    },
};

const OEM_NAMESPACE: &str = "/vehicle/v15/x-itest-oem";
/// Path as seen by `send_cda_request`, which prefixes `/vehicle/v15/`.
const OEM_ECUS_PATH: &str = "x-itest-oem/ecus";

/// Counts how many times the extension hook ran, so a test can prove the hook is
/// invoked once per startup rather than per request.
///
/// Process-global, and every test in this file starts a CDA with the extension
/// installed. It is therefore reset by [`start_with_extension`] rather than read
/// as an absolute total: tests are serialized by the shared-runtime guard, but
/// their *order* is not fixed, so an absolute assertion would pass or fail
/// depending on which test ran first.
static HOOK_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct OemState {
    diagnostics: Arc<dyn DiagnosticServices>,
}

/// Answers from the *live* component, so a stale handle would show up here.
async fn list_ecus(Extension(state): Extension<OemState>) -> impl IntoApiResponse {
    // Re-read per request: this is what makes the handle follow a runtime
    // database update instead of pinning the generation it was registered with.
    let mut ecus = state.diagnostics.uds().await.get_physical_ecus().await;
    ecus.sort();
    (StatusCode::OK, Json(ecus))
}

struct OemHealth;

#[async_trait]
impl cda_interfaces::health::HealthStatus for OemHealth {
    async fn status(&self) -> cda_interfaces::health::Status {
        cda_interfaces::health::Status::Up
    }
}

/// The extension an OEM would register.
async fn register_extension(context: ExtensionContext) -> Result<(), AppError> {
    HOOK_INVOCATIONS.fetch_add(1, Ordering::SeqCst);

    context
        .health()
        .register("x-itest-oem", Arc::new(OemHealth))
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

    let state = OemState {
        diagnostics: context.diagnostics(),
    };
    let routes = ApiRouter::new()
        .route("/ecus", get(list_ecus))
        .layer(Extension(state));

    context.routes().register(OEM_NAMESPACE, routes).await;
    Ok(())
}

async fn get_oem_ecus(
    config: &opensovd_cda_lib::config::configfile::Configuration,
) -> Result<Vec<String>, TestingError> {
    let response = send_cda_request(
        config,
        OEM_ECUS_PATH,
        StatusCode::OK,
        Method::GET,
        None,
        None,
        None,
    )
    .await?;
    response_to_t(&response)
}

/// A CDA started with the OEM extension installed.
///
/// The previous instance is already stopped by the time this runs, so resetting
/// the hook counter here makes it count invocations for *this* startup only.
fn start_with_extension(config: &opensovd_cda_lib::config::configfile::Configuration) {
    HOOK_INVOCATIONS.store(0, Ordering::SeqCst);
    start_cda_with_setup(
        config.clone(),
        opensovd_cda_lib::Setup::<
            cda_plugin_security::DefaultSecurityPluginData,
            cda_plugin_security::DefaultSecurityPlugin,
        >::new()
        .with_existing_tracing()
        .with_update_plugin(opensovd_cda_lib::update::update_plugin_fn(
            |context: opensovd_cda_lib::setup::UpdatePluginContext| async {
                opensovd_cda_lib::update::create_default_update_plugin::<
                    cda_plugin_security::DefaultSecurityPluginData,
                >(context)
                .await
            },
        ))
        .with_extension(register_extension),
    );
}

#[tokio::test]
async fn oem_routes_registered_via_extension_are_reachable() -> Result<(), TestingError> {
    if skip_without_in_process_cda(
        "oem_routes_registered_via_extension_are_reachable",
        "injecting a Setup requires building the CDA in-process",
    ) {
        return Ok(());
    }

    let (runtime, _guard) = setup_integration_test(true).await?;
    // Replace the shared instance with one that has the extension installed.
    stop_cda().await?;
    mark_cda_stopped().await;
    start_with_extension(&runtime.config);
    wait_for_cda_online(&runtime.config.server).await?;
    mark_cda_started(&runtime.config).await;

    let ecus = get_oem_ecus(&runtime.config).await?;

    assert!(
        !ecus.is_empty(),
        "the OEM route must answer from the live UDS manager, got an empty ECU list"
    );
    assert_eq!(
        HOOK_INVOCATIONS.load(Ordering::SeqCst),
        1,
        "the extension hook must run exactly once per startup"
    );
    Ok(())
}

#[tokio::test]
async fn oem_diagnostics_handle_survives_a_runtime_database_update() -> Result<(), TestingError> {
    // The property the whole extension design rests on: the diagnostics capability holds
    // a `ComponentSlot`, not a snapshot, so an apply that rebuilds the UDS manager
    // leaves an already-registered OEM handler working. A snapshot would keep
    // answering from components that were shut down.
    if skip_without_in_process_cda(
        "oem_diagnostics_handle_survives_a_runtime_database_update",
        "injecting a Setup requires building the CDA in-process",
    ) {
        return Ok(());
    }

    let (runtime, _guard) = setup_integration_test(true).await?;
    stop_cda().await?;
    mark_cda_stopped().await;
    start_with_extension(&runtime.config);
    wait_for_cda_online(&runtime.config.server).await?;
    mark_cda_started(&runtime.config).await;

    let before = get_oem_ecus(&runtime.config).await?;
    assert!(!before.is_empty(), "precondition: ECUs are present");

    // A full apply rebuilds the UDS manager and republishes the vehicle routes.
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;
    stage_full_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    teardown_lock(&runtime.config, &auth, &lock_id).await;

    let after = get_oem_ecus(&runtime.config).await?;
    assert_eq!(
        before, after,
        "the OEM route must still answer from the live components after an apply"
    );
    Ok(())
}
