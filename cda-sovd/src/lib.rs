/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::{
    future::Future,
    sync::{Arc, atomic::AtomicBool},
};

use aide::{axum::routing, swagger::Swagger};
use axum::{
    Json,
    http::{self, Request},
};
use cda_config::datatypes::FunctionalDescriptionConfig;
use cda_interfaces::{
    DoipGatewaySetupError, HashMap, SchemaProvider, UdsEcu, datatypes::ComponentsConfig, dlt_ctx,
    file_manager::FileManager,
};
use cda_plugin_security::SecurityPluginLoader;
use dynamic_router::DynamicRouter;
pub use dynamic_router::{RouteGroupNotFound, RouteHandle};
pub use http::Method;
use opensovd_axum_extra::ExtractHost;
use tokio::net::TcpListener;
use tower::{Layer, ServiceExt as TowerServiceExt};
use tower_http::{normalize_path::NormalizePathLayer, trace::TraceLayer};

/// Public API surface re-exported from the crate-internal `sovd` module.
pub use crate::sovd::{
    EcuExecutionRegistry, SovdLockStateProvider,
    apps::sovd2uds::bulk_data::runtimefiles::RuntimeUpdateRouteState,
    error::VendorErrorCode,
    locks::Locks,
    static_data::add_static_data_endpoint,
    update_guard::{ExemptRoute, UpdateGuardLayer, UpdateGuardState},
};
pub mod dynamic_router;
mod openapi;
pub(crate) mod sovd;

// Consts for HTTP
pub const SWAGGER_UI_ROUTE: &str = "/swagger-ui";
pub const OPENAPI_JSON_ROUTE: &str = "/openapi.json";
#[derive(Clone)]
pub struct WebServerConfig {
    pub host: String,
    pub port: u16,
}

/// Static configuration for vehicle SOVD routes.
pub struct VehicleConfig {
    pub flash_files_path: String,
    pub functional_group_config: FunctionalDescriptionConfig,
    pub components_config: ComponentsConfig,
}

/// Runtime resources (handles, shared state) for vehicle SOVD routes.
pub struct VehicleResources<T, M> {
    pub ecu_uds: T,
    pub file_manager: HashMap<String, M>,
    pub locks: Arc<Locks>,
    pub update_in_progress: Arc<AtomicBool>,
}

/// [[ dimpl~sovd-api-http-server, Starts HTTP Server ]]
///
/// Launches the http(s) webserver with deferred initialization
///
/// The server starts immediately with static endpoints. SOVD routes and other functionality
/// can be added later by calling methods on the returned `DynamicRouter`.
///
/// # Errors
/// Will return `Err` in case that the webserver couldn't be launched.
/// This can be caused due to invalid config, ports or addresses already being in use.
///
#[tracing::instrument(
    skip(config, shutdown_signal),
    fields(
        host = %config.host,
        port = %config.port,
    )
)]
pub async fn launch_webserver<F>(
    config: WebServerConfig,
    shutdown_signal: F,
) -> Result<(DynamicRouter, tokio::task::JoinHandle<()>), DoipGatewaySetupError>
where
    F: Future<Output = ()> + Clone + Send + 'static,
{
    let dynamic_router = DynamicRouter::new();
    let listen_address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&listen_address).await.map_err(|e| {
        DoipGatewaySetupError::ServerError(format!("Failed to bind to {listen_address}: {e}"))
    })?;

    let dynamic_router_for_service = dynamic_router.clone();
    let webserver_task = cda_interfaces::spawn_named!("webserver", async move {
        let service = tower::service_fn(move |request: Request<axum::body::Body>| {
            let dr = dynamic_router_for_service.clone();
            async move {
                let router = dr.get_router().await;
                TowerServiceExt::oneshot(router, request).await
            }
        });

        let middleware = tower::util::MapRequestLayer::new(rewrite_request_uri);
        let trim_trailing_slash_middleware = NormalizePathLayer::trim_trailing_slash();
        let service_with_middleware =
            middleware.layer(trim_trailing_slash_middleware.layer(service));

        let _ = axum::serve(listener, tower::make::Shared::new(service_with_middleware))
            .with_graceful_shutdown(shutdown_signal)
            .await;
    });

    Ok((dynamic_router, webserver_task))
}

/// Add vehicle routes to the dynamic router
///
/// This function should be called after the database is loaded to add all vehicle routes
///
/// # Errors
/// Returns `Err` if routes cannot be added to the dynamic router.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
#[tracing::instrument(
    skip(dynamic_router, config, resources),
    fields(
        flash_files_path = %config.flash_files_path
    )
)]
pub async fn add_vehicle_routes<T, M, S>(
    dynamic_router: &DynamicRouter,
    config: VehicleConfig,
    resources: VehicleResources<T, M>,
) -> Result<(EcuExecutionRegistry, RouteHandle), DoipGatewaySetupError>
where
    T: UdsEcu + SchemaProvider + Clone + Send + Sync + 'static,
    M: FileManager + Send + Sync + 'static,
    S: SecurityPluginLoader,
{
    let (vehicle_router, registry) = build_vehicle_routes::<T, M, S>(config, resources).await;

    let handle = dynamic_router.add_routes(vehicle_router).await;

    tracing::info!("Vehicle routes added to webserver");
    Ok((registry, handle))
}

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub async fn build_vehicle_routes<T, M, S>(
    config: VehicleConfig,
    resources: VehicleResources<T, M>,
) -> (aide::axum::ApiRouter, EcuExecutionRegistry)
where
    T: UdsEcu + SchemaProvider + Clone + Send + Sync + 'static,
    M: FileManager + Send + Sync + 'static,
    S: SecurityPluginLoader,
{
    let (router, registry) = sovd::route::<T, M, S>(
        config.functional_group_config,
        config.components_config,
        &resources.ecu_uds,
        config.flash_files_path,
        resources.file_manager,
        resources.locks,
        resources.update_in_progress,
    )
    .await;
    (router, registry)
}

/// Mounts the runtime-update HTTP routes onto the dynamic router and returns a handle to them.
///
/// Adds the runtime-file update endpoints to the router, registers exempt routes on the
/// [`UpdateGuardState`], and logs when the routes become active.
pub async fn add_runtime_update_routes<S, P, L>(
    dynamic_router: &DynamicRouter,
    plugin: Arc<P>,
    lock_state: Arc<L>,
    update_guard: &UpdateGuardState,
    upload_limit: usize,
    retry_after_seconds: u64,
) -> RouteHandle
where
    S: SecurityPluginLoader,
    P: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin,
    L: cda_interfaces::runtime_update_api::LockStateProvider,
{
    update_guard
        .extend_exempt(sovd::apps::sovd2uds::bulk_data::runtimefiles::update_exempt_routes())
        .await;

    let route_state = RuntimeUpdateRouteState {
        plugin,
        vehicle_lock_states: lock_state,
        retry_after_seconds,
    };
    let router =
        sovd::apps::sovd2uds::bulk_data::runtimefiles::routes::<S, P, L>(route_state, upload_limit);
    let handle = dynamic_router.add_routes(router.into()).await;
    tracing::info!("Runtime update routes added to webserver");
    handle
}

/// `OpenAPI` spec regenerates on every recomposition, reflecting current routes.
///
/// The server URL embedded in `openapi.json` is derived dynamically from each
/// request's `Host` header (with `X-Forwarded-Host` / `Forwarded` taking
/// precedence for reverse-proxy deployments), so the Swagger-UI always reflects
/// the address the client actually used to reach CDA.
pub async fn add_openapi_routes(dynamic_router: &DynamicRouter, _update_guard: &UpdateGuardState) {
    let dr = dynamic_router.clone();
    dynamic_router
        .add_finalizer(Arc::new(move |router: axum::Router| -> axum::Router {
            let dr = dr.clone();
            let swagger_route: axum::routing::MethodRouter =
                Swagger::new(OPENAPI_JSON_ROUTE).axum_route().into();
            let openapi_route: axum::routing::MethodRouter =
                routing::get(move |ExtractHost(host): ExtractHost| {
                    let dr = dr.clone();
                    async move {
                        let mut api = (*dr.get_openapi().await).clone();
                        let server_url = format!("http://{host}");
                        let _ = openapi::api_docs(
                            aide::transform::TransformOpenApi::new(&mut api),
                            server_url,
                        );
                        Json(api)
                    }
                })
                .into();
            router
                .route(SWAGGER_UI_ROUTE, swagger_route)
                .route(OPENAPI_JSON_ROUTE, openapi_route)
        }))
        .await;
}

pub async fn install_update_guard(dynamic_router: &DynamicRouter, update_guard: UpdateGuardState) {
    let layer = UpdateGuardLayer::new(update_guard);
    dynamic_router
        .add_finalizer(Arc::new(move |router: axum::Router| -> axum::Router {
            router.layer(layer.clone())
        }))
        .await;
}

fn rewrite_request_uri<B>(mut req: Request<B>) -> Request<B> {
    let uri = req.uri();
    // Decode URI here, so we can use query params later without
    // needing to decode them later on.
    let decoded = percent_encoding::percent_decode_str(
        uri.path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            .unwrap_or_default(),
    )
    .decode_utf8()
    .unwrap_or_else(|_| uri.to_string().into());

    let new_uri = match decoded.to_lowercase().parse() {
        Ok(uri) => uri,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse URI, using original");
            uri.clone()
        }
    };
    *req.uri_mut() = new_uri;
    req
}

fn create_trace_layer<S>(route: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    route.layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &axum::http::Request<_>| {
                tracing::info_span!(
                        "request",
                    method = ?request.method(),
                        path = request.uri().to_string(),
                        status_code = tracing::field::Empty,
                        latency = tracing::field::Empty,
                        error = tracing::field::Empty,
                        dlt_context = dlt_ctx!("SOVD"),
                )
            })
            .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                tracing::debug!(
                    method = %request.method(),
                    path = %request.uri(),
                    "Request received"
                );
            })
            .on_response(
                |response: &axum::http::Response<_>,
                 latency: std::time::Duration,
                 span: &tracing::Span| {
                    span.record("status_code", response.status().as_u16());
                    span.record("latency", format!("{latency:?}"));
                },
            )
            .on_failure(
                |error: tower_http::classify::ServerErrorsFailureClass,
                 latency: std::time::Duration,
                 span: &tracing::Span| {
                    span.record("latency", format!("{latency:?}"));
                    if let tower_http::classify::ServerErrorsFailureClass::StatusCode(status) =
                        error
                    {
                        span.record("status_code", status.as_u16());
                        if status == http::StatusCode::BAD_GATEWAY {
                            return; // Ignore 502 errors
                        }
                    }
                    span.record("error", error.to_string());
                    tracing::error!("HTTP request failed");
                },
            ),
    )
}

#[cfg(test)]
pub(crate) mod test_utils {
    use serde::de::DeserializeOwned;

    pub(crate) async fn axum_response_into<T: DeserializeOwned>(
        response: axum::response::Response,
    ) -> Result<T, serde_json::Error> {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<T>(body.as_ref())
    }
}
