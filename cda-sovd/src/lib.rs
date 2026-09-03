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

use std::{sync::Arc, time::Duration};

use aide::{axum::routing, swagger::Swagger};
use axum::{
    Json,
    http::{self, Request},
};
use cda_comm_doip::DoipGatewaySetupError;
use cda_interfaces::{
    FunctionalDescriptionConfig, HashMap, SchemaProvider, UdsEcu,
    communication_control::CommunicationAccess, datatypes::ComponentsConfig, dlt_ctx,
    file_manager::FileManager, http_protection::registry::HttpRouteMatcher,
};
use cda_plugin_security::SecurityPluginLoader;
use dynamic_router::DynamicRouter;
pub use dynamic_router::{RouteGroupNotFound, RouteHandle};
pub use http::Method;
use opensovd_axum_extra::ExtractHost;
use sovd::apps::sovd2uds::bulk_data::runtimefiles::RuntimeUpdateRouteState;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tower::{Layer, ServiceExt as TowerServiceExt};
use tower_http::{normalize_path::NormalizePathLayer, trace::TraceLayer};

/// Public API surface re-exported from the crate-internal `sovd` module.
pub use crate::sovd::{
    SovdLockStateProvider, error::VendorErrorCode, locks::Locks,
    request_guard::install_http_restriction_guard, static_data::add_static_data_endpoint,
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
    /// When set, the server binds to this Unix domain socket path instead of
    /// `host`/`port`. Takes priority silently over the TCP settings when
    /// present - the two are not combined.
    pub unix_socket: Option<String>,
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
    pub file_managers: HashMap<String, M>,
    pub locks: Arc<Locks>,
    /// Access-only view used to admit diagnostic communication activities.
    pub communication_access: Arc<dyn CommunicationAccess>,
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
        unix_socket = config.unix_socket.as_deref().unwrap_or(""),
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
    let dynamic_router_for_service = dynamic_router.clone();
    let service = tower::service_fn(move |request: Request<axum::body::Body>| {
        let dr = dynamic_router_for_service.clone();
        async move {
            let router = dr.get_router().await;
            TowerServiceExt::oneshot(router, request).await
        }
    });

    let middleware = tower::util::MapRequestLayer::new(rewrite_request_uri);
    let trim_trailing_slash_middleware = NormalizePathLayer::trim_trailing_slash();
    let service_with_middleware = middleware.layer(trim_trailing_slash_middleware.layer(service));

    let webserver_task = if let Some(socket_path) = config.unix_socket {
        #[cfg(unix)]
        {
            remove_stale_unix_socket(&socket_path)?;
            let listener = UnixListener::bind(&socket_path).map_err(|e| {
                DoipGatewaySetupError::ServerError(format!(
                    "Failed to bind to unix socket {socket_path}: {e}"
                ))
            })?;
            tracing::info!("SOVD HTTP server listening on unix socket {socket_path}");
            cda_interfaces::spawn_named!("webserver", async move {
                let _ = axum::serve(listener, tower::make::Shared::new(service_with_middleware))
                    .with_graceful_shutdown(shutdown_signal)
                    .await;
            })
        }
        #[cfg(not(unix))]
        {
            return Err(DoipGatewaySetupError::ServerError(format!(
                "Unix domain sockets are not supported on this platform (requested path: \
                 {socket_path})"
            )));
        }
    } else {
        let listen_address = format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(&listen_address).await.map_err(|e| {
            DoipGatewaySetupError::ServerError(format!("Failed to bind to {listen_address}: {e}"))
        })?;
        tracing::info!("SOVD HTTP server listening on {listen_address}");
        cda_interfaces::spawn_named!("webserver", async move {
            let _ = axum::serve(listener, tower::make::Shared::new(service_with_middleware))
                .with_graceful_shutdown(shutdown_signal)
                .await;
        })
    };

    Ok((dynamic_router, webserver_task))
}

/// Removes a pre-existing file at `socket_path`, if any, so that binding a
/// fresh `UnixListener` there doesn't fail with `AddrInUse` because of a
/// socket file left behind by a previous unclean shutdown.
#[cfg(unix)]
fn remove_stale_unix_socket(socket_path: &str) -> Result<(), DoipGatewaySetupError> {
    match std::fs::remove_file(socket_path) {
        Ok(()) => {
            tracing::debug!("Removed stale unix socket file at {socket_path}");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DoipGatewaySetupError::ServerError(format!(
            "Failed to remove stale unix socket file at {socket_path}: {e}"
        ))),
    }
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
) -> Result<RouteHandle, DoipGatewaySetupError>
where
    T: UdsEcu + SchemaProvider + Clone + Send + Sync + 'static,
    M: FileManager + Send + Sync + 'static,
    S: SecurityPluginLoader,
{
    let vehicle_router = build_vehicle_routes::<T, M, S>(config, resources).await;

    let handle = dynamic_router.add_routes(vehicle_router).await;

    tracing::info!("Vehicle routes added to webserver");
    Ok(handle)
}

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub async fn build_vehicle_routes<T, M, S>(
    config: VehicleConfig,
    resources: VehicleResources<T, M>,
) -> aide::axum::ApiRouter
where
    T: UdsEcu + SchemaProvider + Clone + Send + Sync + 'static,
    M: FileManager + Send + Sync + 'static,
    S: SecurityPluginLoader,
{
    sovd::route::<T, M, S>(
        config.functional_group_config,
        config.components_config,
        &resources.ecu_uds,
        config.flash_files_path,
        resources.file_managers,
        resources.locks,
        resources.communication_access,
    )
    .await
}

/// Mounts the runtime-update HTTP routes onto the dynamic router and returns a handle to them.
///
/// Adds the runtime-file update endpoints to the router.
pub async fn add_runtime_update_routes<S, P, L>(
    dynamic_router: &DynamicRouter,
    plugin: Arc<P>,
    lock_state: Arc<L>,
    upload_limit: usize,
    retry_after: Duration,
) -> RouteHandle
where
    S: SecurityPluginLoader,
    P: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin,
    L: cda_interfaces::runtime_update_api::LockStateProvider,
{
    let route_state = RuntimeUpdateRouteState {
        plugin,
        vehicle_lock_states: lock_state,
        retry_after,
    };
    let bulk_data_router = sovd::apps::sovd2uds::bulk_data::runtimefiles::routes::<S, P, L>(
        route_state.clone(),
        upload_limit,
    );
    let operations_router =
        sovd::apps::sovd2uds::operations::runtimefilesupdate::routes::<S, P, L>(route_state);
    let router = bulk_data_router.merge(operations_router);
    let handle = dynamic_router.add_routes(router.into()).await;
    tracing::info!("Runtime update routes added to webserver");
    handle
}

/// Routes that remain available while an update execution blocks other HTTP requests.
#[must_use]
pub fn routes_accessible_during_update() -> Vec<HttpRouteMatcher> {
    sovd::apps::sovd2uds::operations::runtimefilesupdate::routes_accessible_during_update()
}

/// `OpenAPI` spec regenerates on every recomposition, reflecting current routes.
///
/// The server URL embedded in `openapi.json` is derived dynamically from each
/// request's `Host` header (with `X-Forwarded-Host` / `Forwarded` taking
/// precedence for reverse-proxy deployments), so the Swagger-UI always reflects
/// the address the client actually used to reach CDA.
pub async fn add_openapi_routes(dynamic_router: &DynamicRouter) {
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

#[cfg(all(test, unix))]
mod webserver_bind_tests {
    use std::time::Duration;

    use futures::FutureExt;
    use http_body_util::Empty;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use hyperlocal::UnixConnector;

    use super::*;

    /// Sends a GET request over a Unix domain socket using a real HTTP
    /// client (`hyperlocal` on top of `hyper-util`) and returns the response
    /// status code. Used instead of parsing raw bytes off a `UnixStream`, so
    /// the tests exercise a spec-compliant HTTP client the same way a real
    /// consumer of the Unix socket transport would.
    async fn get_over_unix_socket(socket_path: &str, path: &str) -> http::StatusCode {
        let client: Client<UnixConnector, Empty<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build(UnixConnector);
        let uri: http::Uri = hyperlocal::Uri::new(socket_path, path).into();

        let response = client
            .get(uri)
            .await
            .expect("failed to send request over unix socket");
        response.status()
    }

    fn shutdown_channel() -> (
        tokio::sync::broadcast::Sender<()>,
        impl Future<Output = ()> + Clone + Send + 'static,
    ) {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<()>(1);
        let signal = async move {
            rx.recv().await.ok();
        }
        .shared();
        (tx, signal)
    }

    /// Asserts that `socket_path` is reachable (a request gets routed through
    /// the dynamic router, even if it 404s because no routes are registered),
    /// then signals shutdown and waits for `webserver_task` to finish.
    async fn assert_reachable_then_shutdown(
        socket_path: &str,
        shutdown_tx: tokio::sync::broadcast::Sender<()>,
        webserver_task: tokio::task::JoinHandle<()>,
    ) {
        // No routes are registered, so the dynamic router responds with 404 -
        // that's fine, we only need to confirm the connection was accepted
        // and routed.
        let status = get_over_unix_socket(socket_path, "/").await;
        assert_eq!(status, http::StatusCode::NOT_FOUND);

        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(5), webserver_task)
            .await
            .expect("webserver task didn't shut down in time")
            .expect("webserver task panicked");
    }

    #[tokio::test]
    async fn launch_webserver_binds_unix_socket() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let socket_path = dir.path().join("cda.sock").to_string_lossy().to_string();

        let config = WebServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
            unix_socket: Some(socket_path.clone()),
        };
        let (shutdown_tx, shutdown_signal) = shutdown_channel();

        let (_dynamic_router, webserver_task) = launch_webserver(config, shutdown_signal)
            .await
            .expect("failed to launch webserver on unix socket");

        assert_reachable_then_shutdown(&socket_path, shutdown_tx, webserver_task).await;
    }

    #[tokio::test]
    async fn launch_webserver_unix_socket_takes_priority_over_tcp() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let socket_path = dir.path().join("cda.sock").to_string_lossy().to_string();

        // Deliberately bind the TCP host/port too, to confirm it's ignored.
        let tcp_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to reserve a tcp port");
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        drop(tcp_listener);

        let config = WebServerConfig {
            host: "127.0.0.1".to_owned(),
            port: tcp_port,
            unix_socket: Some(socket_path.clone()),
        };
        let (shutdown_tx, shutdown_signal) = shutdown_channel();

        let (_dynamic_router, webserver_task) = launch_webserver(config, shutdown_signal)
            .await
            .expect("failed to launch webserver");

        // The TCP port must remain free, proving TCP was never bound (the
        // unix socket reachability itself is checked below).
        let retry_listener = TcpListener::bind(("127.0.0.1", tcp_port)).await;
        assert!(
            retry_listener.is_ok(),
            "TCP port should not have been bound when unix_socket is set"
        );

        assert_reachable_then_shutdown(&socket_path, shutdown_tx, webserver_task).await;
    }

    #[tokio::test]
    async fn launch_webserver_removes_stale_unix_socket_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let socket_path = dir.path().join("cda.sock").to_string_lossy().to_string();

        // Simulate a leftover socket file from a previous unclean shutdown.
        std::fs::write(&socket_path, b"stale").expect("failed to create stale socket file");

        let config = WebServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
            unix_socket: Some(socket_path.clone()),
        };
        let (shutdown_tx, shutdown_signal) = shutdown_channel();

        let (_dynamic_router, webserver_task) = launch_webserver(config, shutdown_signal)
            .await
            .expect("failed to launch webserver despite stale socket file");

        assert_reachable_then_shutdown(&socket_path, shutdown_tx, webserver_task).await;
    }

    #[tokio::test]
    async fn launch_webserver_fails_if_stale_socket_cannot_be_removed() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        // A directory can't be removed with `remove_file`, so binding must fail
        // with a clear error instead of silently misbehaving.
        let socket_path = dir.path().join("cda.sock");
        std::fs::create_dir(&socket_path).expect("failed to create directory");

        let config = WebServerConfig {
            host: "127.0.0.1".to_owned(),
            port: 0,
            unix_socket: Some(socket_path.to_string_lossy().to_string()),
        };
        let (_shutdown_tx, shutdown_signal) = shutdown_channel();

        let result = launch_webserver(config, shutdown_signal).await;
        assert!(
            result.is_err(),
            "expected launch_webserver to fail when the stale socket path is a directory"
        );
    }
}
