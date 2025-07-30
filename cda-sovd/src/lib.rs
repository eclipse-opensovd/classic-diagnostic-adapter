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

use axum::{
    Router, ServiceExt,
    http::{self, Request},
    middleware,
};
use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};
use futures::future::FutureExt;
use hashbrown::HashMap;
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::trace::TraceLayer;

mod sovd;

// Consts for HTTP
pub const SWAGGER_UI_ROUTE: &str = "/swagger-ui";
pub const OPENAPI_JSON_ROUTE: &str = "/openapi.json";

#[derive(Clone)]
pub struct WebServerConfig {
    pub host: String,
    pub port: u16,
}

/// Launches the http(s) webserver for handling SOVD requests
///
/// # Errors
/// Will return `Err` in case that the webserver couldn´t be launched.
/// This can be caused due to invalid config, ports or addresses already
/// being in use or an error when initializing the `DoIP` gateway.
pub async fn launch_webserver<F, R, T, M>(
    config: WebServerConfig,
    ecu_uds: T,
    flash_files_path: String,
    file_manager: HashMap<String, M>,
    shutdown_signal: F,
) -> Result<(), String>
where
    F: Future<Output = ()> + Send + 'static,
    R: DiagServiceResponse,
    T: UdsEcu + Send + Sync + Clone,
    M: FileManager,
{
    let mut app = Router::new();

    let clonable_shutdown_signal = shutdown_signal.shared();

    let vdetect = ecu_uds.clone();
    cda_interfaces::spawn_named!("startup-variant-detection", async move {
        vdetect.start_variant_detection().await;
    });

    app = create_trace_layer(
        app.merge(sovd::route::<R, T, M>(&ecu_uds, flash_files_path, file_manager).await),
    )
    .layer(tower_http::timeout::TimeoutLayer::new(
        std::time::Duration::from_secs(30),
    ))
    .layer(middleware::from_fn(
        sovd::error::sovd_method_not_allowed_handler,
    ))
    .fallback(sovd::error::sovd_not_found_handler);

    let middleware = tower::util::MapRequestLayer::new(rewrite_request_uri);
    let app_with_middleware = middleware.layer(app);

    let app_with_middleware = tower_http::normalize_path::NormalizePathLayer::trim_trailing_slash()
        .layer(app_with_middleware);

    let listen_address = format!("{}:{}", config.host, config.port);
    match TcpListener::bind(&listen_address).await {
        Ok(listener) => {
            log::info!(target: "main", "Listening on: {listen_address}");
            axum::serve(listener, app_with_middleware.into_make_service())
                .with_graceful_shutdown(clonable_shutdown_signal)
                .await
                .map_err(|e| format!("Axum serve error: {e}"))?;
        }
        Err(e) => {
            log::error!(target: "main", "Failed to bind to: {listen_address}: {e}");
        }
    }

    Ok(())
}

fn rewrite_request_uri<B>(mut req: Request<B>) -> Request<B> {
    let new_uri = req.uri().to_string().to_lowercase().parse().unwrap();
    *req.uri_mut() = new_uri;
    req
}

fn create_trace_layer<S>(route: Router<S>) -> Router<S>
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
                )
            })
            .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                log::info!(target: "webserver", "Request: {:?} {}", request.method(), request.uri());
            })
            .on_response(
                |response: &axum::http::Response<_>,
                 latency: std::time::Duration,
                 span: &tracing::Span| {
                    log::info!(target: "webserver", "Response: {} in {:?}",
                        response.status(), latency);

                    span.record("status_code", response.status().as_u16());
                    span.record("latency", format!("{latency:?}",));
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
                    log::error!(target: "webserver", "Error: {error} in {latency:?}");
                    span.record("error", error.to_string());
                },
            ),
    )
}
