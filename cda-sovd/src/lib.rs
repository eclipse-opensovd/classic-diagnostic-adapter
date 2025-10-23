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

use std::sync::Arc;

use aide::{axum::ApiRouter as Router, openapi::OpenApi, swagger::Swagger};
use axum::{
    Extension, Json, ServiceExt,
    http::{self, Request},
    middleware, routing,
};
use cda_interfaces::{
    DoipGatewaySetupError, SchemaProvider, UdsEcu, diagservices::DiagServiceResponse,
    file_manager::FileManager,
};
use cda_plugin_security::SecurityPluginLoader;
use futures::future::FutureExt;
use hashbrown::HashMap;
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::trace::TraceLayer;

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

/// Launches the http(s) webserver for handling SOVD requests
///
/// # Errors
/// Will return `Err` in case that the webserver couldn´t be launched.
/// This can be caused due to invalid config, ports or addresses already
/// being in use or an error when initializing the `DoIP` gateway.
#[tracing::instrument(
    skip(config, ecu_uds, file_manager, shutdown_signal),
    fields(
        host = %config.host,
        port = %config.port,
        flash_files_path = %flash_files_path
    )
)]
pub async fn launch_webserver<F, R, T, M, S>(
    config: WebServerConfig,
    ecu_uds: T,
    flash_files_path: String,
    file_manager: HashMap<String, M>,
    shutdown_signal: F,
) -> Result<(), DoipGatewaySetupError>
where
    F: Future<Output = ()> + Send + 'static,
    R: DiagServiceResponse,
    T: UdsEcu + SchemaProvider + Clone,
    M: FileManager,
    S: SecurityPluginLoader,
{
    let clonable_shutdown_signal = shutdown_signal.shared();

    let vdetect = ecu_uds.clone();
    cda_interfaces::spawn_named!("startup-variant-detection", async move {
        vdetect.start_variant_detection().await;
    });

    aide::generate::on_error(|e| {
        if let aide::Error::DuplicateRequestBody = e {
            // skip DuplicateRequestBody
            // those are triggered when overwriting the input type
            return;
        }
        tracing::error!(error = %e, "OpenAPI generation error");
    });
    aide::generate::extract_schemas(true);
    let mut api = OpenApi::default();

    // Main application routes (with NormalizePathLayer)
    let app_routes = {
        let app = Router::new()
            .merge(sovd::route::<R, T, M, S>(&ecu_uds, flash_files_path, file_manager).await)
            .finish_api_with(&mut api, openapi::api_docs);

        create_trace_layer(app)
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(30),
            ))
            .layer(middleware::from_fn(
                sovd::error::sovd_method_not_allowed_handler,
            ))
            .fallback(sovd::error::sovd_not_found_handler)
            .route(
                SWAGGER_UI_ROUTE,
                Swagger::new(OPENAPI_JSON_ROUTE).axum_route().into(),
            )
            .route(
                OPENAPI_JSON_ROUTE,
                routing::get(|Extension(api): Extension<Arc<OpenApi>>| async move {
                    Json((*api).clone())
                }),
            )
            .layer(Extension(Arc::new(api)))
    };

    let middleware = tower::util::MapRequestLayer::new(rewrite_request_uri);
    let trim_trailing_slash_middleware =
        tower_http::normalize_path::NormalizePathLayer::trim_trailing_slash().layer(app_routes);
    let app_with_middleware = middleware.layer(trim_trailing_slash_middleware);

    let listen_address = format!("{}:{}", config.host, config.port);
    match TcpListener::bind(&listen_address).await {
        Ok(listener) => {
            tracing::info!(listen_address = %listen_address, "Server listening");
            axum::serve(listener, app_with_middleware.into_make_service())
                .with_graceful_shutdown(clonable_shutdown_signal)
                .await
                .map_err(|e| {
                    DoipGatewaySetupError::ServerError(format!("Axum serve error: {e}"))
                })?;
        }
        Err(e) => {
            tracing::error!(
                listen_address = %listen_address,
                error = %e,
                "Failed to bind to address"
            );
        }
    }

    Ok(())
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
