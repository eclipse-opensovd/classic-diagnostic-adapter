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

use std::{future::Future, sync::Arc};

use aide::{
    axum::{ApiRouter as Router, routing},
    openapi::OpenApi,
    swagger::Swagger,
};
use axum::{
    Extension, Json,
    http::{self, Request},
};
use cda_interfaces::{
    DoipGatewaySetupError, FunctionalDescriptionConfig, HashMap, SchemaProvider, UdsEcu,
    diagservices::DiagServiceResponse, dlt_ctx, file_manager::FileManager,
};
use cda_plugin_security::SecurityPluginLoader;
use dynamic_router::DynamicRouter;
use tokio::net::TcpListener;
use tower::{Layer, ServiceExt as TowerServiceExt};
use tower_http::{normalize_path::NormalizePathLayer, trace::TraceLayer};

pub use crate::sovd::locks::Locks;

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

/// Launches the http(s) webserver with deferred initialization
///
/// The server starts immediately with static endpoints. SOVD routes and other functionality
/// can be added later by calling methods on the returned `DynamicRouter`.
///
/// # Errors
/// Will return `Err` in case that the webserver couldn't be launched.
/// This can be caused due to invalid config, ports or addresses already being in use.
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
) -> Result<DynamicRouter, DoipGatewaySetupError>
where
    F: Future<Output = ()> + Clone + Send + 'static,
{
    let dynamic_router = DynamicRouter::new();
    let listen_address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&listen_address).await.map_err(|e| {
        DoipGatewaySetupError::ServerError(format!("Failed to bind to {listen_address}: {e}"))
    })?;

    let dynamic_router_for_service = dynamic_router.clone();
    cda_interfaces::spawn_named!("webserver", async move {
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

    Ok(dynamic_router)
}

/// Add vehicle routes to the dynamic router
///
/// This function should be called after the database is loaded to add all vehicle routes
/// to the webserver.
///
/// # Errors
/// Will return `Err` if routes cannot be added to the dynamic router.
// type alias does not allow specifying hasher, we set the hasher globally.
#[allow(clippy::implicit_hasher)]
#[tracing::instrument(
    skip(dynamic_router, ecu_uds, file_manager, locks),
    fields(
        flash_files_path = %flash_files_path
    )
)]
pub async fn add_vehicle_routes<R, T, M, S>(
    dynamic_router: &DynamicRouter,
    ecu_uds: T,
    flash_files_path: String,
    file_manager: HashMap<String, M>,
    locks: Arc<Locks>,
    functional_group_config: FunctionalDescriptionConfig,
) -> Result<(), DoipGatewaySetupError>
where
    R: DiagServiceResponse,
    T: UdsEcu + SchemaProvider + Clone + Send + Sync + 'static,
    M: FileManager + Send + Sync + 'static,
    S: SecurityPluginLoader,
{
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
    let vehicle_router = sovd::route::<R, T, M, S>(
        functional_group_config,
        &ecu_uds,
        flash_files_path,
        file_manager,
        locks,
    )
    .await
    .route(
        SWAGGER_UI_ROUTE,
        Swagger::new(OPENAPI_JSON_ROUTE).axum_route(),
    )
    .route(
        OPENAPI_JSON_ROUTE,
        routing::get(|Extension(api): Extension<Arc<OpenApi>>| async move { Json((*api).clone()) }),
    )
    .finish_api_with(&mut api, openapi::api_docs)
    .layer(Extension(Arc::new(api)));

    // Update the router with the new routes,
    // merge with existing router to preserve existing routes
    dynamic_router
        .update_router(move |old_router| old_router.merge(vehicle_router))
        .await;

    tracing::info!("Vehicle routes added to webserver");
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
