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
    axum::ApiRouter as Router,
    openapi::{Contact, License, OpenApi, Server, Tag},
    swagger::Swagger,
    transform::TransformOpenApi,
};
use axum::{Extension, Json, ServiceExt};
use cda_interfaces::dlt_ctx;
use cda_tracing::create_axum_trace_layer;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{RwLock, broadcast},
};
use tower::Layer;

use crate::{config::HealthConfig, serve::rewrite_request_uri};

pub mod config;

pub const SWAGGER_UI_ROUTE: &str = "/swagger-ui";
pub const OPENAPI_JSON_ROUTE: &str = "/openapi.json";

/// Health status response containing overall application health and component details.
///
/// This response provides a comprehensive view of the application's health status,
/// including the overall status, timestamp, version, and individual component health.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HealthResponse {
    /// Overall health status of the application.
    #[serde(flatten)]
    pub status: Status,
    /// Timestamp of the health check in RFC 3339 format.
    pub timestamp: String,
    /// Application version.
    pub version: String,
    /// Detailed health status of individual components.
    pub components: Vec<ComponentHealth>,
}

#[derive(thiserror::Error, Debug)]
pub enum HealthError {
    #[error("Webserver failed to start: {0}")]
    WebServerFailed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
#[serde(tag = "status", content = "error")]
pub enum Status {
    Up,
    Starting,
    Pending,
    Failed(String),
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
/// Health status of a specific component within the application.
pub struct ComponentHealth {
    /// Name of the component.
    pub name: String,
    /// Current status of the component.
    #[serde(flatten)]
    pub status: Status,
    /// Additional details about the component's health in JSON format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

struct WebserverState<T: ?Sized + ComponentHealthProvider, F: Future<Output = ()> + Send + 'static>
{
    components: Vec<Arc<RwLock<T>>>,
    version: String,
    shutdown_signal: F,
    health_rx: broadcast::Receiver<()>,
}

impl<T: ?Sized + ComponentHealthProvider, F: Future<Output = ()> + Send + 'static + Clone> Clone
    for WebserverState<T, F>
{
    fn clone(&self) -> Self {
        Self {
            components: self.components.clone(),
            version: self.version.clone(),
            shutdown_signal: self.shutdown_signal.clone(),
            health_rx: self.health_rx.resubscribe(),
        }
    }
}

pub trait ComponentHealthProvider: Send + Sync {
    fn health(&self) -> ComponentHealth;
}

#[tracing::instrument(skip(config, providers, shutdown_signal),
    fields(
        dlt_context = dlt_ctx!("HLTH"),
    )
)]
/// Launches the health webserver with the specified configuration and health providers.
/// # Errors
/// Returns `HealthError` if the webserver fails to start.
pub async fn launch_webserver<T, F>(
    config: &HealthConfig,
    providers: Vec<Arc<RwLock<T>>>,
    shutdown_signal: F,
    version: String,
    receiver: broadcast::Receiver<()>,
) -> Result<(), HealthError>
where
    // Relaxed size bounds to allow for trait objects, so it's
    // possible to pass different implementations of ComponentHealthProvider.
    T: ComponentHealthProvider + Sync + Send + ?Sized + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let clonable_shutdown_signal = shutdown_signal.shared();
    let mut api = OpenApi::default();

    let app_routes = {
        let app = Router::new()
            .merge(serve::route::<T, F>(
                providers,
                version,
                receiver,
                clonable_shutdown_signal.clone(),
            ))
            .finish_api_with(&mut api, |api| api_docs(api, config.clone()));

        create_axum_trace_layer(app, "HLTH".to_owned())
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(30),
            ))
            .route(
                SWAGGER_UI_ROUTE,
                Swagger::new(OPENAPI_JSON_ROUTE).axum_route().into(),
            )
            .route(
                OPENAPI_JSON_ROUTE,
                axum::routing::get(|Extension(api): Extension<Arc<OpenApi>>| async move {
                    Json((*api).clone())
                }),
            )
            .layer(Extension(Arc::new(api)))
    };

    let middleware = tower::util::MapRequestLayer::new(rewrite_request_uri);
    let trim_trailing_slash_middleware =
        tower_http::normalize_path::NormalizePathLayer::trim_trailing_slash().layer(app_routes);
    let app_with_middleware = middleware.layer(trim_trailing_slash_middleware);

    let listen_address = format!("{}:{}", config.address, config.port);
    match TcpListener::bind(&listen_address).await {
        Ok(listener) => {
            tracing::info!(listen_address = %listen_address, "Server listening");
            axum::serve(listener, app_with_middleware.into_make_service())
                .with_graceful_shutdown(clonable_shutdown_signal)
                .await
                .map_err(|e| HealthError::WebServerFailed(format!("Axum serve error: {e}")))?;
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

// Allowing pass by value here for the config, to prevent life-time issues with the
// borrowed config in the closure.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn api_docs(api: TransformOpenApi, config: HealthConfig) -> TransformOpenApi {
    api.title("Eclipse OpenSOVD - Classic Diagnostic Adapter - Health API")
        .summary(
            "Health monitoring endpoint for the Classic Diagnostic Adapter. Provides real-time \
             status information about the application and its components, including overall \
             health, version information, and detailed component status.",
        )
        .contact(Contact {
            name: Some("Classic Diagnostic Adapter".to_owned()),
            url: Some("https://github.com/eclipse-opensovd/classic-diagnostic-adapter/".to_owned()),
            email: Some("opensovd-dev@eclipse.org".to_owned()),
            ..Default::default()
        })
        .license(License {
            name: "Apache 2.0".to_owned(),
            identifier: Some("Apache-2.0".to_owned()),
            ..Default::default()
        })
        .tag(Tag {
            name: "OpenSOVD CDA - Health".to_owned(),
            description: Some(
                "Health endpoit for the Classic Diagnostic Adapter written in Rust".to_owned(),
            ),
            ..Default::default()
        })
        .server(Server {
            url: format!("http://{}:{}", config.address, config.port),
            ..Default::default()
        })
}

mod serve {
    use std::sync::Arc;

    use aide::axum::{ApiRouter, RouterExt, routing};
    use axum::{Router, http::Request};
    use futures::future::Shared;
    use tokio::sync::RwLock;

    use crate::{ComponentHealthProvider, WebserverState};

    pub(crate) fn rewrite_request_uri<B>(mut req: Request<B>) -> Request<B> {
        if let Ok(new_uri) = req.uri().to_string().to_lowercase().parse() {
            *req.uri_mut() = new_uri;
        }
        req
    }

    pub(crate) fn route<
        T: ?Sized + ComponentHealthProvider + Sync + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    >(
        providers: Vec<Arc<RwLock<T>>>,
        version: String,
        health_rx: tokio::sync::broadcast::Receiver<()>,
        shutdown_signal: Shared<F>,
    ) -> ApiRouter {
        let state = WebserverState {
            components: providers,
            version,
            shutdown_signal,
            health_rx,
        };

        Router::new()
            .api_route("/health", routing::get_with(health::get, health::docs_get))
            .api_route(
                "/health/ready",
                routing::get_with(health::ready::get, health::ready::docs_get),
            )
            // WebSocket endpoint uses standard route instead of api_route because
            // aide does not support WebSocketUpgrade extractors
            // for OpenAPI documentation generation
            .route("/health/ws", axum::routing::get(health::websocket::get))
            .with_state(state)
    }

    pub(crate) mod health {
        use std::sync::Arc;

        use aide::transform::TransformOperation;
        use axum::{
            Json,
            extract::State,
            response::{IntoResponse, Response},
        };
        use tokio::sync::RwLock;

        use crate::{
            ComponentHealth, ComponentHealthProvider, HealthResponse, Status, WebserverState,
        };
        pub(crate) async fn get<
            T: ?Sized + ComponentHealthProvider,
            F: Future<Output = ()> + Send + 'static,
        >(
            State(WebserverState {
                components,
                version,
                ..
            }): State<WebserverState<T, F>>,
        ) -> Response {
            (
                axum::http::StatusCode::OK,
                Json(health_response(&components, version).await),
            )
                .into_response()
        }

        pub(crate) async fn health_response<T: ?Sized + ComponentHealthProvider>(
            components: &[Arc<RwLock<T>>],
            version: String,
        ) -> HealthResponse {
            let component_states = futures::future::join_all(
                components.iter().map(|p| async { p.read().await.health() }),
            )
            .await;

            let overall_status = if component_states
                .iter()
                .all(|s| matches!(s.status, Status::Up))
            {
                // if all providers are up, overall status is up
                Status::Up
            } else {
                let failures: Vec<String> = component_states
                    .iter()
                    .filter_map(|s| {
                        if let Status::Failed(msg) = &s.status {
                            Some(msg.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                if failures.is_empty() {
                    // if all providers are starting or pending, overall status is starting
                    Status::Starting
                } else {
                    Status::Failed(failures.join(", "))
                }
            };

            HealthResponse {
                status: overall_status,
                timestamp: chrono::Utc::now().to_rfc3339(),
                version,
                components: component_states,
            }
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description(
                "Get the health status of the application. Appending `/ws` to the url opens a \
                 WebSocket for real-time health updates. Details are optional and provided by the \
                 specific health providers.",
            )
            .response_with::<200, Json<HealthResponse>, _>(|res| {
                res.description("Valid health response")
                    .example(HealthResponse {
                        status: Status::Up,
                        timestamp: "2025-12-11T15:30:00Z".to_owned(),
                        version: "1.0.0".to_owned(),
                        components: vec![ComponentHealth {
                            name: "database".to_owned(),
                            status: Status::Up,
                            details: Some(serde_json::json!({
                                "loaded_databases": 42,
                                "errors": {
                                    "MyEcu.mdd": "No diagnostic description found in MDD file"
                                }
                            })),
                        }],
                    })
            })
        }

        pub(crate) mod ready {
            use aide::transform::TransformOperation;
            use axum::{
                extract::State,
                http::StatusCode,
                response::{IntoResponse, Response},
            };

            use crate::{
                ComponentHealthProvider, Status, WebserverState, serve::health::health_response,
            };

            pub(crate) async fn get<
                T: ?Sized + ComponentHealthProvider,
                F: Future<Output = ()> + Send + 'static,
            >(
                State(WebserverState {
                    components,
                    version,
                    ..
                }): State<WebserverState<T, F>>,
            ) -> Response {
                let health = health_response(&components, version).await;
                match health.status {
                    Status::Up => StatusCode::NO_CONTENT.into_response(),
                    _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                }
            }

            pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
                op.description(
                    "Get the readiness status of the application. Returns 200 OK if ready, 503 \
                     Service Unavailable otherwise.",
                )
                .response_with::<200, String, _>(|res| res.description("Application is ready"))
                .response_with::<503, String, _>(|res| res.description("Application is not ready"))
            }
        }

        pub(crate) mod websocket {
            use std::sync::Arc;

            use axum::{
                extract::{
                    State,
                    ws::{WebSocket, WebSocketUpgrade},
                },
                response::Response,
            };
            use futures::{SinkExt, StreamExt};
            use tokio::sync::{RwLock, broadcast};

            use crate::{WebserverState, serve::health::health_response};

            pub(crate) async fn get<
                T: crate::ComponentHealthProvider + ?Sized + 'static,
                F: Future<Output = ()> + Send + Clone + 'static,
            >(
                ws: WebSocketUpgrade,
                State(WebserverState {
                    health_rx,
                    shutdown_signal,
                    version,
                    components,
                }): State<WebserverState<T, F>>,
            ) -> Response {
                ws.on_upgrade(move |socket| {
                    handle_ws(
                        socket,
                        health_rx,
                        version,
                        components.clone(),
                        shutdown_signal,
                    )
                })
            }

            async fn handle_ws<
                T: crate::ComponentHealthProvider + ?Sized + 'static,
                F: Future<Output = ()> + Send + 'static + Clone,
            >(
                socket: WebSocket,
                mut health_rx: broadcast::Receiver<()>,
                version: String,
                components: Vec<Arc<RwLock<T>>>,
                shutdown_signal: F,
            ) {
                async fn send_health<T: crate::ComponentHealthProvider + ?Sized + 'static>(
                    sender: &mut futures::stream::SplitSink<WebSocket, axum::extract::ws::Message>,
                    components: &[Arc<RwLock<T>>],
                    version: &str,
                ) -> bool {
                    let health = health_response(components, version.to_owned()).await;
                    sender
                        .send(axum::extract::ws::Message::Text(
                            serde_json::json!(health).to_string().into(),
                        ))
                        .await
                        .is_ok()
                }

                let (mut sender, mut receiver) = socket.split();

                // Spawn a task to forward messages from the broadcast channel to the WebSocket
                let mut send_task = tokio::spawn(async move {
                    loop {
                        // Send initial health status upon connection
                        if !send_health(&mut sender, &components, &version).await {
                            break;
                        }

                        let signal = shutdown_signal.clone();
                        tokio::select! {
                            msg_result = health_rx.recv() => {
                                match msg_result {
                                    Ok(()) => {
                                        if !send_health(&mut sender, &components, &version).await {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        match e {
                                            broadcast::error::RecvError::Lagged(count) => {
                                                tracing::debug!(
                                                    "Websocket lagged and missed {count} messages");
                                            }
                                            broadcast::error::RecvError::Closed => {
                                                tracing::error!("Health broadcast channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
                            },
                            () = signal => {
                                if let Err(e) =
                                    sender.send(axum::extract::ws::Message::Close(None)).await {
                                   tracing::debug!(
                                        "Failed to send websocket close during shutdown: {e}");
                                }
                                // Shutdown signal received
                                break;
                            }
                        }
                    }
                });

                // Spawn a task to handle incoming messages from the client
                let mut recv_task = tokio::spawn(async move {
                    while let Some(Ok(_msg)) = receiver.next().await {
                        // We don't process incoming messages, just keep the connection alive
                    }
                });

                tokio::select! {
                    _ = &mut send_task => {
                        recv_task.abort();
                    }
                    _ = &mut recv_task => {
                        send_task.abort();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;

    struct MockComponent {
        status: Status,
        name: String,
    }

    impl ComponentHealthProvider for MockComponent {
        fn health(&self) -> ComponentHealth {
            ComponentHealth {
                name: self.name.clone(),
                status: self.status.clone(),
                details: None,
            }
        }
    }

    fn make_component(name: &str, status: Status) -> Arc<RwLock<MockComponent>> {
        Arc::new(RwLock::new(MockComponent {
            status,
            name: name.to_owned(),
        }))
    }

    #[tokio::test]
    async fn test_health_response_overall_status_all_up() {
        let components = vec![
            make_component("database", Status::Up),
            make_component("server", Status::Up),
        ];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        assert_eq!(response.status, Status::Up);
    }

    #[tokio::test]
    async fn test_health_response_overall_status_single_failed() {
        let error = "Connection timeout".to_owned();
        let components = vec![
            make_component("database", Status::Up),
            make_component("server", Status::Failed(error.clone())),
        ];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        assert_eq!(response.status, Status::Failed(error));
    }

    #[tokio::test]
    async fn test_health_response_overall_status_multiple_failed() {
        let first_error = "Database failed".to_owned();
        let second_error = "Server failed".to_owned();
        let components = vec![
            make_component("db", Status::Failed(first_error.clone())),
            make_component("server", Status::Failed(second_error.clone())),
        ];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        // Returns all failures comma-separated
        assert_eq!(
            response.status,
            Status::Failed(format!("{first_error}, {second_error}"))
        );
    }

    #[tokio::test]
    async fn test_health_response_overall_status_starting() {
        let components = vec![
            make_component("database", Status::Starting),
            make_component("server", Status::Pending),
        ];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        assert_eq!(response.status, Status::Starting);
    }

    #[tokio::test]
    async fn test_health_response_failed_takes_precedence() {
        let error = "Critical failure".to_owned();
        let components = vec![
            make_component("c1", Status::Starting),
            make_component("c2", Status::Failed(error.clone())),
            make_component("c3", Status::Up),
        ];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        assert_eq!(response.status, Status::Failed(error));
    }

    #[tokio::test]
    async fn test_health_response_metadata() {
        let components = vec![make_component("database", Status::Up)];
        let response = serve::health::health_response(&components, "2.1.0".to_owned()).await;

        assert_eq!(response.version, "2.1.0");
        assert_eq!(response.components.len(), 1);
        assert_eq!(response.components.first().unwrap().name, "database");

        chrono::DateTime::parse_from_rfc3339(&response.timestamp).unwrap();
    }

    #[tokio::test]
    async fn test_health_response_empty() {
        let components: Vec<Arc<RwLock<MockComponent>>> = vec![];
        let response = serve::health::health_response(&components, "1.0.0".to_owned()).await;
        assert_eq!(response.status, Status::Up);
        assert_eq!(response.components.len(), 0);
    }
}
