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
use tokio::{net::TcpListener, sync::RwLock};
use tower::Layer;

use crate::{config::HealthEndpointConfig, serve::rewrite_request_uri};

pub mod config;

pub const SWAGGER_UI_ROUTE: &str = "/swagger-ui"; // todo re-use?
pub const OPENAPI_JSON_ROUTE: &str = "/openapi.json";

#[macro_export]
macro_rules! update_status {
    ($health_provider:expr, $status:expr) => {
        if let Some(hp) = &$health_provider {
            hp.write().await.status = $status;
        }
    };
}

#[macro_export]

macro_rules! try_with_health {
    ($health_provider:expr, $expr:expr) => {
        match $expr {
            Ok(val) => Ok(val),
            Err(e) => {
                cda_health::update_status!(
                    $health_provider,
                    cda_health::Status::Failed(e.to_string())
                );
                Err(e)
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
pub enum HealthError {
    #[error("Webserver failed to start: {0}")]
    WebServerFailed(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Status {
    Up,
    Starting,
    Pending,
    Failed(String),
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
/// Health status of a specific component within the application.
pub struct ComponentHealth {
    /// Name of the component.
    pub name: String,
    /// Current status of the component.
    pub status: Status,
    /// Additional details about the component's health in JSON format.
    pub details: serde_json::Value,
}

struct WebserverState<T: ComponentHealthProvider> {
    components: Vec<Arc<RwLock<T>>>,
    version: String,
}

impl<T: ComponentHealthProvider> Clone for WebserverState<T> {
    fn clone(&self) -> Self {
        Self {
            components: self.components.clone(),
            version: self.version.clone(),
        }
    }
}

pub trait ComponentHealthProvider {
    fn health(&self) -> ComponentHealth;
}

pub async fn launch_webserver<T, F>(
    config: &HealthEndpointConfig,
    providers: Vec<Arc<RwLock<T>>>,
    shutdown_signal: F,
    version: String,
) -> Result<(), HealthError>
where
    T: ComponentHealthProvider + Sync + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let clonable_shutdown_signal = shutdown_signal.shared();
    let mut api = OpenApi::default();

    // Main application routes (with NormalizePathLayer)
    let app_routes = {
        let app = Router::new()
            .merge(serve::route::<T>(providers, version).await)
            .finish_api_with(&mut api, |api| api_docs(api, config.clone()));

        create_axum_trace_layer(app, dlt_ctx!("HLTH").map(ToOwned::to_owned))
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

pub(crate) fn api_docs(api: TransformOpenApi, config: HealthEndpointConfig) -> TransformOpenApi {
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
    use tokio::sync::RwLock;

    use crate::{ComponentHealthProvider, WebserverState};

    pub(crate) fn rewrite_request_uri<B>(mut req: Request<B>) -> Request<B> {
        let new_uri = req.uri().to_string().to_lowercase().parse().unwrap();
        *req.uri_mut() = new_uri;
        req
    }

    pub(crate) async fn route<T: ComponentHealthProvider + Sync + Send + 'static>(
        providers: Vec<Arc<RwLock<T>>>,
        version: String,
    ) -> ApiRouter {
        let state = WebserverState {
            components: providers,
            version,
        };

        Router::new()
            .api_route("/health", routing::get_with(health::get, health::docs_get))
            .with_state(state)
    }

    pub(crate) mod health {
        use aide::transform::TransformOperation;
        use axum::{
            Json,
            extract::State,
            response::{IntoResponse, Response},
        };
        use serde::{Deserialize, Serialize};

        use crate::{ComponentHealth, ComponentHealthProvider, Status, WebserverState};

        /// Health status response containing overall application health and component details.
        ///
        /// This response provides a comprehensive view of the application's health status,
        /// including the overall status, timestamp, version, and individual component health.
        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
        struct HealthResponse {
            /// Overall health status of the application.
            status: Status,
            /// Timestamp of the health check in RFC 3339 format.
            timestamp: String,
            /// Application version.
            version: String,
            /// Detailed health status of individual components.
            components: Vec<ComponentHealth>,
        }

        pub(crate) async fn get<T: ComponentHealthProvider>(
            State(WebserverState {
                components,
                version,
            }): State<WebserverState<T>>,
        ) -> Response {
            let component_states = futures::future::join_all(
                components
                    .iter()
                    .map(|p| async { p.read().await.health() }),
            )
            .await;

            // if all providers are up, overall status is up
            let overall_status = if component_states
                .iter()
                .all(|s| matches!(s.status, Status::Up))
            {
                Status::Up
            // if one provider is failed, overall status is failed
            } else if component_states
                .iter()
                .any(|s| matches!(s.status, Status::Failed(_)))
            {
                Status::Failed("One or more components failed".to_owned())
            // if all providers are starting or pending, overall status is starting
            } else {
                Status::Starting
            };

            let health_response = HealthResponse {
                status: overall_status,
                timestamp: chrono::Utc::now().to_rfc3339(),
                version,
                components: component_states,
            };
            (axum::http::StatusCode::OK, Json(health_response)).into_response()
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get the health status of the application")
                .response_with::<200, Json<HealthResponse>, _>(|res| {
                    res.description("Valid health response")
                        .example(HealthResponse {
                            status: Status::Up,
                            timestamp: "2025-12-11T15:30:00Z".to_string(),
                            version: "1.0.0".to_string(),
                            components: vec![ComponentHealth {
                                name: "database".to_string(),
                                status: Status::Up,
                                details: serde_json::json!({
                                    "loaded_databases": 42,
                                    "db_errors": {
                                        "MyEcu": "No diagnostic description found in MDD file"
                                    }
                                }),
                            }],
                        })
                })
        }
    }
}
