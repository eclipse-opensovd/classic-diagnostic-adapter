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

use aide::axum::{ApiRouter as Router, routing};
use cda_interfaces::HashMap;
use cda_sovd::dynamic_router::DynamicRouter;
use futures::future;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub mod config;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum HealthError {
    #[error("Provider {0} already exists")]
    ProviderAlreadyExists(String),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
pub enum Status {
    Up,
    Starting,
    Pending,
    Failed,
}

/// Trait for health providers that are queried on-demand when a health check request comes in.
/// Implementors should return the current health status when `check_health` is called.
#[async_trait::async_trait]
pub trait HealthProvider: Send + Sync {
    /// Returns the current health status of the component.
    async fn check_health(&self) -> Status;
}

/// A simple health provider implementation that stores the last status.
/// Useful for components that run through an initialization once and their health
/// state does not change afterward anymore.
/// For example loading the database or initializing something once.
pub struct StatusHealthProvider {
    status: Arc<RwLock<Status>>,
}

impl StatusHealthProvider {
    /// Creates a new `StatusHealthProvider` with the given initial status.
    #[must_use]
    pub fn new(initial_status: Status) -> Self {
        Self {
            status: Arc::new(RwLock::new(initial_status)),
        }
    }

    /// Updates the health status of this provider.
    pub async fn update_status(&self, status: Status) {
        *self.status.write().await = status;
    }
}

#[async_trait::async_trait]
impl HealthProvider for StatusHealthProvider {
    async fn check_health(&self) -> Status {
        *self.status.read().await
    }
}

#[derive(Clone)]
pub struct HealthState {
    providers: Arc<RwLock<HashMap<String, Arc<dyn HealthProvider>>>>,
    version: String,
}

impl HealthState {
    /// Register a health provider for a component.
    /// The provider will be queried when health status is requested.
    /// # Errors
    /// Returns `HealthError::ProviderAlreadyExists` if a provider with
    /// the same name is already registered.
    pub async fn register_provider(
        &self,
        name: impl Into<String>,
        provider: Arc<dyn HealthProvider>,
    ) -> Result<(), HealthError> {
        let name = name.into();
        let mut providers = self.providers.write().await;

        if providers.contains_key(&name) {
            return Err(HealthError::ProviderAlreadyExists(name));
        }

        providers.insert(name, provider);
        Ok(())
    }

    /// Query all registered health providers and return their current status.
    async fn query_all_providers(&self) -> HashMap<String, Status> {
        let providers = self.providers.read().await;

        let futures = providers.iter().map(|(name, provider)| async move {
            let status = provider.check_health().await;
            (name.clone(), status)
        });

        future::join_all(futures).await.into_iter().collect()
    }
}

/// Adds health check routes to the provided dynamic router,
/// which makes the health endpoint available
pub async fn add_health_routes(dynamic_router: &DynamicRouter, cda_version: String) -> HealthState {
    let state = HealthState {
        providers: Arc::new(RwLock::default()),
        version: cda_version,
    };

    let router = Router::new()
        .api_route("/health", routing::get_with(routes::get, routes::docs_get))
        .api_route(
            "/health/ready",
            routing::get_with(routes::ready::get, routes::ready::docs_get),
        )
        .with_state(state.clone());

    dynamic_router.merge_routes(router).await;
    state
}

mod routes {
    use aide::transform::TransformOperation;
    use axum::{
        Json,
        extract::State,
        response::{IntoResponse, Response},
    };
    use cda_interfaces::HashMap;
    use serde::{Deserialize, Serialize};

    use crate::{HealthState, Status};

    /// Health status response containing overall application health and component details.
    ///
    /// This response provides a comprehensive view of the application's health status,
    /// including the overall status, version, and individual component health.
    #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
    pub(crate) struct HealthResponse {
        /// Overall health status of the application.
        pub status: Status,
        /// Application version.
        pub version: String,
        /// Detailed health status of individual components.
        pub components: Vec<ComponentHealth>,
    }

    /// Health status of a specific component within the application.
    #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
    pub(crate) struct ComponentHealth {
        /// Name of the component.
        pub name: String,
        /// Current status of the component.
        pub status: Status,
    }

    pub(crate) async fn get(state: State<HealthState>) -> Response {
        (
            axum::http::StatusCode::OK,
            Json(health_response(&state).await),
        )
            .into_response()
    }

    pub(crate) async fn health_response(state: &HealthState) -> HealthResponse {
        // Query all providers for their current status
        let states: HashMap<String, Status> = state.query_all_providers().await;

        let overall_status = if states.values().all(|s| matches!(s, Status::Up)) {
            // if all providers are up, overall status is up
            Status::Up
        } else if states.values().any(|s| matches!(s, Status::Failed)) {
            Status::Failed
        } else {
            // if no providers failed,
            // but some are starting or pending, overall status is starting
            Status::Starting
        };

        HealthResponse {
            status: overall_status,
            version: state.version.clone(),
            components: states
                .into_iter()
                .map(|(name, status)| ComponentHealth { name, status })
                .collect(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description(
            "Get the health status of the application. Use `/stream` endpoint for real-time \
             health updates via Server-Sent Events. Details are optional and provided by the \
             specific health providers.",
        )
        .response_with::<200, Json<HealthResponse>, _>(|res| {
            res.description("Valid health response")
                .example(HealthResponse {
                    status: Status::Up,
                    version: "1.0.0".to_owned(),
                    components: vec![ComponentHealth {
                        name: "database".to_owned(),
                        status: Status::Up,
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

        use crate::{HealthState, Status, routes::health_response};

        pub(crate) async fn get(state: State<HealthState>) -> Response {
            let health = health_response(&state).await;
            match health.status {
                Status::Up => StatusCode::NO_CONTENT.into_response(),
                _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description(
                "Get the readiness status of the application. Returns 204 OK if ready, 503 \
                 Service Unavailable otherwise.",
            )
            .response_with::<204, String, _>(|res| res.description("Application is ready"))
            .response_with::<503, String, _>(|res| res.description("Application is not ready"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Default for HealthState {
        fn default() -> Self {
            HealthState {
                providers: Arc::new(RwLock::default()),
                version: "1.0.0".to_string(),
            }
        }
    }

    async fn set_component_status(state: &HealthState, name: &str, status: Status) {
        let provider = Arc::new(StatusHealthProvider::new(status));
        state.register_provider(name, provider).await.unwrap();
    }

    #[tokio::test]
    async fn test_health_response_overall_status_all_up() {
        let state = HealthState::default();
        set_component_status(&state, "database", Status::Up).await;
        set_component_status(&state, "doip", Status::Up).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Up);
    }

    #[tokio::test]
    async fn test_health_response_overall_status_single_failed() {
        let state = HealthState::default();
        set_component_status(&state, "database", Status::Up).await;
        set_component_status(&state, "doip", Status::Failed).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Failed);
    }

    #[tokio::test]
    async fn test_health_response_overall_status_multiple_failed() {
        let state = HealthState::default();
        set_component_status(&state, "db", Status::Failed).await;
        set_component_status(&state, "doip", Status::Failed).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Failed);
    }

    #[tokio::test]
    async fn test_health_response_overall_status_starting() {
        let state = HealthState::default();
        set_component_status(&state, "database", Status::Starting).await;
        set_component_status(&state, "doip", Status::Pending).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Starting);
    }

    #[tokio::test]
    async fn test_health_response_failed_takes_precedence() {
        let state = HealthState::default();
        set_component_status(&state, "c1", Status::Starting).await;
        set_component_status(&state, "c2", Status::Failed).await;
        set_component_status(&state, "c3", Status::Up).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Failed);
    }

    #[tokio::test]
    async fn test_health_response_metadata() {
        let state = HealthState {
            providers: Arc::new(RwLock::default()),
            version: "2.1.0".to_string(),
        };
        set_component_status(&state, "database", Status::Up).await;

        let response = routes::health_response(&state).await;

        assert_eq!(response.version, "2.1.0");
        assert_eq!(response.components.len(), 1);
        assert_eq!(response.components.first().unwrap().name, "database");
    }

    #[tokio::test]
    async fn test_health_response_empty() {
        let state = HealthState::default();

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Up);
        assert_eq!(response.components.len(), 0);
    }

    #[tokio::test]
    async fn test_mixed_providers() {
        let state = HealthState::default();

        // Register multiple providers
        let custom_provider = Arc::new(StatusHealthProvider::new(Status::Up));
        state
            .register_provider("custom", custom_provider)
            .await
            .unwrap();

        set_component_status(&state, "database", Status::Up).await;

        let response = routes::health_response(&state).await;
        assert_eq!(response.status, Status::Up);
        assert_eq!(response.components.len(), 2);
    }

    #[tokio::test]
    async fn test_provider_can_be_updated() {
        let state = HealthState::default();
        let provider = Arc::new(StatusHealthProvider::new(Status::Starting));
        let provider_clone = Arc::clone(&provider);
        state
            .register_provider("database", provider_clone as Arc<dyn HealthProvider>)
            .await
            .unwrap();

        let response1 = routes::health_response(&state).await;
        assert_eq!(response1.status, Status::Starting);

        // Update the provider status
        provider.update_status(Status::Up).await;

        let response2 = routes::health_response(&state).await;
        assert_eq!(response2.status, Status::Up);
    }

    #[tokio::test]
    async fn test_register_provider_already_exists() {
        let state = HealthState::default();
        let provider1 = Arc::new(StatusHealthProvider::new(Status::Up));
        let provider2 = Arc::new(StatusHealthProvider::new(Status::Failed));
        let name = "database".to_owned();

        state
            .register_provider(name.clone(), provider1)
            .await
            .unwrap();
        let result = state.register_provider(name.clone(), provider2).await;
        let err = result.unwrap_err();
        assert_eq!(err, HealthError::ProviderAlreadyExists(name));
    }
}
