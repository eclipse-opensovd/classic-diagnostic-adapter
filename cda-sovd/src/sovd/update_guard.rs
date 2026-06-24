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

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
    task::{
        Context,
        Poll,
    },
};

use axum::{
    Json,
    http::StatusCode,
    response::{
        IntoResponse,
        Response,
    },
};
use http::Method;
use tokio::sync::RwLock;
use tower::{
    Layer,
    Service,
};

/// A route prefix and set of HTTP methods that are allowed to bypass the update guard.
#[derive(Clone)]
pub struct ExemptRoute {
    pub prefix: String,
    pub methods: Vec<Method>,
}

/// Shared state for the update guard middleware
/// that rejects non-exempt requests while an update is in progress.
#[derive(Clone, Default)]
pub struct UpdateGuardState {
    busy: Arc<AtomicBool>,
    exempt_routes: Arc<RwLock<Vec<ExemptRoute>>>,
}

impl UpdateGuardState {
    /// Creates a new [`UpdateGuardState`] with
    /// no update in progress and an empty exempt-route list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            busy: Arc::new(AtomicBool::new(false)),
            exempt_routes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Returns a shared handle to the in-progress flag.
    ///
    /// Callers can set or clear this flag to signal whether an update is currently active.
    #[must_use]
    pub fn busy_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.busy)
    }

    /// Registers a single route that should bypass the update guard.
    pub async fn add_exempt(&self, route: ExemptRoute) {
        self.exempt_routes.write().await.push(route);
    }

    /// Registers multiple routes that should bypass the update guard.
    pub async fn extend_exempt(&self, routes: impl IntoIterator<Item = ExemptRoute>) {
        self.exempt_routes.write().await.extend(routes);
    }
}

/// Tower [`Layer`] that wraps services with the update guard middleware.
#[derive(Clone)]
pub struct UpdateGuardLayer {
    state: UpdateGuardState,
}

impl UpdateGuardLayer {
    #[must_use]
    pub fn new(state: UpdateGuardState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for UpdateGuardLayer {
    type Service = UpdateGuardService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UpdateGuardService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Tower [`Service`] that rejects non-exempt
/// requests with `409 Conflict` while an update is in progress.
#[derive(Clone)]
pub struct UpdateGuardService<S> {
    inner: S,
    state: UpdateGuardState,
}

impl<S> Service<axum::extract::Request> for UpdateGuardService<S>
where
    S: Service<axum::extract::Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        // Heap-allocate the future because async blocks are opaque, unsized types
        // that cannot satisfy the concrete `Pin<Box<dyn Future>>` return type directly.
        Box::pin(async move {
            if state.busy.load(Ordering::Acquire) {
                let path = req.uri().path().to_owned();
                let method = req.method().clone();
                let exempt_routes = state.exempt_routes.read().await;
                let is_exempt = exempt_routes.iter().any(|exempt| {
                    path.starts_with(&exempt.prefix) && exempt.methods.contains(&method)
                });

                if !is_exempt {
                    return Ok((
                        StatusCode::CONFLICT,
                        Json(sovd_interfaces::error::ApiErrorResponse::<String> {
                            message: "Database update in progress, all diagnostic operations are \
                                      blocked"
                                .to_owned(),
                            error_code: sovd_interfaces::error::ErrorCode::UpdateProcessInProgress,
                            vendor_code: None,
                            parameters: None,
                            error_source: None,
                            schema: None,
                        }),
                    )
                        .into_response());
                }
            }

            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        routing::get,
    };
    use http::Request;
    use tower::ServiceExt;

    use super::*;

    fn test_state() -> UpdateGuardState {
        UpdateGuardState::new()
    }

    #[tokio::test]
    async fn allows_requests_when_no_update_in_progress() {
        let state = test_state();
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(UpdateGuardLayer::new(state));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blocks_requests_when_update_in_progress() {
        let state = test_state();
        state.busy.store(true, Ordering::Release);

        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(UpdateGuardLayer::new(state));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn allows_exempt_routes_during_update() {
        let state = test_state();
        state.busy.store(true, Ordering::Release);
        state
            .add_exempt(ExemptRoute {
                prefix: "/exempt".to_string(),
                methods: vec![Method::GET],
            })
            .await;

        let app = Router::new()
            .route("/exempt/thing", get(|| async { "ok" }))
            .layer(UpdateGuardLayer::new(state));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/exempt/thing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn exempt_route_respects_method_filter() {
        let state = test_state();
        state.busy.store(true, Ordering::Release);
        state
            .add_exempt(ExemptRoute {
                prefix: "/api".to_string(),
                methods: vec![Method::GET],
            })
            .await;

        let app = Router::new()
            .route("/api/data", get(|| async { "ok" }))
            .layer(UpdateGuardLayer::new(state));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/data")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
