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

//! Tower middleware that gates HTTP requests behind an [`HttpRestrictionGuard`].
//!
//! Any type implementing [`HttpRestrictionGuard`] can be installed as a Tower layer that
//! evaluates incoming requests and either passes them through or denies them with a
//! structured SOVD error response.
//!
//! # Fast-path optimization
//!
//! [`HttpRestrictionGuard::is_active`] provides a cheap atomic check. When it returns
//! `false`, the middleware passes requests through immediately without allocating the
//! async evaluation future.
//!
//! # Installation
//!
//! Install globally via [`install_http_restriction_guard`] on a
//! [`DynamicRouter`](crate::dynamic_router::DynamicRouter), or manually construct an
//! [`HttpRestrictionLayer`] and apply it to any Tower service.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    Json,
    http::{HeaderValue, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use cda_plugin_communication_management::http_protection::evaluator::{
    HttpRestrictionDecision, HttpRestrictionDenial, HttpRestrictionGuard,
};
use sovd_interfaces::error::ErrorCode;
use tower::{Layer, Service};

/// Tower [`Layer`] that wraps a service with an [`HttpRestrictionGuard`] middleware.
///
/// Produces an [`HttpRestrictionService`] that evaluates every incoming request.
#[derive(Clone)]
pub struct HttpRestrictionLayer {
    /// The guard evaluated on each request.
    guard: std::sync::Arc<dyn HttpRestrictionGuard>,
}

impl HttpRestrictionLayer {
    /// Creates a new layer from the given arc-guard.
    #[must_use]
    pub fn new(guard: std::sync::Arc<dyn HttpRestrictionGuard>) -> Self {
        Self { guard }
    }
}

impl<S> Layer<S> for HttpRestrictionLayer {
    type Service = HttpRestrictionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpRestrictionService {
            inner,
            guard: std::sync::Arc::clone(&self.guard),
        }
    }
}

/// Tower [`Service`] that evaluates an [`HttpRestrictionGuard`] before forwarding requests.
///
/// When [`HttpRestrictionGuard::is_active`] returns `false` the request is forwarded
/// immediately without evaluating the full restriction state.
#[derive(Clone)]
pub struct HttpRestrictionService<S> {
    /// The wrapped inner service.
    inner: S,
    /// The guard evaluated on each request.
    guard: std::sync::Arc<dyn HttpRestrictionGuard>,
}

impl<S> Service<axum::extract::Request> for HttpRestrictionService<S>
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

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        let guard = std::sync::Arc::clone(&self.guard);
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // todo alexmohr, why pinned?
            if !guard.is_active() {
                return inner.call(request).await;
            }

            match guard.evaluate(request.uri().path(), request.method()) {
                HttpRestrictionDecision::Pass => inner.call(request).await,
                HttpRestrictionDecision::Deny(denial) => {
                    Ok(http_restriction_denial_to_sovd_response(denial))
                }
            }
        })
    }
}

/// Converts an [`HttpRestrictionDenial`]
/// to an SOVD HTTP error response.
///
/// Maps HTTP status codes to SOVD error codes and adds a `Retry-After` header when
/// a retry hint is present.
fn http_restriction_denial_to_sovd_response(denial: HttpRestrictionDenial) -> Response {
    let body = sovd_interfaces::error::ApiErrorResponse::<String> {
        message: denial.message,
        error_code: ErrorCode::VendorSpecific,
        vendor_code: None,
        parameters: None,
        error_source: None,
        schema: None,
    };
    let mut response = (denial.status, Json(body)).into_response();

    if let Some(retry_after_seconds) = denial.retry_after_seconds
        && let Ok(v) = HeaderValue::from_str(&retry_after_seconds.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, v);
    }
    response
}

/// Installs an [`HttpRestrictionGuard`] as a finalizer layer on the
/// [`DynamicRouter`](crate::dynamic_router::DynamicRouter).
///
/// The guard is applied globally to all routes, including routes added after this call.
/// Path/method filtering is delegated to the guard's [`evaluate`](HttpRestrictionGuard::evaluate)
/// implementation.
pub async fn install_http_restriction_guard(
    dynamic_router: &crate::dynamic_router::DynamicRouter,
    guard: std::sync::Arc<dyn HttpRestrictionGuard>,
) {
    let layer = HttpRestrictionLayer::new(guard);
    dynamic_router
        .add_finalizer(std::sync::Arc::new(
            move |router: axum::Router| -> axum::Router { router.layer(layer.clone()) },
        ))
        .await;
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use axum::{Router, body::Body, routing::get};
    use cda_plugin_communication_management::{
        http_protection::{
            config::{HttpProtectionConfig, HttpProtectionReason},
            evaluator::{HttpRestrictionDecision, HttpRestrictionDenial, HttpRestrictionGuard},
            registry::HttpProtectionRegistry,
        },
        lifecycle::{access::CommunicationAccess, error::CommunicationError},
    };
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    /// A mock guard that always passes.
    struct AlwaysPassGuard {
        active: Arc<AtomicBool>,
    }

    impl AlwaysPassGuard {
        fn new(active: bool) -> Self {
            Self {
                active: Arc::new(AtomicBool::new(active)),
            }
        }
    }

    impl HttpRestrictionGuard for AlwaysPassGuard {
        fn is_active(&self) -> bool {
            self.active.load(Ordering::Acquire)
        }

        fn evaluate(&self, _path: &str, _method: &http::Method) -> HttpRestrictionDecision {
            HttpRestrictionDecision::Pass
        }
    }

    /// A mock guard that always denies with a configurable status.
    struct AlwaysDenyGuard {
        status: StatusCode,
        retry_after_seconds: Option<u64>,
    }

    impl HttpRestrictionGuard for AlwaysDenyGuard {
        fn is_active(&self) -> bool {
            true
        }

        fn evaluate(&self, _path: &str, _method: &http::Method) -> HttpRestrictionDecision {
            HttpRestrictionDecision::Deny(HttpRestrictionDenial {
                status: self.status,
                message: "denied by test guard".to_owned(),
                retry_after_seconds: self.retry_after_seconds,
            })
        }
    }

    #[tokio::test]
    async fn guard_always_pass_allows_request() {
        let guard = Arc::new(AlwaysPassGuard::new(true)) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_deny_503_returns_service_unavailable() {
        let guard = Arc::new(AlwaysDenyGuard {
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after_seconds: Some(30),
        }) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        assert_eq!(retry, Some(30));
    }

    #[tokio::test]
    async fn guard_deny_409_preserves_configured_retry_after() {
        let guard = Arc::new(AlwaysDenyGuard {
            status: StatusCode::CONFLICT,
            retry_after_seconds: Some(17),
        }) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "17");
    }

    #[tokio::test]
    async fn guard_inactive_passes_through_immediately() {
        let guard = Arc::new(AlwaysPassGuard::new(false)) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protections_preserve_precedence_and_owner_scoped_cleanup() {
        let factory = HttpProtectionRegistry::new();
        let update = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::UpdateInProgress,
                    StatusCode::CONFLICT,
                    "Update in progress",
                )
                .with_retry_after(17),
            )
            .unwrap();
        let communication = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::Custom("communication not ready".to_owned()),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Diagnostic communication is unavailable",
                )
                .with_retry_after(3),
            )
            .unwrap();
        let guard = Arc::new(factory.clone()) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/diagnostic", get(|| async { StatusCode::IM_A_TEAPOT }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "17");

        drop(communication);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        drop(update);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn dropping_communication_protection_does_not_affect_update_protection() {
        let factory = HttpProtectionRegistry::new();

        // First install update protection (should win with 409)
        let update = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::UpdateInProgress,
                    StatusCode::CONFLICT,
                    "Update in progress",
                )
                .with_retry_after(20),
            )
            .unwrap();

        // Then install communication protection (would return 503 if it were first)
        let communication = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::Custom("communication not ready".to_owned()),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Diagnostic communication is unavailable",
                )
                .with_retry_after(5),
            )
            .unwrap();

        let guard = Arc::new(factory.clone()) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/diagnostic", get(|| async { StatusCode::OK }))
            .layer(HttpRestrictionLayer::new(guard));

        // With both protections active, update protection wins (first-installed)
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "update protection should win with 409 when both are active"
        );
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "20");

        // Drop communication protection (simulating resume failure lifting communication protection)
        drop(communication);

        // Update protection should still be active
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "update protection should remain active after communication protection is dropped"
        );
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "20");

        // Drop update protection (update owner completes)
        drop(update);

        // Now requests should pass through to the handler
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "requests should reach handler after both protections are dropped"
        );
    }

    // Mock communication access that returns Disabled error (simulating Error state)
    struct DisabledAccess;
    impl CommunicationAccess for DisabledAccess {
        fn state(
            &self,
        ) -> cda_plugin_communication_management::lifecycle::state::CommunicationState {
            cda_plugin_communication_management::lifecycle::state::CommunicationState::Error(
                cda_plugin_communication_management::lifecycle::operation::CommunicationOperationFailure::TransportFailure {
                    operation: cda_plugin_communication_management::lifecycle::operation::CommunicationOperation::Resume,
                    error: "simulated resume failure".to_owned(),
                }
            )
        }
        fn acquire(
            &self,
        ) -> Result<
            cda_plugin_communication_management::lifecycle::guard::CommunicationGuard,
            CommunicationError,
        > {
            Err(CommunicationError::Disabled)
        }

        fn request_activate(
            &self,
            _cause: cda_plugin_communication_management::lifecycle::operation::ActivationCause,
        ) -> cda_plugin_communication_management::lifecycle::state::CommunicationState {
            self.state()
        }
    }

    #[tokio::test]
    async fn handler_communication_errors_pass_through_after_protections_removed() {
        // Handler that mimics SOVD behavior: checks communication access and returns error
        async fn diagnostic_handler(
            axum::Extension(comm): axum::Extension<Arc<dyn CommunicationAccess>>,
        ) -> Response {
            match comm.acquire() {
                Ok(_guard) => (StatusCode::OK, "diagnostic operation succeeded").into_response(),
                Err(CommunicationError::Disabled) => {
                    let error = sovd_interfaces::error::ApiErrorResponse::<String> {
                        message: "Diagnostic communication is unavailable".to_owned(),
                        error_code: ErrorCode::VendorSpecific,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    };
                    (StatusCode::CONFLICT, Json(error)).into_response()
                }
                Err(e) => {
                    let error = sovd_interfaces::error::ApiErrorResponse::<String> {
                        message: format!("Communication error: {e}"),
                        error_code: ErrorCode::VendorSpecific,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    };
                    (StatusCode::CONFLICT, Json(error)).into_response()
                }
            }
        }

        let factory = HttpProtectionRegistry::new();

        // Create both protections (simulating update in progress + communication not ready)
        let update = factory
            .protect(HttpProtectionConfig::new(
                HttpProtectionReason::UpdateInProgress,
                StatusCode::CONFLICT,
                "Update in progress",
            ))
            .unwrap();

        let communication = factory
            .protect(HttpProtectionConfig::new(
                HttpProtectionReason::Custom("communication not ready".to_owned()),
                StatusCode::SERVICE_UNAVAILABLE,
                "Communication not ready",
            ))
            .unwrap();

        let guard = Arc::new(factory.clone()) as Arc<dyn HttpRestrictionGuard>;

        let comm_access: Arc<dyn CommunicationAccess> = Arc::new(DisabledAccess);

        let app = Router::new()
            .route("/diagnostic", get(diagnostic_handler))
            .layer(axum::Extension(comm_access))
            .layer(HttpRestrictionLayer::new(guard));

        // With both protections active, middleware returns 409 (update protection wins)
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "middleware should return 409 while update protection is active"
        );
        let body_text = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body_text).unwrap();
        assert!(
            body_str.contains("Update in progress"),
            "middleware 409 should have update protection message, got: {body_str}"
        );

        // Drop both protections (simulating resume failure lifting communication protection,
        // then update completing)
        drop(communication);
        drop(update);

        // Now request should reach handler, which returns its own 409 for communication unavailable
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/diagnostic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "handler should return 409 for communication unavailable after protections removed"
        );
        let body_text = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = std::str::from_utf8(&body_text).unwrap();
        assert!(
            body_str.contains("Diagnostic communication is unavailable"),
            "handler 409 should have communication error message, got: {body_str}"
        );
    }
}
