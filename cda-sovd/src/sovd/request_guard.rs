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
//! [`HttpRestrictionGuard::is_active`] provides a cheap check. When it returns
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
    response::{IntoResponse, Response},
};
use cda_interfaces::http_protection::registry::{
    HttpProtectionReason, HttpRestrictionDenial, HttpRestrictionGuard,
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

        // Box::pin is required: async blocks produce unnameable types, and Tower's
        // Service::Future associated type must be concrete.
        Box::pin(async move {
            if !guard.is_active() {
                return inner.call(request).await;
            }

            match guard.evaluate(request.uri().path(), request.method()) {
                Ok(()) => inner.call(request).await,
                Err(denial) => Ok(http_restriction_denial_to_sovd_response(denial)),
            }
        })
    }
}

/// Converts an [`HttpRestrictionDenial`]
/// to an SOVD HTTP error response.
///
/// Maps the denial's [`HttpProtectionReason`] to an appropriate SOVD `error_code` and
/// `vendor_code`, and adds a `Retry-After` header when a retry hint is present.
///
/// - [`HttpProtectionReason::UpdateInProgress`] uses the standard SOVD
///   [`ErrorCode::UpdateProcessInProgress`] code with no vendor code.
/// - [`HttpProtectionReason::CommunicationNotReady`] and
///   [`HttpProtectionReason::Custom`] both use [`ErrorCode::VendorSpecific`]
///   with [`VendorErrorCode::CommunicationNotReady`] as the vendor code: SOVD
///   defines no standard code for either, and a custom protection is opaque to
///   this layer, so both surface as the same vendor-specific not-ready signal.
///   The human-readable distinction rides in `denial.message`.
fn http_restriction_denial_to_sovd_response(denial: HttpRestrictionDenial) -> Response {
    use crate::sovd::error::VendorErrorCode;

    let (error_code, vendor_code) = match &denial.reason {
        HttpProtectionReason::UpdateInProgress => (ErrorCode::UpdateProcessInProgress, None),
        HttpProtectionReason::CommunicationNotReady | HttpProtectionReason::Custom(_) => (
            ErrorCode::VendorSpecific,
            Some(VendorErrorCode::CommunicationNotReady),
        ),
    };

    let body = sovd_interfaces::error::ApiErrorResponse {
        message: denial.message,
        error_code,
        vendor_code,
        parameters: None,
        error_source: None,
        schema: None,
    };
    let response = (denial.status, Json(body)).into_response();

    crate::sovd::with_retry_after(response, denial.retry_after)
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
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use axum::{Router, body::Body, http::header::RETRY_AFTER, routing::get};
    use cda_interfaces::http_protection::registry::{
        HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry, HttpRestrictionDenial,
        HttpRestrictionGuard,
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

        fn evaluate(
            &self,
            _path: &str,
            _method: &http::Method,
        ) -> Result<(), HttpRestrictionDenial> {
            Ok(())
        }
    }

    /// A guard that proves the inactive fast path skips evaluation.
    struct InactiveGuard;

    impl HttpRestrictionGuard for InactiveGuard {
        fn is_active(&self) -> bool {
            false
        }

        fn evaluate(
            &self,
            _path: &str,
            _method: &http::Method,
        ) -> Result<(), HttpRestrictionDenial> {
            panic!("inactive guards must not be evaluated");
        }
    }

    /// A mock guard that always denies with a configurable status.
    struct AlwaysDenyGuard {
        reason: HttpProtectionReason,
        status: StatusCode,
        retry_after: Option<Duration>,
    }

    impl HttpRestrictionGuard for AlwaysDenyGuard {
        fn is_active(&self) -> bool {
            true
        }

        fn evaluate(
            &self,
            _path: &str,
            _method: &http::Method,
        ) -> Result<(), HttpRestrictionDenial> {
            Err(HttpRestrictionDenial {
                reason: self.reason.clone(),
                status: self.status,
                message: "denied by test guard".to_owned(),
                retry_after: self.retry_after,
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
            reason: HttpProtectionReason::Custom("test".to_owned()),
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: Some(Duration::from_secs(30)),
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
            reason: HttpProtectionReason::UpdateInProgress,
            status: StatusCode::CONFLICT,
            retry_after: Some(Duration::from_secs(17)),
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
    async fn guard_deny_409_without_retry_hint_preserves_status_without_header() {
        let guard = Arc::new(AlwaysDenyGuard {
            reason: HttpProtectionReason::UpdateInProgress,
            status: StatusCode::CONFLICT,
            retry_after: None,
        }) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(HttpRestrictionLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn guard_inactive_passes_through_immediately() {
        let guard = Arc::new(InactiveGuard) as Arc<dyn HttpRestrictionGuard>;
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

        // Install update protection first so it has precedence.
        let update = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::UpdateInProgress,
                    StatusCode::CONFLICT,
                    "Update in progress",
                )
                .with_retry_after(Duration::from_secs(17)),
            )
            .unwrap();

        // Add a lower-priority communication protection.
        let communication = factory
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::Custom("communication not ready".to_owned()),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Diagnostic communication is unavailable",
                )
                .with_retry_after(Duration::from_secs(3)),
            )
            .unwrap();

        let guard = Arc::new(factory.clone()) as Arc<dyn HttpRestrictionGuard>;
        let app = Router::new()
            .route("/diagnostic", get(|| async { StatusCode::IM_A_TEAPOT }))
            .layer(HttpRestrictionLayer::new(guard));

        // The first protection determines the response.
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

        // Removing the lower-priority owner leaves update protection active.
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

        // Removing the final owner restores the handler response.
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
                .with_retry_after(Duration::from_secs(20)),
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
                .with_retry_after(Duration::from_secs(5)),
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
}
