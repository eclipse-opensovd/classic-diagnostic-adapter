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

//! Generic Tower middleware that gates requests behind an arbitrary
//! [`RequestGuard`] trait.
//!
//! This provides a reusable pattern for composable request gating: any type
//! implementing [`RequestGuard`] can be installed as a Tower layer that
//! evaluates incoming requests and either passes them through or denies them
//! with a structured SOVD error response.
//!
//! # Fast-path optimization
//!
//! Implementors expose [`RequestGuard::is_active`] as a cheap atomic check.
//! When it returns `false`, the middleware passes requests through immediately
//! without allocating the async evaluation future.
//!
//! # Usage
//!
//! Install via [`install_guard`] on a [`DynamicRouter`](crate::dynamic_router::DynamicRouter),
//! or manually construct a [`GuardLayer`] and apply it to any Tower service.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
// Re-export unified guard types from cda-interfaces
pub use cda_interfaces::guard::{HttpMethod, RequestGuard};
use http::Method;
use tower::{Layer, Service};

/// Converts an `http::Method` to `cda_interfaces::HttpMethod`.
fn method_to_http_method(method: &Method) -> HttpMethod {
    match *method {
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        Method::DELETE => HttpMethod::Delete,
        Method::PATCH => HttpMethod::Patch,
        Method::HEAD => HttpMethod::Head,
        Method::OPTIONS => HttpMethod::Options,
        _ => HttpMethod::Get, // GET and non-standard methods
    }
}

/// Tower [`Layer`] that wraps services with a [`RequestGuard`] middleware.
#[derive(Clone)]
pub struct GuardLayer<G: cda_interfaces::guard::RequestGuard> {
    guard: G,
}

impl<G: cda_interfaces::guard::RequestGuard> GuardLayer<G> {
    /// Creates a new layer from the given guard.
    #[must_use]
    pub fn new(guard: G) -> Self {
        Self { guard }
    }
}

impl<G: cda_interfaces::guard::RequestGuard, S> Layer<S> for GuardLayer<G> {
    type Service = GuardService<G, S>;

    fn layer(&self, inner: S) -> Self::Service {
        GuardService {
            inner,
            guard: self.guard.clone(),
        }
    }
}

/// Tower [`Service`] that evaluates a [`RequestGuard`] before forwarding
/// requests to the inner service.
#[derive(Clone)]
pub struct GuardService<G: cda_interfaces::guard::RequestGuard, S> {
    inner: S,
    guard: G,
}

impl<G, S> Service<axum::extract::Request> for GuardService<G, S>
where
    G: cda_interfaces::guard::RequestGuard,
    S: Service<axum::extract::Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    // Heap-allocate the future because async blocks are opaque, unsized types
    // that cannot satisfy the concrete `Pin<Box<dyn Future>>` return type directly.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        let guard = self.guard.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Fast path: guard not active - pass through immediately.
            if !guard.is_active() {
                return inner.call(req).await;
            }

            let path = req.uri().path().to_owned();
            let http_method = method_to_http_method(req.method());

            match guard.evaluate(&path, http_method).await {
                cda_interfaces::guard::GuardDecision::Pass => inner.call(req).await,
                cda_interfaces::guard::GuardDecision::Deny(denial) => {
                    Ok(guard_denial_to_response(denial))
                }
            }
        })
    }
}

/// Converts a u16 error code to the corresponding `ErrorCode` variant.
fn error_code_from_u16(code: u16) -> sovd_interfaces::error::ErrorCode {
    match code {
        4096 => sovd_interfaces::error::ErrorCode::UpdateProcessInProgress,
        4280 => sovd_interfaces::error::ErrorCode::PreconditionsNotFulfilled,
        _ => sovd_interfaces::error::ErrorCode::SovdServerFailure,
    }
}

/// Converts a `cda_interfaces::guard::GuardDenial` to an HTTP response.
fn guard_denial_to_response(denial: cda_interfaces::guard::GuardDenial) -> Response {
    let status = StatusCode::from_u16(denial.status.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = sovd_interfaces::error::ApiErrorResponse::<String> {
        message: denial.message,
        error_code: error_code_from_u16(denial.error_code),
        vendor_code: None,
        parameters: None,
        error_source: None,
        schema: None,
    };
    let mut response = (status, Json(body)).into_response();
    if let Some(seconds) = denial.retry_after_seconds
        && let Ok(v) = HeaderValue::from_str(&seconds.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, v);
    }
    response
}

/// Installs a [`RequestGuard`] as a finalizer layer on the
/// [`DynamicRouter`](crate::dynamic_router::DynamicRouter).
///
/// The guard is applied globally to all routes; path/method filtering is
/// delegated to the guard's [`evaluate`](RequestGuard::evaluate) implementation.
/// Routes added after this call (e.g. by OEM plugins) are automatically covered.
pub async fn install_guard<G: cda_interfaces::guard::RequestGuard>(
    dynamic_router: &crate::dynamic_router::DynamicRouter,
    guard: G,
) {
    let layer = GuardLayer::new(guard);
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
    use http::Request;
    use tower::ServiceExt;

    use super::*;

    /// A mock guard that always passes.
    #[derive(Clone)]
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

    impl cda_interfaces::guard::RequestGuard for AlwaysPassGuard {
        fn is_active(&self) -> bool {
            self.active.load(Ordering::Acquire)
        }

        fn evaluate<'a>(
            &'a self,
            _path: &'a str,
            _method: cda_interfaces::guard::HttpMethod,
        ) -> Pin<Box<dyn Future<Output = cda_interfaces::guard::GuardDecision> + Send + 'a>>
        {
            Box::pin(async { cda_interfaces::guard::GuardDecision::Pass })
        }
    }

    /// A mock guard that always denies with a configurable status.
    #[derive(Clone)]
    struct AlwaysDenyGuard {
        status: StatusCode,
        retry_after: Option<u64>,
        /// Which error code variant to use. We store a discriminant
        /// because `ErrorCode` is not `Clone`.
        use_update_in_progress: bool,
    }

    impl cda_interfaces::guard::RequestGuard for AlwaysDenyGuard {
        fn is_active(&self) -> bool {
            true
        }

        fn evaluate<'a>(
            &'a self,
            _path: &'a str,
            _method: cda_interfaces::guard::HttpMethod,
        ) -> Pin<Box<dyn Future<Output = cda_interfaces::guard::GuardDecision> + Send + 'a>>
        {
            Box::pin(async move {
                let error_code = if self.use_update_in_progress {
                    sovd_interfaces::error::ErrorCode::UpdateProcessInProgress
                } else {
                    sovd_interfaces::error::ErrorCode::PreconditionsNotFulfilled
                };
                let denial = cda_interfaces::guard::GuardDenial {
                    status: cda_interfaces::guard::StatusCode(self.status.as_u16()),
                    message: "denied by test guard".to_owned(),
                    error_code: error_code as u16,
                    retry_after_seconds: self.retry_after,
                };
                cda_interfaces::guard::GuardDecision::Deny(denial)
            })
        }
    }

    #[tokio::test]
    async fn guard_always_pass_allows_request() {
        let guard = AlwaysPassGuard::new(true);
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(GuardLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_deny_503_returns_service_unavailable() {
        let guard = AlwaysDenyGuard {
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: Some(30),
            use_update_in_progress: false,
        };
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(GuardLayer::new(guard));

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
    async fn guard_deny_409_returns_conflict() {
        let guard = AlwaysDenyGuard {
            status: StatusCode::CONFLICT,
            retry_after: None,
            use_update_in_progress: true,
        };
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(GuardLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn guard_inactive_passes_through_immediately() {
        let guard = AlwaysPassGuard::new(false);
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(GuardLayer::new(guard));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
