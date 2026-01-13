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

use aide::axum::ApiRouter;
use axum::middleware;
use tokio::sync::RwLock;

use crate::{create_trace_layer, sovd};

#[derive(Clone)]
pub struct DynamicRouter {
    router: Arc<RwLock<ApiRouter>>,
}

impl DynamicRouter {
    #[must_use]
    pub fn new() -> Self {
        aide::generate::extract_schemas(true);
        aide::generate::on_error(|e| {
            if let aide::Error::DuplicateRequestBody = e {
                // skip DuplicateRequestBody
                // those are triggered when overwriting the input type
                return;
            }
            tracing::error!(error = %e, "OpenAPI generation error");
        });

        let router = create_trace_layer(ApiRouter::new())
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(30),
            ))
            .layer(middleware::from_fn(
                sovd::error::sovd_method_not_allowed_handler,
            ))
            .fallback(sovd::error::sovd_not_found_handler);

        Self {
            router: Arc::new(RwLock::new(router)),
        }
    }

    /// Retrieves a clone of the current router.
    pub async fn get_router(&self) -> ApiRouter {
        let router = self.router.read().await;
        router.clone()
    }

    /// Updates the dynamic router using the provided update function.
    /// This is used to modify the router at runtime to add new routes or overwrite existing ones.
    pub async fn update_router<F>(&self, update_fn: F)
    where
        F: FnOnce(ApiRouter) -> ApiRouter + Send + 'static,
    {
        let mut router = self.router.write().await;
        *router = update_fn(router.clone());
    }

    pub async fn merge_routes(&self, new_routes: ApiRouter) {
        self.update_router(|router| router.merge(new_routes)).await;
    }
}

impl Default for DynamicRouter {
    fn default() -> Self {
        Self::new()
    }
}
