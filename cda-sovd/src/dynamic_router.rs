/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use aide::{axum::ApiRouter, openapi::OpenApi};
use axum::middleware;
use indexmap::IndexMap;
use tokio::sync::RwLock;

use crate::{create_trace_layer, sovd};

type RouteFinalizer = Arc<dyn Fn(axum::Router) -> axum::Router + Send + Sync>;
/// Insertion order determines override precedence in the fallback chain.
type RouteGroups = Arc<RwLock<IndexMap<u64, ApiRouter>>>;

/// An opaque handle to a route group registered with a [`DynamicRouter`].
///
/// Returned by [`DynamicRouter::add_routes`] and must be retained if you need to
/// [`replace`](DynamicRouter::replace_routes) or [`remove`](DynamicRouter::remove_routes)
/// those routes later. This is essential for hot-reload scenarios (e.g., swapping vehicle
/// routes after an MDD database reload) where the old route group must be atomically
/// replaced with a new one.
///
/// Without a handle, registered routes cannot be referenced after insertion.
#[derive(Clone, Debug)]
pub struct RouteHandle {
    id: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("route group {id} not found")]
pub struct RouteGroupNotFound {
    id: u64,
}

/// A thread-safe router that supports adding, removing, and replacing route groups at runtime.
///
/// Routes are organized into groups identified by opaque [`RouteHandle`]s. When any group
/// changes, the router recomposes all groups with base layers and registered finalizers.
///
/// Later-added groups take precedence over earlier groups at the **path level**: if a later
/// group registers any method on a path that an earlier group also serves, the latter groups
/// handler wins for that entire path. This enables override/plugin scenarios where custom
/// logic replaces built-in endpoints without rebuilding the original route group.
///
/// **Limitation**: override granularity is per-path, not per-method. If a later group claims
/// `/foo` (even for a single HTTP method), all of `/foo` becomes unreachable in earlier
/// groups. To partially override, re-register all desired methods on that path in the
/// overriding group.
///
/// Handles are returned on registration and must be stored by the caller if the routes need
/// to be replaced or removed later (e.g., during a runtime database reload).
#[derive(Clone)]
pub struct DynamicRouter {
    route_groups: RouteGroups,
    finalizers: Arc<RwLock<Vec<RouteFinalizer>>>,
    router: Arc<RwLock<axum::Router>>,
    openapi: Arc<RwLock<OpenApi>>,
    next_id: Arc<AtomicU64>,
}

impl DynamicRouter {
    /// Creates a new [`DynamicRouter`] with default base layers and no route groups.
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

        let route_groups = Arc::new(RwLock::new(IndexMap::new()));
        let finalizers: Arc<RwLock<Vec<RouteFinalizer>>> = Arc::new(RwLock::new(Vec::new()));

        let initial_router = Self::apply_base_layers(axum::Router::new());

        Self {
            route_groups,
            finalizers,
            router: Arc::new(RwLock::new(initial_router)),
            openapi: Arc::new(RwLock::new(OpenApi::default())),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns a clone of the current composed router.
    pub async fn get_router(&self) -> axum::Router {
        let router = self.router.read().await;
        router.clone()
    }

    /// Returns a clone of the current `OpenAPI` specification.
    pub async fn get_openapi(&self) -> Arc<OpenApi> {
        Arc::new(self.openapi.read().await.clone())
    }

    /// Registers a route group and recomposes the router.
    ///
    /// Returns a [`RouteHandle`] that can be used to later
    /// [`replace`](Self::replace_routes) or [`remove`](Self::remove_routes) this group.
    ///
    /// Later-added groups take precedence: if this group registers a path that an earlier
    /// group already serves, this group's handler wins (path-level override).
    ///
    /// Retain the returned handle if you will need to hot-swap these routes at runtime
    /// (e.g., replacing vehicle routes after an MDD database reload).
    pub async fn add_routes(&self, routes: ApiRouter) -> RouteHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut groups = self.route_groups.write().await;
            groups.insert(id, routes);
        }
        self.recompose().await;
        RouteHandle { id }
    }

    /// Replaces the route group identified by `handle` with new routes and recomposes the router.
    ///
    /// This is the primary mechanism for hot-reloading routes at runtime: the caller retains
    /// the [`RouteHandle`] from the initial [`add_routes`](Self::add_routes) call and passes it
    /// here to atomically swap the old routes with new ones (e.g., after rebuilding vehicle
    /// routes from freshly loaded MDD databases).
    ///
    /// # Errors
    ///
    /// Returns [`RouteGroupNotFound`] if the handle refers to a group that was already removed.
    pub async fn replace_routes(
        &self,
        handle: &RouteHandle,
        routes: ApiRouter,
    ) -> Result<(), RouteGroupNotFound> {
        {
            let mut groups = self.route_groups.write().await;
            match groups.entry(handle.id) {
                indexmap::map::Entry::Occupied(mut entry) => {
                    let _ = entry.insert(routes);
                }
                indexmap::map::Entry::Vacant(_) => {
                    return Err(RouteGroupNotFound { id: handle.id });
                }
            }
        }
        self.recompose().await;
        Ok(())
    }

    /// Removes the route group identified by `handle` and recomposes the router.
    ///
    /// No-op if the handle refers to a group that does not exist
    pub async fn remove_routes(&self, handle: &RouteHandle) {
        {
            let mut groups = self.route_groups.write().await;
            groups.shift_remove(&handle.id);
        }
        self.recompose().await;
    }

    /// Finalizers persist across recompositions and are applied after the fallback chain is built.
    pub async fn add_finalizer(&self, f: RouteFinalizer) {
        {
            let mut finalizers = self.finalizers.write().await;
            finalizers.push(f);
        }
        self.recompose().await;
    }

    /// Adds routes under an auto-generated name. Useful for one-off route additions
    /// where the caller does not need to replace or remove them later.
    pub async fn merge_routes(&self, new_routes: ApiRouter) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut groups = self.route_groups.write().await;
            groups.insert(id, new_routes);
        }
        self.recompose().await;
    }

    async fn recompose(&self) {
        let groups = self.route_groups.read().await;
        let finalizers = self.finalizers.read().await;

        // Build request-handling router via fallback chain.
        // Later-added groups (later in insertion order) take precedence: each group's
        // router becomes the primary handler, falling back to the previously composed
        // chain for paths it doesn't cover.
        // The not-found handler sits at the base so it only fires when no group matches.
        let composed = groups.iter().fold(
            axum::Router::new().fallback(sovd::error::sovd_not_found_handler),
            |acc, (_id, group)| {
                let group_router: axum::Router = group.clone().into();
                group_router.fallback_service(acc)
            },
        );

        let composed = Self::apply_base_layers(composed);

        let composed = finalizers.iter().fold(composed, |acc, f| f(acc));

        // Build OpenAPI spec from groups (latest-added wins per path).
        // aide's PathItem::merge_with favors self, so by iterating latest-first and
        // only inserting paths not yet claimed, later groups' docs override earlier ones.
        let api = groups
            .iter()
            .rev()
            .fold(OpenApi::default(), |mut api, (_id, group)| {
                let mut group_api = OpenApi::default();
                let _router = group.clone().finish_api(&mut group_api);
                if let Some(paths) = group_api.paths {
                    let api_paths = api.paths.get_or_insert_with(Default::default);
                    paths.paths.into_iter().for_each(|(path, item)| {
                        api_paths.paths.entry(path).or_insert(item);
                    });
                }
                api
            });

        let mut router = self.router.write().await;
        *router = composed;
        let mut openapi = self.openapi.write().await;
        *openapi = api;
    }

    fn apply_base_layers(router: axum::Router) -> axum::Router {
        create_trace_layer(router)
            .layer(tower_http::timeout::TimeoutLayer::with_status_code(
                http::StatusCode::REQUEST_TIMEOUT,
                std::time::Duration::from_secs(30),
            ))
            .layer(middleware::from_fn(
                sovd::error::sovd_method_not_allowed_handler,
            ))
    }
}

impl Default for DynamicRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use aide::{axum::routing, openapi::ReferenceOr};
    use axum::{http::StatusCode, response::IntoResponse};
    use tower::ServiceExt;

    use super::*;

    async fn body_to_string(body: axum::body::Body) -> String {
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn request(method: &str, path: &str) -> http::Request<axum::body::Body> {
        http::Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn get_path_description(api: &OpenApi, path: &str) -> Option<String> {
        let paths = api.paths.as_ref()?;
        match paths.paths.get(path)? {
            ReferenceOr::Item(item) => item.get.as_ref()?.description.clone(),
            ReferenceOr::Reference { .. } => None,
        }
    }

    #[tokio::test]
    async fn later_group_overrides_earlier_on_same_path() {
        let dr = DynamicRouter::new();

        let group_a =
            ApiRouter::new().route("/foo", routing::get(|| async { "group_a".into_response() }));
        let group_b =
            ApiRouter::new().route("/foo", routing::get(|| async { "group_b".into_response() }));

        dr.add_routes(group_a).await;
        dr.add_routes(group_b).await;

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_to_string(resp.into_body()).await, "group_b");
    }

    #[tokio::test]
    async fn non_overridden_path_remains_reachable() {
        let dr = DynamicRouter::new();

        let group_a = ApiRouter::new()
            .route("/foo", routing::get(|| async { "a_foo".into_response() }))
            .route("/bar", routing::get(|| async { "a_bar".into_response() }));
        let group_b =
            ApiRouter::new().route("/foo", routing::get(|| async { "b_foo".into_response() }));

        dr.add_routes(group_a).await;
        dr.add_routes(group_b).await;

        let router = dr.get_router().await;

        let resp = router
            .clone()
            .oneshot(request("GET", "/foo"))
            .await
            .unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "b_foo");

        let resp = router.oneshot(request("GET", "/bar")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_to_string(resp.into_body()).await, "a_bar");
    }

    #[tokio::test]
    async fn remove_overriding_group_restores_original() {
        let dr = DynamicRouter::new();

        let group_a =
            ApiRouter::new().route("/foo", routing::get(|| async { "group_a".into_response() }));
        let group_b =
            ApiRouter::new().route("/foo", routing::get(|| async { "group_b".into_response() }));

        dr.add_routes(group_a).await;
        let handle_b = dr.add_routes(group_b).await;

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "group_b");

        dr.remove_routes(&handle_b).await;
        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "group_a");
    }

    #[tokio::test]
    async fn replace_preserves_insertion_order() {
        let dr = DynamicRouter::new();

        let group_a =
            ApiRouter::new().route("/foo", routing::get(|| async { "a_v1".into_response() }));
        let group_b =
            ApiRouter::new().route("/foo", routing::get(|| async { "b_v1".into_response() }));

        let handle_a = dr.add_routes(group_a).await;
        dr.add_routes(group_b).await;

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "b_v1");

        let group_a_v2 =
            ApiRouter::new().route("/foo", routing::get(|| async { "a_v2".into_response() }));
        dr.replace_routes(&handle_a, group_a_v2).await.unwrap();

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "b_v1");
    }

    #[tokio::test]
    async fn openapi_reflects_override_latest_wins() {
        let dr = DynamicRouter::new();

        let group_a = ApiRouter::new().api_route(
            "/foo",
            routing::get_with(
                || async { "a".into_response() },
                |op| op.description("from group a"),
            ),
        );
        let group_b = ApiRouter::new().api_route(
            "/foo",
            routing::get_with(
                || async { "b".into_response() },
                |op| op.description("from group b"),
            ),
        );

        dr.add_routes(group_a).await;
        dr.add_routes(group_b).await;

        let api = dr.get_openapi().await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from group b")
        );
    }

    #[tokio::test]
    async fn openapi_preserves_non_overridden_paths() {
        let dr = DynamicRouter::new();

        let group_a = ApiRouter::new()
            .api_route(
                "/foo",
                routing::get_with(
                    || async { "a_foo".into_response() },
                    |op| op.description("a foo"),
                ),
            )
            .api_route(
                "/bar",
                routing::get_with(
                    || async { "a_bar".into_response() },
                    |op| op.description("a bar"),
                ),
            );
        let group_b = ApiRouter::new().api_route(
            "/foo",
            routing::get_with(
                || async { "b_foo".into_response() },
                |op| op.description("b foo"),
            ),
        );

        dr.add_routes(group_a).await;
        dr.add_routes(group_b).await;

        let api = dr.get_openapi().await;
        assert_eq!(get_path_description(&api, "/foo").as_deref(), Some("b foo"));
        assert_eq!(get_path_description(&api, "/bar").as_deref(), Some("a bar"));
    }

    #[tokio::test]
    async fn openapi_updates_after_remove() {
        let dr = DynamicRouter::new();

        let group_a = ApiRouter::new().api_route(
            "/foo",
            routing::get_with(
                || async { "a".into_response() },
                |op| op.description("from a"),
            ),
        );
        let group_b = ApiRouter::new().api_route(
            "/foo",
            routing::get_with(
                || async { "b".into_response() },
                |op| op.description("from b"),
            ),
        );

        dr.add_routes(group_a).await;
        let handle_b = dr.add_routes(group_b).await;

        let api = dr.get_openapi().await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from b")
        );

        dr.remove_routes(&handle_b).await;
        let api = dr.get_openapi().await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from a")
        );
    }
}
