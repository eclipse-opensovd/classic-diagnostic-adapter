/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
type RouteGroups = Arc<RwLock<IndexMap<u64, RouteGroup>>>;

/// A registered group: its router, plus the `OpenAPI` document generated from it.
///
/// The document is generated once, when the group is registered, and reused by every
/// later recomposition. It cannot be regenerated on demand -- see [`RouteGroup::new`].
struct RouteGroup {
    router: ApiRouter,
    api: OpenApi,
}

impl RouteGroup {
    /// Generates the group's document **once**, at registration.
    ///
    /// `finish_api` is not a pure function of `router`. aide accumulates schemas in a
    /// thread-local generator as routers are built, and finishing a document drains that
    /// generator into it (`aide::generate::extract_schemas`, enabled in
    /// [`DynamicRouter::new`]). So the first `finish_api` on a thread collects every schema
    /// registered so far and every later one yields empty `components`.
    ///
    /// Finishing each group exactly once, immediately after it is handed over, keeps that
    /// drain aligned with the group that caused it: each schema lands in exactly one group's
    /// document, and the union assembled by [`DynamicRouter::recompose`] holds all of them.
    /// Re-finishing on every recomposition instead would return empty `components` from the
    /// second recomposition onwards, leaving every `$ref` in the served document dangling.
    fn new(router: ApiRouter) -> Self {
        let mut api = OpenApi::default();
        let _router = router.clone().finish_api(&mut api);
        Self { router, api }
    }
}

/// An opaque handle to a route group registered with a [`DynamicRouter`].
///
/// Returned by [`DynamicRouter::add_routes`] and retained when an OEM route
/// group may later be replaced or removed.
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
/// Handles are returned on registration and must be stored by callers that
/// replace or remove OEM route groups later.
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
    pub async fn get_openapi(&self) -> OpenApi {
        self.openapi.read().await.clone()
    }

    /// Registers a route group and recomposes the router.
    ///
    /// Returns a [`RouteHandle`] that can be used to later
    /// [`replace`](Self::replace_routes) or [`remove`](Self::remove_routes) this group.
    ///
    /// Later-added groups take precedence: if this group registers a path that an earlier
    /// group already serves, this group's handler wins (path-level override).
    ///
    /// Retain the returned handle when the OEM route group may change later.
    pub async fn add_routes(&self, routes: ApiRouter) -> RouteHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut groups = self.route_groups.write().await;
            groups.insert(id, RouteGroup::new(routes));
        }
        self.recompose().await;
        RouteHandle { id }
    }

    /// Replaces the route group identified by `handle` with new routes and recomposes the router.
    ///
    /// The caller retains the [`RouteHandle`] from the initial
    /// [`add_routes`](Self::add_routes) call and passes it here to atomically
    /// replace an OEM route group.
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
                    let _ = entry.insert(RouteGroup::new(routes));
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
                let group_router: axum::Router = group.router.clone().into();
                group_router.fallback_service(acc)
            },
        );

        let composed = Self::apply_base_layers(composed);

        let composed = finalizers.iter().fold(composed, |acc, f| f(acc));

        // Build the OpenAPI spec from the documents captured at registration (see
        // `RouteGroup::new`; they cannot be regenerated here). Iterating latest-first gives
        // paths the same precedence the fallback chain has, while components and other
        // document-level data are unioned across every group.
        let api = groups
            .iter()
            .rev()
            .fold(OpenApi::default(), |mut api, (_id, group)| {
                crate::openapi::merge_openapi_prefer_existing(&mut api, group.api.clone());
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
    use axum::{Json, http::StatusCode, response::IntoResponse};
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

    /// A group serving `body` at `path`, undocumented: enough for the fallback chain.
    fn text_group(path: &str, body: &'static str) -> ApiRouter {
        ApiRouter::new().route(
            path,
            routing::get(move || async move { body.into_response() }),
        )
    }

    /// A group whose single operation carries `description`, which is what the
    /// document-level assertions match on.
    fn described_group(path: &str, description: &'static str) -> ApiRouter {
        ApiRouter::new().api_route(
            path,
            routing::get_with(
                move || async move { description.into_response() },
                move |op| op.description(description),
            ),
        )
    }

    /// A group whose single operation responds with `T`, so registering it makes aide
    /// generate a schema for `T` and a `$ref` to it.
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "The method item is not sufficiently lifetime-generic for get_with"
    )]
    fn schema_group<T>(path: &str) -> ApiRouter
    where
        T: schemars::JsonSchema + serde::Serialize + Default + Send + 'static,
    {
        ApiRouter::new().api_route(
            path,
            routing::get_with(
                || async { Json(T::default()) },
                |op| op.response::<200, Json<T>>(),
            ),
        )
    }

    fn get_path_description(api: &OpenApi, path: &str) -> Option<String> {
        let paths = api.paths.as_ref()?;
        match paths.paths.get(path)? {
            ReferenceOr::Item(item) => item.get.as_ref()?.description.clone(),
            ReferenceOr::Reference { .. } => None,
        }
    }

    fn local_references(value: &serde_json::Value, references: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str)
                    && reference.starts_with('#')
                {
                    references.push(reference.to_owned());
                }
                for child in object.values() {
                    local_references(child, references);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    local_references(child, references);
                }
            }
            _ => {}
        }
    }

    /// `serde_json`'s `pointer` treats a fragment as a raw JSON Pointer, but `$ref` values are
    /// URI fragments: schemars percent-encodes every byte that is unsafe there, `~` and `/`
    /// included. Split on `/` first (the producer never leaves a raw one inside a name), then
    /// undo both encodings per segment.
    fn resolve_local_reference<'a>(
        document: &'a serde_json::Value,
        reference: &str,
    ) -> Option<&'a serde_json::Value> {
        let mut current = document;
        for segment in reference.trim_start_matches('#').split('/').skip(1) {
            let name = percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .ok()?
                .replace("~1", "/")
                .replace("~0", "~");
            current = match current {
                serde_json::Value::Object(object) => object.get(&name)?,
                serde_json::Value::Array(array) => array.get(name.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(current)
    }

    fn assert_every_local_reference_resolves(document: &serde_json::Value) {
        let mut references = Vec::new();
        local_references(document, &mut references);
        assert!(!references.is_empty(), "no local references were emitted");
        for reference in &references {
            assert!(
                resolve_local_reference(document, reference).is_some(),
                "unresolved local OpenAPI reference: {reference}"
            );
        }
    }

    fn schemas_of(document: &serde_json::Value) -> &serde_json::Map<String, serde_json::Value> {
        document
            .pointer("/components/schemas")
            .and_then(serde_json::Value::as_object)
            .expect("merged document has components.schemas")
    }

    #[tokio::test]
    async fn later_group_overrides_earlier_on_same_path() {
        let dr = DynamicRouter::new();

        dr.add_routes(text_group("/foo", "group_a")).await;
        dr.add_routes(text_group("/foo", "group_b")).await;

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_to_string(resp.into_body()).await, "group_b");
    }

    #[tokio::test]
    async fn non_overridden_path_remains_reachable() {
        let dr = DynamicRouter::new();

        dr.add_routes(text_group("/foo", "a_foo").merge(text_group("/bar", "a_bar")))
            .await;
        dr.add_routes(text_group("/foo", "b_foo")).await;

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

        dr.add_routes(text_group("/foo", "group_a")).await;
        let handle_b = dr.add_routes(text_group("/foo", "group_b")).await;

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

        let handle_a = dr.add_routes(text_group("/foo", "a_v1")).await;
        dr.add_routes(text_group("/foo", "b_v1")).await;

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "b_v1");

        dr.replace_routes(&handle_a, text_group("/foo", "a_v2"))
            .await
            .unwrap();

        let router = dr.get_router().await;
        let resp = router.oneshot(request("GET", "/foo")).await.unwrap();
        assert_eq!(body_to_string(resp.into_body()).await, "b_v1");
    }

    #[tokio::test]
    async fn openapi_reflects_override_latest_wins() {
        let dr = DynamicRouter::new();

        dr.add_routes(described_group("/foo", "from group a")).await;
        dr.add_routes(described_group("/foo", "from group b")).await;

        let api = dr.get_openapi().await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from group b")
        );
    }

    #[tokio::test]
    async fn openapi_preserves_non_overridden_paths() {
        let dr = DynamicRouter::new();

        dr.add_routes(described_group("/foo", "a foo").merge(described_group("/bar", "a bar")))
            .await;
        dr.add_routes(described_group("/foo", "b foo")).await;

        let api = dr.get_openapi().await;
        assert_eq!(get_path_description(&api, "/foo").as_deref(), Some("b foo"));
        assert_eq!(get_path_description(&api, "/bar").as_deref(), Some("a bar"));
    }

    #[tokio::test]
    async fn openapi_updates_after_remove() {
        let dr = DynamicRouter::new();

        dr.add_routes(described_group("/foo", "from a")).await;
        let handle_b = dr.add_routes(described_group("/foo", "from b")).await;

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

    #[tokio::test]
    async fn openapi_composition_preserves_all_local_reference_targets() {
        #[derive(Default, serde::Serialize, schemars::JsonSchema)]
        struct Foo {
            value: String,
        }

        let dr = DynamicRouter::new();
        dr.add_routes(schema_group::<Foo>("/foo")).await;

        let document = serde_json::to_value(dr.get_openapi().await).unwrap();
        assert_every_local_reference_resolves(&document);
    }

    /// Recomposition must survive being repeated. `RouteGroup::new` finishes each
    /// group's document once at registration because `finish_api` drains aide's
    /// thread-local schema generator; re-finishing on later recompositions would
    /// return empty `components` from the second one onwards and dangle every `$ref`.
    #[tokio::test]
    async fn repeated_recomposition_keeps_every_schema_and_reference() {
        #[derive(Default, serde::Serialize, schemars::JsonSchema)]
        struct First {
            first: String,
        }
        #[derive(Default, serde::Serialize, schemars::JsonSchema)]
        struct Second {
            second: u32,
        }
        #[derive(Default, serde::Serialize, schemars::JsonSchema)]
        struct Third {
            third: bool,
        }

        let dr = DynamicRouter::new();
        dr.add_routes(schema_group::<First>("/first")).await;
        dr.add_routes(schema_group::<Second>("/second")).await;
        // A third registration recomposes again: the earlier groups' documents
        // must be reused, not regenerated.
        dr.add_routes(schema_group::<Third>("/third")).await;

        let after_three = serde_json::to_value(dr.get_openapi().await).unwrap();
        assert_every_local_reference_resolves(&after_three);

        let schemas = schemas_of(&after_three);
        for name in ["First", "Second", "Third"] {
            assert!(
                schemas.contains_key(name),
                "{name} lost after recomposition"
            );
        }

        // `get_openapi` is a pure read of the composed document, so this only
        // guards against it gaining side effects later.
        let again = serde_json::to_value(dr.get_openapi().await).unwrap();
        assert_eq!(after_three, again, "recomposition is not idempotent");
    }
}
