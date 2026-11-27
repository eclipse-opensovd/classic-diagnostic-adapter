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

use aide::{
    axum::ApiRouter,
    openapi::{OpenApi, Paths},
    transform::TransformOpenApi,
};
use axum::middleware;
use indexmap::IndexMap;
use tokio::sync::RwLock;

use crate::{create_trace_layer, sovd};

mod openapi_document;

type RouteFinalizer = Arc<dyn Fn(axum::Router) -> axum::Router + Send + Sync>;

/// The resources served under a collection, so the collection can list them.
///
/// Maps the collection path (e.g. `/vehicle/v15/data`) to the id of each resource in it
/// and one value per resource, in registration order.
#[derive(Clone)]
struct Catalog<V>(Arc<RwLock<IndexMap<String, IndexMap<String, V>>>>);

impl<V> Default for Catalog<V> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<V: Clone> Catalog<V> {
    async fn register(&self, path: &str, value: V) {
        let Some((collection, id)) = path.trim_end_matches('/').rsplit_once('/') else {
            tracing::warn!(path, "Resource path has no collection, not listed");
            return;
        };
        self.0
            .write()
            .await
            .entry(collection.to_owned())
            .or_default()
            .insert(id.to_owned(), value);
    }

    async fn list(&self, collection: &str) -> Vec<(String, V)> {
        self.0
            .read()
            .await
            .get(collection)
            .map(|resources| {
                resources
                    .iter()
                    .map(|(id, value)| (id.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The resources served under each `/data` collection, with their data category.
/// Handlers read it as a request extension.
#[derive(Clone, Default)]
pub(crate) struct DataResources(Catalog<String>);

impl DataResources {
    /// Returns `(id, category)` of each resource registered in `collection`.
    pub(crate) async fn list(&self, collection: &str) -> Vec<(String, String)> {
        self.0.list(collection).await
    }
}

/// The operations served under each `operations` collection, with whether their execution
/// is asynchronous. Handlers read it as a request extension.
#[derive(Clone, Default)]
pub(crate) struct OperationResources(Catalog<bool>);

impl OperationResources {
    /// Returns `(id, asynchronous)` of each operation registered in `collection`.
    pub(crate) async fn list(&self, collection: &str) -> Vec<(String, bool)> {
        self.0.list(collection).await
    }
}

/// The categories served under each `bulk-data` collection. Handlers read it as a
/// request extension.
#[derive(Clone, Default)]
pub(crate) struct BulkDataCategories(Catalog<()>);

impl BulkDataCategories {
    /// Returns the id of each category registered in `collection`.
    pub(crate) async fn list(&self, collection: &str) -> Vec<String> {
        self.0
            .list(collection)
            .await
            .into_iter()
            .map(|(id, ())| id)
            .collect()
    }
}

/// Insertion order determines override precedence in the fallback chain.
type RouteGroups = Arc<RwLock<IndexMap<u64, ApiRoutes>>>;

/// A route group to register with a [`DynamicRouter`]: its request-handling router and its
/// finished `OpenAPI` documentation.
///
/// The documentation is split off and finished on creation, so recompositions only clone
/// the cheap axum router instead of the whole [`ApiRouter`] including its documentation.
/// It is kept as serialized JSON, which is several times smaller than in memory and only
/// needed when `openapi.json` is requested.
pub struct ApiRoutes {
    router: axum::Router,
    /// Serialized [`Paths`]: those of the router itself, then those of nested routers
    /// finished with [`FinishedDocs::nest`].
    paths_json: Vec<Box<[u8]>>,
    /// Serialized schemas (`#/components/schemas`) referenced by the paths.
    schemas_json: Option<Box<[u8]>>,
}

impl ApiRoutes {
    /// Finishes the documentation of `router` and of the routers nested into it through
    /// `nested`.
    ///
    /// aide collects the schema definitions in a thread-local context, so this has to run
    /// on the thread that built the routes, without an `.await` in between that could move
    /// the task to another thread.
    pub(crate) fn finish(router: ApiRouter, nested: FinishedDocs) -> Self {
        let mut api = OpenApi::default();
        let router = router.finish_api(&mut api);
        // `finish_api` resets the generation context, including its configuration.
        configure_openapi_generation();
        let schemas_json = api
            .components
            .filter(|components| !components.schemas.is_empty())
            .and_then(|components| serialize_json(&components.schemas, "schemas"));
        let paths_json = api
            .paths
            .and_then(|paths| serialize_json(&paths, "paths"))
            .into_iter()
            .chain(nested.0)
            .collect();
        Self {
            router,
            paths_json,
            schemas_json,
        }
    }
}

impl From<ApiRouter> for ApiRoutes {
    fn from(router: ApiRouter) -> Self {
        Self::finish(router, FinishedDocs::default())
    }
}

/// Documentation of nested routers, finished and serialized one router at a time.
///
/// [`ApiRouter::nest_api_service`] keeps the in-memory documentation of every nested router
/// until the whole router is finished. With many nested routers (e.g. the routes of each
/// ECU) that is a large, short-lived peak. Nesting through [`FinishedDocs::nest`] keeps only
/// one nested router's documentation in memory at a time.
#[derive(Default)]
pub(crate) struct FinishedDocs(Vec<Box<[u8]>>);

impl FinishedDocs {
    /// Nests `routes` under `path` like [`ApiRouter::nest_api_service`], but finishes and
    /// serializes their documentation right away.
    pub(crate) fn nest<S: Clone + Send + Sync + 'static>(
        &mut self,
        router: ApiRouter<S>,
        path: &str,
        routes: ApiRouter,
    ) -> ApiRouter<S> {
        let (nested, paths_json) = finish_nested(path, routes);
        self.0.extend(paths_json);
        router.nest_service(path, nested)
    }
}

/// Finishes the documentation of `routes` nested under `path` and serializes its paths.
fn finish_nested(path: &str, routes: ApiRouter) -> (axum::Router, Option<Box<[u8]>>) {
    // `finish_api` takes the schema definitions collected so far and resets aide's
    // thread-local generation context. Move the schema generator out of the way while
    // finishing, so schema names stay unique across all routes and the definitions remain
    // for the final `finish_api` of the whole group, as with `nest_api_service`.
    let schema_generator = aide::generate::in_context(|ctx| std::mem::take(&mut ctx.schema));
    let mut api = OpenApi::default();
    let router = routes.finish_api(&mut api);
    configure_openapi_generation();
    aide::generate::in_context(|ctx| ctx.schema = schema_generator);

    let paths_json = api.paths.and_then(|paths| {
        // Same path joining as `ApiRouter::nest_api_service`.
        let nested = Paths {
            paths: paths
                .paths
                .into_iter()
                .map(|(route, item)| (nested_route_path(path, &route), item))
                .collect(),
            extensions: paths.extensions,
        };
        serialize_json(&nested, "paths")
    });
    (router, paths_json)
}

/// Starts a fresh `OpenAPI` generation context on the current thread, dropping schema
/// definitions left over from routes built earlier on it.
pub(crate) fn reset_openapi_generation() {
    aide::generate::reset_context();
    configure_openapi_generation();
}

/// Configures aide's thread-local `OpenAPI` generation context.
fn configure_openapi_generation() {
    aide::generate::extract_schemas(true);
    aide::generate::on_error(|e| {
        if let aide::Error::DuplicateRequestBody = e {
            // skip DuplicateRequestBody
            // those are triggered when overwriting the input type
            return;
        }
        tracing::error!(error = %e, "OpenAPI generation error");
    });
}

fn nested_route_path(path: &str, route: &str) -> String {
    match (path.ends_with('/'), route) {
        (true, _) => format!("{path}{}", route.trim_start_matches('/')),
        (false, "/") => path.to_owned(),
        (false, _) => format!("{path}{route}"),
    }
}

fn serialize_json<T: serde::Serialize>(value: &T, what: &str) -> Option<Box<[u8]>> {
    serde_json::to_vec(value)
        .inspect_err(
            |e| tracing::error!(error = %e, what, "Failed to serialize OpenAPI documentation"),
        )
        .ok()
        .map(Vec::into_boxed_slice)
}

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
    next_id: Arc<AtomicU64>,
    data_resources: DataResources,
    operation_resources: OperationResources,
    bulk_data_categories: BulkDataCategories,
}

impl DynamicRouter {
    /// Creates a new [`DynamicRouter`] with default base layers and no route groups.
    #[must_use]
    pub fn new() -> Self {
        configure_openapi_generation();

        let route_groups = Arc::new(RwLock::new(IndexMap::new()));
        let finalizers: Arc<RwLock<Vec<RouteFinalizer>>> = Arc::new(RwLock::new(Vec::new()));

        let data_resources = DataResources::default();
        let operation_resources = OperationResources::default();
        let bulk_data_categories = BulkDataCategories::default();
        let initial_router = Self::apply_base_layers(
            axum::Router::new(),
            &data_resources,
            &operation_resources,
            &bulk_data_categories,
        );

        Self {
            route_groups,
            finalizers,
            router: Arc::new(RwLock::new(initial_router)),
            next_id: Arc::new(AtomicU64::new(0)),
            data_resources,
            operation_resources,
            bulk_data_categories,
        }
    }

    /// Registers a resource served under a `/data` collection, so that the collection
    /// lists it with the given data category (ISO 17978-3 Table 70, e.g. `identData`).
    ///
    /// `path` is the full path of the resource, e.g. `/vehicle/v15/data/version`; its
    /// parent is the collection, its last segment the id. Registering the same path
    /// again replaces the category.
    pub async fn register_data_resource(&self, path: &str, category: &str) {
        self.data_resources
            .0
            .register(path, category.to_owned())
            .await;
    }

    /// Registers an operation served under an `operations` collection, so that the
    /// collection lists it.
    ///
    /// `path` is the full path of the operation, e.g.
    /// `/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate`; its parent is the
    /// collection, its last segment the id. `asynchronous` tells whether its execution is
    /// asynchronous. Registering the same path again replaces the flag.
    pub async fn register_operation(&self, path: &str, asynchronous: bool) {
        self.operation_resources
            .0
            .register(path, asynchronous)
            .await;
    }

    /// Registers a category served under a `bulk-data` collection, so that the collection
    /// lists it. `path` is the full path of the category, e.g.
    /// `/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles`.
    pub async fn register_bulk_data_category(&self, path: &str) {
        self.bulk_data_categories.0.register(path, ()).await;
    }

    /// Returns a clone of the current composed router.
    pub async fn get_router(&self) -> axum::Router {
        let router = self.router.read().await;
        router.clone()
    }

    /// Builds the serialized `OpenAPI` document (`openapi.json`) from the current route
    /// groups.
    ///
    /// `transform` sets the document-level information (info, servers, ...). Paths and
    /// schemas are copied from the stored documentation of the route groups as raw JSON, so
    /// the document never exists in memory as a whole. Later-added groups win per path.
    ///
    /// # Errors
    /// Returns an error if the document-level information cannot be serialized.
    pub async fn openapi_json(
        &self,
        transform: impl FnOnce(TransformOpenApi<'_>) -> TransformOpenApi<'_>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut header = OpenApi::default();
        let _ = transform(TransformOpenApi::new(&mut header));
        let groups = self.route_groups.read().await;
        openapi_document::build(&header, groups.values().rev())
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
    ///
    /// An [`ApiRouter`] is finished into [`ApiRoutes`] before anything is awaited. aide
    /// collects the schema definitions in a thread-local context, so build the router on the
    /// calling thread with no `.await` between building it and calling this, or its schemas
    /// can be missing from `openapi.json`.
    pub async fn add_routes(&self, routes: impl Into<ApiRoutes>) -> RouteHandle {
        let routes = routes.into();
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
    ///
    /// See [`add_routes`](Self::add_routes) on where to build an [`ApiRouter`].
    pub async fn replace_routes(
        &self,
        handle: &RouteHandle,
        routes: impl Into<ApiRoutes>,
    ) -> Result<(), RouteGroupNotFound> {
        let routes = routes.into();
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
            |acc, (_id, group)| group.router.clone().fallback_service(acc),
        );

        let composed = Self::apply_base_layers(
            composed,
            &self.data_resources,
            &self.operation_resources,
            &self.bulk_data_categories,
        );

        let composed = finalizers.iter().fold(composed, |acc, f| f(acc));

        let mut router = self.router.write().await;
        *router = composed;
    }

    fn apply_base_layers(
        router: axum::Router,
        data_resources: &DataResources,
        operation_resources: &OperationResources,
        bulk_data_categories: &BulkDataCategories,
    ) -> axum::Router {
        create_trace_layer(
            router
                .layer(axum::Extension(data_resources.clone()))
                .layer(axum::Extension(operation_resources.clone()))
                .layer(axum::Extension(bulk_data_categories.clone())),
        )
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

    /// Builds the document like `openapi.json` and parses it, for assertions.
    async fn openapi(dr: &DynamicRouter) -> OpenApi {
        serde_json::from_slice(&dr.openapi_json(|api| api).await.unwrap()).unwrap()
    }

    fn get_path_description(api: &OpenApi, path: &str) -> Option<String> {
        let paths = api.paths.as_ref()?;
        match paths.paths.get(path)? {
            ReferenceOr::Item(item) => item.get.as_ref()?.description.clone(),
            ReferenceOr::Reference { .. } => None,
        }
    }

    #[tokio::test]
    async fn operations_collection_lists_registered_operations() {
        let dr = DynamicRouter::new();
        let operations = crate::sovd::apps::sovd2uds::OPERATIONS_PATH;
        dr.add_routes(ApiRouter::new().route(
            crate::sovd::apps::sovd2uds::OPERATIONS_PATH,
            axum::routing::get(crate::sovd::apps::sovd2uds::operations_get),
        ))
        .await;
        dr.register_operation(&format!("{operations}/update"), true)
            .await;
        dr.register_operation(&format!("{operations}/connect"), false)
            .await;
        // Resources of other collections are not listed.
        dr.register_bulk_data_category("/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles")
            .await;

        let resp = dr
            .get_router()
            .await
            .oneshot(request("GET", operations))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "items": [
                {
                    "id": "update",
                    "name": "update",
                    "proximity_proof_required": false,
                    "asynchronous_execution": true,
                },
                {
                    "id": "connect",
                    "name": "connect",
                    "proximity_proof_required": false,
                    "asynchronous_execution": false,
                },
            ]})
        );
    }

    #[tokio::test]
    async fn app_links_operations_only_if_one_is_registered() {
        let dr = DynamicRouter::new();
        dr.add_routes(ApiRouter::new().route(
            "/vehicle/v15/apps/sovd2uds",
            axum::routing::get(crate::sovd::apps::sovd2uds::get),
        ))
        .await;
        let get = |dr: DynamicRouter| async move {
            let request = http::Request::builder()
                .uri("/vehicle/v15/apps/sovd2uds")
                .header("host", "localhost:20002")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = dr.get_router().await.oneshot(request).await.unwrap();
            serde_json::from_str::<serde_json::Value>(&body_to_string(resp.into_body()).await)
                .unwrap()
        };

        assert!(get(dr.clone()).await.get("operations").is_none());

        dr.register_operation("/vehicle/v15/apps/sovd2uds/operations/update", true)
            .await;
        assert_eq!(
            get(dr).await.get("operations").and_then(|v| v.as_str()),
            Some("http://localhost:20002/vehicle/v15/apps/sovd2uds/operations")
        );
    }

    #[tokio::test]
    async fn data_collection_lists_registered_resources_with_category() {
        let dr = DynamicRouter::new();
        dr.add_routes(ApiRouter::new().route(
            sovd::vehicle::DATA_PATH,
            axum::routing::get(sovd::vehicle::data_get),
        ))
        .await;
        crate::VersionRegistrar::new("CDA", "0.1.0", "abc123", "2026-11-19")
            .register_data(&dr, "/vehicle/v15/data/version")
            .await;
        dr.register_data_resource("/vehicle/v15/data/x-vendor-info", "sysInfo")
            .await;
        // Resources of other collections are not listed.
        dr.register_data_resource(
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            "sysInfo",
        )
        .await;

        let resp = dr
            .get_router()
            .await
            .oneshot(request("GET", sovd::vehicle::DATA_PATH))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "items": [
                { "id": "version", "name": "version", "category": "identData" },
                { "id": "x-vendor-info", "name": "x-vendor-info", "category": "sysInfo" },
            ]})
        );

        let resp = dr
            .get_router()
            .await
            .oneshot(request("GET", "/vehicle/v15/data/version"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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

        let api = openapi(&dr).await;
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

        let api = openapi(&dr).await;
        assert_eq!(get_path_description(&api, "/foo").as_deref(), Some("b foo"));
        assert_eq!(get_path_description(&api, "/bar").as_deref(), Some("a bar"));
    }

    // Two different types with the same name: the schema generator numbers them (`Item`,
    // `Item2`) if they are documented with the same generator.
    mod first {
        #[derive(serde::Serialize, schemars::JsonSchema)]
        pub(super) struct Item {
            pub(super) a: u8,
        }
    }
    mod second {
        #[derive(serde::Serialize, schemars::JsonSchema)]
        pub(super) struct Item {
            pub(super) b: String,
        }
    }

    fn first_item_route(path: &str) -> ApiRouter {
        ApiRouter::new().api_route(
            path,
            routing::get_with(
                || async { axum::Json(first::Item { a: 1 }) },
                |op| op.description("first"),
            ),
        )
    }

    fn second_item_route(path: &str) -> ApiRouter {
        ApiRouter::new().api_route(
            path,
            routing::get_with(
                || async {
                    axum::Json(second::Item {
                        b: "second".to_owned(),
                    })
                },
                |op| op.description("second"),
            ),
        )
    }

    /// Returns the schema a `$ref` of the response of `GET path` resolves to.
    fn response_schema<'d>(doc: &'d serde_json::Value, path: &str) -> &'d serde_json::Value {
        let reference = doc
            .get("paths")
            .and_then(|paths| paths.get(path))
            .and_then(|item| {
                item.pointer("/get/responses/200/content/application~1json/schema/$ref")
            })
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("no schema reference for {path}"));
        let name = reference.trim_start_matches("#/components/schemas/");
        doc.get("components")
            .and_then(|components| components.get("schemas"))
            .and_then(|schemas| schemas.get(name))
            .unwrap_or_else(|| panic!("{reference} of {path} does not resolve"))
    }

    /// Returns every schema reference of `doc` that has no schema.
    fn unresolved_schema_refs(doc: &serde_json::Value) -> Vec<String> {
        fn collect<'v>(value: &'v serde_json::Value, refs: &mut Vec<&'v str>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        match (key.as_str(), value.as_str()) {
                            ("$ref", Some(reference)) => refs.push(reference),
                            _ => collect(value, refs),
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        collect(value, refs);
                    }
                }
                _ => {}
            }
        }
        let mut refs = Vec::new();
        collect(doc, &mut refs);
        let schemas = doc.pointer("/components/schemas");
        refs.into_iter()
            .filter(|reference| {
                reference
                    .strip_prefix("#/components/schemas/")
                    .is_none_or(|name| schemas.and_then(|s| s.get(name)).is_none())
            })
            .map(str::to_owned)
            .collect()
    }

    #[tokio::test]
    async fn finished_nested_docs_match_nest_api_service() {
        fn ecu_routes() -> ApiRouter {
            second_item_route("/data/{id}").api_route(
                "/",
                routing::get_with(|| async { "root" }, |op| op.description("root")),
            )
        }

        let expected = {
            let dr = DynamicRouter::new();
            dr.add_routes(
                first_item_route("/components")
                    .nest_api_service("/components/a", ecu_routes())
                    .nest_api_service("/components/b", ecu_routes()),
            )
            .await;
            serde_json::to_value(openapi(&dr).await).unwrap()
        };

        let dr = DynamicRouter::new();
        let mut docs = FinishedDocs::default();
        let router = docs.nest(
            first_item_route("/components"),
            "/components/a",
            ecu_routes(),
        );
        let router = docs.nest(router, "/components/b", ecu_routes());
        dr.add_routes(ApiRoutes::finish(router, docs)).await;

        let actual = serde_json::to_value(openapi(&dr).await).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(unresolved_schema_refs(&actual), Vec::<String>::new());
        assert!(
            response_schema(&actual, "/components")
                .pointer("/properties/a")
                .is_some()
        );
        for path in ["/components/a/data/{id}", "/components/b/data/{id}"] {
            assert!(
                response_schema(&actual, path)
                    .pointer("/properties/b")
                    .is_some(),
                "{path}"
            );
        }
        for (path, body) in [
            ("/components/a", "root"),
            ("/components/b/data/x", r#"{"b":"second"}"#),
        ] {
            let resp = dr
                .get_router()
                .await
                .oneshot(request("GET", path))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(body_to_string(resp.into_body()).await, body, "{path}");
        }
    }

    #[tokio::test]
    async fn openapi_json_renames_conflicting_schemas_of_separate_groups() {
        let dr = DynamicRouter::new();
        // Each group is documented on its own, so both name their type `Item`.
        dr.add_routes(first_item_route("/first")).await;
        dr.add_routes(second_item_route("/second")).await;

        let doc: serde_json::Value =
            serde_json::from_slice(&dr.openapi_json(|api| api).await.unwrap()).unwrap();

        assert_eq!(unresolved_schema_refs(&doc), Vec::<String>::new());
        assert!(
            response_schema(&doc, "/first")
                .pointer("/properties/a")
                .is_some()
        );
        assert!(
            response_schema(&doc, "/second")
                .pointer("/properties/b")
                .is_some()
        );
        assert_eq!(
            doc.pointer("/components/schemas")
                .and_then(serde_json::Value::as_object)
                .map(serde_json::Map::len),
            Some(2)
        );
    }

    #[tokio::test]
    async fn openapi_json_applies_document_transform() {
        let dr = DynamicRouter::new();
        dr.add_routes(first_item_route("/first")).await;

        let doc: serde_json::Value = serde_json::from_slice(
            &dr.openapi_json(|api| api.title("CDA").version("1.0"))
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            doc.pointer("/info/title")
                .and_then(serde_json::Value::as_str),
            Some("CDA")
        );
        assert!(doc.pointer("/paths/~1first/get").is_some());
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

        let api = openapi(&dr).await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from b")
        );

        dr.remove_routes(&handle_b).await;
        let api = openapi(&dr).await;
        assert_eq!(
            get_path_description(&api, "/foo").as_deref(),
            Some("from a")
        );
    }
}
