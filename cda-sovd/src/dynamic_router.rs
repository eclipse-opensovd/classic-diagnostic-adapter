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
    axum::{ApiRouter, routing::ApiMethodRouter},
    openapi::{OpenApi, Paths},
};
use axum::middleware;
use indexmap::IndexMap;
use tokio::sync::RwLock;

use crate::{create_trace_layer, sovd};

type RouteFinalizer = Arc<dyn Fn(axum::Router) -> axum::Router + Send + Sync>;

/// What a collection lists about one of its resources.
#[derive(Clone, Debug)]
enum ListingKind {
    /// A resource of a `/data` collection, with its data category.
    Data(String),
    /// An operation of an `operations` collection, with whether its execution is
    /// asynchronous.
    Operation(bool),
    /// A category of a `bulk-data` collection.
    BulkData,
    /// An entity listed by its entity collection, with its display name.
    Entity(String),
    /// A mode, with its display name.
    Mode(String),
}

/// A resource listed by its collection, declared together with the routes serving it.
#[derive(Clone, Debug)]
struct Listing {
    collection: String,
    id: String,
    kind: ListingKind,
}

/// A route group to register with a [`DynamicRouter`]. Its resource methods install
/// handlers and declare their collection entries together.
///
/// The listings share the lifecycle of the route group: they are listed while the group
/// is registered, and replaced or removed together with it. Any [`ApiRouter`] converts
/// into [`Routes`] without listings. Resources determined dynamically, such as ECU
/// services, are still discovered by their collection handlers.
pub struct Routes<S = ()> {
    router: ApiRouter<S>,
    listings: Vec<Listing>,
}

impl<S: Clone + Send + Sync + 'static> Routes<S> {
    /// Creates a route group from `router`, without listings.
    #[must_use]
    pub fn new(router: ApiRouter<S>) -> Self {
        Self {
            router,
            listings: Vec::new(),
        }
    }

    /// Transforms the router while retaining this group's listings.
    ///
    /// This can be used to add routes or middleware to a group returned by
    /// [`crate::build_vehicle_routes`]. The caller must keep the listings consistent
    /// with any routes changed by the transformation. Routes added here are not
    /// automatically listed; use the resource methods instead for discoverable resources.
    #[must_use]
    pub fn map_router(self, transform: impl FnOnce(ApiRouter<S>) -> ApiRouter<S>) -> Self {
        Self {
            router: transform(self.router),
            listings: self.listings,
        }
    }

    /// Adds a resource and lists it in its `/data` collection with the given data category
    /// (ISO 17978-3 Table 70, e.g. `identData`).
    ///
    /// `path` is the full path of the resource, e.g. `/vehicle/v15/data/version`; its
    /// parent is the collection, its last segment the id.
    #[must_use]
    pub fn data(
        mut self,
        path: &str,
        category: &str,
        handler: impl Into<ApiMethodRouter<S>>,
    ) -> Self {
        self.router = self.router.api_route(path, handler.into());
        self.listed(path, ListingKind::Data(category.to_owned()))
    }

    /// Adds an operation's execution route and lists the operation in its collection.
    ///
    /// `path` is the full path of the operation, e.g.
    /// `/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate`; its parent is the
    /// collection, its last segment the id. `asynchronous` tells whether its execution is
    /// asynchronous.
    #[must_use]
    pub fn operation(
        mut self,
        path: &str,
        asynchronous: bool,
        handler: impl Into<ApiMethodRouter<S>>,
    ) -> Self {
        self.router = self
            .router
            .api_route(&format!("{path}/executions"), handler.into());
        self.listed(path, ListingKind::Operation(asynchronous))
    }

    /// Adds a category and lists it in its `bulk-data` collection. `path` is the full path of the
    /// category, e.g. `/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles`.
    #[must_use]
    pub fn bulk_data(mut self, path: &str, handler: impl Into<ApiMethodRouter<S>>) -> Self {
        self.router = self.router.api_route(path, handler.into());
        self.listed(path, ListingKind::BulkData)
    }

    /// Adds an entity and lists it in its parent entity collection.
    #[must_use]
    pub fn entity(mut self, path: &str, handler: impl Into<ApiMethodRouter<S>>) -> Self {
        self.router = self.router.api_route(path, handler.into());
        let name = path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default();
        self.listed(path, ListingKind::Entity(name.to_owned()))
    }

    /// Adds a mode and lists it in its parent `modes` collection.
    #[must_use]
    pub fn mode(mut self, path: &str, name: &str, handler: impl Into<ApiMethodRouter<S>>) -> Self {
        self.router = self.router.api_route(path, handler.into());
        self.listed(path, ListingKind::Mode(name.to_owned()))
    }

    /// Supplies router state while retaining the group's resource listings.
    #[must_use]
    pub fn with_state<S2: Clone + Send + Sync + 'static>(self, state: S) -> Routes<S2> {
        Routes {
            router: self.router.with_state(state),
            listings: self.listings,
        }
    }

    /// Merges two route groups and their resource listings.
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        self.router = self.router.merge(other.router);
        self.listings.extend(other.listings);
        self
    }

    /// Nests a state-bound route group, retaining and prefixing its listings.
    #[must_use]
    pub fn nest(mut self, prefix: &str, nested: Routes) -> Self {
        self.router = self.router.nest_api_service(prefix, nested.router);
        self.listings
            .extend(nested.listings.into_iter().map(|mut listing| {
                listing.collection =
                    format!("{}{}", prefix.trim_end_matches('/'), listing.collection);
                listing
            }));
        self
    }

    /// Nests an entity's routes and lists the entity in its parent collection.
    #[must_use]
    pub fn nest_entity(self, prefix: &str, name: &str, nested: Routes) -> Self {
        self.nest(prefix, nested)
            .listed(prefix, ListingKind::Entity(name.to_owned()))
    }

    fn listed(mut self, path: &str, kind: ListingKind) -> Self {
        match path.trim_end_matches('/').rsplit_once('/') {
            Some((collection, id)) if !id.is_empty() => self.listings.push(Listing {
                collection: collection.to_owned(),
                id: id.to_owned(),
                kind,
            }),
            _ => tracing::warn!(path, "Resource path has no collection, not listed"),
        }
        self
    }
}

impl Default for Routes {
    fn default() -> Self {
        Self::new(ApiRouter::new())
    }
}

impl From<ApiRouter> for Routes {
    fn from(router: ApiRouter) -> Self {
        Self::new(router)
    }
}

/// Maps the collection path (e.g. `/vehicle/v15/data`) to the id of each resource in it
/// and one value per resource, in registration order.
type Collections<V> = IndexMap<String, IndexMap<String, V>>;

/// The resources listed by the collections of all registered route groups.
///
/// Rebuilt from the resource declarations of the route groups on every recomposition.
/// Handlers read it as a request extension.
#[derive(Default)]
pub(crate) struct ResourceCatalog {
    data: Collections<String>,
    operations: Collections<bool>,
    bulk_data: Collections<()>,
    entities: Collections<String>,
    modes: Collections<String>,
}

impl ResourceCatalog {
    /// Builds the catalog from listings in route group order. A later group's listing of
    /// the same resource overrides an earlier one, like its routes do.
    fn from_listings<'a>(listings: impl Iterator<Item = &'a Listing>) -> Self {
        fn insert<V>(collections: &mut Collections<V>, listing: &Listing, value: V) {
            collections
                .entry(listing.collection.clone())
                .or_default()
                .insert(listing.id.clone(), value);
        }

        let mut catalog = Self::default();
        for listing in listings {
            match &listing.kind {
                ListingKind::Data(category) => {
                    insert(&mut catalog.data, listing, category.clone());
                }
                ListingKind::Operation(asynchronous) => {
                    insert(&mut catalog.operations, listing, *asynchronous);
                }
                ListingKind::BulkData => insert(&mut catalog.bulk_data, listing, ()),
                ListingKind::Entity(name) => insert(&mut catalog.entities, listing, name.clone()),
                ListingKind::Mode(name) => insert(&mut catalog.modes, listing, name.clone()),
            }
        }
        catalog
    }

    fn entries<V: Clone>(collections: &Collections<V>, collection: &str) -> Vec<(String, V)> {
        collections
            .get(collection)
            .map(|resources| {
                resources
                    .iter()
                    .map(|(id, value)| (id.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns `(id, category)` of each resource listed in the `/data` collection
    /// `collection`.
    pub(crate) fn data(&self, collection: &str) -> Vec<(String, String)> {
        Self::entries(&self.data, collection)
    }

    /// Returns `(id, asynchronous)` of each operation listed in the `operations`
    /// collection `collection`.
    pub(crate) fn operations(&self, collection: &str) -> Vec<(String, bool)> {
        Self::entries(&self.operations, collection)
    }

    /// Returns the id of each category listed in the `bulk-data` collection `collection`.
    pub(crate) fn bulk_data(&self, collection: &str) -> Vec<String> {
        self.bulk_data
            .get(collection)
            .map(|categories| categories.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns entity IDs and names listed in `collection`.
    pub(crate) fn entities(&self, collection: &str) -> Vec<(String, String)> {
        Self::entries(&self.entities, collection)
    }

    /// Returns mode IDs and names listed in `collection`.
    pub(crate) fn modes(&self, collection: &str) -> Vec<(String, String)> {
        Self::entries(&self.modes, collection)
    }
}

/// Insertion order determines override precedence in the fallback chain.
type RouteGroups = Arc<RwLock<IndexMap<u64, RouteGroup>>>;

/// A route group split into its request-handling router, its `OpenAPI` paths and the
/// resources its collections list.
///
/// The [`ApiRouter`] is split once on registration, so recompositions only clone the
/// cheap axum router instead of the whole [`ApiRouter`] including its documentation.
/// The paths are kept as serialized JSON, which is several times smaller than the
/// in-memory [`Paths`] and only needs to be parsed when `openapi.json` is requested.
struct RouteGroup {
    router: axum::Router,
    paths_json: Option<Box<[u8]>>,
    listings: Vec<Listing>,
}

impl RouteGroup {
    fn paths(&self) -> Option<Paths> {
        let json = self.paths_json.as_deref()?;
        serde_json::from_slice(json)
            .inspect_err(|e| tracing::error!(error = %e, "Failed to deserialize OpenAPI paths"))
            .ok()
    }
}

impl From<Routes> for RouteGroup {
    fn from(Routes { router, listings }: Routes) -> Self {
        let mut api = OpenApi::default();
        let router = router.finish_api(&mut api);
        let paths_json = api.paths.and_then(|paths| {
            serde_json::to_vec(&paths)
                .inspect_err(|e| tracing::error!(error = %e, "Failed to serialize OpenAPI paths"))
                .ok()
                .map(Vec::into_boxed_slice)
        });
        Self {
            router,
            paths_json,
            listings,
        }
    }
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
///
/// Resource and entity listings created by [`Routes`] are added, replaced and removed
/// together with the group.
#[derive(Clone)]
pub struct DynamicRouter {
    route_groups: RouteGroups,
    finalizers: Arc<RwLock<Vec<RouteFinalizer>>>,
    router: Arc<RwLock<axum::Router>>,
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

        let initial_router = Self::apply_base_layers(axum::Router::new(), Arc::default());

        Self {
            route_groups,
            finalizers,
            router: Arc::new(RwLock::new(initial_router)),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns a clone of the current composed router.
    pub async fn get_router(&self) -> axum::Router {
        let router = self.router.read().await;
        router.clone()
    }

    /// Builds the `OpenAPI` specification from the current route groups.
    ///
    /// The specification is generated on demand instead of being kept in memory,
    /// as it is only needed when `openapi.json` is requested.
    pub async fn get_openapi(&self) -> Arc<OpenApi> {
        let groups = self.route_groups.read().await;
        // Latest-added group wins per path: iterating latest-first and only inserting
        // paths not yet claimed lets later groups' docs override earlier ones.
        let api = groups
            .values()
            .rev()
            .fold(OpenApi::default(), |mut api, group| {
                if let Some(paths) = group.paths() {
                    let api_paths = api.paths.get_or_insert_with(Default::default);
                    for (path, item) in paths.paths {
                        api_paths.paths.entry(path).or_insert(item);
                    }
                }
                api
            });
        Arc::new(api)
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
    /// `routes` is an [`ApiRouter`], or [`Routes`] to also list resources of the group in
    /// their collections.
    pub async fn add_routes(&self, routes: impl Into<Routes>) -> RouteHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut groups = self.route_groups.write().await;
            groups.insert(id, routes.into().into());
        }
        self.recompose().await;
        RouteHandle { id }
    }

    /// Replaces the route group identified by `handle` with new routes and recomposes the router.
    ///
    /// This is the primary mechanism for hot-reloading routes at runtime: the caller retains
    /// the [`RouteHandle`] from the initial [`add_routes`](Self::add_routes) call and passes it
    /// here to atomically swap the old routes with new ones (e.g., after rebuilding vehicle
    /// routes from freshly loaded MDD databases). The listings of the old group are replaced
    /// by those of `routes`.
    ///
    /// # Errors
    ///
    /// Returns [`RouteGroupNotFound`] if the handle refers to a group that was already removed.
    pub async fn replace_routes(
        &self,
        handle: &RouteHandle,
        routes: impl Into<Routes>,
    ) -> Result<(), RouteGroupNotFound> {
        {
            let mut groups = self.route_groups.write().await;
            match groups.entry(handle.id) {
                indexmap::map::Entry::Occupied(mut entry) => {
                    let _ = entry.insert(routes.into().into());
                }
                indexmap::map::Entry::Vacant(_) => {
                    return Err(RouteGroupNotFound { id: handle.id });
                }
            }
        }
        self.recompose().await;
        Ok(())
    }

    /// Removes the route group identified by `handle`, together with its listings, and
    /// recomposes the router.
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

        let catalog =
            ResourceCatalog::from_listings(groups.values().flat_map(|group| group.listings.iter()));
        let composed = Self::apply_base_layers(composed, Arc::new(catalog));

        let composed = finalizers.iter().fold(composed, |acc, f| f(acc));

        let mut router = self.router.write().await;
        *router = composed;
    }

    fn apply_base_layers(router: axum::Router, catalog: Arc<ResourceCatalog>) -> axum::Router {
        create_trace_layer(router.layer(axum::Extension(catalog)))
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

    async fn get_json(dr: &DynamicRouter, path: &str) -> serde_json::Value {
        let request = http::Request::builder()
            .uri(path)
            .header("host", "localhost:20002")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = dr.get_router().await.oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap()
    }

    /// Adds the route of the vehicle `/data` collection.
    async fn add_vehicle_data_collection(dr: &DynamicRouter) {
        dr.add_routes(ApiRouter::new().route(
            sovd::vehicle::DATA_PATH,
            axum::routing::get(sovd::vehicle::data_get),
        ))
        .await;
    }

    /// Returns `(id, category)` of each item of the vehicle `/data` collection.
    async fn vehicle_data_items(dr: &DynamicRouter) -> Vec<(String, String)> {
        let body = get_json(dr, sovd::vehicle::DATA_PATH).await;
        body.get("items")
            .and_then(serde_json::Value::as_array)
            .unwrap()
            .iter()
            .map(|item| {
                let field = |name: &str| item.get(name).and_then(|v| v.as_str()).unwrap();
                (field("id").to_owned(), field("category").to_owned())
            })
            .collect()
    }

    fn item(id: &str, category: &str) -> (String, String) {
        (id.to_owned(), category.to_owned())
    }

    #[tokio::test]
    async fn transforming_router_preserves_listings_and_adds_routes() {
        let dr = DynamicRouter::new();
        add_vehicle_data_collection(&dr).await;
        let routes = Routes::default()
            .data(
                "/vehicle/v15/data/version",
                "identData",
                routing::get(|| async { "version" }),
            )
            .map_router(|router| {
                router
                        .route(
                            "/custom",
                            routing::get(
                                |axum::Extension(value): axum::Extension<&'static str>| async move {
                                    value
                                },
                            ),
                        )
                        .layer(axum::Extension("custom"))
            });
        let handle = dr.add_routes(routes).await;

        assert_eq!(
            vehicle_data_items(&dr).await,
            [item("version", "identData")]
        );
        for (path, expected) in [
            ("/vehicle/v15/data/version", "version"),
            ("/custom", "custom"),
        ] {
            let response = dr
                .get_router()
                .await
                .oneshot(request("GET", path))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body_to_string(response.into_body()).await, expected);
        }

        dr.remove_routes(&handle).await;
        assert!(vehicle_data_items(&dr).await.is_empty());
        let response = dr
            .get_router()
            .await
            .oneshot(request("GET", "/custom"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn operations_collection_lists_registered_operations() {
        let dr = DynamicRouter::new();
        let operations = crate::sovd::apps::sovd2uds::OPERATIONS_PATH;
        dr.add_routes(ApiRouter::new().route(
            operations,
            axum::routing::get(crate::sovd::apps::sovd2uds::operations_get),
        ))
        .await;
        dr.add_routes(
            Routes::default()
                .operation(
                    &format!("{operations}/update"),
                    true,
                    routing::get(|| async {}),
                )
                .operation(
                    &format!("{operations}/connect"),
                    false,
                    routing::get(|| async {}),
                )
                // Resources of other collections are not listed.
                .bulk_data(
                    "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
                    routing::get(|| async {}),
                ),
        )
        .await;

        assert_eq!(
            get_json(&dr, operations).await,
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
    async fn entity_collection_tracks_registered_routes() {
        let dr = DynamicRouter::new();
        let collection = "/vehicle/v15/apps";
        dr.add_routes(ApiRouter::new().route(collection, axum::routing::get(sovd::apps::get)))
            .await;
        let handle = dr
            .add_routes(Routes::default().entity(
                "/vehicle/v15/apps/example",
                routing::get(|| async { "example" }),
            ))
            .await;
        let body = get_json(&dr, collection).await;
        assert_eq!(
            body.get("items")
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("id"))
                .and_then(serde_json::Value::as_str),
            Some("example")
        );
        let response = dr
            .get_router()
            .await
            .oneshot(request("GET", "/vehicle/v15/apps/example"))
            .await
            .unwrap();
        assert_eq!(body_to_string(response.into_body()).await, "example");
        dr.remove_routes(&handle).await;
        assert_eq!(
            get_json(&dr, collection).await.get("items"),
            Some(&serde_json::json!([]))
        );
    }

    #[tokio::test]
    async fn nested_entity_is_listed_with_display_name() {
        let dr = DynamicRouter::new();
        dr.add_routes(ApiRouter::new().route(
            "/vehicle/v15/components",
            axum::routing::get(
                |axum::Extension(catalog): axum::Extension<Arc<ResourceCatalog>>| async move {
                    axum::Json(catalog.entities("/vehicle/v15/components"))
                },
            ),
        ))
        .await;
        let entity =
            Routes::new(ApiRouter::new().route("/", routing::get(|| async { "component" })));
        let handle = dr
            .add_routes(Routes::default().nest_entity("/vehicle/v15/components/ecu", "ECU", entity))
            .await;
        assert_eq!(
            get_json(&dr, "/vehicle/v15/components").await,
            serde_json::json!([["ecu", "ECU"]])
        );
        dr.remove_routes(&handle).await;
        assert_eq!(
            get_json(&dr, "/vehicle/v15/components").await,
            serde_json::json!([])
        );
    }

    #[tokio::test]
    async fn nested_bulk_data_is_listed_with_its_full_path() {
        let dr = DynamicRouter::new();
        let collection = "/vehicle/v15/components/example/bulk-data";
        let nested = Routes::default()
            .map_router(|router| {
                router.route(
                    "/bulk-data",
                    axum::routing::get(sovd::components::ecu::x_sovd2uds_bulk_data::get),
                )
            })
            .bulk_data("/bulk-data/files", routing::get(|| async { "files" }));
        let handle = dr
            .add_routes(Routes::default().nest("/vehicle/v15/components/example", nested))
            .await;
        assert_eq!(
            get_json(&dr, collection)
                .await
                .get("items")
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("id"))
                .and_then(serde_json::Value::as_str),
            Some("files")
        );
        let response = dr
            .get_router()
            .await
            .oneshot(request(
                "GET",
                "/vehicle/v15/components/example/bulk-data/files",
            ))
            .await
            .unwrap();
        assert_eq!(body_to_string(response.into_body()).await, "files");
        dr.remove_routes(&handle).await;
        let response = dr
            .get_router()
            .await
            .oneshot(request("GET", collection))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nested_mode_routes_and_metadata_share_lifecycle() {
        let dr = DynamicRouter::new();
        let collection = "/entity/modes";
        let nested = Routes::default()
            .map_router(|router| {
                router.route("/modes", axum::routing::get(
                |axum::Extension(catalog): axum::Extension<Arc<ResourceCatalog>>| async move {
                    axum::Json(catalog.modes("/entity/modes"))
                },
            ))
            })
            .mode(
                "/modes/drive",
                "Drive mode",
                routing::get(|| async { "drive" }),
            );
        let handle = dr
            .add_routes(Routes::default().nest("/entity", nested))
            .await;
        assert_eq!(
            get_json(&dr, collection).await,
            serde_json::json!([["drive", "Drive mode"]])
        );
        let response = dr
            .get_router()
            .await
            .oneshot(request("GET", "/entity/modes/drive"))
            .await
            .unwrap();
        assert_eq!(body_to_string(response.into_body()).await, "drive");
        dr.remove_routes(&handle).await;
        let response = dr
            .get_router()
            .await
            .oneshot(request("GET", collection))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn functional_group_modes_handler_reads_registered_modes() {
        use aide::UseApi;
        use axum::{
            Extension,
            extract::{OriginalUri, Query, State},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::mock::MockUdsEcu;
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};

        let routes = Routes::default().mode(
            "/vehicle/v15/functions/functionalgroups/group/modes/custom",
            "Custom mode",
            routing::get(|| async {}),
        );
        let catalog = Arc::new(ResourceCatalog::from_listings(routes.listings.iter()));
        let state = sovd::functions::functional_groups::tests::create_test_fg_state(
            MockUdsEcu::new(),
            "group".to_owned(),
        );
        let response = sovd::functions::functional_groups::modes::get(
            Extension(catalog),
            OriginalUri(
                "/vehicle/v15/functions/functionalgroups/group/modes"
                    .parse()
                    .unwrap(),
            ),
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                Query(sovd_interfaces::IncludeSchemaQuery {
                    include_schema: false,
                }),
                std::marker::PhantomData,
            ),
            State(state),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_to_string(response.into_body()).await).unwrap();
        assert_eq!(
            body.get("items"),
            Some(&serde_json::json!([{ "id": "custom", "name": "Custom mode" }]))
        );
    }

    #[tokio::test]
    async fn ecu_modes_handler_filters_authentication_using_live_capability() {
        use aide::UseApi;
        use axum::{
            Extension,
            extract::{OriginalUri, Query, State},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            file_manager::mock::MockFileManager,
            mock::{MockUdsEcu, mock_ecu_state_online_variant_detected},
        };
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};

        let routes = Routes::default()
            .mode(
                "/vehicle/v15/components/test/modes/session",
                "Session",
                routing::get(|| async {}),
            )
            .mode(
                "/vehicle/v15/components/test/modes/authentication",
                "Authentication",
                routing::get(|| async {}),
            );
        let catalog = Arc::new(ResourceCatalog::from_listings(routes.listings.iter()));
        let mut uds = MockUdsEcu::new();
        uds.expect_get_ecu_state()
            .returning(|_| Ok(mock_ecu_state_online_variant_detected()));
        uds.expect_has_authentication_services()
            .returning(|_| false);
        let state = sovd::tests::create_test_webserver_state(
            "test".to_owned(),
            uds,
            MockFileManager::new(),
        );
        let response = sovd::components::ecu::modes::get(
            Extension(catalog),
            OriginalUri("/vehicle/v15/components/test/modes".parse().unwrap()),
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                Query(sovd_interfaces::IncludeSchemaQuery {
                    include_schema: false,
                }),
                std::marker::PhantomData,
            ),
            State(state),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_to_string(response.into_body()).await).unwrap();
        assert_eq!(
            body.get("items"),
            Some(&serde_json::json!([{ "id": "session", "name": "Session" }]))
        );
    }

    #[tokio::test]
    async fn app_links_operations_only_if_one_is_registered() {
        let dr = DynamicRouter::new();
        let app = "/vehicle/v15/apps/sovd2uds";
        dr.add_routes(
            ApiRouter::new().route(app, axum::routing::get(crate::sovd::apps::sovd2uds::get)),
        )
        .await;

        assert!(get_json(&dr, app).await.get("operations").is_none());

        let handle = dr
            .add_routes(Routes::default().operation(
                &format!("{app}/operations/update"),
                true,
                routing::get(|| async {}),
            ))
            .await;
        assert_eq!(
            get_json(&dr, app)
                .await
                .get("operations")
                .and_then(|v| v.as_str()),
            Some("http://localhost:20002/vehicle/v15/apps/sovd2uds/operations")
        );

        dr.remove_routes(&handle).await;
        assert!(get_json(&dr, app).await.get("operations").is_none());
    }

    #[tokio::test]
    async fn data_collection_lists_registered_resources_with_category() {
        let dr = DynamicRouter::new();
        add_vehicle_data_collection(&dr).await;
        crate::VersionRegistrar::new("CDA", "0.1.0", "abc123", "2026-11-19")
            .register_data(&dr, "/vehicle/v15/data/version")
            .await;
        dr.add_routes(
            Routes::default()
                .data(
                    "/vehicle/v15/data/x-vendor-info",
                    "sysInfo",
                    routing::get(|| async {}),
                )
                // Resources of other collections are not listed.
                .data(
                    "/vehicle/v15/apps/sovd2uds/data/networkstructure",
                    "sysInfo",
                    routing::get(|| async {}),
                ),
        )
        .await;

        assert_eq!(
            get_json(&dr, sovd::vehicle::DATA_PATH).await,
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
    async fn removing_a_group_removes_its_listings() {
        let dr = DynamicRouter::new();
        add_vehicle_data_collection(&dr).await;
        dr.add_routes(Routes::default().data(
            "/vehicle/v15/data/kept",
            "sysInfo",
            routing::get(|| async {}),
        ))
        .await;
        let handle = dr
            .add_routes(Routes::default().data(
                "/vehicle/v15/data/removed",
                "sysInfo",
                routing::get(|| async {}),
            ))
            .await;
        assert_eq!(
            vehicle_data_items(&dr).await,
            [item("kept", "sysInfo"), item("removed", "sysInfo")]
        );

        dr.remove_routes(&handle).await;
        assert_eq!(vehicle_data_items(&dr).await, [item("kept", "sysInfo")]);
    }

    #[tokio::test]
    async fn replacing_a_group_replaces_its_listings() {
        let dr = DynamicRouter::new();
        add_vehicle_data_collection(&dr).await;
        let handle = dr
            .add_routes(
                Routes::default()
                    .data(
                        "/vehicle/v15/data/old",
                        "sysInfo",
                        routing::get(|| async {}),
                    )
                    .data(
                        "/vehicle/v15/data/changed",
                        "sysInfo",
                        routing::get(|| async {}),
                    ),
            )
            .await;
        dr.add_routes(Routes::default().data(
            "/vehicle/v15/data/other",
            "sysInfo",
            routing::get(|| async {}),
        ))
        .await;

        dr.replace_routes(
            &handle,
            Routes::default()
                .data(
                    "/vehicle/v15/data/changed",
                    "identData",
                    routing::get(|| async {}),
                )
                .data(
                    "/vehicle/v15/data/new",
                    "sysInfo",
                    routing::get(|| async {}),
                ),
        )
        .await
        .unwrap();
        // The replaced group keeps its position, so its listings stay before those of
        // later groups.
        assert_eq!(
            vehicle_data_items(&dr).await,
            [
                item("changed", "identData"),
                item("new", "sysInfo"),
                item("other", "sysInfo"),
            ]
        );
    }

    #[tokio::test]
    async fn removing_an_overriding_group_restores_the_overridden_listing() {
        let dr = DynamicRouter::new();
        add_vehicle_data_collection(&dr).await;
        dr.add_routes(Routes::default().data(
            "/vehicle/v15/data/version",
            "identData",
            routing::get(|| async {}),
        ))
        .await;
        let handle = dr
            .add_routes(Routes::default().data(
                "/vehicle/v15/data/version",
                "sysInfo",
                routing::get(|| async {}),
            ))
            .await;
        assert_eq!(vehicle_data_items(&dr).await, [item("version", "sysInfo")]);

        dr.remove_routes(&handle).await;
        assert_eq!(
            vehicle_data_items(&dr).await,
            [item("version", "identData")]
        );
    }

    #[test]
    fn listing_without_collection_is_ignored() {
        let routes = Routes::default()
            .listed("version", ListingKind::Data("identData".to_owned()))
            .listed("/", ListingKind::BulkData);
        assert!(routes.listings.is_empty());
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
