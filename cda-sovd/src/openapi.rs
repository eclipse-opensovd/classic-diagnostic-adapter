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

use aide::{
    openapi::{
        Components, Contact, License, MediaType, OpenApi, Operation, PathItem, ReferenceOr,
        SchemaObject, Server, Tag,
    },
    transform::{TransformOpenApi, TransformOperation},
};
use axum::Json;
use indexmap::IndexMap;
use schemars::JsonSchema;
use sovd_interfaces::error::ApiErrorResponse;

use crate::sovd::{self, error::VendorErrorCode};

/// Expands the templated `{component_id}` / `{functional_group_id}` path keys into
/// one concrete, lowercase path per loaded ECU / functional group, in name order so
/// the document stays stable. Only the document needs concrete paths; the router
/// itself stays templated.
pub(crate) fn expand_templated_paths<'a>(
    api: &mut OpenApi,
    ecus: impl IntoIterator<Item = &'a String>,
    functional_groups: impl IntoIterator<Item = &'a String>,
) {
    let Some(paths) = api.paths.as_mut() else {
        return;
    };
    expand_placeholder(&mut paths.paths, "{component_id}", ecus, InstanceTag::Apply);
    expand_placeholder(
        &mut paths.paths,
        "{functional_group_id}",
        functional_groups,
        InstanceTag::Skip,
    );
}

/// Whether an expanded path's operations carry the instance name as an `OpenAPI` tag.
///
/// Swagger UI groups operations by tag. Before the router was templated, each ECU
/// had its own concrete router and every operation was tagged with that ECU's name,
/// which is what gave the UI one collapsible section per ECU. Expansion has to put
/// that back, because a templated route cannot know the name at registration.
/// Functional groups were never tagged, so they stay untagged.
#[derive(Clone, Copy)]
enum InstanceTag {
    Apply,
    Skip,
}

/// Tags every operation in `item` with `name`, leaving existing tags in place.
fn tag_operations(item: &mut ReferenceOr<PathItem>, name: &str) {
    let ReferenceOr::Item(path_item) = item else {
        return;
    };
    let PathItem {
        get,
        put,
        post,
        delete,
        options,
        head,
        patch,
        trace,
        ..
    } = path_item;
    let operations = [get, put, post, delete, options, head, patch, trace];
    for operation in operations.into_iter().filter_map(Option::as_mut) {
        let Operation { tags, .. } = operation;
        if !tags.iter().any(|tag| tag == name) {
            tags.push(name.to_owned());
        }
    }
}

fn expand_placeholder<'a>(
    paths: &mut IndexMap<String, ReferenceOr<PathItem>>,
    placeholder: &str,
    names: impl IntoIterator<Item = &'a String>,
    tagging: InstanceTag,
) {
    let mut sorted: Vec<String> = names.into_iter().map(|name| name.to_lowercase()).collect();
    sorted.sort();
    sorted.dedup();

    let mut expanded = IndexMap::with_capacity(paths.len());
    for (path, item) in paths.drain(..) {
        if !path.contains(placeholder) {
            expanded.insert(path, item);
            continue;
        }
        for name in &sorted {
            let mut instance = item.clone();
            if matches!(tagging, InstanceTag::Apply) {
                tag_operations(&mut instance, name);
            }
            expanded.insert(path.replace(placeholder, name), instance);
        }
    }
    *paths = expanded;
}

pub(crate) mod aide_helper {
    /// Helper macro to generate path params that have an openapi
    ///
    /// # Usage
    /// ## With single field
    /// The macro requires at least 3 arguments:
    ///  - Name of the struct that should be generated
    ///  - Name of the path parameter
    ///  - Type of the path parameter
    ///
    /// `gen_path_param!(IdPathParam, id, String)`
    /// ## With multiple fields
    /// Alternatively it can be called with multiple pairs of
    /// (name, type) to generate a struct with multiple fields.
    ///
    /// `gen_path_param!(MultiFieldParam, id, String, name, String)`
    macro_rules! gen_path_param {
        ($struct_name:ident $value_name:ident $type:ty) => {
            #[derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
            pub(crate) struct $struct_name {
                pub $value_name: $type,
            }

            impl std::ops::Deref for $struct_name {
                type Target = $type;

                fn deref(&self) -> &Self::Target {
                    &self.$value_name
                }
            }
        };
        ($struct_name:ident $($value_name:ident $type:ty)+) => {
            #[derive(serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
            pub(crate) struct $struct_name {
                $(
                $value_name: $type,
                )*
            }

            impl $struct_name {
            $(
                #[allow(dead_code)]
                pub(crate) fn $value_name(&self) -> &$type {
                    &self.$value_name
                }
            )*
            }
        };
    }

    pub(crate) use gen_path_param;
}

// Allowing pass by value here for the config, to prevent life-time issues with the
// borrowed config in the closure.
pub(crate) fn api_docs(api: TransformOpenApi, server_url: String) -> TransformOpenApi {
    api.title("Eclipse OpenSOVD - Classic Diagnostic Adapter")
        .summary(
            "In the SOVD (Service-Oriented Vehicle Diagnostics) context, a Classic Diagnostic \
             Adapter serves as a compatibility bridge between traditional (legacy) diagnostic \
             interfaces and the modern SOVD-based diagnostic architecture used in modern vehicles.",
        )
        // .description(include_str!("../../README.md"))
        .contact(Contact {
            name: Some("Classic Diagnostic Adapter".to_owned()),
            url: Some("https://github.com/eclipse-opensovd/classic-diagnostic-adapter/".to_owned()),
            email: Some("opensovd-dev@eclipse.org".to_owned()),
            ..Default::default()
        })
        .license(License {
            name: "Apache 2.0".to_owned(),
            identifier: Some("Apache-2.0".to_owned()),
            ..Default::default()
        })
        .tag(Tag {
            name: "OpenSOVD CDA".to_owned(),
            description: Some("Classic Diagnostic Adapter written in Rust".to_owned()),
            ..Default::default()
        })
        .server(Server {
            url: server_url,
            ..Default::default()
        })
}

pub(crate) fn request_json_and_octet<T: JsonSchema>(
    mut op: TransformOperation,
) -> TransformOperation {
    // remove automatically created request_body
    op.inner_mut().request_body = None;
    op = op.input::<Json<T>>();
    op = add_octet_request(op);
    op
}

pub(crate) fn request_octet(mut op: TransformOperation) -> TransformOperation {
    // remove automatically created request_body
    op.inner_mut().request_body = None;
    add_octet_request(op)
}

fn add_octet_request(mut op: TransformOperation) -> TransformOperation {
    if let Some(body) = op.inner_mut().request_body.as_mut()
        && let Some(i) = body.as_item_mut()
    {
        i.content.insert(
            "application/octet-stream".to_owned(),
            MediaType {
                schema: Some(SchemaObject {
                    json_schema: schemars::json_schema!({
                        "description": "Raw bytes",
                        "type": ["string"]
                    }),
                    example: None,
                    external_docs: None,
                }),
                ..Default::default()
            },
        );
    }
    op
}

pub(crate) fn ecu_service_response(op: TransformOperation) -> TransformOperation {
    op.response_with::<200, Json<sovd_interfaces::ObjectDataItem<VendorErrorCode>>, _>(|res| {
        let mut res =
            res.description("ECU Response as JSON")
                .example(sovd_interfaces::ObjectDataItem {
                    id: "example_service".to_string(),
                    data: [
                        ("ecu_state".to_owned(), serde_json::json!("active")),
                        ("version".to_owned(), serde_json::json!("1.0.0")),
                        ("manufacturer".to_owned(), serde_json::json!("Example Corp")),
                    ]
                    .into_iter()
                    .collect(),
                    errors: vec![],
                    schema: None,
                });
        res.inner().content.insert(
            "application/octet-stream".to_owned(),
            MediaType {
                example: Some(serde_json::json!([0xABu8, 0xCD, 0xEF, 0x00])),
                ..Default::default()
            },
        );
        res
    })
}

pub(crate) fn lock_not_found(op: TransformOperation) -> TransformOperation {
    op.response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Given lock does not exist.")
    })
}

pub(crate) fn lock_not_owned(op: TransformOperation) -> TransformOperation {
    op.response_with::<403, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Lock is not owned.")
    })
}

pub(crate) fn error_forbidden(op: TransformOperation) -> TransformOperation {
    op.response_with::<403, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description(
            "Forbidden: The SOVD client does not have the right to access the resource.",
        )
        .example(ApiErrorResponse {
            message: "Forbidden".to_string(),
            error_code: sovd_interfaces::error::ErrorCode::InsufficientAccessRights,
            vendor_code: None,
            parameters: None,
            error_source: None,
            schema: None,
        })
    })
}

pub(crate) fn error_not_found(op: TransformOperation) -> TransformOperation {
    op.response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Not Found: The requested resource does not exist.")
            .example(ApiErrorResponse {
                message: "Not found".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::NotFound),
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
}

pub(crate) fn error_bad_gateway(op: TransformOperation) -> TransformOperation {
    op.response_with::<502, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Bad Gateway: ECU responded with an NRC")
            .example(ApiErrorResponse {
                message: "NRC".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::ErrorResponse,
                vendor_code: None,
                parameters: None,
                error_source: Some("ECU".to_string()),
                schema: None,
            })
    })
}

pub(crate) fn error_internal_server(op: TransformOperation) -> TransformOperation {
    op.response_with::<500, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Internal Server Error: An internal error occurred in the SOVD server.")
            .example(ApiErrorResponse {
                message: "Internal Server Error".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::SovdServerFailure,
                vendor_code: None,
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
}

pub(crate) fn error_conflict(op: TransformOperation) -> TransformOperation {
    op.response_with::<409, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Conflict: The preconditions to execute the method are not fulfilled.")
            .example(ApiErrorResponse {
                message: "Conflict".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::PreconditionsNotFulfilled,
                vendor_code: None,
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
}

pub(crate) fn error_bad_request(op: TransformOperation) -> TransformOperation {
    op.response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Bad Request: The request was invalid or cannot be otherwise served.")
            .example(ApiErrorResponse {
                message: "Bad Request".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
}

pub(crate) fn comparam_execution_errors(op: TransformOperation) -> TransformOperation {
    op.response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Id does not exist or execution failed")
            .example(ApiErrorResponse {
                message: "Bad Request".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
    .response_with::<404, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
        res.description("Id does not exist")
            .example(ApiErrorResponse {
                message: "Not Found".to_string(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(sovd::error::VendorErrorCode::NotFound),
                parameters: None,
                error_source: None,
                schema: None,
            })
    })
}

/// What it means for two route groups to define the same key in a given `OpenAPI` map.
///
/// Both cases keep `target`'s entry; they differ only in whether that is worth reporting.
#[derive(Clone, Copy)]
pub(crate) enum Conflict<'a> {
    /// Groups are *expected* to shadow each other here. The request-handling fallback chain
    /// already lets a later-registered group take over a path, and its documentation follows
    /// the same precedence, so a duplicate is the override mechanism working as designed.
    Override,
    /// The key lives in a namespace shared by every group, a `$ref` target and the like,
    /// where a duplicate is a name clash rather than an intentional override. The `&str`
    /// names the map for the warning and appears nowhere else.
    Collision(&'a str),
}

/// Copies entries from `source` that `target` does not already define.
///
/// A key present in both with a *different* definition is resolved in `target`'s favour.
/// Under [`Conflict::Collision`] that is also logged: it is unavoidable in a single flat
/// document, but it silently changes the meaning of every operation in the losing group
/// that references the key. Under [`Conflict::Override`] it is intended and stays silent.
pub(crate) fn insert_missing<V: PartialEq>(
    conflict: Conflict<'_>,
    target: &mut IndexMap<String, V>,
    source: IndexMap<String, V>,
) {
    for (name, value) in source {
        match target.entry(name) {
            indexmap::map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            indexmap::map::Entry::Occupied(entry) => {
                if let Conflict::Collision(section) = conflict
                    && *entry.get() != value
                {
                    tracing::warn!(
                        section,
                        key = %entry.key(),
                        "OpenAPI route groups define the same key with different content; \
                         keeping the later-registered group's definition. Operations from the \
                         earlier group that reference this key now resolve to the wrong \
                         definition -- rename one of the colliding types.",
                    );
                }
            }
        }
    }
}

/// Folds every map of `$source` into the same-named map of `$target` via [`insert_missing`].
///
/// The section label each conflict is reported under is derived from the field itself
/// (`Components.request_bodies`), so there is no hand-written name to drift out of sync.
///
/// `$ty` is destructured without `..` on purpose: a field added to it upstream then fails
/// to compile here instead of being silently dropped from every group after the first,
/// which would surface much later as a dangling `$ref` in the served document.
macro_rules! merge_maps {
    ($target:expr, $source:expr, $ty:ident { $($field:ident),* $(,)? }) => {{
        let $ty { $($field),* } = $source;
        let target = $target;
        $(insert_missing(
            Conflict::Collision(concat!(stringify!($ty), ".", stringify!($field))),
            &mut target.$field,
            $field,
        );)*
    }};
}

/// Merges `source` into `api`, keeping `api`'s entry whenever both define the same key.
///
/// Callers fold groups in reverse registration order, so `api` always holds the
/// *later-registered* group's data: "prefer existing" is how "latest registered wins" is
/// spelled when the accumulator is built latest-first. That matches the precedence of the
/// request-handling fallback chain, so a group that overrides a path also overrides its docs.
pub(crate) fn merge_openapi_prefer_existing(api: &mut OpenApi, mut source: OpenApi) {
    if let Some(source_paths) = source.paths.take() {
        let paths = api.paths.get_or_insert_with(Default::default);
        // A path defined by two groups is the override mechanism, not a clash: the group
        // that wins the fallback chain wins the documentation too.
        insert_missing(Conflict::Override, &mut paths.paths, source_paths.paths);
        insert_missing(
            Conflict::Collision("paths.extensions"),
            &mut paths.extensions,
            source_paths.extensions,
        );
    }
    if let Some(source_components) = source.components.take() {
        merge_maps!(
            api.components.get_or_insert_with(Default::default),
            source_components,
            Components {
                security_schemes,
                responses,
                parameters,
                examples,
                request_bodies,
                headers,
                schemas,
                links,
                callbacks,
                path_items,
                extensions,
            }
        );
    }
    insert_missing(
        Conflict::Collision("webhooks"),
        &mut api.webhooks,
        source.webhooks,
    );
    insert_missing(
        Conflict::Collision("extensions"),
        &mut api.extensions,
        source.extensions,
    );
    for server in source.servers {
        if !api
            .servers
            .iter()
            .any(|existing| existing.url == server.url)
        {
            api.servers.push(server);
        }
    }
    for requirement in source.security {
        if !api.security.contains(&requirement) {
            api.security.push(requirement);
        }
    }
    for tag in source.tags {
        if !api.tags.iter().any(|existing| existing.name == tag.name) {
            api.tags.push(tag);
        }
    }
    if api.info == aide::openapi::Info::default() {
        api.info = source.info;
    }
    if api.json_schema_dialect.is_none() {
        api.json_schema_dialect = source.json_schema_dialect;
    }
    if api.external_docs.is_none() {
        api.external_docs = source.external_docs;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aide::axum::ApiRouter;
    use axum::{body::Body, http::Request};
    use cda_interfaces::{HashMap, ReloadComponent, datatypes::ComponentsConfig, mock::MockUdsEcu};
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use cda_plugin_security::mock::TestSecurityPlugin;
    use tower::ServiceExt;

    use super::{
        Components, OpenApi, SchemaObject, expand_templated_paths, merge_openapi_prefer_existing,
    };
    use crate::sovd::{self, SovdIdentities, SovdLockStateProvider, SovdRegistry};

    /// `route()` clones the `UdsEcu` handle itself (once for `WebserverState`, once for
    /// the final `.with_state()`); `mockall` clones don't inherit expectations, so each
    /// clone needs its own, recursively.
    fn mock_uds(ecus: Vec<String>, groups: Vec<String>) -> MockUdsEcu {
        let mut uds = MockUdsEcu::new();
        let physical_ecus = ecus.clone();
        uds.expect_get_physical_ecus()
            .returning(move || physical_ecus.clone());
        uds.expect_get_ecus()
            .returning(|| vec!["functional_groups".to_owned()]);
        let fg_groups = groups.clone();
        uds.expect_ecu_functional_groups()
            .returning(move |_| Ok(fg_groups.clone()));
        uds.expect_clone()
            .returning(move || mock_uds(ecus.clone(), groups.clone()));
        uds
    }

    /// Builds the vehicle router for a fixed ECU / functional-group set and returns its
    /// normalized instance lists, mirroring what `add_openapi_routes` reads at render time.
    fn build_test_router(
        ecus: &[&str],
        groups: &[&str],
    ) -> (
        ApiRouter,
        Vec<String>,
        Vec<String>,
        SovdRegistry,
        Arc<SovdLockStateProvider>,
    ) {
        let ecus: Vec<String> = ecus.iter().map(|e| e.to_lowercase()).collect();
        let groups: Vec<String> = groups.iter().map(|g| (*g).to_owned()).collect();
        let uds = mock_uds(ecus.clone(), groups.clone());
        let lock_provider = Arc::new(SovdLockStateProvider::new(ecus.clone()));
        let registry = SovdRegistry::new(SovdIdentities::new(
            ecus.iter().cloned().collect(),
            groups.iter().map(|g| g.to_lowercase()).collect(),
        ));
        let router = sovd::route::<MockUdsEcu, TestSecurityPlugin>(
            ComponentsConfig {
                additional_fields: HashMap::default(),
            },
            &uds,
            "/tmp".to_owned(),
            Arc::new(lock_provider.view()),
            enabled_communication_access_for_test(),
            registry.view(),
        );
        (router, ecus, groups, registry, lock_provider)
    }

    fn build_test_api(ecus: &[&str], groups: &[&str]) -> (OpenApi, Vec<String>, Vec<String>) {
        let (router, ecus, groups, _, _) = build_test_router(ecus, groups);
        let mut api = OpenApi::default();
        let _ = router.finish_api(&mut api);
        (api, ecus, groups)
    }

    #[tokio::test]
    async fn removed_instances_return_exact_standard_sovd_not_found() {
        let (router, _, _, registry, _) = build_test_router(&["ECU_A"], &["Group_A"]);
        registry.apply(SovdIdentities::default()).await;
        let router = axum::Router::from(router);
        for path in [
            "/vehicle/v15/components/ecu_a",
            "/vehicle/v15/functions/functionalgroups/group_a",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "message": format!("Resource not found: {path}"),
                    "error_code": "vendor-specific",
                    "vendor_code": "not-found"
                })
            );
        }
    }

    #[tokio::test]
    async fn malformed_instance_paths_return_standard_sovd_not_found() {
        let (router, _, _, _, _) = build_test_router(&["ECU_A"], &["Group_A"]);
        let router = axum::Router::from(router);
        for path in [
            "/vehicle/v15/components/%FF",
            "/vehicle/v15/components/%ZZ",
            "/vehicle/v15/functions/functionalgroups/%FF",
            "/vehicle/v15/functions/functionalgroups/%ZZ",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "message": format!("Resource not found: {path}"),
                    "error_code": "vendor-specific",
                    "vendor_code": "not-found"
                })
            );
        }
    }

    #[tokio::test]
    async fn expansion_replaces_templated_paths_with_one_per_instance() {
        let (mut api, ecus, groups) = build_test_api(&["ecu_b", "ecu_a"], &["Group_B", "Group_A"]);

        let templated = api.paths.as_ref().unwrap();
        assert!(templated.paths.keys().any(|p| p.contains("{component_id}")));
        assert!(
            templated
                .paths
                .keys()
                .any(|p| p.contains("{functional_group_id}"))
        );

        expand_templated_paths(&mut api, &ecus, &groups);

        let paths = &api.paths.as_ref().unwrap().paths;
        assert!(!paths.keys().any(|p| p.contains("{component_id}")));
        assert!(!paths.keys().any(|p| p.contains("{functional_group_id}")));

        for path in [
            "/vehicle/v15/components/ecu_a",
            "/vehicle/v15/components/ecu_b",
            "/vehicle/v15/components/ecu_a/locks",
            "/vehicle/v15/components/ecu_b/data",
            "/vehicle/v15/functions/functionalgroups/group_a",
            "/vehicle/v15/functions/functionalgroups/group_b/locks",
        ] {
            assert!(paths.contains_key(path), "missing expanded path {path}");
        }

        // Stable, name-sorted order regardless of the registration order above
        // (`Paths.paths` emits in insertion order).
        let idx_a = paths.get_index_of("/vehicle/v15/components/ecu_a").unwrap();
        let idx_b = paths.get_index_of("/vehicle/v15/components/ecu_b").unwrap();
        assert!(idx_a < idx_b);
    }

    #[tokio::test]
    async fn expansion_omits_group_instances_but_keeps_empty_collection() {
        let (mut api, ecus, groups) = build_test_api(&["ecu_a"], &[]);

        expand_templated_paths(&mut api, &ecus, &groups);

        let paths = &api.paths.as_ref().unwrap().paths;
        assert!(
            !paths
                .keys()
                .any(|path| path.contains("{functional_group_id}"))
        );
        assert!(!paths.keys().any(|path| path.contains("{*")));
        assert!(paths.contains_key("/vehicle/v15/functions/functionalgroups"));
        assert!(
            !paths
                .keys()
                .any(|path| path.starts_with("/vehicle/v15/functions/functionalgroups/"))
        );
    }

    /// A schema whose only distinguishing feature is its description, so a merged document
    /// says which side's definition survived.
    fn described_schema(description: &str) -> SchemaObject {
        SchemaObject {
            json_schema: schemars::json_schema!({ "description": description }),
            example: None,
            external_docs: None,
        }
    }

    fn api_with_schemas(schemas: &[(&str, &str)]) -> OpenApi {
        let mut components = Components::default();
        for (name, description) in schemas {
            components
                .schemas
                .insert((*name).to_owned(), described_schema(description));
        }
        OpenApi {
            components: Some(components),
            ..Default::default()
        }
    }

    fn schema_description(api: &OpenApi, name: &str) -> String {
        let schema = api
            .components
            .as_ref()
            .expect("merged document has components")
            .schemas
            .get(name)
            .unwrap_or_else(|| panic!("merged document has schema {name}"));
        serde_json::to_value(&schema.json_schema)
            .unwrap()
            .get("description")
            .and_then(serde_json::Value::as_str)
            .expect("schema carries a description")
            .to_owned()
    }

    /// Every route group runs its own schema generator, so components must be unioned
    /// rather than taken from whichever group won the path.
    #[test]
    fn merge_unions_components_across_documents() {
        let mut api = api_with_schemas(&[("Alpha", "alpha")]);

        merge_openapi_prefer_existing(&mut api, api_with_schemas(&[("Beta", "beta")]));

        assert_eq!(schema_description(&api, "Alpha"), "alpha");
        assert_eq!(schema_description(&api, "Beta"), "beta");
    }

    /// Groups generate schemas independently, so two of them can name different types the
    /// same. A single flat document keeps only one: callers fold latest-first, so the entry
    /// already in the accumulator wins, matching the path precedence of the fallback chain.
    #[test]
    fn merge_keeps_existing_on_schema_name_collision() {
        let mut api = api_with_schemas(&[("Conflict", "later")]);

        merge_openapi_prefer_existing(
            &mut api,
            api_with_schemas(&[("Conflict", "earlier"), ("Other", "earlier other")]),
        );

        assert_eq!(schema_description(&api, "Conflict"), "later");
        assert_eq!(
            schema_description(&api, "Other"),
            "earlier other",
            "a collision must not drop the rest of the source document"
        );
    }
}
