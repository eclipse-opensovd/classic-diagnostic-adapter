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
        Contact, License, MediaType, OpenApi, PathItem, ReferenceOr, SchemaObject, Server, Tag,
    },
    transform::{TransformOpenApi, TransformOperation},
};
use axum::Json;
use cda_interfaces::{FunctionalDescriptionConfig, UdsEcu};
use indexmap::IndexMap;
use schemars::JsonSchema;
use sovd_interfaces::error::ApiErrorResponse;

use crate::sovd::{self, error::VendorErrorCode};

/// Reads the effective functional groups and builds their normalized route index.
/// The original database spelling is retained as the value.
///
/// # Errors
/// Returns a message describing why no groups are available: the functional
/// description database is not loaded, or the lookup against it failed.
pub(crate) async fn functional_group_index<T: UdsEcu>(
    uds: &T,
    config: &FunctionalDescriptionConfig,
) -> Result<cda_interfaces::HashMap<String, String>, String> {
    let database = uds
        .get_ecus()
        .await
        .into_iter()
        .find(|ecu| ecu.eq_ignore_ascii_case(&config.description_database))
        .ok_or_else(|| {
            format!(
                "Functional Description Database '{}' is missing from loaded databases.",
                config.description_database
            )
        })?;
    let groups = uds.ecu_functional_groups(&database).await.map_err(|e| {
        format!("Failed to get functional groups from functional description database: {e}")
    })?;
    Ok(groups
        .into_iter()
        .filter(|group| {
            config
                .enabled_functional_groups
                .as_ref()
                .is_none_or(|enabled| enabled.iter().any(|name| name.eq_ignore_ascii_case(group)))
        })
        .map(|group| (group.to_lowercase(), group))
        .collect())
}

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
    expand_placeholder(&mut paths.paths, "{component_id}", ecus);
    expand_placeholder(&mut paths.paths, "{functional_group_id}", functional_groups);
}

fn expand_placeholder<'a>(
    paths: &mut IndexMap<String, ReferenceOr<PathItem>>,
    placeholder: &str,
    names: impl IntoIterator<Item = &'a String>,
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
            expanded.insert(path.replace(placeholder, name), item.clone());
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use aide::axum::ApiRouter;
    use axum::{body::Body, http::Request};
    use cda_interfaces::{
        FunctionalDescriptionConfig, HashMap, datatypes::ComponentsConfig, mock::MockUdsEcu,
        runtime_update_api::VehicleDatabaseLockUpdater,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use cda_plugin_security::mock::TestSecurityPlugin;
    use tower::ServiceExt;

    use super::{OpenApi, expand_templated_paths, functional_group_index};
    use crate::sovd::{self, SovdLockStateProvider, SovdRegistry};

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
    async fn build_test_router(
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
        let registry = SovdRegistry::default();
        let lock_provider = Arc::new(SovdLockStateProvider::new(ecus.clone()));
        let router = sovd::route::<MockUdsEcu, TestSecurityPlugin>(
            FunctionalDescriptionConfig::default(),
            ComponentsConfig {
                additional_fields: HashMap::default(),
            },
            &uds,
            "/tmp".to_owned(),
            Arc::clone(&lock_provider),
            enabled_communication_access_for_test(),
            registry.clone(),
        )
        .await;
        (router, ecus, groups, registry, lock_provider)
    }

    async fn build_test_api(ecus: &[&str], groups: &[&str]) -> (OpenApi, Vec<String>, Vec<String>) {
        let (router, ecus, groups, _, _) = build_test_router(ecus, groups).await;
        let mut api = OpenApi::default();
        let _ = router.finish_api(&mut api);
        (api, ecus, groups)
    }

    fn documented_methods(item: &serde_json::Value) -> Vec<&str> {
        let mut methods: Vec<_> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|key| ["delete", "get", "patch", "post", "put"].contains(key))
            .collect();
        methods.sort_unstable();
        methods
    }

    fn expected_methods(path: &str) -> &'static [&'static str] {
        let ecu_suffix = path
            .strip_prefix("/vehicle/v15/components/ecu_a")
            .or_else(|| path.strip_prefix("/vehicle/v15/components/ecu_b"));
        if let Some(suffix) = ecu_suffix {
            return match suffix {
                "" => &["get", "post", "put"],
                "/locks"
                | "/operations/comparam/executions"
                | "/operations/{service}/executions"
                | "/x-sovd2uds-download/flashtransfer" => &["get", "post"],
                "/locks/{lock}" | "/operations/comparam/executions/{id}" => {
                    &["delete", "get", "put"]
                }
                "/configurations/{service}"
                | "/data/{service}"
                | "/modes/commctrl"
                | "/modes/dtcsetting"
                | "/modes/security"
                | "/modes/session" => &["get", "put"],
                "/operations/{service}/executions/{id}"
                | "/x-sovd2uds-download/flashtransfer/{id}"
                | "/faults"
                | "/faults/{id}" => &["delete", "get"],
                "/genericservice"
                | "/x-sovd2uds-download/requestdownload"
                | "/x-sovd2uds-download/transferexit" => &["put"],
                "/configurations"
                | "/configurations/{service}/docs"
                | "/data"
                | "/data/{service}/docs"
                | "/operations"
                | "/operations/{service}"
                | "/operations/{service}/docs"
                | "/modes"
                | "/x-single-ecu-jobs"
                | "/x-single-ecu-jobs/{job_name}"
                | "/x-sovd2uds-bulk-data"
                | "/x-sovd2uds-bulk-data/mdd-embedded-files"
                | "/x-sovd2uds-bulk-data/mdd-embedded-files/{id}"
                | "/x-sovd2uds-download" => &["get"],
                _ => panic!("missing expected ECU methods for {path}"),
            };
        }

        if let Some(suffix) = path.strip_prefix("/vehicle/v15/functions/functionalgroups/group_") {
            let suffix = suffix.strip_prefix(['a', 'b']).unwrap();
            return match suffix {
                "" | "/data" | "/operations" | "/operations/{service}/docs" | "/modes" => &["get"],
                "/locks" | "/operations/{service}/executions" => &["get", "post"],
                "/locks/{lock}" => &["delete", "get", "put"],
                "/data/{service}" | "/modes/commctrl" | "/modes/dtcsetting" | "/modes/session" => {
                    &["get", "put"]
                }
                "/operations/{operation}/executions/{id}" => &["delete", "get"],
                _ => panic!("missing expected functional-group methods for {path}"),
            };
        }

        match path {
            "/vehicle/v15/authorize" => &["post"],
            "/vehicle/v15/locks" => &["get", "post"],
            "/vehicle/v15/locks/{lock}" => &["delete", "get", "put"],
            "/vehicle/v15/apps"
            | "/vehicle/v15/apps/sovd2uds"
            | "/vehicle/v15/apps/sovd2uds/bulk-data"
            | "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles"
            | "/vehicle/v15/apps/sovd2uds/data/networkstructure"
            | "/vehicle/v15/components"
            | "/vehicle/v15/functions"
            | "/vehicle/v15/functions/functionalgroups" => &["get"],
            _ => panic!("missing expected methods for {path}"),
        }
    }

    #[tokio::test]
    async fn removed_instances_return_exact_standard_sovd_not_found() {
        let (router, _, _, registry, _) = build_test_router(&["ECU_A"], &["Group_A"]).await;
        registry.apply(HashMap::default(), HashMap::default());
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
        let (router, _, _, _, _) = build_test_router(&["ECU_A"], &["Group_A"]).await;
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

    /// A request held up resolving locks reads the registry afterwards, so an
    /// ECU removed while it waited is not served.
    #[tokio::test]
    async fn request_waiting_on_locks_reads_the_registry_afterwards() {
        let (router, _, _, registry, lock_provider) =
            build_test_router(&["ECU_A"], &["Group_A"]).await;
        lock_provider
            .update_lock_resources(Vec::new())
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        lock_provider.set_resolution_barrier(Arc::clone(&barrier));

        let request = tokio::spawn(
            axum::Router::from(router).oneshot(
                Request::builder()
                    .uri("/vehicle/v15/components/ecu_a")
                    .body(Body::empty())
                    .unwrap(),
            ),
        );
        // Apply before releasing the barrier, so the waiting request is
        // guaranteed to resolve against the emptied registry.
        registry.apply(HashMap::default(), HashMap::default());
        barrier.wait().await;

        let response = request.await.unwrap().unwrap();
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn expansion_replaces_templated_paths_with_one_per_instance() {
        let (mut api, ecus, groups) =
            build_test_api(&["ecu_b", "ecu_a"], &["Group_B", "Group_A"]).await;

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

    /// Pins the complete emitted path set, so a path silently disappearing or
    /// appearing during expansion fails here rather than in a client.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "The exact route manifest is clearest as one complete assertion"
    )]
    async fn expansion_emits_exactly_the_expected_path_set() {
        const EXPECTED: &[&str] = &[
            "/vehicle/v15/apps",
            "/vehicle/v15/apps/sovd2uds",
            "/vehicle/v15/apps/sovd2uds/bulk-data",
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            "/vehicle/v15/authorize",
            "/vehicle/v15/components",
            "/vehicle/v15/components/ecu_a",
            "/vehicle/v15/components/ecu_a/configurations",
            "/vehicle/v15/components/ecu_a/configurations/{service}",
            "/vehicle/v15/components/ecu_a/configurations/{service}/docs",
            "/vehicle/v15/components/ecu_a/data",
            "/vehicle/v15/components/ecu_a/data/{service}",
            "/vehicle/v15/components/ecu_a/data/{service}/docs",
            "/vehicle/v15/components/ecu_a/faults",
            "/vehicle/v15/components/ecu_a/faults/{id}",
            "/vehicle/v15/components/ecu_a/genericservice",
            "/vehicle/v15/components/ecu_a/locks",
            "/vehicle/v15/components/ecu_a/locks/{lock}",
            "/vehicle/v15/components/ecu_a/modes",
            "/vehicle/v15/components/ecu_a/modes/commctrl",
            "/vehicle/v15/components/ecu_a/modes/dtcsetting",
            "/vehicle/v15/components/ecu_a/modes/security",
            "/vehicle/v15/components/ecu_a/modes/session",
            "/vehicle/v15/components/ecu_a/operations",
            "/vehicle/v15/components/ecu_a/operations/comparam/executions",
            "/vehicle/v15/components/ecu_a/operations/comparam/executions/{id}",
            "/vehicle/v15/components/ecu_a/operations/{service}",
            "/vehicle/v15/components/ecu_a/operations/{service}/docs",
            "/vehicle/v15/components/ecu_a/operations/{service}/executions",
            "/vehicle/v15/components/ecu_a/operations/{service}/executions/{id}",
            "/vehicle/v15/components/ecu_a/x-single-ecu-jobs",
            "/vehicle/v15/components/ecu_a/x-single-ecu-jobs/{job_name}",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-bulk-data",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-bulk-data/mdd-embedded-files",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-bulk-data/mdd-embedded-files/{id}",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-download",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-download/flashtransfer",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-download/flashtransfer/{id}",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-download/requestdownload",
            "/vehicle/v15/components/ecu_a/x-sovd2uds-download/transferexit",
            "/vehicle/v15/components/ecu_b",
            "/vehicle/v15/components/ecu_b/configurations",
            "/vehicle/v15/components/ecu_b/configurations/{service}",
            "/vehicle/v15/components/ecu_b/configurations/{service}/docs",
            "/vehicle/v15/components/ecu_b/data",
            "/vehicle/v15/components/ecu_b/data/{service}",
            "/vehicle/v15/components/ecu_b/data/{service}/docs",
            "/vehicle/v15/components/ecu_b/faults",
            "/vehicle/v15/components/ecu_b/faults/{id}",
            "/vehicle/v15/components/ecu_b/genericservice",
            "/vehicle/v15/components/ecu_b/locks",
            "/vehicle/v15/components/ecu_b/locks/{lock}",
            "/vehicle/v15/components/ecu_b/modes",
            "/vehicle/v15/components/ecu_b/modes/commctrl",
            "/vehicle/v15/components/ecu_b/modes/dtcsetting",
            "/vehicle/v15/components/ecu_b/modes/security",
            "/vehicle/v15/components/ecu_b/modes/session",
            "/vehicle/v15/components/ecu_b/operations",
            "/vehicle/v15/components/ecu_b/operations/comparam/executions",
            "/vehicle/v15/components/ecu_b/operations/comparam/executions/{id}",
            "/vehicle/v15/components/ecu_b/operations/{service}",
            "/vehicle/v15/components/ecu_b/operations/{service}/docs",
            "/vehicle/v15/components/ecu_b/operations/{service}/executions",
            "/vehicle/v15/components/ecu_b/operations/{service}/executions/{id}",
            "/vehicle/v15/components/ecu_b/x-single-ecu-jobs",
            "/vehicle/v15/components/ecu_b/x-single-ecu-jobs/{job_name}",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-bulk-data",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-bulk-data/mdd-embedded-files",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-bulk-data/mdd-embedded-files/{id}",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-download",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-download/flashtransfer",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-download/flashtransfer/{id}",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-download/requestdownload",
            "/vehicle/v15/components/ecu_b/x-sovd2uds-download/transferexit",
            "/vehicle/v15/functions",
            "/vehicle/v15/functions/functionalgroups",
            "/vehicle/v15/functions/functionalgroups/group_a",
            "/vehicle/v15/functions/functionalgroups/group_a/data",
            "/vehicle/v15/functions/functionalgroups/group_a/data/{service}",
            "/vehicle/v15/functions/functionalgroups/group_a/locks",
            "/vehicle/v15/functions/functionalgroups/group_a/locks/{lock}",
            "/vehicle/v15/functions/functionalgroups/group_a/modes",
            "/vehicle/v15/functions/functionalgroups/group_a/modes/commctrl",
            "/vehicle/v15/functions/functionalgroups/group_a/modes/dtcsetting",
            "/vehicle/v15/functions/functionalgroups/group_a/modes/session",
            "/vehicle/v15/functions/functionalgroups/group_a/operations",
            "/vehicle/v15/functions/functionalgroups/group_a/operations/{operation}/executions/\
             {id}",
            "/vehicle/v15/functions/functionalgroups/group_a/operations/{service}/docs",
            "/vehicle/v15/functions/functionalgroups/group_a/operations/{service}/executions",
            "/vehicle/v15/functions/functionalgroups/group_b",
            "/vehicle/v15/functions/functionalgroups/group_b/data",
            "/vehicle/v15/functions/functionalgroups/group_b/data/{service}",
            "/vehicle/v15/functions/functionalgroups/group_b/locks",
            "/vehicle/v15/functions/functionalgroups/group_b/locks/{lock}",
            "/vehicle/v15/functions/functionalgroups/group_b/modes",
            "/vehicle/v15/functions/functionalgroups/group_b/modes/commctrl",
            "/vehicle/v15/functions/functionalgroups/group_b/modes/dtcsetting",
            "/vehicle/v15/functions/functionalgroups/group_b/modes/session",
            "/vehicle/v15/functions/functionalgroups/group_b/operations",
            "/vehicle/v15/functions/functionalgroups/group_b/operations/{operation}/executions/\
             {id}",
            "/vehicle/v15/functions/functionalgroups/group_b/operations/{service}/docs",
            "/vehicle/v15/functions/functionalgroups/group_b/operations/{service}/executions",
            "/vehicle/v15/locks",
            "/vehicle/v15/locks/{lock}",
        ];

        let (mut api, ecus, groups) =
            build_test_api(&["ecu_b", "ecu_a"], &["Group_B", "Group_A"]).await;
        expand_templated_paths(&mut api, &ecus, &groups);

        let mut actual: Vec<&str> = api
            .paths
            .as_ref()
            .expect("document has paths")
            .paths
            .keys()
            .map(String::as_str)
            .collect();
        actual.sort_unstable();

        let missing: Vec<&&str> = EXPECTED.iter().filter(|p| !actual.contains(p)).collect();
        let unexpected: Vec<&&str> = actual.iter().filter(|p| !EXPECTED.contains(p)).collect();
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "path set drifted\nmissing: {missing:#?}\nunexpected: {unexpected:#?}"
        );
        assert_eq!(actual, EXPECTED);

        let document = serde_json::to_value(&api).unwrap();
        let paths = document.get("paths").unwrap().as_object().unwrap();
        for (path, item) in paths {
            assert_eq!(
                documented_methods(item),
                expected_methods(path),
                "method set drifted for {path}"
            );
        }
    }

    #[tokio::test]
    async fn expansion_omits_group_instances_but_keeps_empty_collection() {
        let (mut api, ecus, groups) = build_test_api(&["ecu_a"], &[]).await;

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

    #[tokio::test]
    async fn expansion_with_no_instances_has_exact_path_and_method_set() {
        const EXPECTED: &[&str] = &[
            "/vehicle/v15/apps",
            "/vehicle/v15/apps/sovd2uds",
            "/vehicle/v15/apps/sovd2uds/bulk-data",
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles",
            "/vehicle/v15/apps/sovd2uds/data/networkstructure",
            "/vehicle/v15/authorize",
            "/vehicle/v15/components",
            "/vehicle/v15/functions",
            "/vehicle/v15/functions/functionalgroups",
            "/vehicle/v15/locks",
            "/vehicle/v15/locks/{lock}",
        ];
        let (mut api, ecus, groups) = build_test_api(&[], &[]).await;
        expand_templated_paths(&mut api, &ecus, &groups);
        let document = serde_json::to_value(&api).unwrap();
        let paths = document.get("paths").unwrap().as_object().unwrap();
        let mut actual: Vec<_> = paths.keys().map(String::as_str).collect();
        actual.sort_unstable();
        assert_eq!(actual, EXPECTED);
        for (path, item) in paths {
            assert!(!path.contains("{*"), "wildcard path emitted: {path}");
            assert_eq!(
                documented_methods(item),
                expected_methods(path),
                "method set drifted for {path}"
            );
        }
    }

    #[tokio::test]
    async fn every_documented_method_is_served_and_declares_remaining_templates() {
        let (router, ecus, groups, _, _) = build_test_router(&["ECU_A"], &["Group_A"]).await;
        let handler_hits = Arc::new(AtomicUsize::new(0));
        let instrumented_hits = Arc::clone(&handler_hits);
        let serving_router =
            axum::Router::from(router.clone()).route_layer(axum::middleware::from_fn(
                move |request: Request<Body>, next: axum::middleware::Next| {
                    let hits = Arc::clone(&instrumented_hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        next.run(request).await
                    }
                },
            ));
        let mut api = OpenApi::default();
        let _ = router.finish_api(&mut api);
        expand_templated_paths(&mut api, &ecus, &groups);
        let document = serde_json::to_value(&api).unwrap();
        let paths = document
            .get("paths")
            .and_then(serde_json::Value::as_object)
            .unwrap();

        for (path, item) in paths {
            assert!(!path.contains("{*"), "wildcard path emitted: {path}");
            let path_parameters = item
                .get("parameters")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten();
            for method in ["get", "put", "post", "delete", "patch", "head", "options"] {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                for parameter in path
                    .split('{')
                    .skip(1)
                    .filter_map(|suffix| suffix.split_once('}').map(|(name, _)| name))
                {
                    let declared = path_parameters
                        .clone()
                        .chain(
                            operation
                                .get("parameters")
                                .and_then(serde_json::Value::as_array)
                                .into_iter()
                                .flatten(),
                        )
                        .any(|entry| {
                            entry.get("name").and_then(serde_json::Value::as_str) == Some(parameter)
                                && entry.get("in").and_then(serde_json::Value::as_str)
                                    == Some("path")
                        });
                    assert!(declared, "{method} {path} does not declare {{{parameter}}}");
                }
                assert!(
                    http::Method::from_bytes(method.to_uppercase().as_bytes()).is_ok(),
                    "documented method is invalid: {method} {path}"
                );
            }
        }

        let hits_before = handler_hits.load(Ordering::SeqCst);
        let representative = serving_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/vehicle/v15/apps")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            representative.status(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(handler_hits.load(Ordering::SeqCst) > hits_before);

        let unknown = serving_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/not-a-documented-route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown.status(), http::StatusCode::NOT_FOUND);

        let wrong_method = serving_router
            .oneshot(
                Request::builder()
                    .method(http::Method::PATCH)
                    .uri("/vehicle/v15/apps")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_method.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn functional_group_index_filters_and_normalizes_by_config() {
        let mut uds = MockUdsEcu::new();
        uds.expect_get_ecus()
            .returning(|| vec!["functional_groups".to_owned()]);
        uds.expect_ecu_functional_groups()
            .returning(|_| Ok(vec!["Group_A".to_owned(), "Group_B".to_owned()]));

        let config = FunctionalDescriptionConfig {
            enabled_functional_groups: Some(["Group_B".to_owned()].into_iter().collect()),
            ..FunctionalDescriptionConfig::default()
        };

        let groups = functional_group_index(&uds, &config).await.unwrap();
        assert_eq!(groups.get("group_b").map(String::as_str), Some("Group_B"));
        assert_eq!(groups.len(), 1);
    }

    #[tokio::test]
    async fn functional_group_index_errors_when_database_missing() {
        let mut uds = MockUdsEcu::new();
        uds.expect_get_ecus().returning(Vec::new);

        let result = functional_group_index(&uds, &FunctionalDescriptionConfig::default()).await;
        assert!(result.is_err());
    }
}
