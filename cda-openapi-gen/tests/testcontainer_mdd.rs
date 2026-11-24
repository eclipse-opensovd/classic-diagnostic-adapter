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

//! Generates documents from the MDD files of the test container.

use std::path::PathBuf;

use aide::openapi::{OpenApi, PathItem, ReferenceOr};
use cda_openapi_gen::{
    AudienceFilter, CliArgs, DocumentPostProcessor, Endpoint, EndpointContext, EndpointDecorator,
    FaultSchemaDetail, GenContext, GenerationOptions, Generator, GeneratorError,
    OfflineServiceInfo, PathContributor, VariantSelection,
};
use clap::Parser as _;

const ECU: &str = "FLXC1000";
const BASE_PATH: &str = "/vehicle/v15/components/flxc1000";

fn mdd() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testcontainer/odx/FLXC1000.mdd")
}

fn options(variants: VariantSelection) -> GenerationOptions {
    GenerationOptions {
        mdd_path: mdd(),
        variants,
        audiences: AudienceFilter::default(),
        server_url: None,
        config: opensovd_cda_lib::config::load_config(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../testcontainer/cda-test-config.toml"),
        )
        .expect("Test config must load"),
        fault_schemas: FaultSchemaDetail::default(),
    }
}

fn paths(api: &OpenApi) -> Vec<String> {
    api.paths
        .as_ref()
        .map(|p| p.paths.keys().cloned().collect())
        .unwrap_or_default()
}

/// [[ test~openapi-gen-all-variants, One document per variant from a real MDD, test ]]
#[tokio::test]
async fn generates_one_document_per_variant() {
    let docs = Generator::default()
        .generate(&options(VariantSelection::All))
        .await
        .expect("Generation must succeed");

    let names: Vec<_> = docs.iter().map(|d| d.variant.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["FLXC1000", "FLXC1000_Boot_Variant", "FLXC1000_App_0101"]
    );
    for doc in &docs {
        assert_eq!(doc.ecu_name, ECU);
        let paths = paths(&doc.document);
        assert!(
            paths.contains(&format!("{BASE_PATH}/data/VINDataIdentifier")),
            "{paths:?}"
        );
        assert!(
            paths.contains(&format!("{BASE_PATH}/operations/SelfTest/executions")),
            "{paths:?}"
        );
        assert_eq!(
            doc.document.info.extensions.get("x-sovd-ecu-variant"),
            Some(&serde_json::Value::String(doc.variant.name.clone()))
        );
    }
}

/// [[ test~openapi-gen-generic-routes, Generic ECU routes are included and templates replaced, test ]]
#[tokio::test]
async fn generic_ecu_routes_are_included() {
    let docs = Generator::default()
        .generate(&options(VariantSelection::Base))
        .await
        .expect("Generation must succeed");
    let [doc] = docs.as_slice() else {
        panic!("Expected exactly one document for the base variant");
    };
    let paths = paths(&doc.document);
    for generic in [
        "",
        "/data",
        "/operations",
        "/locks",
        "/locks/{lock}",
        "/modes/session",
        "/faults",
        "/genericservice",
    ] {
        assert!(
            paths.contains(&format!("{BASE_PATH}{generic}")),
            "Missing {generic}: {paths:?}"
        );
    }
    // Templates are replaced by the concrete per-service paths, vehicle level
    // routes (functions, vehicle locks) are not part of an ECU document.
    assert!(paths.iter().all(|p| !p.contains("{service}")), "{paths:?}");
    assert!(paths.iter().all(|p| !p.contains("{job_name}")), "{paths:?}");
    assert!(paths.iter().all(|p| p.starts_with(BASE_PATH)), "{paths:?}");
    // All per-resource routes of the CDA exist for every resource.
    for resource in ["/data/VINDataIdentifier", "/operations/SelfTest"] {
        for suffix in ["", "/docs"] {
            let path = format!("{BASE_PATH}{resource}{suffix}");
            assert!(paths.contains(&path), "Missing {path}: {paths:?}");
        }
    }
    // The path parameter of an instantiated template is removed.
    let docs_get = doc
        .document
        .paths
        .as_ref()
        .and_then(|p| {
            p.paths
                .get(&format!("{BASE_PATH}/data/VINDataIdentifier/docs"))
        })
        .and_then(|i| match i {
            ReferenceOr::Item(i) => i.get.as_ref(),
            ReferenceOr::Reference { .. } => None,
        })
        .expect("docs GET");
    assert!(
        docs_get
            .parameters
            .iter()
            .all(|p| !matches!(p, ReferenceOr::Item(aide::openapi::Parameter::Path { .. }))),
        "{:?}",
        docs_get.parameters
    );
    // Schemas referenced by the generic routes are contained.
    assert!(
        doc.document
            .components
            .as_ref()
            .is_some_and(|c| c.schemas.contains_key("ApiErrorResponse"))
    );
}

/// [[ test~openapi-gen-unknown-variant, Unknown variant lists the available variants, test ]]
#[tokio::test]
async fn unknown_variant_fails_with_available_variants() {
    let err = Generator::default()
        .generate(&options(VariantSelection::Named(vec!["Nope".to_owned()])))
        .await
        .expect_err("Unknown variant must fail");
    assert!(
        matches!(&err, GeneratorError::Variant(msg) if msg.contains("FLXC1000_App_0101")),
        "{err}"
    );
}

struct ExtraPath;
impl PathContributor for ExtraPath {
    fn contribute(&self, ctx: &GenContext<'_>, api: &mut OpenApi) -> Result<(), GeneratorError> {
        api.paths.get_or_insert_default().paths.insert(
            format!("{}/x-oem/status", ctx.ecu_base_path),
            ReferenceOr::Item(PathItem::default()),
        );
        Ok(())
    }
}

struct SetDescription;
impl DocumentPostProcessor for SetDescription {
    fn process(&self, ctx: &GenContext<'_>, api: &mut OpenApi) -> Result<(), GeneratorError> {
        // Post processors run after the path contributors.
        assert!(paths(api).iter().any(|p| p.ends_with("/x-oem/status")));
        api.info.description = Some(format!("OEM {}", ctx.variant.name));
        Ok(())
    }
}

/// [[ test~openapi-gen-extensions, OEM filter and path contributor and post processor are applied, test ]]
#[tokio::test]
async fn extension_points_are_applied() {
    let only_vin = |_: &cda_openapi_gen::FilterContext<'_>, s: &OfflineServiceInfo| {
        s.short_name.contains("VIN")
    };
    let docs = Generator::builder()
        .with_service_filter(only_vin)
        .add_path_contributor(ExtraPath)
        .add_post_processor(SetDescription)
        .build()
        .generate(&options(VariantSelection::Base))
        .await
        .expect("Generation must succeed");

    let [doc] = docs.as_slice() else {
        panic!("Expected exactly one document for the base variant");
    };
    let paths = paths(&doc.document);
    let services: Vec<_> = paths
        .iter()
        .filter(|p| p.contains("/data/") || p.ends_with("/executions"))
        .filter(|p| !p.contains("/comparam/"))
        .collect();
    assert!(services.iter().all(|p| p.contains("VIN")), "{services:?}");
    assert!(
        paths.iter().any(|p| p.ends_with("/data/VINDataIdentifier")),
        "{paths:?}"
    );
    assert_eq!(
        doc.document.info.description.as_deref(),
        Some("OEM FLXC1000")
    );
}

struct DescribeData;
impl EndpointDecorator for DescribeData {
    fn decorate(
        &self,
        ctx: &EndpointContext<'_>,
        _path: &str,
        item: &mut PathItem,
    ) -> Result<(), GeneratorError> {
        let Endpoint::Data { id, services } = ctx.endpoint else {
            return Ok(());
        };
        // The MDD service is accessible, e.g. to read its long name.
        let long_name = services
            .iter()
            .find_map(|s| s.diag_comm()?.long_name()?.value())
            .unwrap_or_default();
        item.description = Some(format!("{id}: {long_name}"));
        item.extensions
            .insert("x-oem-services".to_owned(), services.len().into());
        Ok(())
    }
}

/// [[ test~openapi-gen-endpoint-decorator, Endpoint decorator gets the MDD services, test ]]
#[tokio::test]
async fn endpoint_decorator_is_applied() {
    let docs = Generator::builder()
        .add_endpoint_decorator(DescribeData)
        .build()
        .generate(&options(VariantSelection::Base))
        .await
        .expect("Generation must succeed");
    let [doc] = docs.as_slice() else {
        panic!("Expected exactly one document for the base variant");
    };
    let items = &doc.document.paths.as_ref().expect("paths").paths;
    let item = |path: &str| match items.get(&format!("{BASE_PATH}{path}")) {
        Some(ReferenceOr::Item(item)) => item.clone(),
        _ => panic!("Missing {path}"),
    };
    for path in ["/data/VINDataIdentifier", "/data/VINDataIdentifier/docs"] {
        let decorated = item(path);
        assert!(
            decorated
                .description
                .as_deref()
                .is_some_and(|d| d.starts_with("VINDataIdentifier: ") && d.len() > 19),
            "{path}: {:?}",
            decorated.description
        );
        assert!(
            decorated
                .extensions
                .get("x-oem-services")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|n| n >= 1),
            "{path}"
        );
    }
    assert!(item("/operations/SelfTest").description.is_none());
}

/// [[ test~openapi-gen-cli, CLI writes the documents, test ]]
#[tokio::test]
async fn cli_writes_documents() {
    let dir = tempfile::tempdir().expect("Temp dir");
    let mdd = mdd();
    let args = CliArgs::try_parse_from([
        "cda-openapi-gen",
        "--mdd",
        mdd.to_str().expect("UTF-8 path"),
        "--variant",
        "FLXC1000_App_0101",
        "--audience",
        "aftersales",
        "--server-url",
        "http://localhost:20002",
        "--output-dir",
        dir.path().to_str().expect("UTF-8 path"),
    ])
    .expect("Arguments must parse");

    Generator::default()
        .run(&args)
        .await
        .expect("Run must succeed");

    let file = dir.path().join("FLXC1000_FLXC1000_App_0101.openapi.json");
    let text = std::fs::read_to_string(&file).expect("Document must exist");
    // Compact JSON by default.
    assert_eq!(text.lines().count(), 1);
    let api: serde_json::Value = serde_json::from_str(&text).expect("Document must be JSON");
    assert_eq!(
        api.pointer("/openapi").and_then(|v| v.as_str()),
        Some("3.1.0")
    );
    assert_eq!(
        api.pointer("/servers/0/url").and_then(|v| v.as_str()),
        Some("http://localhost:20002")
    );
}

/// [[ test~openapi-gen-cli-pretty, CLI writes indented JSON on request, test ]]
#[tokio::test]
async fn cli_writes_pretty_json_on_request() {
    let dir = tempfile::tempdir().expect("Temp dir");
    let file = dir.path().join("doc.json");
    let mdd = mdd();
    let args = CliArgs::try_parse_from([
        "cda-openapi-gen",
        "--mdd",
        mdd.to_str().expect("UTF-8 path"),
        "--pretty",
        "--output",
        file.to_str().expect("UTF-8 path"),
    ])
    .expect("Arguments must parse");
    Generator::default()
        .run(&args)
        .await
        .expect("Run must succeed");
    let text = std::fs::read_to_string(&file).expect("Document must exist");
    assert!(text.lines().count() > 1);
}

fn collect_refs<'a>(value: &'a serde_json::Value, refs: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                match v {
                    serde_json::Value::String(r) if key == "$ref" => refs.push(r),
                    _ => collect_refs(v, refs),
                }
            }
        }
        serde_json::Value::Array(list) => list.iter().for_each(|v| collect_refs(v, refs)),
        _ => {}
    }
}

/// [[ test~openapi-gen-shared-schemas, Schemas are shared via the components, test ]]
#[tokio::test]
async fn schemas_are_shared_via_components() {
    let docs = Generator::default()
        .generate(&options(VariantSelection::Base))
        .await
        .expect("Generation must succeed");
    let [doc] = docs.as_slice() else {
        panic!("Expected exactly one document for the base variant");
    };
    let value = serde_json::to_value(&doc.document).expect("Serializable");

    let schema = value
        .pointer(&format!(
            "/paths/{}/get/responses/200/content/application~1json/schema",
            format!("{BASE_PATH}/data/VINDataIdentifier").replace('/', "~1")
        ))
        .expect("Response schema");
    let reference = schema
        .get("$ref")
        .and_then(serde_json::Value::as_str)
        .expect("Response schema must be a reference");
    assert!(
        reference.starts_with("#/components/schemas/"),
        "{reference}"
    );

    // Every reference resolves within the document and no local definitions are left.
    let mut refs = Vec::new();
    collect_refs(&value, &mut refs);
    for r in refs {
        let pointer = r.strip_prefix('#').expect("Local reference");
        assert!(value.pointer(pointer).is_some(), "Unresolved {r}");
    }
    assert!(
        value
            .pointer("/paths")
            .is_some_and(|p| !p.to_string().contains("$defs"))
    );
    // Only JSON Schema keywords, e.g. `anyOf` and not `any-of`.
    assert!(!value.to_string().contains("\"any-of\""));
}

/// [[ test~openapi-gen-unique-operation-ids, Operation ids are unique, test ]]
#[tokio::test]
async fn operation_ids_are_unique() {
    let docs = Generator::default()
        .generate(&options(VariantSelection::All))
        .await
        .expect("Generation must succeed");
    for doc in &docs {
        let value = serde_json::to_value(&doc.document).expect("Serializable");
        let mut seen = std::collections::HashSet::new();
        for item in value
            .get("paths")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flat_map(|p| p.values())
        {
            for op in item.as_object().into_iter().flat_map(|i| i.values()) {
                if let Some(id) = op.get("operationId").and_then(serde_json::Value::as_str) {
                    assert!(seen.insert(id.to_owned()), "Duplicate operation id {id}");
                }
            }
        }
    }
}

async fn fault_details_schema(detail: FaultSchemaDetail) -> serde_json::Value {
    let mut options = options(VariantSelection::Base);
    options.fault_schemas = detail;
    let docs = Generator::default()
        .generate(&options)
        .await
        .expect("Generation must succeed");
    let [doc] = docs.as_slice() else {
        panic!("Expected exactly one document for the base variant");
    };
    let value = serde_json::to_value(&doc.document).expect("Serializable");
    let mut schema = value
        .pointer(&format!(
            "/paths/{}/get/responses/200/content/application~1json/schema",
            format!("{BASE_PATH}/faults/{{id}}").replace('/', "~1")
        ))
        .cloned()
        .expect("Fault details schema");
    // Resolve the shared component references to inspect the content.
    resolve(&mut schema, &value);
    schema
}

fn resolve(schema: &mut serde_json::Value, doc: &serde_json::Value) {
    if let Some(target) = schema
        .get("$ref")
        .and_then(serde_json::Value::as_str)
        .and_then(|r| r.strip_prefix('#'))
        .and_then(|p| doc.pointer(p))
    {
        *schema = target.clone();
    }
    match schema {
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| resolve(v, doc)),
        serde_json::Value::Array(list) => list.iter_mut().for_each(|v| resolve(v, doc)),
        _ => {}
    }
}

const SNAPSHOT_ENTRY: &str = "/properties/environment_data/anyOf/0/properties/snapshots/anyOf/0/\
                              properties/data/additionalProperties/properties/DTCSnapshotRecord/\
                              items";

/// [[ test~openapi-gen-fault-environment-data, Fault environment data uses the MDD types, test ]]
#[tokio::test]
async fn fault_snapshots_use_the_mdd_data_types() {
    let full = fault_details_schema(FaultSchemaDetail::Full).await;
    let entry = full
        .pointer(SNAPSHOT_ENTRY)
        .unwrap_or_else(|| panic!("{full:#}"));
    // FLXC1000 snapshot records consist of a DID and its data.
    assert!(
        entry.pointer("/properties/DTCSnapshotRecordDid").is_some(),
        "{entry:#}"
    );

    let generic = fault_details_schema(FaultSchemaDetail::Generic).await;
    assert_eq!(
        generic.pointer(SNAPSHOT_ENTRY),
        Some(&serde_json::Value::Bool(true))
    );
}
