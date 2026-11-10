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
    AudienceFilter, CliArgs, DocumentPostProcessor, GenContext, GenerationOptions, Generator,
    GeneratorError, OfflineServiceInfo, PathContributor, VariantSelection,
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
    assert!(
        paths
            .iter()
            .all(|p| p.contains("VIN") || p.ends_with("/x-oem/status")),
        "{paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.ends_with("/data/VINDataIdentifier")),
        "{paths:?}"
    );
    assert_eq!(
        doc.document.info.description.as_deref(),
        Some("OEM FLXC1000")
    );
}

/// [[ test~openapi-gen-cli, CLI writes the documents, test ]]
#[tokio::test]
async fn cli_writes_documents() {
    let dir = tempfile::tempdir().expect("Temp dir");
    let mdd = mdd();
    let args = CliArgs::try_parse_from([
        "opensovd-cda-openapi",
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
    let api: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("Document must exist"))
            .expect("Document must be JSON");
    assert_eq!(
        api.pointer("/openapi").and_then(|v| v.as_str()),
        Some("3.1.0")
    );
    assert_eq!(
        api.pointer("/servers/0/url").and_then(|v| v.as_str()),
        Some("http://localhost:20002")
    );
}
