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

//! Response bodies checked against the shape of the ISO 17978-3 examples.

use std::time::Duration;

use cda_interfaces::HashMap;
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::cda_version;
use serde_json::Value;

use crate::{
    sovd::{self, ECU_FLXC1000_ENDPOINT, locks},
    util::{
        ecusim::{self, DtcMinimal},
        http::{
            QueryParams, auth_header, extract_field_from_json, response_to_json, send_cda_request,
            send_request,
        },
        runtime::{TestRuntime, setup_integration_test},
    },
};

/// Attributes of Table 53 the CDA may report for a component, plus its extensions.
const CAPABILITY_ATTRIBUTES: [&str; 18] = [
    "id",
    "name",
    "translation_id",
    "variant",
    "configurations",
    "bulk-data",
    "data",
    "data-lists",
    "faults",
    "operations",
    "updates",
    "modes",
    "subcomponents",
    "locks",
    "logs",
    "belongs-to",
    "communication-logs",
    "cyclic-subscriptions",
];
const CAPABILITY_EXTENSIONS: [&str; 2] = ["x-single-ecu-jobs", "sdgs"];

/// Status keys of a fault (Table 61 Note, ISO 14229-1 Annex D.2.3).
const FAULT_STATUS_KEYS: [&str; 9] = [
    "testFailed",
    "testFailedThisOperationCycle",
    "pendingDTC",
    "confirmedDTC",
    "testNotCompletedSinceLastClear",
    "testFailedSinceLastClear",
    "testNotCompletedThisOperationCycle",
    "warningIndicatorRequested",
    "mask",
];

async fn get_url(runtime: &TestRuntime, path: &str) -> Value {
    let host = runtime.config.server.address();
    let port = runtime.config.server.port();
    let url = reqwest::Url::parse(&format!("http://{host}:{port}{path}")).expect("Invalid URL");
    let response = send_request(StatusCode::OK, Method::GET, None, None, url)
        .await
        .unwrap_or_else(|e| panic!("GET {path} failed: {e:?}"));
    response_to_json(&response).expect("Failed to parse response")
}

/// §5.6, Tables 36-38: one entry per served version, `base_uri` relative.
#[tokio::test]
async fn test_version_info_matches_standard() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    for path in ["/version-info", "/vehicle/version-info"] {
        let json = get_url(runtime, path).await;
        let sovd_info = json
            .get("sovd_info")
            .and_then(Value::as_array)
            .expect("Missing 'sovd_info' array");
        let base_uris: Vec<&str> = sovd_info
            .iter()
            .map(|info| {
                assert_eq!(info.get("version"), Some(&Value::from("1.1.0")));
                let vendor_info = info.get("vendor_info").expect("Missing 'vendor_info'");
                assert_eq!(
                    vendor_info.get("name"),
                    Some(&Value::from("Eclipse OpenSOVD Classic Diagnostic Adapter"))
                );
                assert_eq!(
                    vendor_info.get("version"),
                    Some(&Value::from(cda_version()))
                );
                info.get("base_uri")
                    .and_then(Value::as_str)
                    .expect("Missing 'base_uri'")
            })
            .collect();
        assert_eq!(base_uris, ["/vehicle/v15", "/vehicle/v1"], "{path}");
    }
}

/// §5.6: the `v1` segment serves the same API as `v15`.
#[tokio::test]
async fn test_version_alias_serves_same_routes() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    let v15 = get_url(runtime, "/vehicle/v15/components").await;
    let v1 = get_url(runtime, "/vehicle/v1/components").await;
    assert_eq!(v15, v1);
}

/// Table 53: only standard attributes (and the documented extensions) are reported,
/// collection links are strings, and `variant` is a map of strings.
#[tokio::test]
async fn test_capability_document_matches_standard() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    let ecu = sovd::get_ecu_component(&runtime.config, ECU_FLXC1000_ENDPOINT, StatusCode::OK, None)
        .await
        .unwrap();
    let ecu = ecu
        .as_object()
        .expect("Capability document is not an object");

    for (key, value) in ecu {
        assert!(
            CAPABILITY_ATTRIBUTES.contains(&key.as_str())
                || CAPABILITY_EXTENSIONS.contains(&key.as_str()),
            "Unexpected attribute '{key}' in capability document"
        );
        if !matches!(key.as_str(), "variant" | "sdgs") {
            assert!(
                value.is_string(),
                "Attribute '{key}' is not a string: {value}"
            );
        }
    }
    for collection in ["locks", "operations", "faults", "modes", "data"] {
        assert!(
            ecu.get(collection).is_some(),
            "Missing '{collection}' link in capability document"
        );
    }

    let variant = ecu
        .get("variant")
        .and_then(Value::as_object)
        .expect("Missing 'variant' map");
    assert!(variant.values().all(Value::is_string), "{variant:?}");
    assert_eq!(variant.get("logical_address"), Some(&Value::from("0x1000")));
    assert!(variant.contains_key("name"));
    assert!(
        !variant.contains_key("state"),
        "Entity state belongs to the status resource"
    );
}

/// §7.19.2 status and §7.19.4 restart, mapped to `ECUReset` (§8.7).
#[tokio::test]
async fn test_entity_status_and_restart() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let status_endpoint = format!("{ECU_FLXC1000_ENDPOINT}/status");
    let restart_endpoint = format!("{status_endpoint}/restart");

    let status = response_to_json(
        &send_cda_request(
            &runtime.config,
            &status_endpoint,
            StatusCode::OK,
            Method::GET,
            None,
            Some(&auth),
            None,
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(status.get("status"), Some(&Value::from("ready")));
    assert_eq!(status.get("x-sovd2uds-state"), Some(&Value::from("Online")));
    assert!(
        status
            .get("restart")
            .and_then(Value::as_str)
            .is_some_and(|href| href.ends_with("/components/flxc1000/status/restart")),
        "Missing restart link: {status}"
    );

    let restart = |reset_type: &'static str, expected: StatusCode, auth: HeaderMap| {
        let config = runtime.config.clone();
        let endpoint = restart_endpoint.clone();
        async move {
            let body = serde_json::json!({ "parameters": { "ResetType": reset_type } });
            send_cda_request(
                &config,
                &endpoint,
                expected,
                Method::PUT,
                Some(&body.to_string()),
                Some(&auth),
                None,
            )
            .await
            .unwrap()
        }
    };

    // Restarting needs write access, i.e. a lock.
    restart("hardreset", StatusCode::CONFLICT, auth.clone()).await;

    let ecu_lock = locks::create_lock(
        Duration::from_secs(60),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    let response = restart("hardreset", StatusCode::ACCEPTED, auth.clone()).await;
    assert!(
        response
            .header(http::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .is_some_and(|location| location.ends_with("/components/flxc1000/status")),
        "Missing Location header pointing at the status resource"
    );

    restart("notareset", StatusCode::BAD_REQUEST, auth.clone()).await;

    locks::lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// Table 61: DTC status keys follow ISO 14229-1, the filter accepts them with `1` and `true`.
#[tokio::test]
async fn test_fault_status_matches_standard() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_name = "flxc1000";
    let fault_memory = "Standard";

    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");
    // pendingDTC and confirmedDTC set.
    ecusim::add_dtc(
        &runtime.ecu_sim,
        ecu_name,
        fault_memory,
        &DtcMinimal {
            id: "039447".into(),
            status_mask: "0C".into(),
            emissions_related: false,
        },
    )
    .await
    .expect("Failed to add DTC");

    for (key, value) in [("pendingDTC", "1"), ("confirmedDTC", "true")] {
        let query = QueryParams(HashMap::from_iter([(
            format!("status[{key}]"),
            value.to_owned(),
        )]));
        let response = send_cda_request(
            &runtime.config,
            &format!("{ECU_FLXC1000_ENDPOINT}/faults"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(&auth),
            Some(&query),
        )
        .await
        .unwrap();
        let json = response_to_json(&response).unwrap();
        let items = json
            .get("items")
            .and_then(Value::as_array)
            .expect("Missing 'items'");
        let fault = items
            .iter()
            .find(|f| f.get("code") == Some(&Value::from("039447")))
            .unwrap_or_else(|| panic!("Filter status[{key}]={value} did not return the DTC"));
        let status = fault
            .get("status")
            .and_then(Value::as_object)
            .expect("Missing fault status");
        for status_key in status.keys() {
            assert!(
                FAULT_STATUS_KEYS.contains(&status_key.as_str()),
                "Unexpected status key '{status_key}'"
            );
        }
        assert_eq!(status.get("pendingDTC"), Some(&Value::Bool(true)));
        assert_eq!(status.get("confirmedDTC"), Some(&Value::Bool(true)));
        assert_eq!(status.get("testFailed"), Some(&Value::Bool(false)));
    }

    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");
}
