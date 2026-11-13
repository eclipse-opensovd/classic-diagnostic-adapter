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

//! Discovery: a client that follows the links starting at the vehicle root must not run
//! into a dead link.

use std::collections::{BTreeSet, VecDeque};

use http::{Method, StatusCode};

use crate::util::{
    http::{Response, extract_field_from_json, response_to_json, send_request_any_status},
    locks::{COMPONENTS_FLXC1000_LOCKS, create_lock, default_timeout, lock_operation},
    test_env::TestEnv,
};

/// The path of `link` below `/vehicle/v15` without surrounding slashes, e.g.
/// `components/flxc1000`, or `None` if `link` points elsewhere.
///
/// The CDA lowercases request paths, so the case of the prefix is not significant.
fn relative_path(link: &str) -> Option<String> {
    const PREFIX: &str = "/vehicle/v15";
    let url = reqwest::Url::parse(link).ok()?;
    let path = url.path();
    let (head, rest) = (path.get(..PREFIX.len())?, path.get(PREFIX.len()..)?);
    head.eq_ignore_ascii_case(PREFIX)
        .then(|| rest.trim_matches('/').to_owned())
}

/// The segments of `path` below a component or a functional group, `None` for any other
/// path.
fn below_entity(segments: &[&str]) -> Option<Vec<String>> {
    match segments {
        ["components", _, rest @ ..] | ["functions", "functionalgroups", _, rest @ ..] => {
            Some(rest.iter().map(ToString::to_string).collect())
        }
        _ => None,
    }
}

/// Whether `path` is a diagnostic service of an ECU, e.g. `components/flxc1000/faults`.
///
/// Those are tested elsewhere, and an ECU without the service answers 404, so only
/// the resources of the CDA itself, the bulk-data and download collections, are walked.
fn is_ecu_service(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    below_entity(&segments).is_some_and(|rest| {
        !rest.is_empty()
            && !matches!(
                rest.first().map(String::as_str),
                Some("bulk-data" | "x-sovd2uds-bulk-data" | "x-sovd2uds-download")
            )
    })
}

/// Whether `response` is the answer of the router to a path it does not serve.
///
/// A handler can answer 404 too, e.g. `faults` of an ECU without the service or
/// `flashtransfer` while no transfer exists. Both carry a SOVD error body, so only
/// the message of the router's fallback, `Resource not found: <uri>`, tells them apart.
fn is_unrouted(response: &Response) -> bool {
    response.status() == StatusCode::NOT_FOUND
        && response_to_json(response)
            .ok()
            .and_then(|body| body.get("message")?.as_str().map(ToOwned::to_owned))
            .is_some_and(|message| message.starts_with("Resource not found: "))
}

/// The resources a document references: the links of a capability document (its
/// top-level string properties that point into the vehicle), and the `href`s of the
/// items of a list.
fn referenced_paths(document: &serde_json::Value, path: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    if let Some(object) = document.as_object() {
        paths.extend(
            object
                .values()
                .filter_map(serde_json::Value::as_str)
                .filter_map(relative_path),
        );
    }
    if !is_ecu_service(path)
        && let Some(items) = document.get("items").and_then(serde_json::Value::as_array)
    {
        for item in items {
            // Data list items (Table 81) have no `href`, the resource is below the list.
            let href = item.get("href").and_then(serde_json::Value::as_str);
            let id = item.get("id").and_then(serde_json::Value::as_str);
            match (href, id) {
                (Some(href), _) => paths.extend(relative_path(href)),
                (None, Some(id)) if path.ends_with("data") => {
                    paths.insert(format!("{path}/{id}"));
                }
                // The executions of an operation are below it (§7.14), which is
                // not served itself.
                (None, Some(id)) if path == "apps/sovd2uds/operations" => {
                    paths.insert(format!("{path}/{id}/executions"));
                }
                _ => {}
            }
        }
    }
    paths
}

/// Table 43: an item with a `href` references an entity, and has to carry its `id`.
fn entity_references_without_id(document: &serde_json::Value) -> Vec<String> {
    document
        .get("items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("href").is_some())
        .filter(|item| {
            item.get("id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(ToString::to_string)
        .collect()
}

/// Table 169: an operation item has to carry `proximity_proof_required` and
/// `asynchronous_execution`.
fn operations_without_description(document: &serde_json::Value) -> Vec<String> {
    document
        .get("items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            !item
                .get("proximity_proof_required")
                .is_some_and(serde_json::Value::is_boolean)
                || !item
                    .get("asynchronous_execution")
                    .is_some_and(serde_json::Value::is_boolean)
        })
        .map(ToString::to_string)
        .collect()
}

/// None of the links reachable from the vehicle root is dead.
///
/// A route that is not linked from anywhere cannot be found this way.
///
/// The resources are fetched with `GET`. A resource that does not support it
/// answers 405, which is fine: only a 404 of the router means the link is dead.
#[tokio::test]
async fn test_no_dead_links_from_vehicle_root() {
    let test_env = TestEnv::builder().await.unwrap();
    let headers = test_env
        .auth_header()
        .await
        .expect("authorization should succeed");

    // The download collection lists its operations only to the holder of the ECU lock.
    let lock = create_lock(
        default_timeout(),
        COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&lock).unwrap(), "id").unwrap();

    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut dead_links: Vec<String> = Vec::new();
    let mut without_id: Vec<String> = Vec::new();
    let mut without_description: Vec<String> = Vec::new();
    let mut queue: VecDeque<(String, String)> =
        VecDeque::from([(String::new(), "the vehicle root".to_owned())]);

    while let Some((path, referenced_by)) = queue.pop_front() {
        if !reached.insert(path.clone()) {
            continue;
        }
        let url = reqwest::Url::parse(&test_env.vehicle_url(&path)).expect("invalid URL");
        let response = send_request_any_status(Method::GET, None, Some(&headers), url)
            .await
            .unwrap_or_else(|e| panic!("GET {path:?} failed: {e:?}"));

        if is_unrouted(&response) {
            dead_links.push(format!("{path:?}, referenced by {referenced_by}"));
            continue;
        }
        if response.status() != StatusCode::OK {
            continue;
        }
        let Ok(document) = response_to_json(&response) else {
            continue;
        };
        without_id.extend(
            entity_references_without_id(&document)
                .into_iter()
                .map(|item| format!("{item} in {path:?}")),
        );
        if path == "apps/sovd2uds/operations" {
            without_description.extend(operations_without_description(&document));
        }
        queue.extend(
            referenced_paths(&document, &path)
                .into_iter()
                .map(|next| (next, format!("{path:?}"))),
        );
    }

    lock_operation(
        COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    assert!(
        dead_links.is_empty(),
        "links that answer 404: {dead_links:#?}"
    );
    assert!(
        without_id.is_empty(),
        "entity references without an id: {without_id:#?}"
    );

    assert!(
        without_description.is_empty(),
        "operations without the fields of Table 169: {without_description:#?}"
    );

    // Without this, a failing vehicle root would end the walk and pass the test.
    assert!(
        reached.len() > 1,
        "the vehicle root does not link anything: {reached:#?}"
    );
}
