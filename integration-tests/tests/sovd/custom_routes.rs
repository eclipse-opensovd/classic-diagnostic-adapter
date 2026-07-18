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

use std::sync::Arc;

use aide::axum::{ApiRouter, routing};
use axum::{Json, http::StatusCode};
use cda_sovd::dynamic_router::DynamicRouter;
use futures::FutureExt;
use opensovd_cda_lib::{cda_version, config::configfile::ServerConfig};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::util::{
    http::response_to_t,
    runtime::{find_available_tcp_port, host, wait_for_cda_online},
};

const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

#[derive(Serialize, Deserialize, schemars::JsonSchema, Clone, Debug, PartialEq)]
struct TestData {
    oem_name: String,
    version: String,
}

async fn add_custom_routes(dynamic_router: &DynamicRouter) {
    let custom_router = ApiRouter::new().api_route(
        "/test",
        routing::get_with(
            || async {
                (
                    StatusCode::OK,
                    Json(TestData {
                        oem_name: "Eclipse Foundation".to_string(),
                        version: "1.0.0".to_string(),
                    }),
                )
            },
            |op| {
                // OpenAPI documentation for the GET /demo endpoint
                op.description("Get demo data")
                    .response_with::<200, Json<TestData>, _>(|res| {
                        res.example(TestData {
                            oem_name: "Eclipse Foundation".to_string(),
                            version: "1.0.0".to_string(),
                        })
                    })
            },
        )
        .post_with(
            |Json(payload): Json<TestData>| async move {
                // Echo back the payload
                (StatusCode::CREATED, Json(payload))
            },
            |op| {
                op.description("Create demo data")
                    .response_with::<201, Json<TestData>, _>(|res| {
                        res.description("Successfully created")
                    })
            },
        ),
    );

    dynamic_router.add_routes(custom_router).await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Makes sense to keep the test together"
)]
async fn test_custom_demo_endpoint() {
    // Use loopback since we don't need actual ECU connections for this test
    let host = host();
    let test_port = find_available_tcp_port(&host).expect("Failed to find available port");

    let webserver_config = cda_sovd::WebServerConfig {
        host: host.clone(),
        port: test_port,
    };

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let shutdown_signal = async move {
        shutdown_rx.recv().await.ok();
    }
    .shared();

    let (dynamic_router, webserver_join_handle) =
        cda_sovd::launch_webserver(webserver_config, shutdown_signal.clone())
            .await
            .expect("Failed to launch webserver");

    let health = cda_health::add_health_routes(&dynamic_router, cda_version().to_owned()).await;
    let main_health_provider = {
        let provider = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        health
            .register_provider(
                MAIN_HEALTH_COMPONENT_KEY,
                Arc::clone(&provider) as Arc<dyn cda_health::HealthStatus>,
            )
            .await
            .expect("Failed to register main health provider");
        provider
    };

    // Add custom routes directly - no vehicle routes needed for this test
    add_custom_routes(&dynamic_router).await;

    main_health_provider
        .update_status(cda_health::Status::Up)
        .await;

    let url = reqwest::Url::parse(&format!("http://{host}:{test_port}/test")).expect("Invalid URL");
    wait_for_cda_online(&ServerConfig {
        address: host,
        port: test_port,
    })
    .await
    .expect("Webserver did not start in time");

    // Test GET request
    let get_response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, url.clone())
            .await
            .expect("GET request failed");

    let demo_data: TestData = response_to_t(&get_response).expect("Failed to parse GET response");
    assert_eq!(demo_data.oem_name, "Eclipse Foundation");
    assert_eq!(demo_data.version, "1.0.0");

    // Test POST request
    let post_payload = TestData {
        oem_name: "Custom OEM".to_string(),
        version: "2.0.0".to_string(),
    };
    let post_body = serde_json::to_string(&post_payload).expect("Failed to serialize payload");
    let post_response = crate::util::http::send_request(
        StatusCode::CREATED,
        Method::POST,
        Some(&post_body),
        None,
        url,
    )
    .await
    .expect("POST request failed");

    let response_data: TestData =
        response_to_t(&post_response).expect("Failed to parse POST response");
    assert_eq!(response_data, post_payload);

    shutdown_tx.send(()).ok();
    webserver_join_handle
        .await
        .expect("Failed to shutdown webserver");
}
