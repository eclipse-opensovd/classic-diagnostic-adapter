/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::{sync::Arc, time::Duration};

use aide::axum::{ApiRouter, routing};
use axum::{Json, http::StatusCode};
use cda_comm_doip::config::DoipConfig;
use cda_interfaces::{FunctionalDescriptionConfig, UdsEcu};
use cda_sovd::{Locks, dynamic_router::DynamicRouter};
use futures::FutureExt;
use opensovd_cda_lib::{DatabaseMap, FileManagerMap, config::configfile::ServerConfig};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::util::{
    http::response_to_t,
    runtime::{find_available_tcp_port, host, wait_for_cda_online},
};

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

    // Update the router with the new routes,
    // merge with existing router to preserve existing routes
    dynamic_router
        .update_router(move |old_router| old_router.merge(custom_router))
        .await;
}

#[tokio::test]
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

    // Empty db, file managers and gateway for testing
    let databases: DatabaseMap<cda_plugin_security::DefaultSecurityPluginData> =
        DatabaseMap::default();
    let file_managers: FileManagerMap = FileManagerMap::default();
    let databases = Arc::new(databases);
    let gateway_port = find_available_tcp_port(&host).expect("Failed to find available port");
    let (variant_tx, variant_rx) = tokio::sync::mpsc::channel(1);
    let doip_config = DoipConfig {
        tester_address: host.clone(),
        tester_subnet: "255.255.255.0".to_owned(),
        gateway_port,
        send_timeout_ms: 5000,
    };
    let gateway = opensovd_cda_lib::create_diagnostic_gateway(
        Arc::clone(&databases),
        &doip_config,
        variant_tx,
        shutdown_signal.clone(),
    )
    .await
    .expect("Failed to create gateway");

    let uds_manager = opensovd_cda_lib::create_uds_manager(
        gateway,
        databases,
        variant_rx,
        &cda_interfaces::FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
        },
    );
    let server_handle = tokio::spawn({
        let shutdown_signal = shutdown_signal.clone();
        async move {
            // Launch the webserver with static routes
            let dynamic_router =
                cda_sovd::launch_webserver(webserver_config, shutdown_signal).await?;
            add_custom_routes(&dynamic_router).await;

            let ecu_names = uds_manager.get_ecus().await;
            cda_sovd::add_vehicle_routes::<
                cda_core::DiagServiceResponseStruct,
                _,
                _,
                cda_plugin_security::DefaultSecurityPlugin,
            >(
                &dynamic_router,
                uds_manager,
                String::new(),
                file_managers,
                Arc::new(Locks::new(ecu_names)),
                FunctionalDescriptionConfig {
                    description_database: "functional_groups".to_owned(),
                    enabled_functional_groups: None,
                },
            )
            .await
        }
    });

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

    // Cleanup: shutdown the server
    shutdown_tx.send(()).ok();
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(2)) => {
            panic!("Webserver did not shut down in time");
        }
        result = server_handle => {
            match result {
                Ok(Ok(())) => {},
                Ok(Err(e)) => panic!("Webserver error: {e:?}"),
                Err(e) => panic!("Webserver task panicked: {e:?}"),
            }
        }
    }
}
