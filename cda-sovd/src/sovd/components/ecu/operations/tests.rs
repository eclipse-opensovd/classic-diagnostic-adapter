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

use aide::UseApi;
use axum::{extract::State, http::StatusCode};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    datatypes::ComponentOperationsInfo,
    file_manager::mock::MockFileManager,
    mock::{MockUdsEcu, mock_ecu_state_online_variant_detected},
};
use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
use sovd_interfaces::components::ecu::operations::OperationCollectionItem;

use super::*;
use crate::sovd::tests::create_test_webserver_state;

#[tokio::test]
async fn test_get_operations_returns_empty_list() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_ecu_state()
        .returning(|_| Ok(mock_ecu_state_online_variant_detected()));
    mock_uds
        .expect_get_components_operations_info()
        .withf(|ecu, _| ecu == "TestECU")
        .times(1)
        .returning(|_, _| Ok(vec![]));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );

    let response = get::<MockUdsEcu, MockFileManager>(
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: sovd_interfaces::Items<OperationCollectionItem> =
        serde_json::from_slice(&body).unwrap();
    assert!(result.items.is_empty());
    assert!(result.schema.is_none());
}

#[tokio::test]
async fn test_get_operations_returns_items() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_ecu_state()
        .returning(|_| Ok(mock_ecu_state_online_variant_detected()));
    mock_uds
        .expect_get_components_operations_info()
        .withf(|ecu, _| ecu == "TestECU")
        .times(1)
        .returning(|_, _| {
            Ok(vec![
                ComponentOperationsInfo {
                    id: "CalibrateSensor".to_string(),
                    name: "Calibrate Sensor".to_string(),
                    has_stop: true,
                    has_request_results: true,
                },
                ComponentOperationsInfo {
                    id: "RunSelfTest".to_string(),
                    name: "Run Self Test".to_string(),
                    has_stop: false,
                    has_request_results: false,
                },
            ])
        });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );

    let response = get::<MockUdsEcu, MockFileManager>(
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: sovd_interfaces::Items<OperationCollectionItem> =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(result.items.len(), 2);

    let first = result.items.first().expect("Expected at least one item");
    assert_eq!(first.id, "CalibrateSensor");
    assert_eq!(first.name, "Calibrate Sensor");
    assert!(!first.proximity_proof_required);
    assert!(first.asynchronous_execution);

    let second = result.items.get(1).expect("Expected a second item");
    assert_eq!(second.id, "RunSelfTest");
    assert!(!second.proximity_proof_required);
    assert!(!second.asynchronous_execution);
}

#[tokio::test]
async fn test_get_operations_with_schema() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_ecu_state()
        .returning(|_| Ok(mock_ecu_state_online_variant_detected()));
    mock_uds
        .expect_get_components_operations_info()
        .times(1)
        .returning(|_, _| Ok(vec![]));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );

    let response = get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        WithRejection(
            Query(sovd_interfaces::IncludeSchemaQuery {
                include_schema: true,
            }),
            std::marker::PhantomData,
        ),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: sovd_interfaces::Items<OperationCollectionItem> =
        serde_json::from_slice(&body).unwrap();
    assert!(
        result.schema.is_some(),
        "Schema should be included when requested"
    );
}
