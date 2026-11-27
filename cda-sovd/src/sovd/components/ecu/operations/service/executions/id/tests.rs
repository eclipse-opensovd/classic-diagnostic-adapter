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

use std::sync::Arc;

use aide::UseApi;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DiagCommType, DiagServiceError,
    diagservices::{DiagServiceResponseType, mock::MockDiagServiceResponse},
    file_manager::mock::MockFileManager,
    mock::MockUdsEcu,
    util::std_ext::{lock_read, lock_write},
};
use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
use indexmap::IndexMap;
use sovd_interfaces::components::ecu::operations::ExecutionStatus;

use super::super::tests::{
    make_empty_positive_response, make_json_response, make_negative_response,
};
use crate::sovd::{
    ServiceExecution, components::ecu::operations::service::executions::id as id_handlers,
    locks::insert_test_ecu_lock, tests::create_test_webserver_state,
};

#[tokio::test]
async fn test_get_execution_by_id_not_found() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let unknown_id = uuid::Uuid::new_v4().to_string();
    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: unknown_id,
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_execution_by_id_calls_request_results() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // Expect send with subfunction_id = REQUEST_RESULTS (0x03)
    mock_uds
        .expect_send()
        .withf(|ecu, service, _, payload, map_to_json| {
            ecu == "TestECU"
                && service.type_ == DiagCommType::Operations
                && service.subfunction_id
                    == Some(cda_interfaces::subfunction_ids::routine::REQUEST_RESULTS)
                && service.lookup_name.is_none()
                && payload.is_none()
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| {
            Ok(make_json_response(serde_json::json!({
                "result": "ok"
            })))
        });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("completed")
    );
    assert_eq!(
        result.get("capability").expect("missing capability"),
        &serde_json::json!("execute")
    );
    assert_eq!(
        result
            .get("parameters")
            .expect("missing parameters")
            .get("result")
            .expect("missing result"),
        &serde_json::json!("ok")
    );
}

#[tokio::test]
async fn test_get_execution_suppress_service_skips_send_returns_stored() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // suppress_service=true must skip the UDS send entirely
    mock_uds.expect_send().times(0);

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    // Different values per encoding, the request selects hex.
    let stored_params = crate::sovd::StoredParameters::from_fn(|encoding| {
        let mut m = serde_json::Map::new();
        m.insert(
            "stored".to_string(),
            serde_json::json!(encoding.to_string()),
        );
        m
    });
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: stored_params,
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: true,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // suppress_service=true -> should return 200 with stored params, no UDS send
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("running")
    );
    assert_eq!(
        result
            .get("parameters")
            .expect("missing parameters")
            .get("stored")
            .expect("missing stored"),
        &serde_json::json!("hex")
    );
}

#[tokio::test]
async fn test_get_execution_not_found_without_suppress_returns_error() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
        Err(DiagServiceError::NotFound(
            "CalibrateSensor_RequestResults not found".to_string(),
        ))
    });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // suppress_service=false -> NotFound from UDS should propagate as error
    assert!(response.status().is_client_error() || response.status().is_server_error());
}

#[tokio::test]
async fn test_get_execution_in_flight_returns_conflict() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: true,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_request_results_into_json_error_surfaces_in_errors_field() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // RequestResults returns a non-empty response whose into_json() fails
    mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
        let resp = MockDiagServiceResponse::cloneable(move || {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Positive);
            resp.expect_is_empty().returning(|| false);
            resp.expect_into_json().return_once(|_| {
                Err(DiagServiceError::BadPayload(
                    "simulated parse failure".to_string(),
                ))
            });
            resp
        });
        Ok(resp)
    });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationQuery {
                    include_schema: false,
                    suppress_service: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // Must be 200, not 500
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Spec Table 189: field is named `error` (singular key, array value)
    let errors = result.get("error").expect("missing error field");
    assert!(
        errors.as_array().is_some_and(|a| !a.is_empty()),
        "error should be non-empty when RequestResults into_json fails"
    );
}

#[tokio::test]
async fn test_delete_execution_not_found() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, &ecu_name).await;

    let unknown_id = uuid::Uuid::new_v4().to_string();
    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: unknown_id,
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_execution_calls_stop() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // Expect send with subfunction_id = STOP (0x02)
    mock_uds
        .expect_send()
        .withf(|ecu, service, _, _, _| {
            ecu == "TestECU"
                && service.type_ == DiagCommType::Operations
                && service.subfunction_id == Some(cda_interfaces::subfunction_ids::routine::STOP)
                && service.lookup_name.is_none()
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    // Keep a reference to service_executions so we can verify after consuming state
    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    // Verify execution was removed
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_stop_with_data_returns_200_stopped() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // ECU returns a non-empty positive response from Stop
    mock_uds
        .expect_send()
        .withf(|ecu, service, _, _, map_to_json| {
            ecu == "TestECU"
                && service.subfunction_id == Some(cda_interfaces::subfunction_ids::routine::STOP)
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| {
            Ok(make_json_response(serde_json::json!({
                "stop_result": "ok"
            })))
        });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // ECU returned data -> 200 with status=stopped and the parameters
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("stopped")
    );
    assert_eq!(
        result
            .get("parameters")
            .expect("missing parameters")
            .get("stop_result")
            .expect("missing stop_result"),
        &serde_json::json!("ok")
    );
    // Execution must be removed regardless
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_stop_with_null_json_returns_200_empty_parameters() {
    // Stop maps to JSON Null -> 200 with empty parameters (user-requested extension)
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .withf(|ecu, service, _, _, map_to_json| {
            ecu == "TestECU"
                && service.subfunction_id == Some(cda_interfaces::subfunction_ids::routine::STOP)
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_json_response(serde_json::Value::Null)));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("stopped")
    );
    // parameters: None when empty -> field is omitted from JSON
    assert!(
        result.get("parameters").is_none(),
        "parameters should be absent when Stop returns Null"
    );
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_stop_non_object_json_returns_200_stopped_with_error() {
    // Stop maps to a non-object JSON value (e.g. a string) -> 200 stopped, error surfaced
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .withf(|ecu, service, _, _, map_to_json| {
            ecu == "TestECU"
                && service.subfunction_id == Some(cda_interfaces::subfunction_ids::routine::STOP)
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_json_response(serde_json::json!("unexpected_string"))));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("stopped")
    );
    // error list (field name "error" per AsyncGetByIdResponse) must be non-empty
    let errors = result.get("error").expect("missing error field");
    assert!(errors.is_array() && !errors.as_array().unwrap().is_empty());
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_stop_into_json_error_returns_200_stopped_with_error() {
    // Stop response cannot be parsed (into_json fails) -> 200 stopped, error surfaced
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .withf(|ecu, service, _, _, map_to_json| {
            ecu == "TestECU"
                && service.subfunction_id == Some(cda_interfaces::subfunction_ids::routine::STOP)
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Positive);
            resp.expect_is_empty().returning(|| false);
            resp.expect_into_json().return_once(|_| {
                Err(DiagServiceError::BadPayload(
                    "simulated Stop parse failure".to_string(),
                ))
            });
            Ok(resp)
        });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        result.get("status").expect("missing status"),
        &serde_json::json!("stopped")
    );
    let errors = result.get("error").expect("missing error field");
    assert!(errors.is_array() && !errors.as_array().unwrap().is_empty());
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_force_removes_on_uds_error() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // UDS returns an error (non-NotFound)
    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Err(DiagServiceError::SendFailed("timeout".to_string())));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    // Keep a reference to service_executions so we can verify after consuming state
    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: true,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // force=true -> removes execution even on error
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_force_removes_on_negative_response() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_negative_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: true,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // force=true -> removes execution even on negative ECU response
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_without_force_returns_error_on_uds_failure() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Err(DiagServiceError::SendFailed("timeout".to_string())));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    // Keep a reference to service_executions so we can verify after consuming state
    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // force=false -> error should be returned, execution should remain
    assert!(response.status().is_client_error() || response.status().is_server_error());
    assert_eq!(lock_read(&service_executions_ref).len(), 1);
}

#[tokio::test]
async fn test_delete_execution_negative_response_resets_in_flight() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_negative_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // Negative ECU response without force -> error returned, in_flight reset
    assert!(response.status().is_client_error() || response.status().is_server_error());
    let guard = lock_read(&service_executions_ref);
    let exec = guard
        .get("CalibrateSensor")
        .and_then(|m| m.get(&exec_id))
        .expect("execution should still exist");
    assert!(!exec.in_flight, "in_flight should be reset to false");
}

#[tokio::test]
async fn test_delete_execution_suppress_service_skips_send_and_removes() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    // suppress_service=true must skip the UDS Stop entirely
    mock_uds.expect_send().never();

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    // Keep a reference to service_executions so we can verify after consuming state
    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: true,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    // suppress_service=true -> removes execution without UDS send, returns 204
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(
        lock_read(&service_executions_ref)
            .values()
            .all(IndexMap::is_empty)
    );
}

#[tokio::test]
async fn test_delete_execution_in_flight_returns_conflict() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, &ecu_name).await;

    let exec_id = uuid::Uuid::new_v4();
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            exec_id,
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: true,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = id_handlers::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(id_handlers::ServiceAndIdPathParam {
            service: "CalibrateSensor".to_string(),
            id: exec_id.to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                    include_schema: false,
                    suppress_service: false,
                    force: false,
                },
            ),
            std::marker::PhantomData,
        ),
        crate::sovd::binary_encoding::hex_encoding(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
}
