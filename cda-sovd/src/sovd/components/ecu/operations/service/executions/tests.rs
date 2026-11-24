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
    DiagComm, DiagCommType, DiagServiceError,
    diagservices::{
        DiagServiceJsonResponse, DiagServiceResponseType, mock::MockDiagServiceResponse,
    },
    file_manager::mock::MockFileManager,
    mock::MockUdsEcu,
    util::std_ext::{lock_read, lock_write},
};
use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
use sovd_interfaces::{
    common::operations::OperationIdItem, components::ecu::operations::ExecutionStatus,
};

use crate::sovd::{
    ServiceExecution, components::ecu::operations::service::executions as handlers,
    locks::insert_test_ecu_lock, tests::create_test_webserver_state,
};

pub(super) fn make_json_response(data: serde_json::Value) -> MockDiagServiceResponse {
    MockDiagServiceResponse::cloneable(move || {
        let data = data.clone();
        let mut resp = MockDiagServiceResponse::new();
        resp.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        resp.expect_is_empty().returning(|| false);
        resp.expect_into_json().return_once(move |_| {
            Ok(DiagServiceJsonResponse {
                data,
                errors: vec![],
            })
        });
        resp
    })
}

pub(super) fn make_empty_positive_response() -> MockDiagServiceResponse {
    let mut resp = MockDiagServiceResponse::new();
    resp.expect_response_type()
        .returning(|| DiagServiceResponseType::Positive);
    resp.expect_is_empty().returning(|| true);
    resp
}

pub(super) fn make_negative_response() -> MockDiagServiceResponse {
    let mut resp = MockDiagServiceResponse::new();
    resp.expect_response_type()
        .returning(|| DiagServiceResponseType::Negative);
    resp.expect_is_empty().returning(|| false);
    resp.expect_as_nrc().returning(|| {
        Ok(cda_interfaces::diagservices::MappedNRC {
            code: Some(0x22),
            description: Some("conditionsNotCorrect".to_string()),
            sid: None,
        })
    });
    resp
}

pub(super) async fn ecu_operation_write_handler<
    T: cda_interfaces::UdsEcu + cda_interfaces::SchemaProvider + Clone,
>(
    req: handlers::WriteHandlerRequest,
    ecu_name: &str,
    uds: &T,
    service_executions: Arc<
        std::sync::RwLock<
            cda_interfaces::HashMap<String, indexmap::IndexMap<uuid::Uuid, ServiceExecution>>,
        >,
    >,
    security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
    opts: handlers::WriteHandlerOptions,
) -> axum::response::Response {
    let ctx = handlers::OperationWriteContext::new(
        service_executions,
        enabled_communication_access_for_test(),
    );
    handlers::ecu_operation_write_handler_with_activity::<T>(
        req,
        ecu_name,
        uds,
        ctx,
        security_plugin,
        opts,
    )
    .await
}

#[tokio::test]
async fn test_list_executions_empty() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    let response = handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(handlers::OperationServicePathParam {
            service: "CalibrateSensor".to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::service::executions::Query {
                    include_schema: false,
                },
            ),
            std::marker::PhantomData,
        ),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: sovd_interfaces::Items<OperationIdItem> = serde_json::from_slice(&body).unwrap();
    assert!(result.items.is_empty());
}

#[tokio::test]
async fn test_list_executions_shows_tracked_id() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();
    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name,
        mock_uds,
        mock_file_manager,
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;

    // Pre-populate an execution
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

    let response = handlers::get::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(handlers::OperationServicePathParam {
            service: "CalibrateSensor".to_string(),
        }),
        WithRejection(
            Query(
                sovd_interfaces::components::ecu::operations::service::executions::Query {
                    include_schema: false,
                },
            ),
            std::marker::PhantomData,
        ),
        State(state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: sovd_interfaces::Items<OperationIdItem> = serde_json::from_slice(&body).unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(
        result.items.first().expect("Expected at least one item").id,
        exec_id.to_string()
    );
}

fn make_post_headers() -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        axum::http::header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    );
    headers
}

#[tokio::test]
async fn test_post_operation_conflict_when_running_execution_exists() {
    let ecu_name = "TestECU".to_string();
    let mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    // Pre-populate a running execution for CalibrateSensor
    lock_write(&state.service_executions)
        .entry("CalibrateSensor".to_string())
        .or_default()
        .insert(
            uuid::Uuid::new_v4(),
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_post_operation_no_conflict_for_different_service() {
    // An execution running for ServiceA must NOT block ServiceB
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                has_stop: false,
                has_request_results: false,
            })
        });
    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    // Pre-populate a running execution for a DIFFERENT service
    lock_write(&state.service_executions)
        .entry("OtherService".to_string())
        .or_default()
        .insert(
            uuid::Uuid::new_v4(),
            ServiceExecution {
                parameters: crate::sovd::StoredParameters::default(),
                status: ExecutionStatus::Running,
                in_flight: false,
                is_created: true,
                communication_lease: None,
            },
        );

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    // Different service -> no conflict, should pass through to 200
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_post_operation_service_not_found_returns_404() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .withf(|ecu, svc, _p| ecu == "TestECU" && svc == "CalibrateSensor")
        .times(1)
        .returning(|_, _, _| {
            Err(DiagServiceError::NotFound(
                "Routine 'CalibrateSensor' not found in ECU description".to_string(),
            ))
        });
    mock_uds
        .expect_get_io_control_service()
        .withf(|ecu, svc, _p| ecu == "TestECU" && svc == "CalibrateSensor")
        .times(1)
        .returning(|_, _, _| {
            Err(DiagServiceError::NotFound(
                "No InputOutputControlByIdentifier service found".to_owned(),
            ))
        });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_post_operation_sync_returns_200_on_empty_response() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                has_stop: false,
                has_request_results: false,
            })
        });
    mock_uds
        .expect_send()
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_post_named_io_control_uses_exact_operation_service() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Err(DiagServiceError::NotFound(
                "Not a RoutineControl service".to_owned(),
            ))
        });
    mock_uds
        .expect_get_io_control_service()
        .withf(|ecu, svc, _p| ecu == "TestECU" && svc == "TestOutput_Control")
        .times(1)
        .returning(|_, _, _| {
            Ok(DiagComm {
                name: "TestOutput_Control".to_owned(),
                type_: DiagCommType::Operations,
                lookup_name: Some("TestOutput_Control".to_owned()),
                subfunction_id: None,
            })
        });
    mock_uds
        .expect_send()
        .withf(|ecu, service, _, payload, map_to_json| {
            ecu == "TestECU"
                && service.type_ == DiagCommType::Operations
                && service.name == "TestOutput_Control"
                && service.lookup_name.as_deref() == Some("TestOutput_Control")
                && service.subfunction_id.is_none()
                && payload.is_some()
                && *map_to_json
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "TestOutput_Control".to_owned(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(br#"{"parameters":{"OutputValue":"ACTIVE"}}"#),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/TestOutput_Control/executions".to_owned(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_post_operation_async_returns_202_and_tracks_execution() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                has_stop: true,
                has_request_results: true,
            })
        });
    mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
        Ok(make_json_response(serde_json::json!({
            "routineInfo": 1,
            "result": 0
        })))
    });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(result.get("id").is_some(), "202 body must have id");
    assert_eq!(result.get("status"), Some(&serde_json::json!("running")));
    assert_eq!(
        result.get("parameters"),
        Some(&serde_json::json!({"routineInfo": 1, "result": 0}))
    );
    assert_eq!(lock_read(&service_executions_ref).len(), 1);
}

#[tokio::test]
async fn test_post_operation_suppress_service_async_skips_send_returns_202_and_tracks() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds.expect_get_routine_subfunctions().times(0);
    // send must NOT be called when suppress_service=true
    mock_uds.expect_send().times(0);

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: true,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // execution still tracked even though UDS was not called
    assert_eq!(lock_read(&service_executions_ref).len(), 1);
}

#[tokio::test]
async fn test_post_operation_async_into_json_error_returns_empty_parameters() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                has_stop: true,
                has_request_results: true,
            })
        });
    // send returns a response whose into_json() fails
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
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    // Decoding failures do not prevent the asynchronous execution from starting.
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // Execution must still be tracked
    assert_eq!(lock_read(&service_executions_ref).len(), 1);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(result.get("id").is_some(), "202 body must have id");
    assert!(result.get("status").is_some(), "202 body must have status");
    assert_eq!(result.get("parameters"), Some(&serde_json::json!({})));
    let errors = result
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .expect("202 body must contain errors");
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors.first().and_then(|error| error.get("path")),
        Some(&serde_json::json!("/parameters"))
    );
    assert_eq!(
        errors
            .first()
            .and_then(|error| error.get("error"))
            .and_then(|error| error.get("error_code")),
        Some(&serde_json::json!("invalid-response-content"))
    );
}

#[tokio::test]
async fn test_post_operation_async_non_object_json_returns_empty_parameters() {
    let ecu_name = "TestECU".to_string();
    let mut mock_uds = MockUdsEcu::new();
    let mock_file_manager = MockFileManager::new();

    mock_uds
        .expect_get_routine_subfunctions()
        .times(1)
        .returning(|_, _, _| {
            Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                has_stop: true,
                has_request_results: true,
            })
        });
    // send returns a response whose into_json() gives a non-Object JSON value
    mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
        let resp = MockDiagServiceResponse::cloneable(move || {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Positive);
            resp.expect_is_empty().returning(|| false);
            resp.expect_into_json().return_once(|_| {
                Ok(DiagServiceJsonResponse {
                    data: serde_json::Value::String("unexpected_string".to_string()),
                    errors: vec![],
                })
            });
            resp
        });
        Ok(resp)
    });

    let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
        ecu_name.clone(),
        mock_uds,
        mock_file_manager,
    );

    let service_executions_ref = Arc::clone(&state.service_executions);

    let response = ecu_operation_write_handler::<MockUdsEcu>(
        handlers::WriteHandlerRequest {
            service: "CalibrateSensor".to_string(),
            headers: make_post_headers(),
            body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
        },
        &ecu_name,
        &state.uds,
        Arc::clone(&state.service_executions),
        Box::new(cda_plugin_security::mock::TestSecurityPlugin),
        handlers::WriteHandlerOptions {
            include_schema: false,
            suppress_service: false,
            base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
            binary_encoding: cda_interfaces::BinaryEncoding::Hex,
        },
    )
    .await;

    // Non-object response data does not prevent the asynchronous execution from starting.
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(lock_read(&service_executions_ref).len(), 1);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(result.get("id").is_some(), "202 body must have id");
    assert!(result.get("status").is_some(), "202 body must have status");
    assert_eq!(result.get("parameters"), Some(&serde_json::json!({})));
    assert_eq!(
        result
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}
