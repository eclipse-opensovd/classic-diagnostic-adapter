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
use axum::extract::{OriginalUri, Path, Query, State};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    HashMap, HashMapExtensions, file_manager::mock::MockFileManager, mock::MockUdsEcu,
};
use cda_plugin_security::{
    Secured, SecurityPlugin,
    mock::{MockAuthApi, MockClaims, MockSecurityPlugin, TestSecurityPlugin},
};
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::components::ecu::operations::comparams::{self, executions};
use uuid::Uuid;

use crate::sovd::{
    components::{IdPathParam, ecu::operations::comparams::executions as handlers},
    locks::insert_test_ecu_lock,
    tests::create_test_webserver_state,
};

fn foreign_security_plugin() -> Box<dyn SecurityPlugin> {
    let mut claims = MockClaims::new();
    claims.expect_sub().return_const("foreign_user");
    let claims: &'static dyn cda_plugin_security::Claims = Box::leak(Box::new(claims));
    let mut auth = MockAuthApi::new();
    auth.expect_claims().return_const(Box::new(claims));
    let mut plugin = MockSecurityPlugin::new();
    plugin
        .expect_as_auth_plugin()
        .return_const(Box::new(auth) as Box<dyn cda_plugin_security::AuthApi>);
    Box::new(plugin)
}

fn query() -> WithRejection<Query<executions::get::Query>, crate::sovd::error::ApiError> {
    WithRejection(
        Query(sovd_interfaces::IncludeSchemaQuery {
            include_schema: false,
        }),
        std::marker::PhantomData,
    )
}

fn request() -> executions::update::Request {
    executions::update::Request {
        capability: None,
        timeout: None,
        parameters: Some(HashMap::from_iter([(
            "P2ServerMax".to_owned(),
            comparams::ComParamValue::Simple(comparams::ComParamSimpleValue {
                value: "100".to_owned(),
                unit: None,
            }),
        )])),
        proximity_response: None,
    }
}

fn execution(
    communication_access: &dyn cda_interfaces::communication_control::CommunicationAccess,
) -> crate::sovd::ComparamExecution {
    crate::sovd::ComparamExecution::new(
        comparams::Execution {
            capability: executions::Capability::Execute,
            status: sovd_interfaces::components::ecu::operations::ExecutionStatus::Running,
            comparam_override: HashMap::new(),
        },
        communication_access
            .acquire()
            .expect("Test communication must be enabled"),
    )
}

#[tokio::test]
async fn get_foreign_exclusive_lock_skips_uds() {
    let mut uds = MockUdsEcu::new();
    uds.expect_get_comparams().times(0);
    let state = create_test_webserver_state("TestECU".to_owned(), uds, MockFileManager::new());
    insert_test_ecu_lock(&state.locks, "TestECU").await;
    let id = Uuid::new_v4();
    state
        .comparam_executions
        .write()
        .await
        .insert(id, execution(&*state.communication_access));
    let executions = Arc::clone(&state.comparam_executions);

    let response = handlers::id::get::<MockUdsEcu, MockFileManager>(
        UseApi(Secured(foreign_security_plugin()), std::marker::PhantomData),
        Path(IdPathParam { id: id.to_string() }),
        query(),
        State(state),
    )
    .await;

    assert_eq!(response.status(), http::StatusCode::LOCKED);
    assert!(executions.read().await.contains_key(&id));
}

#[tokio::test]
async fn post_without_owned_write_lock_does_not_create_execution() {
    let state = create_test_webserver_state(
        "TestECU".to_owned(),
        MockUdsEcu::new(),
        MockFileManager::new(),
    );
    let executions = Arc::clone(&state.comparam_executions);

    let response = handlers::post::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        query(),
        State(state),
        UseApi(
            ExtractHost("localhost".to_owned()),
            std::marker::PhantomData,
        ),
        OriginalUri(
            "/components/TestECU/operations/comparams/executions"
                .parse()
                .unwrap(),
        ),
        None,
    )
    .await;

    assert_eq!(response.status(), http::StatusCode::CONFLICT);
    assert!(executions.read().await.is_empty());
}

#[tokio::test]
async fn put_without_owned_write_lock_does_not_mutate_execution() {
    let state = create_test_webserver_state(
        "TestECU".to_owned(),
        MockUdsEcu::new(),
        MockFileManager::new(),
    );
    let id = Uuid::new_v4();
    state
        .comparam_executions
        .write()
        .await
        .insert(id, execution(&*state.communication_access));
    let executions = Arc::clone(&state.comparam_executions);

    let response = handlers::id::put::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(IdPathParam { id: id.to_string() }),
        query(),
        State(state),
        UseApi(
            ExtractHost("localhost".to_owned()),
            std::marker::PhantomData,
        ),
        OriginalUri(
            format!("/components/TestECU/operations/comparams/executions/{id}")
                .parse()
                .unwrap(),
        ),
        WithRejection(axum::Json(request()), std::marker::PhantomData),
    )
    .await;

    assert_eq!(response.status(), http::StatusCode::CONFLICT);
    let executions = executions.read().await;
    assert!(
        executions
            .get(&id)
            .is_some_and(|execution| execution.comparam_override.is_empty())
    );
}

#[tokio::test]
async fn delete_without_owned_write_lock_does_not_remove_execution() {
    let state = create_test_webserver_state(
        "TestECU".to_owned(),
        MockUdsEcu::new(),
        MockFileManager::new(),
    );
    let id = Uuid::new_v4();
    state
        .comparam_executions
        .write()
        .await
        .insert(id, execution(&*state.communication_access));
    let executions = Arc::clone(&state.comparam_executions);

    let response = handlers::id::delete::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        Path(IdPathParam { id: id.to_string() }),
        State(state),
    )
    .await;

    assert_eq!(response.status(), http::StatusCode::CONFLICT);
    assert!(executions.read().await.contains_key(&id));
}

#[tokio::test]
async fn post_with_owned_write_lock_creates_execution() {
    let state = create_test_webserver_state(
        "TestECU".to_owned(),
        MockUdsEcu::new(),
        MockFileManager::new(),
    );
    insert_test_ecu_lock(&state.locks, "TestECU").await;
    let executions = Arc::clone(&state.comparam_executions);

    let response = handlers::post::<MockUdsEcu, MockFileManager>(
        UseApi(
            Secured(Box::new(TestSecurityPlugin)),
            std::marker::PhantomData,
        ),
        query(),
        State(state),
        UseApi(
            ExtractHost("localhost".to_owned()),
            std::marker::PhantomData,
        ),
        OriginalUri(
            "/components/TestECU/operations/comparams/executions"
                .parse()
                .unwrap(),
        ),
        Some(axum::Json(request())),
    )
    .await;

    assert_eq!(response.status(), http::StatusCode::ACCEPTED);
    assert_eq!(executions.read().await.len(), 1);
}
