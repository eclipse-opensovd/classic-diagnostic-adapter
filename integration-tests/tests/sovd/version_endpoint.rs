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

use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use axum::http::StatusCode;
use opensovd_cda_lib::{
    CdaEvent, CdaStage, Component, Constructed, ConstructedComponent, LifecycleError,
    StageResources, WeakLifecycleHandle, cda_version,
    config::configfile::Configuration,
    startup::resources::CdaLifecycle,
    update::{create_default_update_plugin, update_plugin_fn},
};
use reqwest::Method;
use serde_json::Value;
use tokio::sync::oneshot;

use crate::util::{
    http::{extract_field_from_json, response_to_json, send_request},
    runtime::{
        setup_integration_test, setup_integration_test_without_cda, start_cda_with_setup, stop_cda,
        wait_for_in_process_cda_online,
    },
};

/// An in-process CDA otherwise opens its storage in the test process's working
/// directory, so it inherits, and adds to, whatever a previous run left in the
/// source tree. An existing but empty `diagnostic_database` collection there is
/// authoritative, which leaves the instance with no databases at all.
fn with_private_storage(config: &Configuration) -> (Configuration, tempfile::TempDir) {
    let storage = tempfile::tempdir().expect("Failed to create a storage directory");
    let mut config = config.clone();
    config.runtime_update_config.storage_dir = storage.path().to_string_lossy().into_owned();
    (config, storage)
}

fn assert_version_response(json: &serde_json::Value) {
    let id = extract_field_from_json::<String>(json, "id").expect("Missing 'id' field");
    assert_eq!(id, "version");

    let data =
        extract_field_from_json::<serde_json::Value>(json, "data").expect("Missing 'data' field");
    let name = extract_field_from_json::<String>(&data, "name").expect("Missing 'data.name' field");
    assert_eq!(name, "Eclipse OpenSOVD Classic Diagnostic Adapter");

    let api =
        extract_field_from_json::<serde_json::Value>(&data, "api").expect("Missing 'data.api'");
    let api_version =
        extract_field_from_json::<String>(&api, "version").expect("Missing 'data.api.version'");
    assert_eq!(api_version, "1.1");

    let implementation = extract_field_from_json::<serde_json::Value>(&data, "implementation")
        .expect("Missing 'data.implementation'");
    let impl_version = extract_field_from_json::<String>(&implementation, "version")
        .expect("Missing 'data.implementation.version'");
    assert_eq!(impl_version, cda_version());
}

/// [[ itest~sovd-api-version-endpoint, Version Endpoint Integration Test, itest ]]
#[tokio::test]
async fn test_version_endpoint() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let host = &runtime.config.server.address;
    let port = runtime.config.server.port;

    // Test app-scoped version endpoint
    let app_url = reqwest::Url::parse(&format!(
        "http://{host}:{port}/vehicle/v15/apps/sovd2uds/data/version"
    ))
    .expect("Invalid URL");

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, app_url)
            .await
            .expect("GET app version endpoint failed");

    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);

    // Test global version endpoint
    let global_url = reqwest::Url::parse(&format!("http://{host}:{port}/vehicle/v15/data/version"))
        .expect("Invalid URL");

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, global_url)
            .await
            .expect("GET global version endpoint failed");

    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);
}

/// Holds the start sequence between the accept loop and the database load
/// until the test releases it.
struct ParkStartup {
    parked: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

#[async_trait::async_trait]
impl ConstructedComponent<CdaEvent> for ParkStartup {
    fn name(&self) -> &'static str {
        "park-startup"
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        if let Some(parked) = self.parked.lock().expect("Poisoned").take() {
            parked.send(()).ok();
        }
        let release = self.release.lock().expect("Poisoned").take();
        if let Some(release) = release {
            release.await.ok();
        }
        Ok(())
    }
}

/// Sits in the stage between the one that opens the port and the one that
/// reads the databases, so it starts after the listener is accepting and before
/// the load.
struct ParkAfterServing {
    parked: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

#[async_trait::async_trait]
impl Component<CdaEvent> for ParkAfterServing {
    type Provides = ();

    fn name(&self) -> &'static str {
        "park-startup"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::DatabaseFiles
    }

    async fn construct(
        self,
        _resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        Ok(Constructed::new(()).with_component(Arc::new(ParkStartup {
            parked: Mutex::new(self.parked),
            release: Mutex::new(self.release),
        })))
    }
}

/// `/health` and the version endpoints are mounted, and the listener is
/// accepting, before the databases are read: the stage that loads them runs
/// after the one that opens the port. Parking a component in a stage between
/// the two pins that window instead of racing a load that may be fast.
#[tokio::test]
async fn static_endpoints_answer_while_ecu_data_is_still_loading() {
    let (runtime, _lock) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to set up the test runtime");
    let (config, _storage) = with_private_storage(&runtime.config);

    let (parked_tx, parked_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    start_cda_with_setup(
        config.clone(),
        opensovd_cda_lib::Setup::new()
            .with_existing_tracing()
            .with_update_plugin(update_plugin_fn(|resources| async {
                create_default_update_plugin(resources).await
            }))
            .with_component(ParkAfterServing {
                parked: Some(parked_tx),
                release: Some(release_rx),
            }),
    );

    parked_rx
        .await
        .expect("Startup never reached the parked component");

    let host = &config.server.address;
    let port = config.server.port;
    let health_url =
        reqwest::Url::parse(&format!("http://{host}:{port}/health")).expect("Invalid URL");
    send_request(StatusCode::OK, Method::GET, None, None, health_url)
        .await
        .expect("GET /health was not answered while the ECU data was still loading");

    let version_url =
        reqwest::Url::parse(&format!("http://{host}:{port}/vehicle/v15/data/version"))
            .expect("Invalid URL");
    let response = send_request(StatusCode::OK, Method::GET, None, None, version_url)
        .await
        .expect("GET the version endpoint was not answered while the ECU data was still loading");
    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);

    // Let the parked component go and shut the instance down again. How long the
    // rest of startup takes is not what this test pins, and an in-process debug
    // build loads the databases far slower than the shared release instance.
    release_tx.send(()).ok();
    stop_cda().await.expect("Failed to stop the CDA");
}

/// Owns no static data, and counts the [`CdaEvent::ReloadStaticData`]
/// dispatches that reach it anyway, by sitting in the stage the event visits.
struct CountStaticReloads {
    name: &'static str,
    seen: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ConstructedComponent<CdaEvent> for CountStaticReloads {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        if matches!(event, CdaEvent::ReloadStaticData) {
            self.seen.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Component<CdaEvent> for CountStaticReloads {
    type Provides = ();

    fn name(&self) -> &'static str {
        self.name
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Version
    }

    async fn construct(
        self,
        _resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let counter = Arc::new(CountStaticReloads {
            name: self.name,
            seen: self.seen,
        });
        Ok(Constructed::new(()).with_component(counter))
    }
}

fn counting(name: &'static str) -> (CountStaticReloads, Arc<AtomicUsize>) {
    let seen = Arc::new(AtomicUsize::new(0));
    let component = CountStaticReloads {
        name,
        seen: Arc::clone(&seen),
    };
    (component, seen)
}

/// Publishes the manager's handle, so the test can dispatch an event no product
/// path triggers yet. A component rather than a `Setup` method: the handle is a
/// resource like any other, and asking for it is how anything gets one. It sits
/// in the first stage after the one that builds the manager, because a required
/// value has to come from a strictly earlier stage.
struct CaptureLifecycle {
    handle: Arc<OnceLock<WeakLifecycleHandle<CdaEvent>>>,
}

#[async_trait::async_trait]
impl Component<CdaEvent> for CaptureLifecycle {
    type Provides = ();

    fn name(&self) -> &'static str {
        "capture-lifecycle"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Storage
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let lifecycle = resources.get::<CdaLifecycle>()?;
        let _ = self.handle.set(lifecycle.handle());
        Ok(Constructed::new(()))
    }
}

async fn version_databases(config: &opensovd_cda_lib::config::configfile::Configuration) -> Value {
    let host = &config.server.address;
    let port = config.server.port;
    let url = reqwest::Url::parse(&format!("http://{host}:{port}/vehicle/v15/data/version"))
        .expect("Invalid URL");
    let response = send_request(StatusCode::OK, Method::GET, None, None, url)
        .await
        .expect("GET the version endpoint failed");
    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);
    let data = extract_field_from_json::<Value>(&json, "data").expect("Missing the 'data' field");
    extract_field_from_json::<Value>(&data, "databases").expect("Missing 'data.databases'")
}

/// `ReloadStaticData` is a bare signal with no guards, and it visits the one
/// stage that owns static data. The components in that stage that own none
/// return without doing anything. Only the `Version` component owns any today,
/// and its source is the revisions the loaded databases recorded, so the payload
/// it republishes is the one it was already serving. A component registered into
/// that stage purely to be a bystander pins both halves: it is reached, and
/// nothing it did shows up in what the endpoint answers.
///
/// No product path dispatches this event yet, so the test asks the manager
/// directly, through a component that requires the handle like any other
/// resource.
#[tokio::test]
async fn reload_static_data_republishes_the_version_payload_without_touching_ecu_data() {
    let (runtime, _lock) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to set up the test runtime");
    let (config, _storage) = with_private_storage(&runtime.config);

    let (bystander, bystander_seen) = counting("count-static-reloads");

    let lifecycle: Arc<OnceLock<WeakLifecycleHandle<CdaEvent>>> = Arc::new(OnceLock::new());
    start_cda_with_setup(
        config.clone(),
        opensovd_cda_lib::Setup::new()
            .with_existing_tracing()
            .with_update_plugin(update_plugin_fn(|resources| async {
                create_default_update_plugin(resources).await
            }))
            .with_component(bystander)
            .with_component(CaptureLifecycle {
                handle: Arc::clone(&lifecycle),
            }),
    );
    wait_for_in_process_cda_online(&config.server)
        .await
        .expect("The CDA did not come online");

    let before = version_databases(&config).await;
    assert!(
        before
            .as_object()
            .is_some_and(|databases| !databases.is_empty()),
        "the startup dispatch must have recorded database revisions: {before}"
    );
    assert_eq!(
        bystander_seen.load(Ordering::SeqCst),
        0,
        "starting up must not dispatch a static data reload"
    );

    let handle = lifecycle
        .get()
        .expect("A component that requires it receives the lifecycle handle");
    let accepted = handle
        .accept(CdaEvent::ReloadStaticData)
        .await
        .expect("The static data reload was refused");
    accepted
        .completion
        .await
        .expect("The static data reload never reported completion")
        .expect("The static data reload failed");

    assert_eq!(
        bystander_seen.load(Ordering::SeqCst),
        1,
        "the signal reaches every component of the stage it visits"
    );

    assert_eq!(
        version_databases(&config).await,
        before,
        "the components that own no static data must have left the payload alone"
    );

    stop_cda().await.expect("Failed to stop the CDA");
}
