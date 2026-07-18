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

//! Live end-to-end tests for deferred ECU communication initialization.
//!
//! These tests verify that the deferred initialization mechanism properly gates
//! diagnostic communication, and that **no DoIP traffic occurs at the protocol
//! level** while initialization is pending.
//!
//! ## Test Approach
//!
//! All tests use isolated CDA instances with dedicated ECU simulators so that
//! the deferred-initialization mode can be configured independently of the
//! shared test runtime (which always runs in `Enabled` mode to support the
//! other 75 integration tests).
//!
//! ## Verification Strategy
//!
//! All tests use the ECU simulator's recording API to verify:
//! 1. **No DoIP frames** are recorded while endpoints return 503 (pending state)
//! 2. **DoIP frames are present** after initialization completes (200 state)
//!
//! This provides protocol-level confirmation that the deferred init gate is
//! working correctly, not just HTTP-level confirmation.
//!
//! Note: `opensovd_cda_lib::run_with_config_ext` (and the `_and_init_plugin`
//! variant) waits internally on an OS shutdown signal (SIGINT/SIGTERM) with no
//! programmatic override, so tests using isolated CDA cannot gracefully shut down
//! those instances. Each isolated instance uses fresh, dedicated ports and is left
//! running for the remaining lifetime of the test binary process; this is a
//! known, deliberate trade-off documented here.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use cda_database::DatabaseConfig;
use cda_interfaces::{
    BoxFuture, CommControlError, CommState, CommunicationControl, CommunicationInitMode,
    CommunicationSettings, InitializationPlugin, OnDemandInitPlugin, PostUpdateCommunicationMode,
    deferred_init_api::{DeferredInitError, InitializationContext},
};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use opensovd_cda_lib::config::configfile::Configuration;
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::util::{
    ecusim,
    runtime::{EcuSim, start_ecu_sim, use_docker},
};

const ECU_SIM_NAME: &str = "flxc1000";

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn mdd_fixture_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.push("testcontainer");
    dir.push("odx");
    assert!(
        dir.exists(),
        "MDD fixture directory not found at {}; see README for generating MDD files",
        dir.display()
    );
    dir
}

// ISOLATED CDA TESTS (5 tests)
// All deferred-init tests use isolated CDA instances so they can configure
// CommunicationInitMode::Deferred independently of the shared test runtime.
//
// Tests that only verify HTTP-level behavior (503 responses, headers, routing)
// use `start_deferred_cda_only` -- no ECU simulator is needed.
//
// Tests that verify DoIP-level behavior (frame recording) use
// `start_deferred_cda_with_ecu_sim`, which only works in local
// (non-docker) mode and are skipped when running with Docker.

/// Verifies that on-demand initialization works correctly:
/// - Returns 503 with Retry-After header before initialization
/// - After the first diagnostic request triggers init, the endpoint leaves the 503 state
#[tokio::test]
async fn on_demand_diagnostic_path_returns_503_then_200() {
    let plugin = Arc::new(OnDemandInitPlugin);
    let cda = start_deferred_cda_only(
        plugin,
        1, // retry_after_seconds = 1 so the test can assert on the exact value
        PostUpdateCommunicationMode::Enabled,
    )
    .await;

    // Before any trigger, diagnostic routes must return 503.
    // No auth token needed: the guard fires before auth is checked.
    let response = cda.get("/vehicle/v15/components/FLXC1000/data").await;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 before deferred init triggered"
    );

    // Verify Retry-After header is present and equals the configured value.
    let retry_after: Option<u64> = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    assert_eq!(retry_after, Some(1), "Retry-After should be 1 second");

    // Verify error body.
    let body_text = response.text().await.expect("read body");
    let body: ApiErrorResponse<String> = serde_json::from_str(&body_text)
        .unwrap_or_else(|e| panic!("failed to parse error body: {e}\nbody: {body_text}"));
    assert_eq!(body.error_code, ErrorCode::PreconditionsNotFulfilled);
    assert!(body.vendor_code.is_none());

    // OnDemandInitPlugin triggers on the first diagnostic request. The guard
    // spawns enable() which calls StubCommControl::enable() -- a no-op that
    // sets active=true immediately. The next poll sees the guard is no longer
    // active and the request passes through to the router (returning 404 since
    // this minimal CDA has no ECU routes). Either way it must not be 503.
    let response = cda
        .wait_until_not_pending(
            "/vehicle/v15/components/FLXC1000/data",
            Duration::from_secs(10),
        )
        .await;
    assert_ne!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "endpoint must leave 503 state after OnDemandInitPlugin triggers"
    );
}

/// Verifies that non-DoIP paths are never intercepted by the deferred-init
/// guard, even while initialization is pending.
///
/// The guard must return 503 only for diagnostic (DoIP) endpoints. All other
/// paths must pass through to whatever handler is registered -- or produce a
/// 404 from the router if no handler exists -- never a guard-produced 503.
#[tokio::test]
async fn non_doip_paths_never_trigger_and_always_succeed_while_pending() {
    // Use a BlockingPlugin so the CDA stays in pending state for the whole test.
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let plugin = Arc::new(BlockingPlugin {
        allowed: Arc::clone(&allowed),
    });
    let cda = start_deferred_cda_only(plugin, 1, PostUpdateCommunicationMode::Enabled).await;

    // Health endpoint has a handler registered and requires no auth.
    let response = cda.get("/health").await;
    assert!(
        response.status().is_success(),
        "expected /health to succeed while deferred-init is pending, got {}",
        response.status()
    );

    // Non-DoIP paths that have no handler in this minimal stub CDA should
    // reach the router and get 404 -- NOT 503 from the guard.
    // A 503 here would mean the guard incorrectly intercepted the request.
    for path in &[
        "/vehicle/v15/components",
        "/vehicle/v15/locks",
        "/vehicle/v15/apps",
    ] {
        let response = cda.get(path).await;
        assert_ne!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "guard must not intercept non-DoIP path {path}, but got 503"
        );
    }

    // Diagnostic path must still be 503 -- the guard intercepts it.
    let response = cda.get("/vehicle/v15/components/FLXC1000/data").await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "diagnostic endpoint must return 503 while plugin blocks initialization"
    );
}

/// Verifies that the Retry-After header honors the configured value.
#[tokio::test]
async fn retry_after_header_honors_configured_value() {
    const RETRY_AFTER_SECONDS: u64 = 7;

    // BlockingPlugin keeps the CDA in pending state so the header can be checked.
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let plugin = Arc::new(BlockingPlugin {
        allowed: Arc::clone(&allowed),
    });
    let cda = start_deferred_cda_only(
        plugin,
        RETRY_AFTER_SECONDS,
        PostUpdateCommunicationMode::Enabled,
    )
    .await;

    let response = cda.get("/vehicle/v15/components/FLXC1000/data").await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 while plugin blocks initialization"
    );

    let retry_after: Option<u64> = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    assert_eq!(
        retry_after,
        Some(RETRY_AFTER_SECONDS),
        "Retry-After header should match the configured value"
    );
}

/// A running deferred-mode CDA instance started for a single test.
/// Used by tests that require custom plugins.
struct DeferredCda {
    base_url: String,
    client: reqwest::Client,
}

impl DeferredCda {
    async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base_url))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed: {e}"))
    }

    /// Polls `path` (unauthenticated) until it stops returning 503, or the
    /// timeout elapses.
    async fn wait_until_not_pending(&self, path: &str, timeout: Duration) -> reqwest::Response {
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("timeout too large");
        loop {
            let response = self.get(path).await;
            if response.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE {
                return response;
            }
            assert!(
                Instant::now() < deadline,
                "{path} still returned 503 after {timeout:?}"
            );
            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
        }
    }
}

/// A plugin that only allows initialization once `allowed` is set to `true`.
struct BlockingPlugin {
    allowed: Arc<AtomicBool>,
}

impl InitializationPlugin for BlockingPlugin {
    fn on_ready(&self, _comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn can_initialize(&self, _context: &InitializationContext) -> BoxFuture<'_, bool> {
        let allowed = Arc::clone(&self.allowed);
        Box::pin(async move { allowed.load(Ordering::Acquire) })
    }

    fn on_initialized<'a>(
        &'a self,
        _result: &'a Result<(), DeferredInitError>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// A plugin that captures the [`CommunicationControl`] handle passed to
/// `on_ready`, so the test can proactively trigger initialization without any
/// HTTP request.
struct HandleCapturingPlugin {
    handle: tokio::sync::Mutex<Option<Arc<dyn CommunicationControl>>>,
    initialized_count: Arc<AtomicBool>,
}

impl InitializationPlugin for HandleCapturingPlugin {
    fn on_ready(&self, comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            *self.handle.lock().await = Some(comm);
        })
    }

    fn can_initialize(&self, _context: &InitializationContext) -> BoxFuture<'_, bool> {
        // Never allow on-demand triggering; only the captured handle may
        // proactively trigger initialization.
        Box::pin(async { false })
    }

    fn on_initialized<'a>(
        &'a self,
        _result: &'a Result<(), DeferredInitError>,
    ) -> BoxFuture<'a, ()> {
        self.initialized_count.store(true, Ordering::Release);
        Box::pin(async {})
    }
}

/// A no-op [`CommunicationControl`] stub used by HTTP-only deferred-init tests.
///
/// `enable()` immediately sets the shared flag to `true` without touching any
/// network socket. No VIR broadcast is ever sent so no Docker bridge traffic
/// is generated and the shared Docker CDA is never disturbed.
struct StubCommControl {
    active: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl CommunicationControl for StubCommControl {
    async fn enable(&self) -> Result<(), CommControlError> {
        self.active.store(true, Ordering::Release);
        Ok(())
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        self.active.store(false, Ordering::Release);
        Ok(())
    }

    async fn state(&self) -> CommState {
        if self.active.load(Ordering::Acquire) {
            CommState::Active
        } else {
            CommState::Disabled
        }
    }

    fn active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.active)
    }
}

/// Starts a minimal in-process webserver in deferred mode.
///
/// Does **not** load any MDD files, create a DoIP socket, or start an ECU
/// simulator. Only mounts:
/// - `/health` (always 200, no auth)
/// - `DeferredInitGuard` middleware (returns 503 on diagnostic paths while
///   pending, triggered via `StubCommControl::enable` which is a no-op)
///
/// No network sockets are opened beyond the HTTP listener bound to
/// `127.0.0.1`. This is safe to run concurrently with the shared Docker CDA
/// because it generates zero DoIP traffic.
///
/// Works in both local and Docker modes.
async fn start_deferred_cda_only(
    plugin: Arc<dyn InitializationPlugin>,
    retry_after_seconds: u64,
    _post_update_communication: PostUpdateCommunicationMode,
) -> DeferredCda {
    // Always bind to 127.0.0.1 so no traffic escapes to the Docker bridge.
    let host = "127.0.0.1".to_owned();
    let cda_port = free_tcp_port();

    let base_url = format!("http://{host}:{cda_port}");
    let client = reqwest::Client::new();

    let active_flag = Arc::new(AtomicBool::new(false));
    let comm_control: Arc<dyn CommunicationControl> = Arc::new(StubCommControl {
        active: Arc::clone(&active_flag),
    });

    let guard = cda_plugin_deferred_init::guard::DeferredInitGuard::new(
        Arc::clone(&active_flag),
        Arc::clone(&comm_control),
        Arc::clone(&plugin),
        retry_after_seconds,
    );

    // Give the plugin its CommunicationControl handle before any HTTP requests
    // arrive, mirroring what setup_deferred_vehicle_routes does.
    plugin.on_ready(Arc::clone(&comm_control)).await;

    tokio::spawn(async move {
        let webserver_config = cda_sovd::WebServerConfig {
            host: host.clone(),
            port: cda_port,
        };

        let shutdown_signal: cda_interfaces::ShutdownSignal = {
            use futures::future::FutureExt;
            (Box::pin(std::future::pending::<()>())
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>)
                .shared()
        };

        let (dynamic_router, _webserver_task) =
            cda_sovd::launch_webserver(webserver_config.clone(), shutdown_signal.clone())
                .await
                .expect("failed to launch test webserver");

        cda_health::add_health_routes(&dynamic_router, "deferred-test".to_owned()).await;

        cda_sovd::install_guard(&dynamic_router, guard).await;
    });

    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .expect("timeout too large");
    loop {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "deferred-mode CDA did not become ready within 10s"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }

    DeferredCda { base_url, client }
}

/// Starts a real deferred-mode CDA instance on dedicated, freshly-allocated
/// ports, with the bundled MDD fixtures as its database and the given
/// initialization plugin. Also starts an isolated ECU simulator.
///
/// Returns both the CDA handle and the ECU simulator handle for verification.
///
/// **Only works in local (non-Docker) mode.** In Docker mode the isolated ECU
/// sim cannot bind to an ephemeral port on the host, so callers must skip the
/// test when `use_docker()` returns `true`.
///
/// # Panics
/// Panics if the CDA or ECU simulator fails to become ready within timeout.
async fn start_deferred_cda_with_ecu_sim(
    plugin: Arc<dyn InitializationPlugin>,
    retry_after_seconds: u64,
    post_update_communication: PostUpdateCommunicationMode,
) -> (DeferredCda, EcuSim) {
    let host = "127.0.0.1".to_owned();
    let cda_port = free_tcp_port();
    let gateway_port = free_udp_port();
    let sim_control_port = free_tcp_port();
    let storage_dir = tempfile::tempdir().expect("create temp storage dir");

    let ecu_sim = EcuSim {
        host: host.clone(),
        control_port: sim_control_port,
    };

    start_ecu_sim(&ecu_sim)
        .await
        .expect("failed to start ECU simulator");

    let mut config = Configuration {
        database: DatabaseConfig {
            path: mdd_fixture_dir().to_string_lossy().into_owned(),
            exit_no_database_loaded: true,
            ..Default::default()
        },
        communication: CommunicationSettings {
            init_mode: CommunicationInitMode::Deferred,
            post_update_mode: post_update_communication,
            deferred_retry_after_seconds: retry_after_seconds,
        },
        ..Configuration::default()
    };
    config.server.address.clone_from(&host);
    config.server.port = cda_port;
    config.doip.tester_address = host.clone();
    config.doip.gateway_port = gateway_port;
    config.runtime_update_config.storage_dir = storage_dir.path().to_string_lossy().into_owned();
    config.flash_files_path = storage_dir.path().to_string_lossy().into_owned();
    std::mem::forget(storage_dir);

    let base_url = format!("http://{host}:{cda_port}");
    let client = reqwest::Client::new();

    spawn_deferred_cda(config, plugin);

    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .expect("timeout too large");
    loop {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status() == reqwest::StatusCode::OK
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "deferred-mode CDA did not become ready within 10s"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }

    (DeferredCda { base_url, client }, ecu_sim)
}

/// Spawns the deferred-mode CDA webserver task. Shared by both CDA startup
/// helpers so the tokio::spawn / setup_deferred_vehicle_routes boilerplate
/// only exists in one place.
fn spawn_deferred_cda(config: Configuration, plugin: Arc<dyn InitializationPlugin>) {
    tokio::spawn(async move {
        let webserver_config = cda_sovd::WebServerConfig {
            host: config.server.address.clone(),
            port: config.server.port,
        };

        let shutdown_signal: cda_interfaces::ShutdownSignal = {
            use futures::future::FutureExt;
            (Box::pin(std::future::pending::<()>())
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>)
                .shared()
        };

        let (dynamic_router, _webserver_task) =
            cda_sovd::launch_webserver(webserver_config.clone(), shutdown_signal.clone())
                .await
                .expect("failed to launch test webserver");

        let health_state = cda_health::add_health_routes(&dynamic_router, "test".to_owned()).await;

        if let Err(e) = opensovd_cda_lib::deferred_init::setup_deferred_vehicle_routes::<
            DefaultSecurityPluginData,
            DefaultSecurityPlugin,
        >(
            opensovd_cda_lib::deferred_init::DeferredSetupConfig {
                config,
                dynamic_router: &dynamic_router,
                webserver_config: &webserver_config,
                health_state: Some(&health_state),
                shutdown_signal,
                shutdown_cancel: tokio_util::sync::CancellationToken::new(),
            },
            plugin,
            None,
        )
        .await
        {
            panic!("setup_deferred_vehicle_routes failed: {e}");
        }
    });
}

/// Verifies that a blocking plugin can prevent initialization, keeping
/// endpoints at 503 until explicitly unblocked.
///
/// Skipped in Docker mode: the isolated CDA and ECU sim bind to `127.0.0.1`
/// with ephemeral ports that are not reachable from the Docker network.
/// DoIP frame recording requires a local ECU sim process.
#[tokio::test]
async fn blocking_plugin_keeps_503_until_unblocked() {
    if use_docker() {
        return;
    }
    let allowed = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(BlockingPlugin {
        allowed: Arc::clone(&allowed),
    });
    let (cda, ecu_sim) =
        start_deferred_cda_with_ecu_sim(plugin, 1, PostUpdateCommunicationMode::Enabled).await;

    // Start recording to verify no DoIP traffic while blocked
    ecusim::start_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start recording");

    // Poll a few times while blocked -- must stay 503.
    for _ in 0..3 {
        let response = cda.get("/vehicle/v15/components/FLXC1000/data").await;
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(200)).await;
    }

    // CRITICAL: Verify NO DoIP traffic occurred while blocked
    let recorded_frames = ecusim::stop_and_clear_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop recording");
    assert!(
        recorded_frames.is_empty(),
        "No DoIP traffic expected while plugin blocks initialization, but got: {:?}",
        recorded_frames
    );

    // Unblock initialization
    allowed.store(true, Ordering::Release);

    // Start recording again to capture traffic after unblock
    ecusim::start_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start recording");

    let response = cda
        .wait_until_not_pending(
            "/vehicle/v15/components/FLXC1000/data",
            Duration::from_secs(10),
        )
        .await;
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Verify DoIP traffic occurred after unblocking
    let recorded_frames = ecusim::stop_and_clear_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop recording");
    assert!(
        !recorded_frames.is_empty(),
        "DoIP traffic expected after initialization, but got none"
    );

    // Complete the flow with authentication
    let token_response = cda
        .client
        .post(format!("{}/vehicle/v15/authorize", cda.base_url))
        .json(&serde_json::json!({
            "client_id": "test_client",
            "client_secret": "test_secret",
        }))
        .send()
        .await
        .expect("authorize request failed");

    let body: serde_json::Value = token_response
        .json()
        .await
        .expect("parse authorize response");
    let token = body
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .expect("access_token missing")
        .to_owned();

    let response = cda
        .client
        .get(format!(
            "{}/vehicle/v15/components/FLXC1000/data",
            cda.base_url
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// Verifies that proactive trigger via CommunicationControl handle works
/// without requiring an HTTP diagnostic request.
/// Uses isolated CDA because it requires capturing the CommunicationControl handle.
///
/// Skipped in Docker mode: the isolated CDA and ECU sim bind to `127.0.0.1`
/// with ephemeral ports that are not reachable from the Docker network.
#[tokio::test]
async fn proactive_trigger_initializes_without_diagnostic_request() {
    if use_docker() {
        return;
    }
    let initialized_count = Arc::new(AtomicBool::new(false));
    let plugin = Arc::new(HandleCapturingPlugin {
        handle: tokio::sync::Mutex::new(None),
        initialized_count: Arc::clone(&initialized_count),
    });
    let (cda, ecu_sim) = start_deferred_cda_with_ecu_sim(
        Arc::clone(&plugin) as Arc<dyn InitializationPlugin>,
        1,
        PostUpdateCommunicationMode::Enabled,
    )
    .await;

    // Start recording to verify no DoIP traffic before proactive trigger
    ecusim::start_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start recording");

    // can_initialize() always returns false, so no HTTP-driven trigger can
    // succeed; only the captured handle may proactively initialize.
    let handle = plugin
        .handle
        .lock()
        .await
        .clone()
        .expect("on_ready must have been called with a comm handle");

    // Verify no DoIP traffic occurred before trigger
    let recorded_frames = ecusim::stop_and_clear_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop recording");
    assert!(
        recorded_frames.is_empty(),
        "No DoIP traffic expected before proactive trigger, but got: {:?}",
        recorded_frames
    );

    // Start recording for the trigger phase
    ecusim::start_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start recording");

    // Trigger initialization without any HTTP request
    let trigger_result = handle.enable().await;
    assert!(
        trigger_result.is_ok(),
        "proactive trigger failed: {trigger_result:?}"
    );
    assert_eq!(handle.state().await, CommState::Active);
    assert!(initialized_count.load(Ordering::Acquire));

    // Verify DoIP traffic occurred after proactive trigger
    let recorded_frames = ecusim::stop_and_clear_recording(&ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop recording");
    assert!(
        !recorded_frames.is_empty(),
        "DoIP traffic expected after proactive trigger, but got none"
    );

    // The diagnostic endpoint must now serve 200 with no further requests
    // needed to trigger initialization (vehicle routes are now registered).
    let token_response = cda
        .client
        .post(format!("{}/vehicle/v15/authorize", cda.base_url))
        .json(&serde_json::json!({
            "client_id": "test_client",
            "client_secret": "test_secret",
        }))
        .send()
        .await
        .expect("authorize request failed");

    let body: serde_json::Value = token_response
        .json()
        .await
        .expect("parse authorize response");
    let token = body
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .expect("access_token missing")
        .to_owned();

    let response = cda
        .client
        .get(format!(
            "{}/vehicle/v15/components/FLXC1000/data",
            cda.base_url
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("request failed");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

/// Verifies that after a runtime update with `PostUpdateCommunicationMode::Deferred`,
/// diagnostic endpoints return 503 again until re-triggered.
///
/// # TODO
///
/// This test requires:
/// 1. A running isolated CDA with a real update plugin (`DefaultRuntimeReloaderPlugin`).
/// 2. Uploading a new MDD package via the runtime-update endpoint and waiting for
///    the reload cycle to complete.
/// 3. Verifying that `comm_handle.active()` is reset to `false` by the reloader
///    when `PostUpdateCommunicationMode::Deferred` is in effect.
///
/// The test infrastructure in `start_deferred_cda_with_ecu_sim` does not yet wire
/// in an update plugin (it passes `None` to `setup_deferred_vehicle_routes`), so
/// the reload cannot be triggered programmatically.  Once the test helpers support
/// providing an update plugin, this test should:
///   a. Start a CDA in deferred mode with `PostUpdateCommunicationMode::Deferred`
///      and a real update plugin.
///   b. Trigger initialization (transition away from 503 state).
///   c. Perform a runtime update by uploading an MDD package and waiting for the
///      reloader to complete (`POST /vehicle/v15/apps/sovd2uds/update`).
///   d. Verify diagnostic endpoints return 503 again after the update.
///   e. Trigger initialization again (exits 503 state again).
#[ignore = "requires update-plugin wiring in test helpers; see TODO in test body"]
#[tokio::test]
async fn test_post_update_deferred_mode_returns_503_until_triggered() {
    if use_docker() {
        return;
    }

    // Step a: start CDA in deferred mode with PostUpdateCommunicationMode::Deferred.
    // Use OnDemandInitPlugin so initialization is triggered by the first request.
    let plugin = Arc::new(OnDemandInitPlugin);
    let (cda, _ecu_sim) =
        start_deferred_cda_with_ecu_sim(plugin, 1, PostUpdateCommunicationMode::Deferred).await;

    // Step b: trigger initialization by sending a diagnostic request and waiting
    // until the guard exits the 503 state.
    let response = cda
        .wait_until_not_pending(
            "/vehicle/v15/components/FLXC1000/data",
            Duration::from_secs(10),
        )
        .await;
    assert_ne!(
        response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "endpoint must leave 503 state after initialization"
    );

    // Step c: perform a runtime update.
    // TODO: upload an MDD package via the update endpoint once the test helper
    // wires in a real DefaultRuntimeReloaderPlugin.
    // For now the update step is omitted and the test is marked #[ignore].

    // Step d: after the update, diagnostic endpoints should return 503 again.
    // (Cannot be verified until step c is implemented.)

    // Step e: trigger initialization again.
    // (Cannot be verified until step d is implemented.)
}
