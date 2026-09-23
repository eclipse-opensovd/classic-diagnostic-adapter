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

//! Tests of the test environments themselves: lifecycle operations, the pool,
//! the test-facing entry points, and the isolation of parallel environments.

use std::{
    cell::Cell,
    net::IpAddr,
    panic::AssertUnwindSafe,
    sync::{LazyLock, Mutex, PoisonError},
    time::{Duration, Instant},
};

use cda_interfaces::communication_control::{
    CommunicationInitMode, CommunicationSettings, PostUpdateCommunicationMode, VariantDetectionMode,
};
use futures::FutureExt;
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response as NetworkStructureResponse;

use crate::{
    sovd::{ECU_FLXC1000_ENDPOINT, ECU_TMCC3000_ENDPOINT},
    util::{
        TestingError, ecusim,
        http::{auth_header, response_to_t, send_cda_request},
        test_env::{
            Pool, TestEnv, Transport, setup_integration_test, setup_integration_test_without_cda,
            skip_for_doip, wait_for_ecus_online,
        },
    },
};

/// Retry-After of the on-demand configuration, distinct from any default.
const ON_DEMAND_RETRY_AFTER_SECONDS: u64 = 7;

/// A diagnostic request that reaches FLXC1000, expecting `status`.
async fn read_flxc1000_data(
    config: &Configuration,
    status: StatusCode,
) -> Result<crate::util::http::Response, TestingError> {
    let headers = auth_header(config, None).await?;
    send_cda_request(
        config,
        &format!("{ECU_FLXC1000_ENDPOINT}/data"),
        status,
        Method::GET,
        None,
        Some(&headers),
        None,
    )
    .await
}

/// Changes `config` to on-demand communication, observable as a `503` with
/// [`ON_DEMAND_RETRY_AFTER_SECONDS`] on the first diagnostic request.
fn make_on_demand(config: &mut Configuration) {
    config.communication = CommunicationSettings {
        init_mode: CommunicationInitMode::OnDemand,
        variant_detection: VariantDetectionMode::Always,
        post_update_mode: PostUpdateCommunicationMode::Enabled,
        deferred_retry_after_seconds: ON_DEMAND_RETRY_AFTER_SECONDS,
    };
}

/// Starts the CDA with on-demand communication, see [`make_on_demand`].
async fn restart_on_demand(env: &mut TestEnv) -> Result<(), TestingError> {
    env.restart_cda_with_config(make_on_demand).await
}

/// The default configuration of `env`, changed by [`make_on_demand`].
fn on_demand_config(env: &TestEnv) -> Configuration {
    let mut config = env.default_config().clone();
    make_on_demand(&mut config);
    config
}

/// Checks that the CDA of `env` runs with the default configuration again.
async fn assert_runs_default(env: &TestEnv) -> Result<(), TestingError> {
    assert_eq!(
        env.config.communication,
        env.default_config().communication,
        "the environment does not report the default configuration"
    );
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;
    Ok(())
}

async fn assert_runs_on_demand(env: &TestEnv) -> Result<(), TestingError> {
    let response = read_flxc1000_data(&env.config, StatusCode::SERVICE_UNAVAILABLE).await?;
    let retry_after = response
        .header(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    assert_eq!(
        retry_after,
        Some(ON_DEMAND_RETRY_AFTER_SECONDS.to_string()),
        "the CDA does not run with the on-demand configuration"
    );
    Ok(())
}

/// Waits until the containers of `env` printed at least `frames` log frames.
async fn wait_for_log_frames(env: &TestEnv, frames: u64) -> Result<(), TestingError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or_else(|| TestingError::SetupError("deadline overflowed".to_owned()))?;
    while env.log_frames() < frames {
        if Instant::now() >= deadline {
            return Err(TestingError::Timeout(
                "no container output was printed".to_owned(),
            ));
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test]
async fn env_lifecycle() -> Result<(), TestingError> {
    let mut env = setup_integration_test_without_cda().await?;
    ecusim::get_ecu_state(&env.ecu_sim, "flxc1000").await?;
    assert!(
        read_flxc1000_data(&env.config, StatusCode::OK)
            .await
            .is_err(),
        "a CDA answers although none was started"
    );
    let server = env.config.server.clone();

    let default_config = env.default_config().clone();
    env.restart_cda(&default_config).await?;
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;

    // A new CDA container with another configuration, on the same port.
    restart_on_demand(&mut env).await?;
    assert_eq!(env.config.server.address, server.address);
    assert_eq!(env.config.server.port, server.port);
    assert_runs_on_demand(&env).await?;

    env.stop_cda().await?;
    assert!(
        read_flxc1000_data(&env.config, StatusCode::OK)
            .await
            .is_err(),
        "the CDA still answers after stop_cda"
    );

    env.restart_cda(&default_config).await?;
    assert_eq!(env.config.server.port, server.port);
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;

    // ecu-sim stops and comes back on the same control port, with its output
    // still printed.
    env.stop_ecu_sim().await?;
    assert!(
        ecusim::get_ecu_state(&env.ecu_sim, "flxc1000")
            .await
            .is_err(),
        "ecu-sim still answers after stop_ecu_sim"
    );
    let frames = env.log_frames();
    env.start_ecu_sim().await?;
    ecusim::get_ecu_state(&env.ecu_sim, "flxc1000").await?;
    wait_for_log_frames(&env, frames.saturating_add(1)).await?;
    // A running CDA did not reconnect to the restarted ecu-sim within the
    // budget of wait_for_ecus_online, so start a fresh one.
    env.restart_cda(&default_config).await?;
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;

    Ok(())
}

#[tokio::test]
async fn leased_env_serves_requests() -> Result<(), TestingError> {
    let env = setup_integration_test().await?;
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;
    Ok(())
}

/// `pre_start` runs before the CDA restarts, `body` against the temporary
/// configuration, and the default configuration is restored afterwards.
#[tokio::test]
async fn with_temporary_cda_restores_default_config() -> Result<(), TestingError> {
    let mut env = setup_integration_test().await?;
    let temporary_config = on_demand_config(&env);
    let pre_started = Cell::new(false);
    let body_ran = Cell::new(false);

    env.with_temporary_cda(
        temporary_config,
        async |env| {
            assert_eq!(
                env.config.communication,
                env.default_config().communication,
                "pre_start runs after the CDA restarted"
            );
            pre_started.set(true);
        },
        async |env| {
            assert!(pre_started.get(), "body runs before pre_start");
            assert_runs_on_demand(env)
                .await
                .expect("body does not run against the temporary configuration");
            body_ran.set(true);
        },
    )
    .await;

    assert!(body_ran.get(), "body did not run");
    assert_runs_default(&env).await
}

/// Payload of the panic of the body in
/// [`with_temporary_cda_restores_default_config_after_panic`], to tell it from
/// a failed assertion.
struct BodyPanic;

#[tokio::test]
async fn with_temporary_cda_restores_default_config_after_panic() -> Result<(), TestingError> {
    let mut env = setup_integration_test().await?;
    let temporary_config = on_demand_config(&env);

    let outcome = AssertUnwindSafe(env.with_temporary_cda(
        temporary_config,
        async |_| {},
        async |env| {
            assert_runs_on_demand(env)
                .await
                .expect("body does not run against the temporary configuration");
            std::panic::panic_any(BodyPanic);
        },
    ))
    .catch_unwind()
    .await;

    let Err(panic) = outcome else {
        panic!("the panic of the body was not resumed");
    };
    assert!(
        panic.is::<BodyPanic>(),
        "the body did not panic as intended: {:?}",
        panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
    );
    assert_runs_default(&env).await
}

/// Pool of one environment, shared by [`first_pooled_lease`] and
/// [`second_pooled_lease`], so that they run one after the other on the same
/// environment.
static SINGLE_ENV_POOL: LazyLock<Pool> = LazyLock::new(|| Pool::new(Transport::from_env(), 1));
/// Name of the environment the first of the two tests leased.
static FIRST_LEASED_ENV: Mutex<Option<String>> = Mutex::new(None);

/// Whichever of the two tests gets the environment first leaves the CDA with
/// another configuration; the second checks that it gets the same environment
/// back restored, and that container output and operations still work
/// although the runtime of the first test is gone.
async fn lease_single_env_pool() -> Result<(), TestingError> {
    let mut env = SINGLE_ENV_POOL.lease().await?;
    let first = FIRST_LEASED_ENV
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(env.name().to_owned());

    let Some(first) = first else {
        restart_on_demand(&mut env).await?;
        return Ok(());
    };

    assert_eq!(first, env.name(), "the pool did not reuse its environment");
    // Restored: ecu-sim runs, and the CDA runs with the default configuration.
    ecusim::get_ecu_state(&env.ecu_sim, "flxc1000").await?;
    wait_for_ecus_online(&env.config).await?;
    read_flxc1000_data(&env.config, StatusCode::OK).await?;

    // One line each from the CDA restored for this test, and from ecu-sim,
    // whose log consumer was started by the first test.
    let frames = env.log_frames();
    env.echo_to_logs("second lease").await?;
    wait_for_log_frames(&env, frames.saturating_add(2)).await?;

    env.stop_ecu_sim().await?;
    env.start_ecu_sim().await?;
    restart_on_demand(&mut env).await?;
    assert_runs_on_demand(&env).await?;

    Ok(())
}

#[tokio::test]
async fn first_pooled_lease() -> Result<(), TestingError> {
    lease_single_env_pool().await
}

#[tokio::test]
async fn second_pooled_lease() -> Result<(), TestingError> {
    lease_single_env_pool().await
}

/// The ECUs a CDA discovered, as `(gateway address, ECU)`.
async fn discovered_ecus(config: &Configuration) -> Result<Vec<(String, String)>, TestingError> {
    let response = send_cda_request(
        config,
        "apps/sovd2uds/data/networkstructure",
        StatusCode::OK,
        Method::GET,
        None,
        None,
        None,
    )
    .await?;
    let structure: NetworkStructureResponse = response_to_t(&response)?;
    let mut ecus: Vec<_> = structure
        .data
        .iter()
        .flat_map(|data| data.gateways.iter())
        .flat_map(|gateway| {
            gateway
                .ecus
                .iter()
                .map(|ecu| (gateway.network_address.clone(), ecu.qualifier.clone()))
        })
        .collect();
    ecus.sort();
    Ok(ecus)
}

fn same_slash_16(a: &str, b: IpAddr) -> bool {
    let (Ok(IpAddr::V4(a)), IpAddr::V4(b)) = (a.parse::<IpAddr>(), b) else {
        return false;
    };
    a.octets()[..2] == b.octets()[..2]
}

/// Every environment has a network of its own, so the `DoIP` discovery of one
/// CDA finds only the ECUs of its own ecu-sim.
#[tokio::test]
async fn parallel_doip_envs_discover_only_their_own_ecus() -> Result<(), TestingError> {
    let (first, second) = tokio::join!(
        TestEnv::start(Transport::DoIp),
        TestEnv::start(Transport::DoIp)
    );
    let (first, second) = (first?, second?);
    let (online_first, online_second) = tokio::join!(
        wait_for_ecus_online(&first.config),
        wait_for_ecus_online(&second.config)
    );
    online_first?;
    online_second?;

    let first_sim = first.ecu_sim_ip().await?;
    let second_sim = second.ecu_sim_ip().await?;
    assert!(
        !same_slash_16(&first_sim.to_string(), second_sim),
        "both environments share a subnet: {first_sim} and {second_sim}"
    );

    let first_ecus = discovered_ecus(&first.config).await?;
    let second_ecus = discovered_ecus(&second.config).await?;
    eprintln!("{} discovered {first_ecus:?}", first.name());
    eprintln!("{} discovered {second_ecus:?}", second.name());
    assert!(!first_ecus.is_empty(), "no ECUs discovered");
    for (ecus, sim) in [(&first_ecus, first_sim), (&second_ecus, second_sim)] {
        for (gateway, ecu) in ecus {
            assert!(
                same_slash_16(gateway, sim),
                "{ecu} was discovered at {gateway}, outside the network of ecu-sim {sim}"
            );
        }
    }
    let qualifiers = |ecus: &[(String, String)]| {
        let mut qualifiers: Vec<_> = ecus.iter().map(|(_, ecu)| ecu.clone()).collect();
        qualifiers.sort();
        qualifiers
    };
    assert_eq!(qualifiers(&first_ecus), qualifiers(&second_ecus));

    Ok(())
}

/// A live read of TMCC3000 through the CDA of `env`. TMCC3000 is served over
/// CAN in pure-CAN and in mixed mode.
async fn read_tmcc3000_identification(
    env: &TestEnv,
) -> Result<crate::util::http::Response, TestingError> {
    let headers = auth_header(&env.config, None).await?;
    send_cda_request(
        &env.config,
        &format!("{ECU_TMCC3000_ENDPOINT}/data/identification"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&headers),
        None,
    )
    .await
}

/// Every CAN environment has a socketcand, and thus a `vcan0`, of its own:
/// with the ecu-sim of one environment stopped, its CDA gets no answer over
/// CAN, although the ecu-sim of the other environment serves the same ECU on
/// the same CAN IDs.
#[tokio::test]
async fn parallel_can_envs_have_their_own_bus() -> Result<(), TestingError> {
    if skip_for_doip(
        "parallel_can_envs_have_their_own_bus",
        "needs the CAN transport (pure-CAN or mixed mode)",
    ) {
        return Ok(());
    }
    let transport = Transport::from_env();
    let (first, second) = tokio::join!(TestEnv::start(transport), TestEnv::start(transport));
    let (mut first, second) = (first?, second?);
    let (online_first, online_second) = tokio::join!(
        wait_for_ecus_online(&first.config),
        wait_for_ecus_online(&second.config)
    );
    online_first?;
    online_second?;
    read_tmcc3000_identification(&first).await?;
    read_tmcc3000_identification(&second).await?;

    first.stop_ecu_sim().await?;
    match read_tmcc3000_identification(&first).await {
        Err(TestingError::UnexpectedResponse { actual, .. }) => {
            eprintln!("{} answers {actual} with its ecu-sim stopped", first.name());
        }
        other => panic!(
            "expected an error status from the CDA of {} with its ecu-sim stopped, got {other:?}",
            first.name()
        ),
    }
    read_tmcc3000_identification(&second).await?;

    Ok(())
}
