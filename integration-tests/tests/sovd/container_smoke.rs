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

//! Smoke tests for the `testcontainers` container builders: each container
//! starts on its own and becomes ready.

use testcontainers::{ContainerAsync, GenericImage, runners::AsyncRunner};

use crate::util::{
    TestingError,
    ecusim::{self, EcuSim},
    test_containers::{
        ECU_SIM_CONTROL_PORT, EcuSimContainer, SocketcandEndpoint, ecu_sim_container,
        socketcand_container,
    },
    test_env::skip_for_doip,
};

#[tokio::test]
async fn ecu_sim_container_serves_control_api() -> Result<(), TestingError> {
    let (_container, sim) = start_ecu_sim(ecu_sim_container(None).await?).await?;

    ecusim::get_ecu_state(&sim, "flxc1000").await?;

    Ok(())
}

/// Needs the `vcan` kernel module on the Docker host, so it only runs with
/// the CAN infrastructure enabled.
#[tokio::test]
async fn ecu_sim_container_starts_with_socketcand() -> Result<(), TestingError> {
    if skip_for_doip(
        "ecu_sim_container_starts_with_socketcand",
        "needs the vcan kernel module",
    ) {
        return Ok(());
    }

    let socketcand = socketcand_container().await?.start().await.map_err(|e| {
        TestingError::SetupError(format!("Failed to start socketcand container: {e}"))
    })?;
    // Both run on the default bridge network, where containers reach each
    // other by IP only.
    let socketcand_ip = socketcand.get_bridge_ip_address().await.map_err(|e| {
        TestingError::SetupError(format!("Failed to get socketcand IP address: {e}"))
    })?;
    let endpoint = SocketcandEndpoint::new(socketcand_ip.to_string());

    let (_container, sim) = start_ecu_sim(ecu_sim_container(Some(&endpoint)).await?).await?;

    ecusim::get_ecu_state(&sim, "tmcc3000").await?;

    Ok(())
}

async fn start_ecu_sim(
    request: EcuSimContainer,
) -> Result<(ContainerAsync<GenericImage>, EcuSim), TestingError> {
    let container = request
        .start()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to start ecu-sim container: {e}")))?;
    let sim = EcuSim {
        host: container
            .get_host()
            .await
            .map_err(|e| TestingError::SetupError(format!("Failed to get ecu-sim host: {e}")))?
            .to_string(),
        control_port: container
            .get_host_port_ipv4(ECU_SIM_CONTROL_PORT)
            .await
            .map_err(|e| TestingError::SetupError(format!("Failed to get ecu-sim port: {e}")))?,
    };

    Ok((container, sim))
}
