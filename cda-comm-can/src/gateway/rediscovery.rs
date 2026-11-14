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

//! Background rediscovery of configured-but-undiscovered ECUs.
//!
//! CAN has no connection events: the only way to learn that an ECU (re)joined
//! the bus is to ask it. Requests to undiscovered ECUs are rejected before
//! reaching the bus, and state reads never touch the transport, so without
//! this task an ECU that was offline during startup discovery - or dropped
//! off and rebooted, or was marked undiscovered after an all-silent
//! exchange (an ECU asleep while the keep-alive broadcast is disabled) -
//! would stay `Offline` until some caller happens to trigger the on-demand
//! probe in `ecu_online`. The transport is responsible for presenting
//! settled online/offline states on its own.
//!
//! Bus load is bounded: only currently-undiscovered ECUs are probed, one
//! round per interval, sequentially.

use std::{sync::Arc, time::Duration};

use cda_interfaces::{VariantDetectionRequest, VariantDetectionSender};
use tokio_util::sync::CancellationToken;

use super::{
    CanDiagGateway, background::BackgroundTask, connection::CanEcuConnection, discovered_on_current,
};

/// Delay between rediscovery rounds. Chosen so a returning ECU is picked up
/// within a few seconds without turning absent ECUs into permanent probe
/// chatter on the bus.
const REDISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

impl CanDiagGateway {
    /// Starts the background task that periodically re-probes ECUs the
    /// gateway knows addresses for but has not (currently) discovered.
    /// Newly answering ECUs are pushed into `variant_detection`, which brings
    /// them `Online` through the regular detection flow.
    pub(super) fn start_rediscovery(
        &self,
        variant_detection: VariantDetectionSender,
    ) -> BackgroundTask {
        let gateway = self.clone();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = cda_interfaces::spawn_named!("can-rediscovery", async move {
            loop {
                tokio::select! {
                    // Prefer shutdown over starting another round.
                    biased;
                    () = task_cancel.cancelled() => break,
                    () = cda_interfaces::util::tokio_ext::sleep_for(REDISCOVERY_INTERVAL) => {}
                }

                gateway.prune_removed_ecus().await;
                let targets = gateway.undiscovered_targets().await;
                if targets.is_empty() {
                    continue;
                }

                let mut recovered = Vec::new();
                for (ecu_name, conn, logical_addr) in targets {
                    if task_cancel.is_cancelled() {
                        return;
                    }
                    if gateway
                        .probe_and_record(&conn, logical_addr, ecu_name.clone())
                        .await
                    {
                        recovered.push(ecu_name);
                    }
                }

                if !recovered.is_empty() {
                    tracing::info!(
                        ecus = ?recovered,
                        "ECUs rediscovered on CAN"
                    );
                    if variant_detection
                        .send(VariantDetectionRequest::new(recovered))
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            "Variant detection channel closed, stopping CAN rediscovery"
                        );
                        break;
                    }
                }
            }
            tracing::debug!("CAN rediscovery stopped");
        });
        BackgroundTask::new(cancel, task)
    }

    /// Copies out what probing the currently undiscovered ECUs needs, so the
    /// topology guard is not held across the probes or the variant detection
    /// send; see `topology`. Undiscovered includes an ECU discovered on
    /// addressing the topology no longer holds for it. Lock order is
    /// topology, then `discovered_ecus`.
    pub(super) async fn undiscovered_targets(&self) -> Vec<(String, CanEcuConnection, u16)> {
        let topology = self.topology.read().await;
        let discovered = self.discovered_ecus.read().await;
        topology
            .connections()
            .iter()
            .filter(|(name, _)| !discovered_on_current(&topology, &discovered, name))
            .map(|(name, addressing)| {
                (
                    name.clone(),
                    CanEcuConnection::new(Arc::clone(addressing)),
                    topology.logical_address_for_ecu(name).unwrap_or_default(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{VariantDetectionSender, util::test_utils::RecordingConnectivityHandler};
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        config::{CanAddressingMode, CanConfig},
        gateway::test_utils::shared_topology,
    };

    fn topology_with(name: &str, request: u32, response: u32) -> crate::gateway::CanTopology {
        shared_topology(vec![(
            name,
            crate::gateway::CanEcuAddressing::new(
                name.to_owned(),
                "test0".to_owned(),
                cda_interfaces::CanId::try_from(request).expect("valid test CAN ID"),
                cda_interfaces::CanId::try_from(response).expect("valid test CAN ID"),
                CanAddressingMode::Standard,
            ),
        )])
    }

    /// The snapshot must not keep a guard alive: a reload applied right after
    /// it has to complete, as it would while the round probes or waits on a
    /// full variant detection channel.
    #[tokio::test]
    async fn target_snapshot_does_not_block_a_topology_reload() {
        let (gateway, reload) = CanDiagGateway::build(
            &CanConfig {
                interface: "test0".to_owned(),
                ..CanConfig::default()
            },
            topology_with("ecu1", 0x700, 0x708),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(RecordingConnectivityHandler::default()),
        )
        .expect("build test gateway");

        let targets = gateway.undiscovered_targets().await;
        assert_eq!(targets.len(), 1);

        tokio::time::timeout(
            Duration::from_secs(1),
            reload.apply(topology_with("ecu2", 0x710, 0x718)),
        )
        .await
        .expect("apply must not wait on the snapshot");

        // The snapshot is owned: still usable after the reload.
        assert_eq!(
            targets.first().map(|(name, ..)| name.as_str()),
            Some("ecu1")
        );
    }

    /// An ECU counts as undiscovered for rediscovery unless its recorded
    /// discovery matches its current addressing, so a reload that changes its
    /// IDs gets it re-probed on the new ones.
    #[tokio::test]
    async fn targets_include_ecus_discovered_on_replaced_addressing() {
        let (gateway, reload) = CanDiagGateway::reloadable_test_instance(
            topology_with("ecu1", 0x700, 0x708),
            vec!["ecu1"],
            Arc::new(RecordingConnectivityHandler::default()),
        );
        assert!(gateway.undiscovered_targets().await.is_empty());

        reload.apply(topology_with("ecu1", 0x7E0, 0x7E8)).await;

        let targets = gateway.undiscovered_targets().await;
        assert_eq!(
            targets
                .iter()
                .map(|(name, conn, _)| (name.as_str(), conn.request_id().raw()))
                .collect::<Vec<_>>(),
            vec![("ecu1", 0x7E0)]
        );
    }
}
