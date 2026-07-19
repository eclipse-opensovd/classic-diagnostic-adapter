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
//! off and rebooted - would stay `Offline` until some caller happens to
//! trigger the on-demand probe in `ecu_online`. The transport is responsible
//! for presenting settled online/offline states on its own.
//!
//! Bus load is bounded: only currently-undiscovered ECUs are probed, one
//! round per interval, sequentially.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::{CanDiagGateway, background::BackgroundTask};

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
        variant_detection: tokio::sync::mpsc::Sender<Vec<String>>,
    ) -> BackgroundTask {
        let gateway = self.clone();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = cda_interfaces::spawn_named!("can-rediscovery", async move {
            loop {
                tokio::select! {
                    () = task_cancel.cancelled() => break,
                    () = cda_interfaces::util::tokio_ext::sleep_for(REDISCOVERY_INTERVAL) => {}
                }

                let undiscovered: Vec<String> = {
                    let discovered = gateway.discovered_ecus.read().await;
                    gateway
                        .connections
                        .keys()
                        .filter(|name| !discovered.contains(*name))
                        .cloned()
                        .collect()
                };
                if undiscovered.is_empty() {
                    continue;
                }

                let mut recovered = Vec::new();
                for ecu_name in undiscovered {
                    if task_cancel.is_cancelled() {
                        return;
                    }
                    if gateway.probe_ecu(&ecu_name).await {
                        recovered.push(ecu_name);
                    }
                }

                if !recovered.is_empty() {
                    tracing::info!(
                        ecus = ?recovered,
                        "ECUs rediscovered on CAN"
                    );
                    if variant_detection.send(recovered).await.is_err() {
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
}
