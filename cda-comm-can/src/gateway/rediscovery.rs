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
//! round per interval, concurrently across ECUs.

use std::time::Duration;

use cda_interfaces::{TransportProbe, VariantDetectionRequest, VariantDetectionSender};
use tokio_util::sync::CancellationToken;

use super::{CanDiagGateway, background::BackgroundTask};

/// Delay between rediscovery rounds. Chosen so a returning ECU is picked up
/// within a few seconds without turning absent ECUs into permanent probe
/// chatter on the bus.
const REDISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

// Probes undiscovered ECUs concurrently and collects the names that respond.
// Waits for the whole batch; cancellation drops pending probes and returns None.
async fn probe_undiscovered<P: TransportProbe>(
    gateway: &P,
    undiscovered: Vec<String>,
    cancel: &CancellationToken,
) -> Option<Vec<String>> {
    let probes = undiscovered.into_iter().map(|ecu_name| async move {
        let responding = gateway.probe_ecu(&ecu_name).await;
        responding.then_some(ecu_name)
    });

    tokio::select! {
        // Prefer shutdown over completing a pending batch.
        biased;
        () = cancel.cancelled() => None,
        results = futures::future::join_all(probes) => {
            Some(results.into_iter().flatten().collect())
        }
    }
}

// Sends recovered ECU names as a single variant-detection request.
// Returns true once queued, or false on cancellation or channel closure.
// Cancellation also interrupts waiting for channel capacity.
async fn notify_recovered(
    variant_detection: &VariantDetectionSender,
    recovered: Vec<String>,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        // Prefer cancellation over blocking on a full channel.
        biased;
        () = cancel.cancelled() => false,
        result = variant_detection.send(VariantDetectionRequest::new(recovered)) => {
            if result.is_err() {
                tracing::warn!(
                    "Variant detection channel closed, stopping CAN rediscovery"
                );
                false
            } else {
                true
            }
        }
    }
}

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

                let Some(recovered) =
                    probe_undiscovered(&gateway, undiscovered, &task_cancel).await
                else {
                    break;
                };

                if !recovered.is_empty() {
                    tracing::info!(
                        ecus = ?recovered,
                        "ECUs rediscovered on CAN"
                    );
                    if !notify_recovered(&variant_detection, recovered, &task_cancel).await {
                        break;
                    }
                }
            }
            tracing::debug!("CAN rediscovery stopped");
        });
        BackgroundTask::new(cancel, task)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "can-socketcand")]
    use cda_interfaces::CanId;
    use tokio::sync::mpsc;

    use super::*;
    #[cfg(feature = "can-socketcand")]
    use crate::{config::CanAddressingMode, gateway::connection::CanEcuConnection};

    // Builds three nonresponding ECU connections on an isolated local endpoint.
    #[cfg(feature = "can-socketcand")]
    fn undiscovered_gateway(
        probe_timeout: Duration,
    ) -> (CanDiagGateway, Vec<String>, std::net::TcpListener) {
        // Reserve a unique endpoint: socketcand caches connections across test runtimes.
        // Keeping the listener open without serving responses makes every probe time out.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve endpoint");
        let interface = format!(
            "socketcand:127.0.0.1:{}:vcan0",
            listener.local_addr().expect("endpoint address").port()
        );
        let connections = [
            ("missing-1", 0x600, 0x608),
            ("missing-2", 0x610, 0x618),
            ("missing-3", 0x620, 0x628),
        ]
        .into_iter()
        .map(|(name, request_id, response_id)| {
            (
                name,
                CanEcuConnection::new(
                    name.to_owned(),
                    interface.clone(),
                    CanId::try_from(request_id).expect("valid request ID"),
                    CanId::try_from(response_id).expect("valid response ID"),
                    CanAddressingMode::Standard,
                ),
            )
        })
        .collect();
        let mut gateway = CanDiagGateway::test_instance(connections, vec![]);
        gateway.probe_timeout = probe_timeout;
        let names = gateway.connections.keys().cloned().collect();
        (gateway, names, listener)
    }

    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    async fn rediscovery_probes_unresponsive_ecus_concurrently() {
        const PROBE_TIMEOUT: Duration = Duration::from_millis(250);
        let (gateway, names, _listener) = undiscovered_gateway(PROBE_TIMEOUT);
        let start = std::time::Instant::now();

        assert_eq!(
            probe_undiscovered(&gateway, names, &CancellationToken::new()).await,
            Some(vec![])
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed >= PROBE_TIMEOUT,
            "probes must wait for a response timeout"
        );
        assert!(
            elapsed < PROBE_TIMEOUT * 2,
            "three probes should complete near one timeout, not three: {elapsed:?}"
        );
    }

    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    async fn rediscovery_cancellation_interrupts_pending_probes() {
        let (gateway, names, _listener) = undiscovered_gateway(Duration::from_secs(60));
        let cancel = CancellationToken::new();
        let batch = probe_undiscovered(&gateway, names, &cancel);
        tokio::pin!(batch);
        assert!(futures::poll!(&mut batch).is_pending());

        cancel.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), batch)
                .await
                .expect("cancellation interrupts pending probes"),
            None
        );
    }

    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    async fn cancelled_rediscovery_returns_none() {
        let (gateway, names, _listener) = undiscovered_gateway(Duration::from_secs(60));
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                probe_undiscovered(&gateway, names, &cancel),
            )
            .await
            .expect("already-cancelled batch completes immediately"),
            None
        );
    }

    #[tokio::test]
    async fn rediscovery_notifies_variant_detection_with_one_recovered_batch() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sender = VariantDetectionSender::new(sender);
        let recovered = vec!["first".to_owned(), "last".to_owned()];

        assert!(notify_recovered(&sender, recovered.clone(), &CancellationToken::new()).await);
        assert_eq!(
            receiver
                .try_recv()
                .expect("recovered batch sent")
                .into_ecus(),
            recovered
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn rediscovery_cancellation_interrupts_a_blocked_notification() {
        // Fill a one-slot channel so the next send must wait for the receiver to make room.
        let (sender, mut receiver) = mpsc::channel(1);
        let sender = VariantDetectionSender::new(sender);
        let queued = VariantDetectionRequest::new(vec!["queued".to_owned()]);
        sender.send(queued.clone()).await.expect("fill channel");
        let cancel = CancellationToken::new();
        let notification = notify_recovered(&sender, vec!["recovered".to_owned()], &cancel);
        // Poll this same future before cancelling to prove the send is already blocked.
        tokio::pin!(notification);
        assert!(futures::poll!(&mut notification).is_pending());
        cancel.cancel();
        assert!(!notification.await);
        assert_eq!(receiver.try_recv().expect("original batch remains"), queued);
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}
