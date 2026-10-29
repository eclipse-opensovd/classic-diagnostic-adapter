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

use async_trait::async_trait;
use cda_interfaces::{
    EcuConnectivityHandler, EcuRuntimeState, HashMap, VariantDetectionRequest,
    VariantDetectionSender, VariantState, dlt_ctx,
};

use crate::coordinator::{
    EcuConnected, EcuCoordinatorHandle, EcuDisconnected, RestoreDisconnectHandling,
    SuppressDisconnectHandling,
};

/// Coordinates ECU state transitions in response to connectivity events.
///
/// Holds per-ECU [`EcuCoordinatorHandle`]s that provide actor-serialized state mutations.
/// Passed to the transport layer so connectivity events can propagate to the diagnostic
/// layer without acquiring any `RwLock<EcuManager>`.
///
/// On disconnect only the variant is cleared (marked for re-detection).
/// Session and security state are preserved, as they are owned by the
/// respective protocol flows (lock release, hard reset) and not by the
/// transport layer.
#[derive(Clone)]
pub struct EcuStateCoordinator {
    handles: Arc<HashMap<String, EcuCoordinatorHandle>>,
    /// A real `Offline` -> `Online` transition pushes the ECU into this
    /// channel for variant re-detection; without it a reconnected ECU
    /// stays `NotTested` until the next UDS request, too late for
    /// state-only consumers like the network structure.
    redetect: VariantDetectionSender,
}

impl EcuStateCoordinator {
    /// Create coordinator handles for all ECUs in the map.
    ///
    /// Each ECU gets its own actor spawned, sharing the `EcuRuntimeState` from the
    /// `EcuManager` stored in `ecus`.
    ///
    /// `redetect` receives reconnected ECUs for variant re-detection; a
    /// coordinator that swallows reconnects leaves ECUs undetected, so it
    /// is required. Tests pass a channel and drop the receiver.
    #[must_use]
    pub fn new(
        runtime_states: HashMap<String, EcuRuntimeState>,
        redetect: VariantDetectionSender,
    ) -> Self {
        let handles: HashMap<String, EcuCoordinatorHandle> = runtime_states
            .into_iter()
            .map(|(ecu_name, state)| {
                let handle = EcuCoordinatorHandle::spawn_with_state(ecu_name.clone(), state);
                (ecu_name, handle)
            })
            .collect();

        Self {
            handles: Arc::new(handles),
            redetect,
        }
    }

    /// Mark the ECU as connected (Online) on the next request.
    ///
    /// Sends a fire-and-forget message to the ECU's coordinator actor.
    /// Does NOT acquire any `RwLock<EcuManager>` - safe to call from any context.
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    pub(crate) async fn handle_ecu_connected(&self, ecu_name: &str) {
        tracing::info!(ecu_name, "ECU connected - setting connectivity to Online");

        if let Some(handle) = self.handles.get(ecu_name) {
            let transitioned = handle.actor_ref.ask(EcuConnected).await.unwrap_or_default();
            // Push a re-detection whenever the reconnected ECU has no valid
            // variant: a real Offline -> Online transition resets it to
            // NotTested, and a reconnect during variant detection (when
            // disconnect events are suppressed, so no transition is seen)
            // can leave a stale offline verdict behind. Triggering on every
            // such reconnect mirrors the transport announcing the ECU;
            // detection runs are coalesced downstream.
            let needs_detection =
                transitioned || crate::transport::needs_variant_detection(&handle.ecu_status());
            if needs_detection {
                let _ = self
                    .redetect
                    .send(VariantDetectionRequest::new(vec![ecu_name.to_owned()]))
                    .await;
            }
        }
    }

    /// Mark the ECU's variant for re-detection on the next request.
    ///
    /// Sends a fire-and-forget message to the ECU's coordinator actor.
    /// Does NOT acquire any `RwLock<EcuManager>` - safe to call from any context.
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    pub(crate) async fn handle_ecu_disconnected(&self, ecu_name: &str) {
        tracing::info!(
            ecu_name,
            "ECU disconnected - setting connectivity to Offline"
        );

        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.tell(EcuDisconnected).await;
        }
    }

    /// Records a reply of the ECU, positive or negative (including the pending
    /// NRCs 0x78, 0x21 and 0x94, and a frame that does not answer the request),
    /// regardless of the overall result of the request: updates `last_seen`.
    pub(crate) fn handle_ecu_responded(&self, ecu_name: &str) {
        let Some(handle) = self.handles.get(ecu_name) else {
            return;
        };
        handle.state.update_last_seen();
    }

    /// Get the coordinator handle for a specific ECU.
    #[must_use]
    pub fn get_handle(&self, ecu_name: &str) -> Option<&EcuCoordinatorHandle> {
        self.handles.get(ecu_name)
    }

    /// Suppress disconnect events for the given ECU during variant detection.
    ///
    /// Uses `ask` (request-response) to guarantee suppression is active before
    /// variant detection sends begin.
    pub(crate) async fn suppress_disconnect_handling(&self, ecu_name: &str) {
        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.ask(SuppressDisconnectHandling).await;
        }
    }

    /// Re-enable disconnect events for the given ECU after variant detection completes.
    ///
    /// Uses `ask` (request-response) to guarantee the restore has been processed
    /// before returning, so concurrent suppress/restore calls cannot interleave.
    pub(crate) async fn restore_disconnect_handling(&self, ecu_name: &str) {
        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.ask(RestoreDisconnectHandling).await;
        }
    }
}

#[async_trait]
impl EcuConnectivityHandler for EcuStateCoordinator {
    async fn on_gateway_connected(&self, ecu_names: &[String]) {
        for ecu_name in ecu_names {
            self.handle_ecu_connected(ecu_name).await;
        }
    }

    async fn on_gateway_disconnected(&self, ecu_names: &[String]) {
        for ecu_name in ecu_names {
            self.handle_ecu_disconnected(ecu_name).await;
        }
    }

    /// A transport reports a frame by the ECU name it maps the frame to; for a
    /// tester present NRC that is every ECU with the frame's source address. An
    /// ECU in state Duplicate shares its address with the detected variant and
    /// did not send the frame, so it is skipped.
    async fn on_ecu_replied(&self, ecu_name: &str) {
        if self
            .handles
            .get(ecu_name)
            .is_some_and(|handle| handle.state.status().variant_state == VariantState::Duplicate)
        {
            return;
        }
        self.handle_ecu_responded(ecu_name);
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        Connectivity, EcuRuntimeState, HashMap, VariantDetectionSender, VariantState,
    };

    use super::EcuStateCoordinator;

    fn make_coordinator() -> (EcuStateCoordinator, EcuRuntimeState) {
        let runtime_state = EcuRuntimeState::new();
        // Set variant to Online + Detected so disconnect can change connectivity
        {
            let mut ecu_state = runtime_state.ecu_state.write().unwrap();
            ecu_state.connectivity = Connectivity::Online;
            ecu_state.variant_state = VariantState::Detected {
                name: "TestVariant".to_owned(),
                is_base_variant: true,
                is_fallback: false,
            };
        }

        let runtime_states: HashMap<String, EcuRuntimeState> =
            HashMap::from_iter([("TestECU".to_string(), runtime_state.clone())]);

        let (redetect_tx, _redetect_rx) = tokio::sync::mpsc::channel(8);
        let coordinator =
            EcuStateCoordinator::new(runtime_states, VariantDetectionSender::new(redetect_tx));
        (coordinator, runtime_state)
    }

    #[tokio::test]
    async fn disconnected_preserves_variant() {
        let (coordinator, runtime_state) = make_coordinator();

        coordinator.handle_ecu_disconnected("TestECU").await;

        // Give actor time to process
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;

        let state = runtime_state.ecu_state.read().unwrap();
        assert_eq!(
            state.connectivity,
            Connectivity::Offline,
            "ECU should be marked as disconnected"
        );
        assert_eq!(
            state.variant_state,
            VariantState::Detected {
                name: "TestVariant".to_owned(),
                is_base_variant: true,
                is_fallback: false,
            },
            "Variant should be preserved after disconnect"
        );
    }

    #[tokio::test]
    async fn disconnected_unknown_ecu_is_noop() {
        let (coordinator, runtime_state) = make_coordinator();

        coordinator.handle_ecu_disconnected("UnknownECU").await;

        // Give actor time to process (nothing should happen)
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;

        let state = runtime_state.ecu_state.read().unwrap();
        assert_eq!(
            state.connectivity,
            Connectivity::Online,
            "Nothing should happen for unknown ECU"
        );
    }

    #[tokio::test]
    async fn connected_event_sets_online() {
        let runtime_state = EcuRuntimeState::new();
        let runtime_states: HashMap<String, EcuRuntimeState> =
            HashMap::from_iter([("TestECU".to_string(), runtime_state.clone())]);
        let (redetect_tx, _redetect_rx) = tokio::sync::mpsc::channel(8);
        let coordinator =
            EcuStateCoordinator::new(runtime_states, VariantDetectionSender::new(redetect_tx));

        coordinator.handle_ecu_connected("TestECU").await;

        // Give actor time to process
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;

        let state = runtime_state.ecu_state.read().unwrap();
        assert_eq!(
            state.connectivity,
            Connectivity::Online,
            "ECU should be marked as Online after connected event"
        );
    }

    /// A frame a transport reports updates `last_seen` of the ECU; an unknown
    /// name is a no-op.
    #[tokio::test]
    async fn transport_reply_updates_last_seen() {
        use cda_interfaces::EcuConnectivityHandler;

        let (coordinator, runtime_state) = make_coordinator();
        assert_eq!(runtime_state.last_seen(), None);

        coordinator.on_ecu_replied("UnknownECU").await;
        assert_eq!(runtime_state.last_seen(), None);

        coordinator.on_ecu_replied("TestECU").await;
        assert!(runtime_state.last_seen().is_some());
    }

    /// An ECU in state Duplicate does not get the replies a transport reports
    /// by address.
    #[tokio::test]
    async fn transport_reply_skips_duplicate_ecu() {
        use cda_interfaces::EcuConnectivityHandler;

        let (coordinator, runtime_state) = make_coordinator();
        runtime_state.ecu_state.write().unwrap().variant_state = VariantState::Duplicate;

        coordinator.on_ecu_replied("TestECU").await;

        assert_eq!(runtime_state.last_seen(), None);
    }
}
