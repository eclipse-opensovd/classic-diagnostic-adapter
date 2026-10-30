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
    Connectivity, EcuConnectivityHandler, EcuRuntimeState, GatewayConnectReport, HashMap,
    VariantState, dlt_ctx,
};

use crate::coordinator::{
    EcuConnected, EcuConnectionLost, EcuCoordinatorHandle, EcuDisconnected, EcuResponded,
    RestoreDisconnectHandling, SuppressDisconnectHandling,
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
}

/// Outcome of [`EcuStateCoordinator::handle_ecu_connected`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct EcuConnectOutcome {
    /// The ECU went from `Offline` to `Online`.
    pub(crate) transitioned: bool,
    /// The ECU needs a variant detection.
    pub(crate) needs_detection: bool,
}

impl EcuStateCoordinator {
    /// Create coordinator handles for all ECUs in the map.
    ///
    /// Each ECU gets its own actor spawned, sharing the `EcuRuntimeState` from the
    /// `EcuManager` stored in `ecus`.
    #[must_use]
    pub fn new(runtime_states: HashMap<String, EcuRuntimeState>) -> Self {
        let handles: HashMap<String, EcuCoordinatorHandle> = runtime_states
            .into_iter()
            .map(|(ecu_name, state)| {
                let handle = EcuCoordinatorHandle::spawn_with_state(ecu_name.clone(), state);
                (ecu_name, handle)
            })
            .collect();

        Self {
            handles: Arc::new(handles),
        }
    }

    /// Mark the ECU as connected: an `Offline` ECU becomes `Online`.
    ///
    /// Asks the ECU's coordinator actor and waits until it has applied the
    /// event. Does NOT acquire any `RwLock<EcuManager>` - safe to call from any
    /// context.
    ///
    /// Requesting the variant detection is up to the caller.
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    pub(crate) async fn handle_ecu_connected(&self, ecu_name: &str) -> EcuConnectOutcome {
        tracing::info!(ecu_name, "ECU connected - setting connectivity to Online");

        let Some(handle) = self.handles.get(ecu_name) else {
            return EcuConnectOutcome::default();
        };
        // An `AssumedOnline` ECU was restored, not detected: no earlier
        // connection can have produced a verdict that needs a second
        // opinion, and recording the connect would make the startup
        // detection run for the restored variant.
        if handle.connectivity() != Connectivity::AssumedOnline {
            handle.record_connected();
        }
        let transitioned = handle.actor_ref.ask(EcuConnected).await.unwrap_or_default();
        // A detection is needed whenever the reconnected ECU has no valid
        // variant: a real Offline -> Online transition resets it to
        // NotTested, and a reconnect of an ECU that a detection already
        // concluded on (a suppressed send timeout is no transition) can
        // leave a stale offline verdict behind. Detection runs are
        // coalesced downstream.
        let needs_detection =
            transitioned || crate::transport::needs_variant_detection(&handle.ecu_status());
        EcuConnectOutcome {
            transitioned,
            needs_detection,
        }
    }

    /// Mark the ECU's variant for re-detection on the next request.
    ///
    /// Waits until the ECU's coordinator actor has applied the event, so the
    /// state is visible to the caller on return (the topology persistence
    /// snapshots it right after).
    /// Does NOT acquire any `RwLock<EcuManager>` - safe to call from any context.
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    pub(crate) async fn handle_ecu_disconnected(&self, ecu_name: &str) {
        tracing::info!(
            ecu_name,
            "ECU disconnected - setting connectivity to Offline"
        );

        if let Some(handle) = self.handles.get(ecu_name)
            && let Err(error) = handle.actor_ref.ask(EcuDisconnected).await
        {
            tracing::warn!(ecu_name, %error, "Failed to report ECU disconnect to coordinator");
        }
    }

    /// The gateway connection of the ECU is lost: mark it Offline, also during
    /// variant detection, see [`EcuConnectionLost`].
    ///
    /// Waits until the coordinator actor has applied the event, like
    /// [`Self::handle_ecu_disconnected`].
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    async fn handle_gateway_connection_lost(&self, ecu_name: &str) {
        tracing::info!(
            ecu_name,
            "Gateway connection lost - setting connectivity to Offline"
        );

        if let Some(handle) = self.handles.get(ecu_name)
            && let Err(error) = handle.actor_ref.ask(EcuConnectionLost).await
        {
            tracing::warn!(ecu_name, %error, "Failed to report lost connection to coordinator");
        }
    }

    /// Records a reply of the ECU, positive or negative (including the pending
    /// NRCs 0x78, 0x21 and 0x94, and a frame that does not answer the request),
    /// regardless of the overall result of the request: updates `last_seen` and
    /// confirms an `AssumedOnline` ECU as `Online`.
    /// [[ dimpl~ecu-state-assumed-online, A reply confirms an assumed online ECU as online, dimpl ]]
    ///
    /// `last_seen` is updated inline. The state transition goes through the actor,
    /// so it is ordered with concurrent connect and disconnect events, and it has
    /// been applied when this returns. It is only sent while the ECU is assumed
    /// online, keeping the common path free of actor messages.
    pub(crate) async fn handle_ecu_responded(&self, ecu_name: &str) {
        let Some(handle) = self.handles.get(ecu_name) else {
            return;
        };
        handle.state.update_last_seen();
        if handle.connectivity() == Connectivity::AssumedOnline
            && let Err(error) = handle.actor_ref.ask(EcuResponded).await
        {
            tracing::warn!(ecu_name, %error, "Failed to report ECU response to coordinator");
        }
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

// The trait is the boundary to the transports: names arrive in any casing here
// and are lowercased to the key of the handles.
#[async_trait]
impl EcuConnectivityHandler for EcuStateCoordinator {
    async fn on_gateway_connected(&self, ecu_names: &[String]) -> GatewayConnectReport {
        let mut report = GatewayConnectReport::default();
        for ecu_name in ecu_names {
            let outcome = self.handle_ecu_connected(&ecu_name.to_lowercase()).await;
            if outcome.transitioned {
                report.brought_online.push(ecu_name.clone());
            }
            if outcome.needs_detection {
                report.needs_detection.push(ecu_name.clone());
            }
        }
        report
    }

    async fn on_gateway_disconnected(&self, ecu_names: &[String]) {
        for ecu_name in ecu_names {
            self.handle_gateway_connection_lost(&ecu_name.to_lowercase())
                .await;
        }
    }

    /// A transport reports a frame by the ECU name it maps the frame to; for a
    /// tester present NRC that is every ECU with the frame's source address. An
    /// ECU in state Duplicate shares its address with the detected variant and
    /// did not send the frame, so it is skipped.
    async fn on_ecu_replied(&self, ecu_name: &str) {
        let ecu_name = ecu_name.to_lowercase();
        if self
            .handles
            .get(&ecu_name)
            .is_some_and(|handle| handle.state.status().variant_state == VariantState::Duplicate)
        {
            return;
        }
        self.handle_ecu_responded(&ecu_name).await;
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        Connectivity, EcuConnectivityHandler as _, EcuRuntimeState, GatewayConnectReport, HashMap,
        VariantState,
    };

    use super::EcuStateCoordinator;

    /// A coordinator of the ECU `testecu` in `connectivity` with the detected
    /// variant `variant`.
    fn coordinator(
        connectivity: Connectivity,
        variant: &str,
    ) -> (EcuStateCoordinator, EcuRuntimeState) {
        let runtime_state = EcuRuntimeState::new();
        {
            let mut ecu_state = runtime_state.ecu_state.write().unwrap();
            ecu_state.connectivity = connectivity;
            ecu_state.variant_state = VariantState::Detected {
                name: variant.to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
            ecu_state.variant_index = Some(3);
        }
        let runtime_states: HashMap<String, EcuRuntimeState> =
            HashMap::from_iter([("testecu".to_string(), runtime_state.clone())]);
        let coordinator = EcuStateCoordinator::new(runtime_states);
        (coordinator, runtime_state)
    }

    #[tokio::test]
    async fn disconnected_preserves_variant() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");

        coordinator.handle_ecu_disconnected("testecu").await;

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
                is_base_variant: false,
                is_fallback: false,
            },
            "Variant should be preserved after disconnect"
        );
    }

    /// [[ test~uds-gateway-disconnect-applied-before-return, A gateway disconnect is applied to the ECU states before the call returns, test ]]
    #[tokio::test]
    async fn gateway_disconnect_is_applied_before_return() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");

        coordinator
            .on_gateway_disconnected(&["testecu".to_owned()])
            .await;

        assert_eq!(runtime_state.status().connectivity, Connectivity::Offline);
    }

    /// A lost connection is a fact, not a verdict of the detection: the ECU must
    /// not stay `Online` on a connection that no longer exists.
    #[tokio::test]
    async fn gateway_disconnect_during_detection_sets_offline() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
        coordinator.suppress_disconnect_handling("testecu").await;

        coordinator
            .on_gateway_disconnected(&["testecu".to_owned()])
            .await;

        assert_eq!(runtime_state.status().connectivity, Connectivity::Offline);
    }

    /// The members of a duplicate group share one transport: a timeout of a
    /// detection request must not mark them offline, no reconnect would follow.
    #[tokio::test]
    async fn send_timeout_during_detection_keeps_ecu_online() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
        coordinator.suppress_disconnect_handling("testecu").await;

        coordinator.handle_ecu_disconnected("testecu").await;

        assert_eq!(runtime_state.status().connectivity, Connectivity::Online);
    }

    #[tokio::test]
    async fn reconnect_after_gateway_disconnect_during_detection_redetects() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
        coordinator.suppress_disconnect_handling("testecu").await;
        let ecu_names = ["testecu".to_owned()];

        coordinator.on_gateway_disconnected(&ecu_names).await;
        let report = coordinator.on_gateway_connected(&ecu_names).await;

        assert_eq!(runtime_state.status().connectivity, Connectivity::Online);
        assert_eq!(
            runtime_state.status().variant_state,
            VariantState::NotTested
        );
        assert_eq!(
            report.needs_detection, ecu_names,
            "the reconnected ECU must be detected again"
        );
    }

    #[tokio::test]
    async fn disconnected_unknown_ecu_is_noop() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");

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
        let coordinator = EcuStateCoordinator::new(runtime_states);

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

    /// Gateway events reach the ECU whatever the casing of the name.
    #[tokio::test]
    async fn gateway_events_ignore_the_casing_of_the_name() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
        let ecu_names = ["TestECU".to_owned()];

        coordinator.on_gateway_disconnected(&ecu_names).await;
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            runtime_state.ecu_state.read().unwrap().connectivity,
            Connectivity::Offline
        );

        coordinator.on_gateway_connected(&ecu_names).await;
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            runtime_state.ecu_state.read().unwrap().connectivity,
            Connectivity::Online
        );
    }

    /// A frame a transport reports updates `last_seen` of the ECU, whatever the
    /// casing of the name; an unknown name is a no-op.
    #[tokio::test]
    async fn transport_reply_updates_last_seen() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
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
        let (coordinator, runtime_state) = coordinator(Connectivity::Online, "TestVariant");
        runtime_state.ecu_state.write().unwrap().variant_state = VariantState::Duplicate;

        coordinator.on_ecu_replied("TestECU").await;

        assert_eq!(runtime_state.last_seen(), None);
    }

    /// [[ test~uds-state-restored-duplicate-survives-connect-but-real-reconnect-redetects, Connecting the gateway keeps a restored variant while a reconnect of an Offline ECU detects it again, test ]]
    #[tokio::test]
    async fn restored_duplicate_survives_connect_but_real_reconnect_redetects() {
        let (coordinator, runtime_state) =
            coordinator(Connectivity::AssumedOnline, "RestoredVariant");
        runtime_state.ecu_state.write().unwrap().variant_state = VariantState::Duplicate;
        let names = ["testecu".to_owned()];
        let report = coordinator.on_gateway_connected(&names).await;
        assert_eq!(
            runtime_state.status().variant_state,
            VariantState::Duplicate
        );
        assert_eq!(
            runtime_state.status().connectivity,
            Connectivity::AssumedOnline
        );
        assert_eq!(report, GatewayConnectReport::default());
        assert!(
            !coordinator
                .get_handle("testecu")
                .unwrap()
                .connected_since_detection(),
            "connecting a restored ECU must not make a detection run"
        );

        coordinator.on_gateway_disconnected(&names).await;
        let report = coordinator.on_gateway_connected(&names).await;
        assert_eq!(
            runtime_state.status().variant_state,
            VariantState::NotTested
        );
        assert_eq!(report.needs_detection, names);
        assert_eq!(report.brought_online, names);
    }

    /// The report lists the names as the caller passed them, and only the ECUs
    /// that went from Offline to Online as brought online.
    /// [[ test~uds-gateway-connect-report-lists-only-offline-ecus, The connect report lists only the ECUs that went from Offline to Online as brought online, test ]]
    #[tokio::test]
    async fn report_lists_only_offline_ecus_as_brought_online() {
        let states: Vec<(&str, Connectivity)> = vec![
            ("offline", Connectivity::Offline),
            ("online", Connectivity::Online),
            ("assumed", Connectivity::AssumedOnline),
        ];
        let runtime_states: HashMap<String, EcuRuntimeState> = states
            .iter()
            .map(|(name, connectivity)| {
                let state = EcuRuntimeState::new();
                {
                    let mut ecu_state = state.ecu_state.write().unwrap();
                    ecu_state.connectivity = *connectivity;
                    ecu_state.variant_state = VariantState::Detected {
                        name: "Variant".to_owned(),
                        is_base_variant: false,
                        is_fallback: false,
                    };
                }
                ((*name).to_owned(), state)
            })
            .collect();
        let coordinator = EcuStateCoordinator::new(runtime_states);
        let names = ["Offline", "Online", "Assumed"].map(str::to_owned);

        let report = coordinator.on_gateway_connected(&names).await;

        assert_eq!(report.brought_online, ["Offline"]);
        assert_eq!(report.needs_detection, ["Offline"]);
    }

    /// The undo of a connect covers the brought online ECUs only: an
    /// `AssumedOnline` ECU keeps state, variant and index, also while the
    /// disconnect handling is suppressed.
    /// [[ test~uds-gateway-connect-undo-keeps-assumed-online-ecu, The undo of a gateway connect keeps an `AssumedOnline` ECU and its restored variant, test ]]
    #[tokio::test]
    async fn undo_of_a_connect_keeps_an_assumed_online_ecu() {
        for suppressed in [false, true] {
            let (coordinator, runtime_state) =
                coordinator(Connectivity::AssumedOnline, "RestoredVariant");
            let before = runtime_state.status();
            if suppressed {
                coordinator.suppress_disconnect_handling("testecu").await;
            }
            let names = ["testecu".to_owned()];

            let report = coordinator.on_gateway_connected(&names).await;
            assert!(report.brought_online.is_empty());
            // What the commit of a connect does with the report.
            coordinator
                .on_gateway_disconnected(&report.brought_online)
                .await;

            let after = runtime_state.status();
            assert_eq!(after.connectivity, before.connectivity, "{suppressed}");
            assert_eq!(after.variant_state, before.variant_state, "{suppressed}");
            assert_eq!(after.variant_index, before.variant_index, "{suppressed}");
            assert_eq!(after.variant_index, Some(3));
        }
    }

    /// A connect of an Offline ECU followed by its undo ends Offline.
    /// [[ test~uds-gateway-connect-undo-leaves-offline-ecu-offline, The undo of a gateway connect leaves an Offline ECU Offline, test ]]
    #[tokio::test]
    async fn undo_of_a_connect_leaves_an_offline_ecu_offline() {
        let (coordinator, runtime_state) = coordinator(Connectivity::Offline, "TestVariant");
        let names = ["testecu".to_owned()];

        let report = coordinator.on_gateway_connected(&names).await;
        assert_eq!(report.brought_online, names);
        assert_eq!(runtime_state.status().connectivity, Connectivity::Online);
        coordinator
            .on_gateway_disconnected(&report.brought_online)
            .await;

        assert_eq!(runtime_state.status().connectivity, Connectivity::Offline);
    }

    /// [[ test~uds-state-assumed-online-becomes-online-on-response, The first reply turns an `AssumedOnline` ECU Online, test ]]
    #[tokio::test]
    async fn assumed_online_becomes_online_on_response() {
        // A reply to a request, and a frame the transport does not pass on as
        // an answer.
        for transport_reply in [false, true] {
            let (coordinator, runtime_state) =
                coordinator(Connectivity::AssumedOnline, "RestoredVariant");
            assert_eq!(runtime_state.last_seen(), None);

            if transport_reply {
                coordinator.on_ecu_replied("TestECU").await;
            } else {
                coordinator.handle_ecu_responded("testecu").await;
            }

            let state = runtime_state.status();
            assert_eq!(
                state.connectivity,
                Connectivity::Online,
                "{transport_reply}"
            );
            assert_eq!(state.name(), Some("RestoredVariant"));
            assert!(runtime_state.last_seen().is_some());
        }
    }

    /// A transport reply does not confirm an assumed online ECU in state
    /// Duplicate: the frame came from the detected variant.
    #[tokio::test]
    async fn transport_reply_keeps_assumed_online_duplicate() {
        let (coordinator, runtime_state) =
            coordinator(Connectivity::AssumedOnline, "RestoredVariant");
        runtime_state.ecu_state.write().unwrap().variant_state = VariantState::Duplicate;

        coordinator.on_ecu_replied("TestECU").await;

        assert_eq!(
            runtime_state.status().connectivity,
            Connectivity::AssumedOnline
        );
        assert_eq!(runtime_state.last_seen(), None);
    }
}
