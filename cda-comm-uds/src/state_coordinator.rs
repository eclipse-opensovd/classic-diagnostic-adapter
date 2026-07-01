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

use cda_interfaces::{EcuRuntimeState, EcuStateEvents, HashMap, dlt_ctx};

use crate::coordinator::{
    EcuCoordinatorHandle, EcuDisconnected, FinishVariantDetection, PrepareVariantDetection,
};

/// Coordinates ECU state transitions in response to connectivity events.
///
/// Holds per-ECU [`EcuCoordinatorHandle`]s that provide actor-serialized state mutations.
/// Passed to the `DoIP` layer (as `impl EcuStateEvents`) so transport-level disconnects
/// can propagate variant invalidation up to the diagnostic layer without acquiring any
/// `RwLock<EcuManager>`.
///
/// On disconnect only the variant is cleared (marked for re-detection).
/// Session and security state are preserved, as they are owned by the
/// respective protocol flows (lock release, hard reset) and not by the
/// transport layer.
#[derive(Clone)]
pub struct EcuStateCoordinator {
    handles: Arc<HashMap<String, EcuCoordinatorHandle>>,
}

impl EcuStateCoordinator {
    /// Create coordinator handles for all ECUs in the map.
    ///
    /// Each ECU gets its own actor spawned, sharing the `EcuRuntimeState` from the
    /// `EcuManager` stored in `ecus`.
    pub(crate) fn new(runtime_states: HashMap<String, EcuRuntimeState>) -> Self {
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

    /// Mark the ECU's variant for re-detection on the next request.
    ///
    /// Sends a fire-and-forget message to the ECU's coordinator actor.
    /// Does NOT acquire any `RwLock<EcuManager>` - safe to call from any context.
    #[tracing::instrument(skip_all, fields(ecu_name, dlt_context = dlt_ctx!("UDS")))]
    pub(crate) async fn handle_ecu_disconnected(&self, ecu_name: &str) {
        tracing::info!(
            ecu_name,
            "ECU disconnected - scheduling variant re-detection"
        );

        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.tell(EcuDisconnected).await;
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
    pub(crate) async fn prepare_variant_detection(&self, ecu_name: &str) {
        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.ask(PrepareVariantDetection).await;
        }
    }

    /// Re-enable disconnect events for the given ECU after variant detection completes.
    pub(crate) async fn finish_variant_detection(&self, ecu_name: &str) {
        if let Some(handle) = self.handles.get(ecu_name) {
            let _ = handle.actor_ref.tell(FinishVariantDetection).await;
        }
    }
}

impl EcuStateEvents for EcuStateCoordinator {
    async fn on_ecu_disconnected(&self, ecu_name: &str) {
        self.handle_ecu_disconnected(ecu_name).await;
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{Connectivity, EcuRuntimeState, EcuStateEvents, HashMap, VariantState};

    use super::EcuStateCoordinator;

    fn make_coordinator() -> (EcuStateCoordinator, EcuRuntimeState) {
        let runtime_state = EcuRuntimeState::new();
        // Set variant to Online + Detected so disconnect can change connectivity
        {
            let mut es = runtime_state.ecu_state.write().unwrap();
            es.connectivity = Connectivity::Online;
            es.variant_state = VariantState::Detected {
                name: "TestVariant".to_owned(),
                is_base_variant: true,
                is_fallback: false,
            };
        }

        let runtime_states: HashMap<String, EcuRuntimeState> =
            HashMap::from_iter([("TestECU".to_string(), runtime_state.clone())]);

        let coordinator = EcuStateCoordinator::new(runtime_states);
        (coordinator, runtime_state)
    }

    #[tokio::test]
    async fn disconnected_clears_variant() {
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
            state.connectivity,
            Connectivity::Offline,
            "Connectivity should be Offline after disconnect"
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
    async fn ecu_state_events_dispatches_to_disconnected() {
        let (coordinator, runtime_state) = make_coordinator();

        // Call via the trait interface
        EcuStateEvents::on_ecu_disconnected(&coordinator, "TestECU").await;

        // Give actor time to process
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(10)).await;

        let state = runtime_state.ecu_state.read().unwrap();
        assert_eq!(
            state.connectivity,
            Connectivity::Offline,
            "Variant should be marked as disconnected via trait dispatch"
        );
    }
}
