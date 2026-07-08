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

//! Per-ECU state coordinator implemented as a kameo actor.
//!
//! The [`EcuCoordinator`] actor serializes connectivity state mutations for a single ECU.
//! Variant detection writes happen directly via `std::sync::RwLock` (from `EcuManager`),
//! while disconnect events go through the actor to avoid races.
//!
//! Reads go directly through [`EcuCoordinatorHandle::state`] (a `std::sync::RwLock`)
//! without touching the actor mailbox.

use cda_interfaces::{
    Connectivity, EcuRuntimeState, EcuState, VariantState, dlt_ctx, util::std_ext,
};
use kameo::{
    Actor,
    actor::{ActorRef, Spawn},
    message::{Context, Message},
};

/// The kameo actor that serializes connectivity state mutations for one ECU.
#[derive(Actor)]
pub struct EcuCoordinator {
    /// Shared runtime state, also held by [`EcuCoordinatorHandle`] for direct synchronous reads.
    state: EcuRuntimeState,
    ecu_name: String,
    /// When `true`, `EcuDisconnected` messages are suppressed.
    /// Set during variant detection to prevent timeout-triggered disconnects
    /// from racing with the detection result.
    suppress_disconnect: bool,
}

/// Cloneable handle providing read access and actor messaging for one ECU.
///
/// Distributed to all components that need to read or mutate ECU runtime state.
/// Direct reads via [`Self::state`] bypass the mailbox; mutations go through
/// [`Self::actor_ref`].
#[derive(Clone)]
pub struct EcuCoordinatorHandle {
    /// Actor reference for sending mutation messages.
    pub actor_ref: ActorRef<EcuCoordinator>,
    /// Shared state for direct synchronous reads. The actor is the sole writer
    /// for connectivity; variant detection writes directly.
    pub state: EcuRuntimeState,
}

impl EcuCoordinatorHandle {
    /// Spawn a new coordinator actor for the given ECU.
    ///
    /// Returns a handle that can be cloned and distributed to all consumers.
    #[must_use]
    pub fn spawn(ecu_name: String) -> Self {
        let state = EcuRuntimeState::new();
        Self::spawn_with_state(ecu_name, state)
    }

    /// Spawn a coordinator actor sharing an existing [`EcuRuntimeState`].
    ///
    /// Use this when the `EcuManager` already owns the `EcuRuntimeState`
    /// and the coordinator should operate on the same instance.
    #[must_use]
    pub fn spawn_with_state(ecu_name: String, state: EcuRuntimeState) -> Self {
        let actor_ref = EcuCoordinator::spawn(EcuCoordinator {
            state: state.clone(),
            ecu_name,
            suppress_disconnect: false,
        });
        Self { actor_ref, state }
    }

    /// Read the current ECU status (synchronous, no mailbox round-trip).
    #[must_use]
    pub fn ecu_status(&self) -> EcuState {
        self.state.status()
    }

    /// Read the current connectivity (synchronous).
    #[must_use]
    pub fn connectivity(&self) -> Connectivity {
        std_ext::lock_read(&self.state.ecu_state).connectivity
    }

    /// Read a service state by SID (synchronous).
    #[must_use]
    pub fn get_service_state(&self, sid: u8) -> Option<String> {
        std_ext::lock_read(&self.state.service_states)
            .get(&sid)
            .cloned()
    }
}

/// Set a single service state entry (e.g. session or security level after UDS response).
pub struct SetServiceState {
    /// UDS service identifier (SID).
    pub sid: u8,
    /// New state value (e.g. "extended", "`level_42`").
    pub value: String,
}

impl Message<SetServiceState> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: SetServiceState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::debug!(
            ecu = %self.ecu_name,
            sid = msg.sid,
            value = %msg.value,
            "Setting service state"
        );
        std_ext::lock_write(&self.state.service_states).insert(msg.sid, msg.value);
    }
}

/// Set default service states (session, security, DTC, comm control) if not already present.
pub struct SetDefaultStates {
    /// Default values to insert if missing: `(SID, default_value)`.
    pub defaults: Vec<(u8, String)>,
}

impl Message<SetDefaultStates> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: SetDefaultStates,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut service_states = std_ext::lock_write(&self.state.service_states);
        for (sid, default_value) in msg.defaults {
            service_states.entry(sid).or_insert(default_value);
        }
    }
}

/// Clear all service states message
pub struct ClearServiceStates;

impl Message<ClearServiceStates> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: ClearServiceStates,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!(
            ecu = %self.ecu_name,
            "Clearing all service states"
        );
        std_ext::lock_write(&self.state.service_states).clear();
    }
}

/// ECU disconnected event -> sets connectivity to Offline, preserving variant state.
///
/// Only transitions from `Online` to `Offline`. If already `Offline`, this is a no-op.
/// Variant state is preserved.
pub struct EcuDisconnected;

impl Message<EcuDisconnected> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: EcuDisconnected,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.suppress_disconnect {
            tracing::debug!(
                ecu = %self.ecu_name,
                "ECU disconnect suppressed during variant detection"
            );
            return;
        }

        let mut ecu_state = std_ext::lock_write(&self.state.ecu_state);

        if ecu_state.connectivity == Connectivity::Online {
            tracing::info!(
                ecu = %self.ecu_name,
                dlt_context = dlt_ctx!("UDS"),
                "ECU disconnected. Setting connectivity to Offline"
            );
            ecu_state.connectivity = Connectivity::Offline;
        } else {
            tracing::debug!(
                ecu = %self.ecu_name,
                current = ?ecu_state.connectivity,
                "ECU disconnect received but already Offline..skipping"
            );
        }
    }
}

/// ECU connected event -> sets connectivity to Online and clears variant for re-detection.
///
/// Only transitions from `Offline` to `Online`. If already `Online`, this is a no-op.
/// Variant state is cleared to `NotTested` because the ECU may have rebooted while offline
/// (e.g. into a different session/variant). The pre-send guard will trigger re-detection
/// on the next UDS request.
pub struct EcuConnected;

impl Message<EcuConnected> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: EcuConnected,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let mut ecu_state = std_ext::lock_write(&self.state.ecu_state);

        if ecu_state.connectivity == Connectivity::Offline {
            tracing::info!(
                ecu = %self.ecu_name,
                dlt_context = dlt_ctx!("UDS"),
                "ECU connected. Setting connectivity to Online"
            );
            ecu_state.connectivity = Connectivity::Online;
            ecu_state.variant_state = VariantState::NotTested;
            ecu_state.variant_index = None;
        } else {
            tracing::debug!(
                ecu = %self.ecu_name,
                current = ?ecu_state.connectivity,
                "ECU connected received but already Online..skipping"
            );
        }
    }
}

/// Suppress disconnect events for this ECU during variant detection.
///
/// Uses `ask` (request-response) to guarantee the suppression is active
/// before variant detection sends begin.
pub struct SuppressDisconnectHandling;

impl Message<SuppressDisconnectHandling> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: SuppressDisconnectHandling,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::debug!(
            ecu = %self.ecu_name,
            "Variant detection starting. Suppressing disconnect events"
        );
        self.suppress_disconnect = true;
    }
}

/// Re-enable disconnect events after variant detection completes.
pub struct RestoreDisconnectHandling;

impl Message<RestoreDisconnectHandling> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: RestoreDisconnectHandling,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::debug!(
            ecu = %self.ecu_name,
            "Variant detection finished. Re-enabling disconnect events"
        );
        self.suppress_disconnect = false;
    }
}

/// Mark ECU as having duplicate logical addresses.
pub struct MarkAsDuplicate;

impl Message<MarkAsDuplicate> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: MarkAsDuplicate,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::warn!(
            ecu = %self.ecu_name,
            "Marking ECU as duplicate"
        );
        let mut ecu_state = std_ext::lock_write(&self.state.ecu_state);
        ecu_state.variant_state = VariantState::Duplicate;
        ecu_state.variant_index = None;
    }
}

/// Mark ECU as having no variant detected (detection failed, no fallback).
pub struct MarkAsNoVariantDetected;

impl Message<MarkAsNoVariantDetected> for EcuCoordinator {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: MarkAsNoVariantDetected,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::warn!(
            ecu = %self.ecu_name,
            "Marking ECU as no-variant-detected"
        );
        let mut ecu_state = std_ext::lock_write(&self.state.ecu_state);
        ecu_state.variant_state = VariantState::NotDetected;
        ecu_state.variant_index = None;
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{Connectivity, VariantState, service_ids};

    use super::*;

    fn spawn_test_coordinator(ecu_name: &str) -> EcuCoordinatorHandle {
        EcuCoordinatorHandle::spawn(ecu_name.to_owned())
    }

    #[tokio::test]
    async fn initial_state_is_offline_not_tested() {
        let handle = spawn_test_coordinator("TestECU");
        let status = handle.ecu_status();
        assert_eq!(status.connectivity, Connectivity::Offline);
        assert_eq!(status.variant_state, VariantState::NotTested);
    }

    #[tokio::test]
    async fn set_service_state_updates_state() {
        let handle = spawn_test_coordinator("TestECU");
        handle
            .actor_ref
            .tell(SetServiceState {
                sid: service_ids::SESSION_CONTROL,
                value: "extended".to_owned(),
            })
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        let session = handle.get_service_state(service_ids::SESSION_CONTROL);
        assert_eq!(session, Some("extended".to_owned()));
    }

    #[tokio::test]
    async fn set_default_states_does_not_override_existing() {
        let handle = spawn_test_coordinator("TestECU");

        handle
            .actor_ref
            .tell(SetServiceState {
                sid: service_ids::SESSION_CONTROL,
                value: "programming".to_owned(),
            })
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        handle
            .actor_ref
            .tell(SetDefaultStates {
                defaults: vec![
                    (service_ids::SESSION_CONTROL, "default".to_owned()),
                    (service_ids::SECURITY_ACCESS, "locked".to_owned()),
                ],
            })
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(
            handle.get_service_state(service_ids::SESSION_CONTROL),
            Some("programming".to_owned()),
            "Existing state must not be overridden"
        );
        assert_eq!(
            handle.get_service_state(service_ids::SECURITY_ACCESS),
            Some("locked".to_owned()),
            "Missing state should be inserted"
        );
    }

    #[tokio::test]
    async fn clear_service_states_empties_map() {
        let handle = spawn_test_coordinator("TestECU");
        handle
            .actor_ref
            .tell(SetServiceState {
                sid: service_ids::SESSION_CONTROL,
                value: "extended".to_owned(),
            })
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        handle
            .actor_ref
            .tell(ClearServiceStates)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert!(
            handle
                .get_service_state(service_ids::SESSION_CONTROL)
                .is_none()
        );
    }

    #[tokio::test]
    async fn ecu_disconnected_transitions_online_to_offline() {
        let handle = spawn_test_coordinator("TestECU");
        // Set to Online first
        handle.state.ecu_state.write().unwrap().connectivity = Connectivity::Online;

        handle
            .actor_ref
            .tell(EcuDisconnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.connectivity(), Connectivity::Offline);
        // Variant state should be untouched
        assert_eq!(handle.ecu_status().variant_state, VariantState::NotTested);
    }

    #[tokio::test]
    async fn ecu_disconnected_is_noop_when_already_offline() {
        let handle = spawn_test_coordinator("TestECU");
        // Initial state is Offline

        handle
            .actor_ref
            .tell(EcuDisconnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.connectivity(), Connectivity::Offline);
    }

    #[tokio::test]
    async fn ecu_disconnected_preserves_variant() {
        let handle = spawn_test_coordinator("TestECU");
        // Set Online + Detected variant
        {
            let mut ecu_state = handle.state.ecu_state.write().unwrap();
            ecu_state.connectivity = Connectivity::Online;
            ecu_state.variant_state = VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
            ecu_state.variant_index = Some(3);
        }

        handle
            .actor_ref
            .tell(EcuDisconnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        let status = handle.ecu_status();
        assert_eq!(status.connectivity, Connectivity::Offline);
        assert_eq!(
            status.variant_state,
            VariantState::Detected {
                name: "MyVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            }
        );
        assert_eq!(status.variant_index, Some(3));
    }

    #[tokio::test]
    async fn mark_as_duplicate_sets_state() {
        let handle = spawn_test_coordinator("TestECU");
        handle
            .actor_ref
            .tell(MarkAsDuplicate)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.ecu_status().variant_state, VariantState::Duplicate);
    }

    #[tokio::test]
    async fn ecu_connected_transitions_offline_to_online() {
        let handle = spawn_test_coordinator("TestECU");
        // Initial state is Offline + NotTested

        handle
            .actor_ref
            .tell(EcuConnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.connectivity(), Connectivity::Online);
        assert_eq!(handle.ecu_status().variant_state, VariantState::NotTested);
    }

    #[tokio::test]
    async fn ecu_connected_clears_variant_for_redetection() {
        let handle = spawn_test_coordinator("TestECU");
        // Simulate: was Online+Detected, then disconnected (Offline+Detected)
        {
            let mut ecu_state = handle.state.ecu_state.write().unwrap();
            ecu_state.connectivity = Connectivity::Offline;
            ecu_state.variant_state = VariantState::Detected {
                name: "Application".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            };
            ecu_state.variant_index = Some(2);
        }

        handle
            .actor_ref
            .tell(EcuConnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        let status = handle.ecu_status();
        assert_eq!(status.connectivity, Connectivity::Online);
        assert_eq!(status.variant_state, VariantState::NotTested);
        assert_eq!(status.variant_index, None);
    }

    #[tokio::test]
    async fn ecu_connected_is_noop_when_already_online() {
        let handle = spawn_test_coordinator("TestECU");
        handle.state.ecu_state.write().unwrap().connectivity = Connectivity::Online;

        handle
            .actor_ref
            .tell(EcuConnected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.connectivity(), Connectivity::Online);
    }

    #[tokio::test]
    async fn mark_as_no_variant_detected_sets_state() {
        let handle = spawn_test_coordinator("TestECU");
        handle
            .actor_ref
            .tell(MarkAsNoVariantDetected)
            .await
            .expect("Actor should be alive");
        tokio::task::yield_now().await;

        assert_eq!(handle.ecu_status().variant_state, VariantState::NotDetected);
    }
}
