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

use cda_interfaces::communication_control::{
    CommunicationAccess, CommunicationError, CommunicationGuard, CommunicationState,
    TransportControl, VariantDetectionMode,
};

use crate::lifecycle::{
    CommunicationHandle,
    disable::{DisableError, DisableReason},
    state::CommunicationStateStore,
    worker,
};

/// Synchronous, all-in-one constructor for test and `test-utils`
/// fixtures only. Production wiring goes through
/// [`super::build_communication_runtime`] instead, which stages construction
/// around the plugin-builder handshake this shortcuts.
#[must_use]
pub(crate) fn communication_handle_new(
    transport_control: Arc<dyn TransportControl>,
) -> CommunicationHandle {
    communication_handle_with_detection_mode(transport_control, VariantDetectionMode::Always)
}

/// As [`communication_handle_new`], but with an explicit detection policy,
/// for fixtures that exercise `VariantDetectionMode::Never`.
#[must_use]
pub(crate) fn communication_handle_with_detection_mode(
    transport_control: Arc<dyn TransportControl>,
    variant_detection: VariantDetectionMode,
) -> CommunicationHandle {
    let resources = worker::new_resources(transport_control);
    communication_handle_from_resources(CommunicationState::Disabled, resources, variant_detection)
}

fn communication_handle_from_resources(
    initial_state: CommunicationState,
    resources: worker::WorkerResources,
    variant_detection: VariantDetectionMode,
) -> CommunicationHandle {
    let state = Arc::new(CommunicationStateStore::new(
        initial_state,
        variant_detection,
    ));
    let (sender, receivers) = worker::channel();
    let worker_task = Arc::new(tokio::sync::Mutex::new(Some(worker::spawn(
        Arc::clone(&state),
        resources,
        receivers,
    ))));
    CommunicationHandle {
        state,
        worker: sender,
        worker_task,
    }
}

#[must_use]
pub fn enabled_communication_access_for_test() -> Arc<dyn CommunicationAccess> {
    struct TestTransport;

    #[async_trait::async_trait]
    impl TransportControl for TestTransport {
        async fn enable(
            &self,
        ) -> Result<(), cda_interfaces::communication_control::CommControlError> {
            Ok(())
        }

        async fn disable(
            &self,
        ) -> Result<(), cda_interfaces::communication_control::CommControlError> {
            Ok(())
        }

        async fn state(&self) -> cda_interfaces::communication_control::TransportState {
            cda_interfaces::communication_control::TransportState::Enabled
        }
    }

    struct Access(CommunicationHandle);

    impl CommunicationAccess for Access {
        fn state(&self) -> CommunicationState {
            self.0.state()
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            self.0.acquire()
        }

        fn request_activate(
            &self,
            _cause: cda_interfaces::communication_control::ActivationCause,
        ) -> CommunicationState {
            self.0.request_enable_and_detect()
        }

        fn variant_detection(&self) -> VariantDetectionMode {
            // Hardcoded rather than delegated, for the same reason the
            // state is: this fixture starts `Enabled` without ever running
            // an activation, so the handle's effective mode was never
            // claimed and would report a fixture artifact rather than what
            // a healthy enabled runtime looks like.
            VariantDetectionMode::Always
        }
    }

    let resources = worker::new_resources(Arc::new(TestTransport));
    Arc::new(Access(communication_handle_from_resources(
        CommunicationState::Enabled,
        resources,
        VariantDetectionMode::Always,
    )))
}

pub fn communication_disable_for_test(
    transport_control: Arc<dyn TransportControl>,
    initially_enabled: bool,
) -> Arc<dyn crate::lifecycle::disable::DisableCommunication> {
    struct Disable(CommunicationHandle);

    #[async_trait::async_trait]
    impl crate::lifecycle::disable::DisableCommunication for Disable {
        async fn disable(
            &self,
            reason: DisableReason,
        ) -> Result<Box<dyn cda_interfaces::communication_control::DisableGuard>, DisableError>
        {
            self.0.disable(reason).await.map(|lease| {
                Box::new(lease) as Box<dyn cda_interfaces::communication_control::DisableGuard>
            })
        }
    }

    let handle = if initially_enabled {
        let resources = worker::new_resources(transport_control);
        communication_handle_from_resources(
            CommunicationState::Enabled,
            resources,
            VariantDetectionMode::Always,
        )
    } else {
        communication_handle_new(transport_control)
    };
    Arc::new(Disable(handle))
}
