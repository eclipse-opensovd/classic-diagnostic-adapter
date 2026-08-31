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

//! Capability-limited transport control over a replaceable gateway.
//!
//! [[ dimpl~communication-control-swappable-gateway, Replaceable gateway transport-control capability, dimpl, req~plugin-diagnostic-database-update; arch~plugin-diagnostic-database-update ]]
use std::sync::Arc;

use async_trait::async_trait;

use super::{CommControlError, TransportControl, TransportState};
use crate::{Shutdown, component_slot::ComponentSlot};

/// [`TransportControl`] proxy over a hot-swappable gateway slot, delegating every
/// call to whatever gateway [`ComponentSlot`] currently holds.
///
/// Private: the only way to obtain one is [`ComponentSlot::transport_control`],
/// which requires owning the slot. The runtime-update plugin only replaces the
/// gateway and is handed a [`crate::component_slot::ReplaceComponent`] instead.
///
/// Each call takes a read guard on the slot rather than a `Mutex`, so `state()`
/// is not blocked behind an in-flight `enable()`. Replacement takes the write
/// guard, so it cannot race a control call.
struct SwappableGateway<G: Shutdown> {
    slot: ComponentSlot<G>,
}

impl<G: TransportControl + Shutdown> ComponentSlot<G> {
    /// Mints a [`TransportControl`] view over this slot. See [`SwappableGateway`].
    #[must_use]
    pub fn transport_control(&self) -> Arc<dyn TransportControl> {
        Arc::new(SwappableGateway { slot: self.clone() })
    }
}

#[async_trait]
impl<G: TransportControl + Shutdown> TransportControl for SwappableGateway<G> {
    async fn enable(&self) -> Result<(), CommControlError> {
        let gateway = self.slot.read().await;
        gateway.enable().await
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let gateway = self.slot.read().await;
        gateway.disable().await
    }

    async fn state(&self) -> TransportState {
        self.slot.read().await.state().await
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;
    use crate::Shutdown;

    /// A gateway whose `enable()` blocks until released, so tests can observe
    /// whether `state()` is blocked behind an in-flight `enable()`.
    struct BlockingGateway {
        release_enable: Arc<Notify>,
        entered_enable: Arc<Notify>,
    }

    #[async_trait]
    impl Shutdown for BlockingGateway {
        async fn shutdown(&self) {}
    }

    #[async_trait]
    impl TransportControl for BlockingGateway {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.entered_enable.notify_one();
            self.release_enable.notified().await;
            Ok(())
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            Ok(())
        }

        async fn state(&self) -> TransportState {
            TransportState::Enabled
        }
    }

    #[tokio::test]
    async fn state_is_not_blocked_behind_an_in_flight_enable() {
        let release_enable = Arc::new(Notify::new());
        let entered_enable = Arc::new(Notify::new());
        let slot = ComponentSlot::new(BlockingGateway {
            release_enable: Arc::clone(&release_enable),
            entered_enable: Arc::clone(&entered_enable),
        });
        let control = slot.transport_control();

        let enable_control = Arc::clone(&control);
        let enable_task = tokio::spawn(async move { enable_control.enable().await });

        // Wait until enable() is actually in flight before racing state().
        entered_enable.notified().await;

        let state = tokio::time::timeout(Duration::from_millis(500), control.state())
            .await
            .expect("state() must not block behind an in-flight enable()");
        assert_eq!(state, TransportState::Enabled);

        release_enable.notify_one();
        enable_task.await.unwrap().unwrap();
    }
}
