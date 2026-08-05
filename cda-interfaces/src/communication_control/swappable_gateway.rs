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
use tokio::sync::Mutex;

use super::{CommControlError, TransportControl, TransportState};

/// Stable [`TransportControl`] proxy over a hot-swappable gateway slot.
///
/// During a runtime database update the diagnostic gateway is replaced with a
/// freshly constructed instance. External consumers hold an `Arc<dyn TransportControl>`
/// that must keep working transparently across that swap, to make sure the communication can
/// be re-enabled again after swapping the gateway.
///
/// `SwappableGateway` solves this by:
///
/// 1. **Indirection** - it delegates every control call (`enable`, `disable`,
///    `state`) to whatever gateway is currently installed inside the
///    `Arc<Mutex<G>>`.
///
/// 2. **Serialization** - the gateway mutex prevents races between concurrent
///    control calls and the gateway-replacement path in the runtime-update
///    plugin.
///
/// # Usage
///
/// ```ignore
/// let gateway = Arc::new(Mutex::new(my_gateway));
/// let handle = SwappableGateway::new(Arc::clone(&gateway));
///
/// // Pass to lifecycle framework internals as Arc<dyn TransportControl>
/// let comm: Arc<dyn TransportControl> = Arc::new(handle);
///
/// // The runtime-update plugin holds `gateway` to perform atomic replacement.
/// ```
pub struct SwappableGateway<G> {
    gateway: Arc<Mutex<G>>,
}

impl<G> SwappableGateway<G> {
    /// Creates a stable control handle over a replaceable gateway slot.
    #[must_use]
    pub fn new(gateway: Arc<Mutex<G>>) -> Self {
        Self { gateway }
    }
}

#[async_trait]
impl<G: TransportControl> TransportControl for SwappableGateway<G> {
    async fn enable(&self) -> Result<(), CommControlError> {
        let gateway = self.gateway.lock().await;
        gateway.enable().await
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let gateway = self.gateway.lock().await;
        gateway.disable().await
    }

    async fn state(&self) -> TransportState {
        self.gateway.lock().await.state().await
    }
}
