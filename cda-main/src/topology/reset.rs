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

//! Core side of the `networkreset` operation.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::topology::{DiscoveryPlan, TopologyResetBackend, TopologyStoreError};

use super::{EcuTopologySource, TopologyContext};

/// [`TopologyResetBackend`] over the topology context and the live ECUs.
pub struct TopologyResetAdapter {
    context: Arc<TopologyContext>,
    source: Arc<dyn EcuTopologySource>,
}

impl TopologyResetAdapter {
    /// Creates the adapter.
    #[must_use]
    pub fn new(context: Arc<TopologyContext>, source: Arc<dyn EcuTopologySource>) -> Self {
        Self { context, source }
    }
}

#[async_trait]
impl TopologyResetBackend for TopologyResetAdapter {
    async fn clear_persisted(&self) -> Result<(), TopologyStoreError> {
        let persistence = self.context.persistence();
        // A pending write must not bring back what is cleared now.
        if let Some(persistence) = persistence {
            persistence.cancel_pending().await;
        }
        let result = self.context.store.clear().await;
        self.context.runtime.set_plan(DiscoveryPlan::Broadcast);
        self.context.runtime.set_has_persisted(false);
        // As if the topology had never been persisted: ECUs not contacted since
        // they were restored are no longer reported Online.
        self.source.reset_ecu_states(true).await;
        if let Some(persistence) = persistence {
            persistence.forget_last_written().await;
            // Later detection runs are persisted again, but the current state is
            // not written back right away.
            persistence.restart_follow_up().await;
        }
        result
    }

    async fn prepare_rediscovery(&self) -> u64 {
        self.context.runtime.set_plan(DiscoveryPlan::Broadcast);
        self.source.reset_ecu_states(false).await;
        self.context
            .persistence()
            .map_or(0, |persistence| persistence.persisted_count())
    }

    async fn wait_rediscovered(&self, marker: u64, timeout: Duration) -> bool {
        if let Some(persistence) = self.context.persistence() {
            return persistence.wait_persisted(marker, timeout).await;
        }
        if self.context.runtime.wait_settled(timeout).await.is_none() {
            return false;
        }
        self.source
            .detection_tracker()
            .await
            .wait_idle(timeout)
            .await
    }
}
