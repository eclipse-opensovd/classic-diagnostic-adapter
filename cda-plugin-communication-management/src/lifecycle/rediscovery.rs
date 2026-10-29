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

//! Narrow rediscovery view over the communication plugin.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::{communication_control::DetectionCause, topology::TopologyRediscovery};

use crate::plugin::CommunicationPlugin;

/// [`TopologyRediscovery`] over the selected communication plugin, so a
/// `networkreset` can trigger a rediscovery without the full plugin authority.
/// The plugin decides the policy for [`DetectionCause::TopologyRediscovery`].
#[derive(Clone)]
pub struct CommunicationRediscoveryView {
    plugin: Arc<dyn CommunicationPlugin>,
}

impl CommunicationRediscoveryView {
    /// Creates a rediscovery-only view over the selected communication plugin.
    #[must_use]
    pub fn new(plugin: Arc<dyn CommunicationPlugin>) -> Self {
        Self { plugin }
    }
}

#[async_trait]
impl TopologyRediscovery for CommunicationRediscoveryView {
    async fn rediscover(&self) -> Result<(), String> {
        self.plugin
            .trigger_detection(DetectionCause::TopologyRediscovery)
            .await
            .map(|_| ())
            .map_err(|failure| failure.to_string())
    }
}
