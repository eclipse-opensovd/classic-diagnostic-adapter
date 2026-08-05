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

use std::{sync::Arc, time::Duration};

use cda_interfaces::communication_control::{
    ActivationCause, CommunicationAccess, CommunicationError, CommunicationGuard,
    CommunicationState, VariantDetectionMode,
};

use crate::plugin::CommunicationPlugin;

/// Cloneable access-only view over the shared authoritative plugin, so
/// diagnostic consumers can depend on [`CommunicationAccess`] without receiving
/// the full [`CommunicationPlugin`] lifecycle authority.
#[derive(Clone)]
pub struct CommunicationAccessView {
    plugin: Arc<dyn CommunicationPlugin>,
    retry_after: Duration,
}

impl CommunicationAccessView {
    /// Creates an access-only view over the selected communication plugin.
    #[must_use]
    pub fn new(plugin: Arc<dyn CommunicationPlugin>, retry_after: Duration) -> Self {
        Self {
            plugin,
            retry_after,
        }
    }
}

impl CommunicationAccess for CommunicationAccessView {
    fn state(&self) -> CommunicationState {
        self.plugin.state()
    }

    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        self.plugin.acquire()
    }

    fn request_activate(&self, cause: ActivationCause) -> CommunicationState {
        self.plugin.request_activate(cause)
    }

    fn retry_after(&self) -> Duration {
        self.retry_after
    }

    fn variant_detection(&self) -> VariantDetectionMode {
        self.plugin.variant_detection()
    }
}
