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

use super::{
    error::CommunicationError, guard::CommunicationGuard, operation::ActivationCause,
    state::CommunicationState,
};
use crate::plugin::CommunicationPlugin;

/// Narrow capability that does not expose full lifecycle control.
///
/// Consumers can inspect state, hold communication active for an operation, and
/// request activation for their own operation's sake, but cannot disable, run
/// explicit whole-vehicle (re-)detection, or otherwise administer the
/// underlying plugin. This can be used to make sure communication cannot be
/// disabled during an important operation, i.e. flash transfer, and to bring
/// communication up on demand for a diagnostic operation without granting the
/// operation any broader lifecycle authority.
///
/// Deliberately synchronous only: a caller behind this narrow view requests
/// activation non-blocking via [`request_activate`](Self::request_activate)
/// and checks [`state`](Self::state)/awaits its own readiness signal (see
/// `cda-sovd`'s variant-readiness gate) rather than awaiting a full activation
/// sequence inline, which can take seconds due to variant detection. It can
/// never reach [`CommunicationPlugin::trigger_detection`], the explicit-only
/// path that bypasses `init_mode`.
pub trait CommunicationAccess: Send + Sync + 'static {
    /// Returns the authoritative lifecycle state.
    fn state(&self) -> CommunicationState;

    /// Acquires diagnostic communication if it is enabled.
    /// The returned guard prevents the communication from being shut down while it is alive.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError>;

    /// Non-blocking activation request, can be used in line with an SOVD request,
    /// to prevent blocking the reply.
    /// See [`CommunicationPlugin::request_activate`].
    fn request_activate(&self, cause: ActivationCause) -> CommunicationState;
}

/// Cloneable access-only view over the shared authoritative plugin.
///
/// This adapter lets diagnostic consumers depend on [`CommunicationAccess`]
/// without receiving the full [`CommunicationPlugin`] lifecycle authority.
#[derive(Clone)]
pub struct CommunicationAccessView {
    plugin: Arc<dyn CommunicationPlugin>,
}

impl CommunicationAccessView {
    /// Creates an access-only view over the selected communication plugin.
    #[must_use]
    pub fn new(plugin: Arc<dyn CommunicationPlugin>) -> Self {
        Self { plugin }
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
}
