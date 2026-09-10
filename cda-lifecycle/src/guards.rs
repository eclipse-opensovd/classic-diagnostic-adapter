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

//! Guard acquisition and release for one dispatch.

use std::sync::Arc;

use cda_interfaces::{
    communication_control::{DisableCommunication, DisableGuard, DisableReason},
    config::ConfigSanityError,
    http_protection::registry::{HttpProtectionConfig, HttpProtectionRegistry},
    lifecycle::{DispatchGuards, LifecycleError},
};

/// Installs the HTTP protection a dispatch declares.
///
/// A trait rather than the concrete registry, so the manager can be exercised
/// without an HTTP stack.
pub trait HttpProtector: Send + Sync + 'static {
    /// Installs `config` and returns a token that lifts the protection on drop.
    ///
    /// # Errors
    /// Returns [`ConfigSanityError`] when `config` is malformed. Nothing is
    /// installed in that case.
    fn protect(&self, config: HttpProtectionConfig) -> Result<Box<dyn Send>, ConfigSanityError>;
}

impl HttpProtector for HttpProtectionRegistry {
    fn protect(&self, config: HttpProtectionConfig) -> Result<Box<dyn Send>, ConfigSanityError> {
        HttpProtectionRegistry::protect(self, config).map(|owned| Box::new(owned) as Box<dyn Send>)
    }
}

/// How a dispatch finishes with the communication lease it took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseOutcome {
    /// Restore what the lease displaced.
    Release,
    /// Relinquish exclusivity, leaving communication down.
    Drop,
}

/// Decides how a dispatch finishes with its communication lease.
///
/// [`DispatchGuards`] only says whether a lease is taken, so the target the
/// event was started for is supplied here instead of being read off the guards.
pub trait LeasePolicy<E>: Send + Sync + 'static {
    /// Outcome for the lease taken on behalf of `event`.
    fn outcome(&self, event: &E) -> LeaseOutcome;
}

/// The guards one dispatch holds, released as the dispatch progresses.
pub(crate) struct HeldGuards {
    // Held for its drop, never read: dropping the token lifts the protection.
    _http: Option<Box<dyn Send>>,
    lease: Option<Box<dyn DisableGuard>>,
    outcome: LeaseOutcome,
}

impl HeldGuards {
    /// Takes the declared guards before the first visited stage.
    pub(crate) async fn acquire(
        guards: &DispatchGuards,
        outcome: LeaseOutcome,
        http: &Arc<dyn HttpProtector>,
        communication: &Arc<dyn DisableCommunication>,
    ) -> Result<Self, LifecycleError> {
        // HTTP first, so nothing slips through between the two guards while the
        // transport is still up.
        let http_token = match guards.http_protection.as_ref() {
            Some(config) => Some(http.protect(config.clone()).map_err(|error| {
                LifecycleError::GuardsUnavailable(format!("HTTP protection rejected: {error}"))
            })?),
            None => None,
        };

        let lease = if guards.communication_lease {
            Some(
                communication
                    .disable(DisableReason::RuntimeUpdate)
                    .await
                    .map_err(LifecycleError::LeaseUnavailable)?,
            )
        } else {
            None
        };

        Ok(Self {
            _http: http_token,
            lease,
            outcome,
        })
    }

    /// Hands the communication lease back, if one is still held.
    ///
    /// `degraded` reports that a revert failed: the runtime is not in a known
    /// state, so the transport must not be resumed whatever the target said.
    pub(crate) async fn resolve_lease(&mut self, degraded: bool) -> Result<(), LifecycleError> {
        let Some(lease) = self.lease.take() else {
            return Ok(());
        };

        if degraded || self.outcome == LeaseOutcome::Drop {
            // Dropping relinquishes exclusivity without enabling a transport
            // that the target wants left down.
            drop(lease);
            return Ok(());
        }

        lease
            .release()
            .await
            .map(|_| ())
            .map_err(LifecycleError::LeaseUnsettled)
    }
}
