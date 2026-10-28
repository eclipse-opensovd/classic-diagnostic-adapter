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

//! Exclusive pause of diagnostic communication that leaves the transport alone.

use async_trait::async_trait;

use crate::communication_control::disable::{DisableError, DisableReason};

/// Exclusive pause of diagnostic communication without changing the transport.
#[async_trait]
pub trait QuiesceCommunication: Send + Sync + 'static {
    /// Pauses diagnostic communication until the returned guard is dropped.
    ///
    /// While the guard is held, new communication guards are refused as not
    /// ready, and neither the transport nor the lifecycle state is touched.
    ///
    /// # Errors
    /// Fails with [`DisableError::InUse`] if communication guards are held, and
    /// with [`DisableError::Conflict`] if another exclusive lease is held or a
    /// lifecycle transition or whole-vehicle detection is in flight.
    async fn quiesce(&self, reason: DisableReason) -> Result<Box<dyn QuiesceGuard>, DisableError>;
}

/// Held while communication is paused; dropping it admits guards again.
pub trait QuiesceGuard: Send + Sync + std::fmt::Debug {}
