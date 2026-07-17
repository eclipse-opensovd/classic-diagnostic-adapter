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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Health status of a component.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, schemars::JsonSchema, Eq, PartialEq)]
pub enum Status {
    Up,
    Starting,
    Pending,
    Failed,
}

/// Read-only health status provider, queried on-demand when a health check request arrives.
///
/// Implement this trait for components whose health is derived from internal state
/// (e.g. [`CommState`]) rather than set externally. The health endpoint only requires
/// `HealthStatus`, so read-only providers do not need to implement `HealthProvider`.
#[async_trait]
pub trait HealthStatus: Send + Sync + 'static {
    /// Returns the current health status of the component.
    async fn status(&self) -> Status;
}

/// Read-write health provider: a [`HealthStatus`] whose status can also be updated externally.
///
/// Use this for components (e.g. database initialization) that report health through
/// an explicit `set_status()` call rather than deriving it from shared state.
#[async_trait]
pub trait HealthProvider: HealthStatus {
    /// Updates the health status of the component.
    async fn set_status(&self, status: Status);
}
