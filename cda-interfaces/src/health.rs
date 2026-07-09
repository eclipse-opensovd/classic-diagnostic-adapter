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

//! Health reporting interfaces.
//!
//! Kept dependency-free (no `cda-sovd`/`cda-health` coupling) so that any crate can
//! implement [`HealthProvider`]

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

/// Trait for health providers that are queried on-demand when a health check request comes in,
/// and updated as components transition between states.
#[async_trait]
pub trait HealthProvider: Send + Sync + 'static {
    /// Returns the current health status of the component.
    async fn check_health(&self) -> Status;

    /// Updates the health status of the component.
    async fn update_status(&self, status: Status);
}
