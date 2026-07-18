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

//! Live health provider derived from the shared `CommState`.

use std::sync::Arc;

use cda_interfaces::{
    communication_control::CommState,
    health::{HealthStatus, Status},
};
use tokio::sync::RwLock;

/// Read-only health provider that derives its status from the shared [`CommState`].
///
/// Updated automatically as the [`DoipCommHandle`](super::comm_handle::DoipCommHandle) transitions
/// state -- no manual `set_status()` calls are needed.
///
/// | `CommState`    | `Status`    |
/// |----------------|-------------|
/// | `Disabled`     | `Pending`   |
/// | `Initializing` | `Starting`  |
/// | `Active`       | `Up`        |
/// | `Failed`       | `Failed`    |
pub struct CommStateHealthProvider {
    comm_state: Arc<RwLock<CommState>>,
}

impl CommStateHealthProvider {
    /// Creates a new `CommStateHealthProvider` backed by the given shared state.
    #[must_use]
    pub fn new(comm_state: Arc<RwLock<CommState>>) -> Self {
        Self { comm_state }
    }
}

#[async_trait::async_trait]
impl HealthStatus for CommStateHealthProvider {
    async fn status(&self) -> Status {
        match *self.comm_state.read().await {
            CommState::Disabled => Status::Pending,
            CommState::Initializing => Status::Starting,
            CommState::Active => Status::Up,
            CommState::Failed => Status::Failed,
        }
    }
}
