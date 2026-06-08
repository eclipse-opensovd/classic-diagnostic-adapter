/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::sync::Arc;

use cda_interfaces::HashMap;
use indexmap::IndexMap;
use sovd_interfaces::components::ecu::operations::comparams::Execution;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::ServiceExecution;

type SharedExecutionMap<T> = Arc<RwLock<T>>;

type ComparamMaps = Vec<SharedExecutionMap<IndexMap<Uuid, Execution>>>;
type ServiceMaps = Vec<SharedExecutionMap<HashMap<String, IndexMap<Uuid, ServiceExecution>>>>;

/// Registry tracking active ECU executions across all connected ECUs.
///
/// Maintains references to the shared execution maps of each ECU so that the system
/// can determine whether any operations are currently in progress (e.g. to prevent
/// runtime updates while diagnostics are running).
///
/// The inner maps are behind a [`RwLock`] so that a runtime database reload
/// can atomically swap the tracked maps via [`replace`](Self::replace) without
/// requiring a new registry instance.
#[derive(Clone, Default)]
pub struct EcuExecutionRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

#[derive(Clone, Default)]
struct RegistryInner {
    comparam_executions: ComparamMaps,
    service_executions: ServiceMaps,
}

impl EcuExecutionRegistry {
    pub(crate) async fn register(
        &self,
        comparam: SharedExecutionMap<IndexMap<Uuid, Execution>>,
        service: SharedExecutionMap<HashMap<String, IndexMap<Uuid, ServiceExecution>>>,
    ) {
        let mut inner = self.inner.write().await;
        inner.comparam_executions.push(comparam);
        inner.service_executions.push(service);
    }

    /// Replaces the tracked execution maps with those from `other`.
    ///
    /// Must only be called while `update_in_progress` is set (i.e. no new operations
    /// can be reserved and no concurrent `is_active` queries from the
    /// update plugin are expected).
    pub async fn replace(&self, other: &EcuExecutionRegistry) {
        let replacement = other.inner.read().await.clone();
        let mut inner = self.inner.write().await;
        *inner = replacement;
    }
}

impl cda_interfaces::runtime_update_api::ActivityGuard for EcuExecutionRegistry {
    fn is_active(&self) -> bool {
        let Ok(inner) = self.inner.try_read() else {
            tracing::error!("EcuExecutionRegistry lock contended in is_active");
            return true; // Assume active if lock is contended (safe default)
        };
        inner
            .comparam_executions
            .iter()
            .any(|a| a.try_read().map_or(true, |g| !g.is_empty()))
            || inner.service_executions.iter().any(|a| {
                a.try_read()
                    .map_or(true, |g| g.values().any(|m| !m.is_empty()))
            })
    }
}
