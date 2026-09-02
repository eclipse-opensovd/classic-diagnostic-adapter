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

//! RAII ownership handle that lifts its HTTP protection record on drop.

use super::registry::{HttpProtectionRegistry, HttpRequestRestrictionId};

/// Opaque, non-cloneable ownership of one HTTP protection record.
pub struct OwnedHttpProtection {
    registry: HttpProtectionRegistry,
    id: Option<HttpRequestRestrictionId>,
}

impl OwnedHttpProtection {
    #[must_use]
    pub(crate) fn new(registry: HttpProtectionRegistry, id: HttpRequestRestrictionId) -> Self {
        Self {
            registry,
            id: Some(id),
        }
    }
    /// Leaves the protection registered for the rest of the process.
    ///
    /// For a runtime that could not be restored to a known-good state: the
    /// record has to outlive its owner so every guarded request keeps being
    /// refused until an operator restarts the process. Consumes the handle,
    /// because after this there is no way to lift the protection again.
    pub fn retain(mut self) {
        self.id = None;
    }

    fn remove(&mut self) {
        if let Some(id) = self.id.take()
            && !self.registry.remove(id)
        {
            tracing::error!("Failed to lift owned HTTP protection: id not found in registry");
        }
    }
}

impl Drop for OwnedHttpProtection {
    fn drop(&mut self) {
        self.remove();
    }
}
