/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Shared HTTP protection registry.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::http_protection::{
    config::{HttpMethod, HttpProtectionConfig},
    evaluator::{HttpRestrictionDecision, HttpRestrictionDenial, HttpRestrictionGuard},
    owned::OwnedHttpProtection,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HttpRequestRestrictionId(uuid::Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpProtectionError {
    #[error("HTTP protection registry is unavailable")]
    Unavailable,
}

struct HttpRequestRestriction {
    id: HttpRequestRestrictionId,
    config: HttpProtectionConfig,
}

/// Shared, cloneable registry of HTTP protection records.
///
/// Held by the HTTP middleware guard, the communication lifecycle manager, and
/// the runtime update plugin. Each subsystem calls [`protect`](Self::protect) to
/// install independently owned protections that block requests until dropped.
#[derive(Clone)]
pub struct HttpProtectionRegistry {
    restrictions: Arc<RwLock<Vec<HttpRequestRestriction>>>,
}

impl Default for HttpProtectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProtectionRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            restrictions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Installs an HTTP protection owned by the returned guard.
    ///
    /// # Errors
    ///
    /// Returns an error when the protection registry is unavailable.
    pub fn protect(
        &self,
        config: HttpProtectionConfig,
    ) -> Result<OwnedHttpProtection, HttpProtectionError> {
        let id = self.create(config)?;
        // Cloned registry is held by the 'protection' so it can remove itself
        // from the registry, when dropped.
        Ok(OwnedHttpProtection::new(self.clone(), id))
    }

    fn read_lock(&self) -> RwLockReadGuard<'_, Vec<HttpRequestRestriction>> {
        self.restrictions.read().unwrap_or_else(|e| {
            tracing::error!("HttpProtectionRegistry read lock poisoned, clearing poisoned state");
            self.restrictions.clear_poison();
            e.into_inner()
        })
    }

    fn write_lock(
        &self,
    ) -> Result<RwLockWriteGuard<'_, Vec<HttpRequestRestriction>>, HttpProtectionError> {
        self.restrictions
            .write()
            .map_err(|_| HttpProtectionError::Unavailable)
    }

    fn create(
        &self,
        config: HttpProtectionConfig,
    ) -> Result<HttpRequestRestrictionId, HttpProtectionError> {
        let id = HttpRequestRestrictionId(uuid::Uuid::new_v4());
        self.write_lock()?
            .push(HttpRequestRestriction { id, config });
        Ok(id)
    }

    pub(super) fn remove(&self, id: HttpRequestRestrictionId) -> Result<bool, HttpProtectionError> {
        let mut records = self.write_lock()?;
        let len = records.len();
        records.retain(|record| record.id != id);
        Ok(records.len() != len)
    }

    fn find_matching_restriction(
        &self,
        path: &str,
        method: &HttpMethod,
    ) -> Option<HttpProtectionConfig> {
        /// A restriction applies to every route except its own [`exempt_routes`](HttpProtectionConfig::exempt_routes).
        fn restriction_matches(
            config: &HttpProtectionConfig,
            path: &str,
            method: &HttpMethod,
        ) -> bool {
            !config
                .exempt_routes
                .iter()
                .any(|route| route.matches(path, method))
        }

        let records = self.read_lock();
        records
            .iter()
            .find(|record| restriction_matches(&record.config, path, method))
            .map(|record| record.config.clone())
    }
}

impl HttpRestrictionGuard for HttpProtectionRegistry {
    fn is_active(&self) -> bool {
        !self.read_lock().is_empty()
    }

    fn evaluate(&self, path: &str, method: &http::Method) -> HttpRestrictionDecision {
        let Some(config) = self.find_matching_restriction(path, method) else {
            return HttpRestrictionDecision::Pass;
        };

        HttpRestrictionDecision::Deny(HttpRestrictionDenial {
            status: config.status,
            message: config.message,
            retry_after_seconds: config.retry_after_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use crate::http_protection::{
        config::{HttpProtectionConfig, HttpProtectionReason},
        evaluator::{HttpRestrictionDecision, HttpRestrictionGuard},
        registry::HttpProtectionRegistry,
    };

    fn config(status: StatusCode) -> HttpProtectionConfig {
        HttpProtectionConfig::new(
            HttpProtectionReason::Custom("test".to_owned()),
            status,
            "blocked",
        )
    }

    #[test]
    fn dropping_one_owner_leaves_other_protection_active() {
        let registry = HttpProtectionRegistry::new();
        let first = registry.protect(config(StatusCode::CONFLICT)).unwrap();
        let second = registry
            .protect(config(StatusCode::SERVICE_UNAVAILABLE))
            .unwrap();

        drop(first);
        assert!(registry.is_active());

        drop(second);
        assert!(!registry.is_active());
    }

    #[test]
    fn first_installed_matching_protection_wins() {
        let registry = HttpProtectionRegistry::new();
        let _first = registry.protect(config(StatusCode::CONFLICT)).unwrap();
        let _second = registry
            .protect(config(StatusCode::SERVICE_UNAVAILABLE))
            .unwrap();

        let HttpRestrictionDecision::Deny(denial) =
            registry.evaluate("/vehicle/v15", &http::Method::GET)
        else {
            panic!("request should be denied");
        };
        assert_eq!(denial.status, StatusCode::CONFLICT);
    }
}
