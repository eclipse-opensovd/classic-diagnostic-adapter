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

//! Shared HTTP protection registry.

use std::sync::{Arc, RwLock};

pub use crate::http_protection::{
    config::{
        HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionScope,
        HttpRouteMatcher, HttpStatusCode,
    },
    evaluator::{HttpRestrictionDenial, HttpRestrictionGuard},
    owned::OwnedHttpProtection,
};
use crate::{
    config::{ConfigSanity, ConfigSanityError},
    util::std_ext,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Identifier for a registered HTTP request restriction.
///
/// This is a newtype rather than a `uuid::Uuid` type alias so the UUID remains
/// an implementation detail of the registry.
pub(crate) struct HttpRequestRestrictionId(uuid::Uuid);

impl HttpRequestRestrictionId {
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

struct HttpRequestRestriction {
    id: HttpRequestRestrictionId,
    config: HttpProtectionConfig,
}

/// Shared, cloneable registry of HTTP protection records.
///
/// Held by the HTTP middleware guard and components such as the runtime-update
/// plugin. Each owner calls [`protect`](Self::protect) to install independently
/// owned protections that block matching requests until dropped.
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
    /// The configuration is validated before it is installed: a malformed route
    /// would otherwise silently widen or defeat its own scope. An empty prefix,
    /// for example, matches every path, so it would exempt (or deny) the whole
    /// API instead of the single route the caller intended.
    ///
    /// # Errors
    /// Returns [`ConfigSanityError`] when `config` fails its sanity check. No
    /// protection is installed in that case.
    pub fn protect(
        &self,
        config: HttpProtectionConfig,
    ) -> Result<OwnedHttpProtection, ConfigSanityError> {
        config.validate_sanity()?;
        let id = self.create(config);
        Ok(OwnedHttpProtection::new(self.clone(), id))
    }

    fn create(&self, config: HttpProtectionConfig) -> HttpRequestRestrictionId {
        let id = HttpRequestRestrictionId::new();
        std_ext::lock_write(&self.restrictions).push(HttpRequestRestriction { id, config });
        id
    }

    pub(super) fn remove(&self, id: HttpRequestRestrictionId) -> bool {
        let mut records = std_ext::lock_write(&self.restrictions);
        let len = records.len();
        records.retain(|record| record.id != id);
        records.len() != len
    }

    fn find_matching_restriction(
        &self,
        path: &str,
        method: &HttpMethod,
    ) -> Option<HttpProtectionConfig> {
        /// A restriction either denies every non-exempt route or only its selected routes.
        fn restriction_matches(
            config: &HttpProtectionConfig,
            path: &str,
            method: &HttpMethod,
        ) -> bool {
            match &config.scope {
                HttpProtectionScope::GlobalWithExemptions(exempt_routes) => !exempt_routes
                    .iter()
                    .any(|route| route.matches(path, method)),
                HttpProtectionScope::SelectedRoutes(routes) => {
                    routes.iter().any(|route| route.matches(path, method))
                }
            }
        }

        let records = std_ext::lock_read(&self.restrictions);
        records
            .iter()
            .find(|record| restriction_matches(&record.config, path, method))
            .map(|record| record.config.clone())
    }
}

impl HttpRestrictionGuard for HttpProtectionRegistry {
    fn is_active(&self) -> bool {
        !std_ext::lock_read(&self.restrictions).is_empty()
    }

    fn evaluate(&self, path: &str, method: &http::Method) -> Result<(), HttpRestrictionDenial> {
        let Some(config) = self.find_matching_restriction(path, method) else {
            return Ok(());
        };

        Err(HttpRestrictionDenial {
            reason: config.reason,
            status: config.status,
            message: config.message,
            retry_after: config.retry_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::*;

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

        let denial = registry
            .evaluate("/vehicle/v15", &http::Method::GET)
            .expect_err("request should be denied");
        assert_eq!(denial.status, StatusCode::CONFLICT);
        assert_eq!(
            denial.reason,
            HttpProtectionReason::Custom("test".to_owned())
        );
    }

    #[test]
    fn selected_routes_only_deny_matching_method_and_path() {
        let registry = HttpProtectionRegistry::new();
        let _owner = registry
            .protect(
                config(StatusCode::SERVICE_UNAVAILABLE).with_selected_routes(vec![
                    HttpRouteMatcher::new("/vehicle", vec![http::Method::GET]),
                ]),
            )
            .expect("Adding http protection should work");

        assert!(
            registry
                .evaluate("/vehicle/v15", &http::Method::GET)
                .is_err()
        );
        assert!(matches!(
            registry.evaluate("/vehicle-extra", &http::Method::GET),
            Ok(())
        ));
        assert!(matches!(
            registry.evaluate("/vehicle", &http::Method::POST),
            Ok(())
        ));
    }

    #[test]
    fn rejects_malformed_config_without_installing_it() {
        let registry = HttpProtectionRegistry::new();

        // An empty prefix matches every path, so it would turn a single-route
        // restriction into a global one.
        let empty_prefix = registry.protect(
            config(StatusCode::SERVICE_UNAVAILABLE)
                .with_selected_routes(vec![HttpRouteMatcher::new("", vec![http::Method::GET])]),
        );

        assert!(empty_prefix.is_err());
        assert!(!registry.is_active());
        assert!(matches!(
            registry.evaluate("/vehicle/v15", &http::Method::GET),
            Ok(())
        ));
    }
}
