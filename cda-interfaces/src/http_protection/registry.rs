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
    http_protection::config::validate_routes,
    util::std_ext,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Identifier for a registered HTTP request restriction.
///
/// A newtype rather than a type alias, so the UUID stays an implementation
/// detail of the registry.
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
///
/// Routes set via [`with_always_accessible_routes`](Self::with_always_accessible_routes)
/// are exempt from every protection with a
/// [`GlobalWithExemptions`](HttpProtectionScope::GlobalWithExemptions) scope, in addition to
/// the exemptions of the protection itself. Protections with a
/// [`SelectedRoutes`](HttpProtectionScope::SelectedRoutes) scope deny their routes regardless.
#[derive(Clone)]
pub struct HttpProtectionRegistry {
    restrictions: Arc<RwLock<Vec<HttpRequestRestriction>>>,
    always_accessible_routes: Arc<[HttpRouteMatcher]>,
}

impl Default for HttpProtectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProtectionRegistry {
    /// Creates an empty registry without always accessible routes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            restrictions: Arc::new(RwLock::new(Vec::new())),
            always_accessible_routes: Arc::from([]),
        }
    }

    /// Creates an empty registry whose global protections never deny `routes`.
    ///
    /// Lets an embedding application keep routes it registers itself, e.g. version or health
    /// endpoints, reachable while a protection such as a runtime update is active, without
    /// each protection owner having to know them.
    ///
    /// # Errors
    /// Returns [`ConfigSanityError`] when a route has an empty or relative prefix, which would
    /// exempt more paths than intended, or no methods.
    pub fn with_always_accessible_routes(
        routes: Vec<HttpRouteMatcher>,
    ) -> Result<Self, ConfigSanityError> {
        validate_routes(&routes, "always_accessible_routes")?;
        Ok(Self {
            restrictions: Arc::new(RwLock::new(Vec::new())),
            always_accessible_routes: Arc::from(routes),
        })
    }

    /// Installs an HTTP protection owned by the returned guard.
    ///
    /// The configuration is validated first, because a malformed route widens
    /// its own scope. An empty prefix matches every path, exempting or denying
    /// the whole API instead of one route.
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
            always_accessible: bool,
            path: &str,
            method: &HttpMethod,
        ) -> bool {
            match &config.scope {
                HttpProtectionScope::GlobalWithExemptions(exempt_routes) => {
                    !always_accessible
                        && !exempt_routes
                            .iter()
                            .any(|route| route.matches(path, method))
                }
                HttpProtectionScope::SelectedRoutes(routes) => {
                    routes.iter().any(|route| route.matches(path, method))
                }
            }
        }

        let always_accessible = self
            .always_accessible_routes
            .iter()
            .any(|route| route.matches(path, method));
        let records = std_ext::lock_read(&self.restrictions);
        records
            .iter()
            .find(|record| restriction_matches(&record.config, always_accessible, path, method))
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

    fn registry_with_version_route() -> HttpProtectionRegistry {
        HttpProtectionRegistry::with_always_accessible_routes(vec![HttpRouteMatcher::new(
            "/vehicle/v15/apps/sovd2uds/data/version",
            vec![http::Method::GET],
        )])
        .expect("Valid always accessible routes should be accepted")
    }

    #[test]
    fn always_accessible_routes_bypass_global_protections() {
        let registry = registry_with_version_route();
        let _owner =
            registry
                .protect(config(StatusCode::CONFLICT).with_exempt_routes(vec![
                    HttpRouteMatcher::new("/health", vec![http::Method::GET]),
                ]))
                .expect("Adding http protection should work");

        assert!(matches!(
            registry.evaluate(
                "/vehicle/v15/apps/sovd2uds/data/version",
                &http::Method::GET
            ),
            Ok(())
        ));
        // The protection's own exemptions still apply.
        assert!(matches!(
            registry.evaluate("/health", &http::Method::GET),
            Ok(())
        ));
        assert!(
            registry
                .evaluate(
                    "/vehicle/v15/apps/sovd2uds/data/version",
                    &http::Method::PUT
                )
                .is_err()
        );
        assert!(
            registry
                .evaluate("/vehicle/v15/components", &http::Method::GET)
                .is_err()
        );
    }

    #[test]
    fn always_accessible_routes_do_not_bypass_selected_routes() {
        let registry = registry_with_version_route();
        let _owner = registry
            .protect(
                config(StatusCode::SERVICE_UNAVAILABLE).with_selected_routes(vec![
                    HttpRouteMatcher::new("/vehicle/v15/apps", vec![http::Method::GET]),
                ]),
            )
            .expect("Adding http protection should work");

        assert!(
            registry
                .evaluate(
                    "/vehicle/v15/apps/sovd2uds/data/version",
                    &http::Method::GET
                )
                .is_err()
        );
    }

    #[test]
    fn always_accessible_routes_are_shared_by_clones() {
        let registry = registry_with_version_route();
        let clone = registry.clone();
        let _owner = clone
            .protect(config(StatusCode::CONFLICT))
            .expect("Adding http protection should work");

        assert!(matches!(
            registry.evaluate(
                "/vehicle/v15/apps/sovd2uds/data/version",
                &http::Method::GET
            ),
            Ok(())
        ));
    }

    #[test]
    fn rejects_malformed_always_accessible_routes() {
        // An empty prefix would exempt the whole API from every global protection.
        assert!(
            HttpProtectionRegistry::with_always_accessible_routes(vec![HttpRouteMatcher::new(
                "",
                vec![http::Method::GET]
            )])
            .is_err()
        );
        assert!(
            HttpProtectionRegistry::with_always_accessible_routes(vec![HttpRouteMatcher::new(
                "/vehicle/v15/data/version",
                vec![]
            )])
            .is_err()
        );
    }
}
