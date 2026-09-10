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

//! What `/health` answers with, and who may add to it.

use std::sync::Arc;

use cda_interfaces::{
    HashMap,
    health::{HealthProvider, HealthStatus},
};

use crate::{AppError, config::configfile::Configuration, mdd};

/// The health providers of the running instance.
///
/// Registration is open: a component publishes through
/// [`ConstructedComponent::health`](cda_interfaces::lifecycle::ConstructedComponent::health)
/// and is registered with the rest, and anything that belongs to no component
/// goes through [`register`](Self::register).
///
/// # Registration has to finish before the port opens
///
/// `/health/ready` answers 204 when every registered provider is up, and an
/// empty provider set satisfies that vacuously. An instance with nothing
/// registered therefore reports itself ready the moment it accepts a
/// connection, and every readiness wait returns at once. Registration runs
/// before the accept loop starts for exactly that reason: adding a provider
/// after the listener is up reopens the window, however briefly.
pub struct Health {
    /// The process itself. `Up` once everything has started, which is what
    /// makes `/health/ready` answer 204.
    main: Option<Arc<cda_health::StatusHealthProvider>>,
    doip: Option<Arc<cda_health::StatusHealthProvider>>,
    database: Option<Arc<cda_health::StatusHealthProvider>>,
    /// What the routes read. Created before them, so a provider registered
    /// before the routes are mounted is not lost and one registered after them
    /// still appears.
    state: Option<cda_health::HealthState>,
}

impl Health {
    /// The providers of an instance configured by `config`.
    #[must_use]
    pub(crate) fn new(config: &Configuration) -> Self {
        if !enabled(config) {
            return Self {
                main: None,
                doip: None,
                database: None,
                state: None,
            };
        }
        let starting = || {
            Arc::new(cda_health::StatusHealthProvider::new(
                cda_health::Status::Starting,
            ))
        };
        Self {
            main: Some(starting()),
            doip: Some(starting()),
            database: Some(starting()),
            state: Some(cda_health::HealthState::new(
                crate::cda_version().to_owned(),
            )),
        }
    }

    /// Adds a provider that belongs to no component, under `name`.
    ///
    /// Call it while the runtime is being built. See the type documentation for
    /// why registering after the instance is reachable is a mistake.
    ///
    /// # Errors
    /// Returns [`AppError`] when `name` is already registered.
    pub async fn register(
        &self,
        name: impl Into<String> + Send,
        provider: Arc<dyn HealthStatus>,
    ) -> Result<(), AppError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        state
            .register_provider(name, provider)
            .await
            .map_err(|error| AppError::InitializationFailed(error.to_string()))
    }

    /// Registers what the constructed components publish, under the names the
    /// manager knows them by.
    ///
    /// # Errors
    /// Returns [`AppError`] when two components published under one name.
    pub(crate) async fn register_all(
        &self,
        providers: Vec<(&'static str, Arc<dyn HealthStatus>)>,
    ) -> Result<(), AppError> {
        for (name, provider) in providers {
            self.register(name, provider).await?;
        }
        Ok(())
    }

    /// Mounts the health routes over this instance's providers.
    #[cfg_attr(
        not(feature = "health"),
        allow(
            unused_variables,
            clippy::unused_async,
            reason = "no health support: there are no routes to mount"
        )
    )]
    pub(crate) async fn mount(&self, dynamic_router: &cda_sovd::dynamic_router::DynamicRouter) {
        #[cfg(feature = "health")]
        if let Some(state) = self.state.as_ref() {
            cda_health::mount_health_routes(dynamic_router, state).await;
        }
    }

    /// Reports that everything has started, which is what makes the instance
    /// ready.
    pub(crate) async fn mark_up(&self) {
        if let Some(main) = self.main.as_ref() {
            main.update_status(cda_health::Status::Up).await;
        }
    }

    /// The state the readiness signal watches, absent when health is disabled.
    #[cfg_attr(
        not(feature = "systemd-notify"),
        allow(dead_code, reason = "only the systemd readiness task reads it")
    )]
    pub(crate) fn state(&self) -> Option<cda_health::HealthState> {
        self.state.clone()
    }

    /// The providers a database load reports on, keyed the way [`crate::mdd`]
    /// and the update plugin look them up.
    pub(crate) fn providers(&self) -> Option<HashMap<String, Arc<dyn HealthProvider>>> {
        let (doip, database) = (self.doip.as_ref()?, self.database.as_ref()?);
        let mut providers: HashMap<String, Arc<dyn HealthProvider>> = HashMap::default();
        providers.insert(
            crate::DOIP_HEALTH_COMPONENT_KEY.to_owned(),
            Arc::clone(doip) as Arc<dyn HealthProvider>,
        );
        providers.insert(
            mdd::DB_HEALTH_COMPONENT_KEY.to_owned(),
            Arc::clone(database) as Arc<dyn HealthProvider>,
        );
        Some(providers)
    }

    /// The `DoIP` transport's own provider, which the gateway writes to.
    pub(crate) fn doip(&self) -> Option<Arc<dyn HealthProvider>> {
        self.doip
            .as_ref()
            .map(|provider| Arc::clone(provider) as Arc<dyn HealthProvider>)
    }

    pub(crate) fn main_status(&self) -> Option<Arc<dyn HealthStatus>> {
        status(self.main.as_ref())
    }

    pub(crate) fn doip_status(&self) -> Option<Arc<dyn HealthStatus>> {
        status(self.doip.as_ref())
    }

    pub(crate) fn database_status(&self) -> Option<Arc<dyn HealthStatus>> {
        status(self.database.as_ref())
    }
}

fn status(
    provider: Option<&Arc<cda_health::StatusHealthProvider>>,
) -> Option<Arc<dyn HealthStatus>> {
    provider.map(|provider| Arc::clone(provider) as Arc<dyn HealthStatus>)
}

#[cfg(feature = "health")]
fn enabled(config: &Configuration) -> bool {
    config.health.enabled
}

#[cfg(not(feature = "health"))]
#[allow(
    clippy::missing_const_for_fn,
    reason = "the health-enabled counterpart reads the configuration"
)]
fn enabled(_config: &Configuration) -> bool {
    false
}
