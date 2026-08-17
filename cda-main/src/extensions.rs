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

//! Public capabilities handed to OEM extension hooks.
//!
//! The design rule here: expose CDA's own interfaces, do not re-wrap them. What
//! broke integrations before was naming concrete transport types
//! (`UdsManager<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>>, _>`),
//! not using UDS traits - so [`Uds`] hands out `dyn UdsEcu` whole rather than a
//! curated subset that inevitably lacks whatever an integration needs next.
//!
//! What *is* wrapped is only what an OEM cannot do correctly on its own:
//! namespacing routes, checking locks by CDA's rules, and reaching the live
//! component generation across a runtime database update.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::component_slot::ComponentSlot;

use crate::vehicle::UdsManagerType;

/// Axum/aide route group accepted by the route-registration adapter.
///
/// Aliased here so OEM crates do not depend on CDA's dynamic-router
/// implementation or its route-handle representation.
pub type HttpRoutes = aide::axum::ApiRouter;

/// The namespace OEM routes are *recommended* to use.
///
/// Built from [`cda_sovd::SOVD_API_VERSION`] rather than spelled out, so an API
/// version bump moves it along.
fn recommended_namespace_prefix() -> String {
    format!("/vehicle/{}/x-", cda_sovd::SOVD_API_VERSION)
}

/// Handle to a registered OEM route group.
///
/// Retain it to [`remove`](RouteRegistrar::remove) the group later. Dropping the
/// handle leaves the routes mounted permanently.
#[derive(Clone, Debug)]
pub struct OemRouteHandle {
    handle: cda_sovd::RouteHandle,
    namespace: String,
}

impl OemRouteHandle {
    /// Returns the namespace these routes are mounted under.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// Capability for registering OEM route groups.
#[derive(Clone)]
pub struct RouteRegistrar {
    router: cda_sovd::dynamic_router::DynamicRouter,
}

impl RouteRegistrar {
    pub(crate) fn new(router: cda_sovd::dynamic_router::DynamicRouter) -> Self {
        Self { router }
    }

    /// Registers routes under `namespace`.
    ///
    /// Any path is accepted, including one that overrides a standard SOVD route:
    /// an integration knows its own deployment, and CDA is in no position to
    /// decide that replacing a built-in endpoint is a mistake.
    ///
    /// `/vehicle/<version>/x-<vendor>` is the recommended namespace and the one
    /// to use unless you mean to override something - it is the ISO extension
    /// space, so nothing CDA adds later can collide with it. Registering outside
    /// it is logged at warn level, once, so an accidental collision is visible in
    /// the startup log rather than silent.
    ///
    /// The returned [`OemRouteHandle`] is required to remove the group later; OEM
    /// routes survive a runtime database update, so a group registered here stays
    /// mounted until explicitly removed.
    pub async fn register(&self, namespace: &str, routes: HttpRoutes) -> OemRouteHandle {
        if !Self::is_recommended_namespace(namespace) {
            tracing::warn!(
                namespace,
                recommended = %recommended_namespace_prefix(),
                "OEM routes registered outside the recommended extension namespace; they may \
                 shadow standard SOVD routes"
            );
        }
        let handle = self
            .router
            .add_routes(aide::axum::ApiRouter::new().nest_api_service(namespace, routes))
            .await;
        OemRouteHandle {
            handle,
            namespace: namespace.to_owned(),
        }
    }

    /// Unmounts a previously registered group. No-op if it is already gone.
    pub async fn remove(&self, handle: &OemRouteHandle) {
        self.router.remove_routes(&handle.handle).await;
    }

    /// A namespace below the extension prefix *and* naming a vendor within it: a
    /// bare prefix would claim the whole `/x-` space rather than a slice of it.
    fn is_recommended_namespace(namespace: &str) -> bool {
        namespace
            .strip_prefix(&recommended_namespace_prefix())
            .is_some_and(|vendor| !vendor.is_empty())
    }
}

/// Stable extension registration errors.
///
/// Non-exhaustive so new failure modes can be added without breaking OEM
/// crates that match on it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionError {
    #[error("health provider {0} is already registered")]
    DuplicateHealthProvider(String),
    #[error("lock check refused the request: {0}")]
    LockDenied(String),
    #[error("no valid security context for this request; it did not pass the security middleware")]
    UnknownSecurityContext,
}

/// Stable capability for registering OEM health providers.
///
/// Wraps the health registry so OEM components report through the same
/// `/health` endpoint as CDA's own components, without the OEM crate holding the
/// registry itself.
#[derive(Clone)]
pub struct HealthRegistrar {
    state: Option<cda_health::HealthState>,
}

impl HealthRegistrar {
    pub(crate) fn new(state: Option<cda_health::HealthState>) -> Self {
        Self { state }
    }

    /// Returns `false` when health reporting is disabled by configuration, in which
    /// case [`Self::register`] silently succeeds without registering anything.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.is_some()
    }

    /// Registers an OEM health provider under `name`.
    ///
    /// The provider is polled whenever the health endpoint is queried. Registration
    /// is a no-op when health reporting is disabled - check [`Self::is_enabled`] if
    /// the distinction matters.
    ///
    /// # Errors
    /// Returns [`ExtensionError::DuplicateHealthProvider`] if `name` is taken.
    /// OEM providers should use a vendor-prefixed name to avoid colliding with
    /// CDA's own components.
    pub async fn register(
        &self,
        name: &str,
        provider: Arc<dyn cda_interfaces::health::HealthStatus>,
    ) -> Result<(), ExtensionError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        state
            .register_provider(name, provider)
            .await
            .map_err(|_| ExtensionError::DuplicateHealthProvider(name.to_owned()))
    }
}

/// The response every diagnostic service returns.
///
/// Fixed by the payload decoder, not by the transport, so it does not move when
/// the transport stack does.
pub type DiagnosticResponse = cda_core::DiagServiceResponseStruct;

/// The full UDS interface, exactly as `cda-sovd`'s own handlers use it.
///
/// Names no transport type - no gateway, no router, no concrete manager - so it
/// survives transport refactors. That is the property that matters; an
/// integration naming `UdsManager<..., ...>` directly is what breaks.
///
/// The surface is everything in [`UdsEcu`](cda_interfaces::UdsEcu): raw and
/// service-level sends, sessions, security access, tester present, flash
/// transfer, DTCs, database queries, functional groups, and variant state.
pub type Uds = dyn cda_interfaces::UdsEcu<Response = DiagnosticResponse>;

/// Hands out the live UDS interface.
///
/// Keep *this* in handler state, not the [`Uds`] it returns: a runtime database
/// update replaces the whole vehicle component generation, and this re-reads the
/// current one per call. An `Arc<Uds>` cached at startup would keep answering
/// from components that have been shut down.
#[async_trait]
pub trait DiagnosticServices: Send + Sync + 'static {
    /// Returns the currently live UDS interface.
    async fn uds(&self) -> Arc<Uds>;
}

struct DiagnosticServicesAdapter<SP: cda_plugin_security::SecurityPlugin> {
    uds: ComponentSlot<UdsManagerType<SP>>,
}

#[async_trait]
impl<SP: cda_plugin_security::SecurityPlugin> DiagnosticServices for DiagnosticServicesAdapter<SP> {
    async fn uds(&self) -> Arc<Uds> {
        // Cloning the manager is `Arc::clone` of its shared state, so this is
        // cheap next to any request made through it, and cloning is what lets
        // the handle outlive the slot guard.
        Arc::new(self.uds.read().await.clone())
    }
}

/// Verifies that a caller may act on a resource, using CDA's own lock rules.
///
/// An OEM route that changes ECU state must take part in the same lock
/// discipline as the standard component routes, or it races them. This asks
/// `cda-sovd` for the same decision those routes make, rather than exposing the
/// lock tables for a caller to interpret.
///
/// The caller's identity comes from the security plugin, so a replacement plugin
/// governs who the lock is compared against.
#[async_trait]
pub trait LockAccess: Send + Sync + 'static {
    /// Requires the caller to hold a lock permitting them to act on `ecu`.
    ///
    /// Satisfied by a lock on that ECU or by the vehicle lock, and every lock in
    /// those scopes must be owned by this caller.
    ///
    /// # Errors
    /// Returns [`ExtensionError::LockDenied`] when the caller may not proceed,
    /// or [`ExtensionError::UnknownSecurityContext`] when `security` is not the
    /// configured plugin - which means the request never passed the security
    /// middleware.
    async fn require_ecu_lock(
        &self,
        ecu: &str,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError>;

    /// Requires the caller to hold a lock permitting them to act on a
    /// functional group.
    ///
    /// Satisfied by a lock on that group or by the vehicle lock. A functional
    /// group addresses several ECUs at once, so this is the check a route that
    /// broadcasts must make - an ECU lock is not enough.
    ///
    /// # Errors
    /// Returns [`ExtensionError::LockDenied`] when the caller may not proceed,
    /// or [`ExtensionError::UnknownSecurityContext`] when `security` is not the
    /// configured plugin.
    async fn require_functional_group_lock(
        &self,
        functional_group: &str,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError>;

    /// Requires the caller to hold the vehicle lock.
    ///
    /// Nothing else satisfies this: a route acting on the whole vehicle is not
    /// authorised by a lock on one ECU or one functional group.
    ///
    /// # Errors
    /// Returns [`ExtensionError::LockDenied`] when the caller may not proceed,
    /// or [`ExtensionError::UnknownSecurityContext`] when `security` is not the
    /// configured plugin.
    async fn require_vehicle_lock(
        &self,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError>;

    /// Returns the ECUs that currently have lock entries.
    async fn ecu_names(&self) -> Vec<String>;
}

struct LockAccessAdapter<SP: cda_plugin_security::SecurityPlugin> {
    locks: Arc<cda_sovd::Locks>,
    _security: std::marker::PhantomData<SP>,
}

#[async_trait]
impl<SP: cda_plugin_security::SecurityPlugin> LockAccess for LockAccessAdapter<SP> {
    async fn require_ecu_lock(
        &self,
        ecu: &str,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError> {
        let plugin = security
            .downcast_ref::<SP>()
            .ok_or(ExtensionError::UnknownSecurityContext)?;
        // `Box<&dyn Claims>` implements `Claims`, so the boxed handle is passed
        // as-is rather than dereferenced into an unsized `dyn Claims`.
        let claims = plugin.as_auth_plugin().claims();
        cda_sovd::check_ecu_lock(&claims, ecu, &self.locks)
            .await
            .map_err(|denied| ExtensionError::LockDenied(denied.to_string()))
    }

    async fn require_functional_group_lock(
        &self,
        functional_group: &str,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError> {
        let plugin = security
            .downcast_ref::<SP>()
            .ok_or(ExtensionError::UnknownSecurityContext)?;
        let claims = plugin.as_auth_plugin().claims();
        cda_sovd::check_functional_group_lock(&claims, functional_group, &self.locks)
            .await
            .map_err(|denied| ExtensionError::LockDenied(denied.to_string()))
    }

    async fn require_vehicle_lock(
        &self,
        security: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), ExtensionError> {
        let plugin = security
            .downcast_ref::<SP>()
            .ok_or(ExtensionError::UnknownSecurityContext)?;
        let claims = plugin.as_auth_plugin().claims();
        cda_sovd::check_vehicle_lock(&claims, &self.locks)
            .await
            .map_err(|denied| ExtensionError::LockDenied(denied.to_string()))
    }

    async fn ecu_names(&self) -> Vec<String> {
        self.locks.ecu_names().await
    }
}

/// Stable capabilities supplied after vehicle components and standard routes are ready.
#[derive(Clone)]
pub struct ExtensionContext {
    routes: RouteRegistrar,
    diagnostics: Arc<dyn DiagnosticServices>,
    locks: Arc<dyn LockAccess>,
    health: HealthRegistrar,
    oem_config: Arc<serde_json::Map<String, serde_json::Value>>,
}

impl ExtensionContext {
    pub(crate) fn new<SP: cda_plugin_security::SecurityPlugin>(
        router: cda_sovd::dynamic_router::DynamicRouter,
        uds: ComponentSlot<UdsManagerType<SP>>,
        locks: Arc<cda_sovd::Locks>,
        health: Option<cda_health::HealthState>,
        oem_config: Arc<serde_json::Map<String, serde_json::Value>>,
    ) -> Self {
        Self {
            routes: RouteRegistrar::new(router),
            diagnostics: Arc::new(DiagnosticServicesAdapter { uds }),
            locks: Arc::new(LockAccessAdapter::<SP> {
                locks,
                _security: std::marker::PhantomData,
            }),
            health: HealthRegistrar::new(health),
            oem_config,
        }
    }

    /// Returns the `[oem]` section of the CDA configuration file.
    ///
    /// Empty when the section is absent. CDA never interprets these values; an
    /// embedding application can deserialize them into its own type with
    /// [`serde_json::from_value`].
    #[must_use]
    pub fn oem_config(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.oem_config
    }

    /// Returns the route-registration capability.
    #[must_use]
    pub fn routes(&self) -> &RouteRegistrar {
        &self.routes
    }

    /// Returns a cloneable diagnostic-service capability for handler state.
    ///
    /// The returned handle stays valid across a runtime database update: the
    /// underlying component is swapped in place, so state captured by a handler
    /// keeps working after an apply.
    #[must_use]
    pub fn diagnostics(&self) -> Arc<dyn DiagnosticServices> {
        Arc::clone(&self.diagnostics)
    }

    /// Returns a cloneable lock-checking capability for handler state.
    ///
    /// A route that mutates ECU state should require the caller's lock through
    /// this, so it obeys the same rules as the standard component routes rather
    /// than racing them.
    #[must_use]
    pub fn locks(&self) -> Arc<dyn LockAccess> {
        Arc::clone(&self.locks)
    }

    /// Returns the health-provider registration capability.
    #[must_use]
    pub fn health(&self) -> &HealthRegistrar {
        &self.health
    }
}

#[cfg(test)]
mod contract_tests {
    //! Stands in for an OEM crate: writes an extension using only the imports an
    //! external crate would have, so a change that makes the extension surface unusable
    //! from outside fails here.
    use std::sync::Arc;

    use aide::axum::{ApiRouter, IntoApiResponse};
    use axum::{Extension, Json, http::StatusCode, response::IntoResponse, routing::put};
    // No UDS sub-traits imported on purpose: they are supertraits of `UdsEcu`, so
    // every method below is callable straight off the trait object. An OEM crate
    // does not have to know the surface is split into nine traits.
    use cda_interfaces::{
        DiagComm, DiagCommType, DiagServiceError, diagservices::DiagServiceResponse,
    };
    use cda_plugin_security::Secured;

    use super::{DiagnosticServices, ExtensionContext, ExtensionError, HttpRoutes, LockAccess};
    use crate::AppError;

    #[derive(Clone)]
    struct OemState {
        diagnostics: Arc<dyn DiagnosticServices>,
        locks: Arc<dyn LockAccess>,
    }

    /// Exercises the shape a real handler has: take the caller's lock, then make
    /// several calls across different halves of the UDS surface.
    async fn oem_handler(
        Extension(state): Extension<OemState>,
        Secured(security): Secured,
    ) -> impl IntoApiResponse {
        let security: cda_interfaces::DynamicPlugin = security;

        // A mutating route must obey the same lock rules as the standard routes.
        if let Err(error) = state.locks.require_ecu_lock("ecu", &security).await {
            let error: ExtensionError = error;
            return (StatusCode::FORBIDDEN, error.to_string()).into_response();
        }

        // Re-read per request, so this follows a runtime database update.
        let uds = state.diagnostics.uds().await;

        // Reaching past "send one service": database queries, sessions and DTCs
        // are all available, which the previous facade could not express.
        let _ecus: Vec<String> = uds.get_physical_ecus().await;
        let _structure = uds.get_network_structure().await;
        if uds
            .set_ecu_session("ecu", "extended", &security, None)
            .await
            .is_err()
        {
            return (StatusCode::BAD_GATEWAY, "session change failed").into_response();
        }
        let _dtcs = uds
            .ecu_dtc_by_mask("ecu", &security, None, None, None, None)
            .await;

        match uds
            .send(
                "ecu",
                DiagComm::new("ExampleRead", DiagCommType::Data),
                &security,
                None,
                true,
            )
            .await
        {
            Ok(response) => {
                // The real response type, not a re-wrapped subset of it.
                let raw_len = response.get_raw().len();
                (
                    StatusCode::OK,
                    Json(serde_json::json!({ "raw_len": raw_len })),
                )
                    .into_response()
            }
            Err(error) => {
                let error: DiagServiceError = error;
                (StatusCode::BAD_GATEWAY, error.to_string()).into_response()
            }
        }
    }

    struct OemHealth;

    #[async_trait::async_trait]
    impl cda_interfaces::health::HealthStatus for OemHealth {
        async fn status(&self) -> cda_interfaces::health::Status {
            cda_interfaces::health::Status::Up
        }
    }

    async fn register_oem_routes(context: ExtensionContext) -> Result<(), AppError> {
        let state = OemState {
            diagnostics: context.diagnostics(),
            locks: context.locks(),
        };

        let _locked_ecus: Vec<String> = state.locks.ecu_names().await;
        let _config: &serde_json::Map<String, serde_json::Value> = context.oem_config();

        context
            .health()
            .register("x-oem", Arc::new(OemHealth))
            .await
            .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

        let routes: HttpRoutes = ApiRouter::new()
            .route("/execute", put(oem_handler))
            .layer(Extension(state));
        let handle = context
            .routes()
            .register("/vehicle/v15/x-oem", routes)
            .await;

        // Routes are removable through the returned handle.
        context.routes().remove(&handle).await;
        Ok(())
    }

    #[test]
    fn oem_extension_contract_type_checks() {
        fn accepts<F, Fut>(_extension: F)
        where
            F: FnOnce(ExtensionContext) -> Fut + Send + 'static,
            Fut: Future<Output = Result<(), crate::AppError>> + Send + 'static,
        {
        }

        accepts(register_oem_routes);
    }
}

#[cfg(test)]
mod route_registrar_tests {
    use aide::axum::ApiRouter;
    use cda_sovd::dynamic_router::DynamicRouter;

    use super::{RouteRegistrar, recommended_namespace_prefix};

    fn registrar() -> RouteRegistrar {
        RouteRegistrar::new(DynamicRouter::new())
    }

    #[test]
    fn recommended_prefix_tracks_the_sovd_api_version() {
        assert_eq!(
            recommended_namespace_prefix(),
            format!("/vehicle/{}/x-", cda_sovd::SOVD_API_VERSION),
            "the recommended namespace must move with the SOVD API version, not a hardcoded one"
        );
    }

    #[tokio::test]
    async fn registers_under_the_recommended_namespace() {
        let handle = registrar()
            .register("/vehicle/v15/x-acme", ApiRouter::new())
            .await;

        assert_eq!(handle.namespace(), "/vehicle/v15/x-acme");
    }

    #[tokio::test]
    async fn registers_outside_the_recommended_namespace_too() {
        // An integration may deliberately override a standard route. CDA warns
        // and mounts it; refusing would make legitimate deployments impossible.
        for namespace in [
            "/vehicle/v15/components",
            "/vehicle/v15/locks",
            "/health",
            "/vehicle/v14/x-acme",
            "/vehicle/v15/x-",
        ] {
            let handle = registrar().register(namespace, ApiRouter::new()).await;
            assert_eq!(handle.namespace(), namespace);
        }
    }

    #[tokio::test]
    async fn only_the_reserved_prefix_with_a_vendor_counts_as_recommended() {
        assert!(RouteRegistrar::is_recommended_namespace(
            "/vehicle/v15/x-acme"
        ));
        // A bare prefix claims the whole `/x-` space rather than a slice of it.
        assert!(!RouteRegistrar::is_recommended_namespace("/vehicle/v15/x-"));
        assert!(!RouteRegistrar::is_recommended_namespace(
            "/vehicle/v15/components"
        ));
    }

    #[tokio::test]
    async fn remove_is_idempotent() {
        let registrar = registrar();
        let handle = registrar
            .register("/vehicle/v15/x-acme", ApiRouter::new())
            .await;

        registrar.remove(&handle).await;
        registrar.remove(&handle).await;
    }
}
