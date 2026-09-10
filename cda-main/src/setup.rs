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

//! CDA startup builder.
//!
//! [`Setup`] is the public entry-point for applications that need to customize how the CDA
//! boots. The default startup path uses [`Setup::new`] with the standard update plugin; a
//! custom path calls [`Setup::with_security_plugin`] to replace the security plugin and
//! its loader, [`Setup::with_update_plugin`] to inject any [`RuntimeFilesUpdatePlugin`]
//! implementation, [`Setup::with_communication_plugin`] to replace the default
//! communication plugin factory, and [`Setup::with_file_inspector`] to replace the
//! reader for the application's database format, before handing the `Setup` to one of
//! the `run_*` functions.
//!
//! [`RuntimeFilesUpdatePlugin`]: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    ShutdownSignal,
    communication_control::{
        ActivationCause, CommunicationAccess, CommunicationInitMode, CommunicationLifecycle,
        CommunicationVariantDetection, TransportControl, VariantDetectionMode,
    },
    http_protection::registry::HttpProtectionRegistry,
    runtime_update_api::RuntimeFileInspector,
};
use cda_lifecycle::{CdaEvent, Component, ErasedComponent, erase};
use cda_plugin_communication_management::{
    lifecycle::{
        CommunicationRuntime, access::CommunicationAccessView, build_communication_runtime,
    },
    plugin::{
        CommunicationPlugin, CommunicationPluginBuilder, default::DefaultCommunicationPluginBuilder,
    },
};
use cda_plugin_security::{
    DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin, SecurityPluginLoader,
};
use cda_storage::LocalStorage;

use crate::{error::AppError, update::UpdatePluginBuilder, vehicle::UdsManagerType};

/// Builder for customizing the CDA startup sequence.
///
/// Use [`Setup::new`] to start with the defaults and then chain optional
/// configuration methods:
///
/// ```rust,ignore
/// use opensovd_cda_lib::{
///     setup::Setup,
///     update::update_plugin_fn,
/// };
///
/// let setup = Setup::new()
///     .with_security_plugin::<MySecurityPlugin, MySecurityLoader>()
///     .with_update_plugin(update_plugin_fn(|resources| async move {
///         Ok(MyCustomUpdatePlugin::new(resources))
///     }))
///     .with_communication_plugin(MyCommunicationPluginBuilder);
///
/// opensovd_cda_lib::run_with_ext_from_config(config, setup).await?;
/// ```
///
/// When no update plugin is configured (`UpdatePluginBuilder = ()`) the runtime-update routes
/// are **not** mounted. Pass a builder, typically via [`update_plugin_fn`] or by implementing
/// [`UpdatePluginBuilder`], to enable them.
///
/// [`update_plugin_fn`]: crate::update::update_plugin_fn
/// [`UpdatePluginBuilder`]: UpdatePluginBuilder
///
/// Type parameters:
/// - `SP`: security plugin, defaults to [`DefaultSecurityPluginData`]
/// - `SL`: security plugin loader, defaults to [`DefaultSecurityPlugin`]
/// - `UPB`: update plugin builder, defaults to `()`
/// - `CPB`: communication plugin builder, defaults to [`DefaultCommunicationPluginBuilder`]
pub struct Setup<
    SP: SecurityPlugin = DefaultSecurityPluginData,
    SL: SecurityPluginLoader = DefaultSecurityPlugin,
    UPB = (),
    CPB = DefaultCommunicationPluginBuilder,
> {
    pub(crate) _phantom: std::marker::PhantomData<(SP, SL)>,
    /// Extra components registered alongside the built-in ones. Erased here,
    /// because a `Setup` collects them before there is a runtime to put them in.
    pub(crate) components: Vec<Box<dyn ErasedComponent<CdaEvent>>>,
    /// Optional update-plugin builder. When `None` (or `UPB = ()`) the runtime-update
    /// routes are not registered.
    pub(crate) build_update_plugin: Option<UPB>,
    pub(crate) build_communication_plugin: CPB,
    /// The one construction site of the application's default file inspector.
    /// Everything that reads a database file goes through this instance.
    pub(crate) file_inspector: Arc<dyn RuntimeFileInspector>,
    pub(crate) initialize_tracing: bool,
    pub(crate) shutdown_signal: Option<ShutdownSignal>,
}

impl Default for Setup {
    fn default() -> Self {
        Self::new()
    }
}

impl Setup {
    /// Creates a new `Setup` with no extra components and no custom update plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            components: Vec::new(),
            build_update_plugin: None,
            build_communication_plugin: DefaultCommunicationPluginBuilder,
            file_inspector: Arc::new(crate::mdd_inspector::MddFileInspector),
            initialize_tracing: true,
            shutdown_signal: None,
        }
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB, CPB> Setup<SP, SL, UPB, CPB> {
    /// Uses the tracing subscriber already installed by the embedding process.
    #[must_use]
    pub fn with_existing_tracing(mut self) -> Self {
        self.initialize_tracing = false;
        self
    }

    /// Uses an externally managed shutdown signal instead of process signals.
    #[must_use]
    pub fn with_shutdown_signal(mut self, shutdown_signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(shutdown_signal);
        self
    }

    /// Replaces the reader used for validation, metadata, revision, and
    /// decompression of the application's database format.
    ///
    /// Startup database parsing stays MDD-specific; the runtime-update plugin
    /// uses this inspector for the format-level operations it needs.
    #[must_use]
    pub fn with_file_inspector(mut self, file_inspector: Arc<dyn RuntimeFileInspector>) -> Self {
        self.file_inspector = file_inspector;
        self
    }

    /// Registers an additional lifecycle component.
    ///
    /// It is constructed, started and stopped in the order its declared
    /// [`Requires`](Component::Requires) and [`Provides`](Component::Provides)
    /// derive, alongside the built-in ones, and is dispatched every event that
    /// visits the stage it labels itself with. Returning an error from it
    /// aborts the whole dispatch.
    #[must_use]
    pub fn with_component<C: Component<CdaEvent>>(mut self, component: C) -> Self {
        self.components.push(erase(component));
        self
    }

    /// Replaces the security plugin and its loader.
    ///
    /// Both stay concrete types rather than trait objects: the SOVD routes are
    /// built with `SP` as the protection middleware's plugin and `SL` as an
    /// axum handler, neither of which survives erasure.
    pub fn with_security_plugin<SP2: SecurityPlugin, SL2: SecurityPluginLoader>(
        self,
    ) -> Setup<SP2, SL2, UPB, CPB> {
        Setup {
            _phantom: std::marker::PhantomData,
            components: self.components,
            build_update_plugin: self.build_update_plugin,
            build_communication_plugin: self.build_communication_plugin,
            file_inspector: self.file_inspector,
            initialize_tracing: self.initialize_tracing,
            shutdown_signal: self.shutdown_signal,
        }
    }

    /// Configures a custom runtime update plugin.
    ///
    /// `builder` is called after vehicle data is loaded and routes are registered.
    /// It receives the [`UpdatePluginResources`] the application grants an update
    /// plugin: its storage, the dispatcher that runs a transition, the database
    /// format reader and a read-only view of the lock topology.
    ///
    /// The returned plugin is wrapped in [`ExclusiveRuntimePlugin`] (read/write mutual
    /// exclusion) and mounted on the standard runtime-update HTTP endpoints automatically.
    ///
    /// Use [`update_plugin_fn`] to wrap a plain async closure without implementing the trait
    /// manually:
    ///
    /// ```rust,ignore
    /// setup.with_update_plugin(update_plugin_fn(|resources| async move {
    ///     Ok(MyPlugin::new(resources))
    /// }))
    /// ```
    ///
    /// [`ExclusiveRuntimePlugin`]: cda_interfaces::runtime_update_api::ExclusiveRuntimePlugin
    /// [`update_plugin_fn`]: crate::update::update_plugin_fn
    /// [`UpdatePluginResources`]: crate::update::UpdatePluginResources
    pub fn with_update_plugin<UPB2>(self, builder: UPB2) -> Setup<SP, SL, UPB2, CPB>
    where
        UPB2: UpdatePluginBuilder<LocalStorage>,
    {
        Setup {
            _phantom: self._phantom,
            components: self.components,
            build_update_plugin: Some(builder),
            build_communication_plugin: self.build_communication_plugin,
            file_inspector: self.file_inspector,
            initialize_tracing: self.initialize_tracing,
            shutdown_signal: self.shutdown_signal,
        }
    }

    /// Replaces the default communication plugin factory.
    ///
    /// The factory is invoked after the passive transport and authoritative manager exist.
    pub fn with_communication_plugin<CPB2: CommunicationPluginBuilder>(
        self,
        plugin: CPB2,
    ) -> Setup<SP, SL, UPB, CPB2> {
        Setup {
            _phantom: self._phantom,
            components: self.components,
            build_update_plugin: self.build_update_plugin,
            build_communication_plugin: plugin,
            file_inspector: self.file_inspector,
            initialize_tracing: self.initialize_tracing,
            shutdown_signal: self.shutdown_signal,
        }
    }
}

/// Installs the global HTTP protection guard, builds the authoritative communication plugin
/// runtime, and derives a narrow access view for UDS manager construction.
///
/// Diagnostic operations request activation directly (see
/// `CommunicationAccess::request_activate`), so `http_protections` is left to the
/// runtime-update plugin's own protection.
pub(crate) async fn build_communication_runtime_and_access<CPB>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    transport_control: Arc<dyn TransportControl>,
    communication_plugin: CPB,
    init_mode: CommunicationInitMode,
    variant_detection: VariantDetectionMode,
    retry_after: Duration,
    http_protections: &HttpProtectionRegistry,
) -> Result<(CommunicationRuntime, Arc<dyn CommunicationAccess>), AppError>
where
    CPB: CommunicationPluginBuilder,
{
    cda_sovd::install_http_restriction_guard(dynamic_router, Arc::new(http_protections.clone()))
        .await;

    let communication_runtime = build_communication_runtime(
        communication_plugin,
        transport_control,
        init_mode,
        variant_detection,
    )
    .await
    .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

    let communication_access: Arc<dyn CommunicationAccess> = Arc::new(
        CommunicationAccessView::new(Arc::clone(&communication_runtime.plugin), retry_after),
    );

    Ok((communication_runtime, communication_access))
}

/// Registers the UDS manager's two communication hooks through the authoritative
/// plugin.
///
/// They register separately because they run at different times: the lifecycle
/// hook on every transport enable, and variant detection as the optional last
/// stage that `trigger_detection()` can run on its own.
pub(crate) async fn register_communication_hooks<SP>(
    plugin: &Arc<dyn CommunicationPlugin>,
    uds_manager: &UdsManagerType<SP>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
{
    plugin
        .register_lifecycle_hook(Arc::new(uds_manager.clone()) as Arc<dyn CommunicationLifecycle>)
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;
    plugin
        .register_variant_detection(
            Arc::new(uds_manager.clone()) as Arc<dyn CommunicationVariantDetection>
        )
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;
    Ok(())
}

/// `Always` initializes whole-vehicle communication eagerly at startup and propagates
/// failure according to existing application-start semantics. `OnDemand` and `Disabled`
/// leave it uninitialized, with HTTP/SOVD already served by the routes registered
/// beforehand. Under `OnDemand` an explicit `activate()` or a qualifying ECU request
/// initializes it. The default plugin offers no activation path under `Disabled`.
pub(crate) async fn activate_communication_per_init_mode(
    plugin: &Arc<dyn CommunicationPlugin>,
    init_mode: CommunicationInitMode,
) -> Result<(), AppError> {
    match init_mode {
        CommunicationInitMode::Always => plugin
            .activate(ActivationCause::Startup)
            .await
            .map(|_| ())
            .map_err(AppError::from),
        CommunicationInitMode::OnDemand | CommunicationInitMode::Disabled => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExecutionMode, RuntimeFileCatalog, RuntimeFileStore,
        RuntimeFilesQuery, RuntimeUpdateError, RuntimeUpdateExecutor, UpdateExecution,
    };

    use super::*;
    use crate::update::{UpdatePluginFn, UpdatePluginResources, update_plugin_fn};

    // Minimal no-op plugin for type-checking.
    struct NoOpPlugin;

    // Minimal component for the registration tests.
    struct NoOpComponent;

    #[async_trait::async_trait]
    impl Component<CdaEvent> for NoOpComponent {
        type Provides = ();

        fn name(&self) -> &'static str {
            "no-op"
        }

        fn stage(&self) -> cda_lifecycle::CdaStage {
            cda_lifecycle::CdaStage::Transports
        }

        async fn construct(
            self,
            _resources: &cda_interfaces::lifecycle::StageResources<'_>,
        ) -> Result<
            cda_lifecycle::Constructed<Self::Provides, CdaEvent>,
            cda_interfaces::lifecycle::LifecycleError,
        > {
            Ok(cda_lifecycle::Constructed::new(()))
        }
    }

    #[async_trait::async_trait]
    impl RuntimeFileCatalog for NoOpPlugin {
        async fn list_current(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }

        async fn list_nextupdate(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }

        async fn list_backup(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }
    }

    #[async_trait::async_trait]
    impl RuntimeFileStore for NoOpPlugin {
        async fn upload(
            &self,
            _files: Vec<cda_interfaces::runtime_update_api::UploadFile>,
        ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
            Ok(BulkDataCreatedList::default())
        }

        async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }

        async fn delete_nextupdate_by_id(&self, _id: &str) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }
    }

    #[async_trait::async_trait]
    impl cda_interfaces::runtime_update_api::RuntimeFileTransaction for NoOpPlugin {
        async fn apply_files(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn rollback_files(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn discard_staged(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn cleanup_files(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn restore_after_apply(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn restore_after_rollback(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl RuntimeUpdateExecutor for NoOpPlugin {
        async fn start_execution(
            &self,
            _mode: ExecutionMode,
        ) -> Result<String, RuntimeUpdateError> {
            Ok(String::new())
        }

        async fn list_executions(&self) -> Vec<UpdateExecution> {
            vec![]
        }

        async fn get_execution_status(&self, _id: &str) -> Option<UpdateExecution> {
            None
        }
    }

    #[test]
    fn documented_public_api_type_checks() {
        let _: Option<UpdatePluginResources<LocalStorage>> = None;
    }

    #[test]
    fn new_has_no_components_and_no_plugin() {
        let s = Setup::new();
        assert!(
            s.components.is_empty(),
            "fresh Setup must have no extra components"
        );
        assert!(
            s.build_update_plugin.is_none(),
            "fresh Setup must have no update plugin"
        );
    }

    #[test]
    fn with_component_stores_component() {
        let s = Setup::new().with_component(NoOpComponent);
        assert_eq!(
            s.components.len(),
            1,
            "with_component must store the provided component"
        );
    }

    #[test]
    fn with_update_plugin_stores_builder() {
        // Use `update_plugin_fn` as a convenient closure adapter.
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_resources: UpdatePluginResources<LocalStorage>| async {
                Ok(NoOpPlugin)
            });

        let s = Setup::new().with_update_plugin(builder);

        assert!(
            s.build_update_plugin.is_some(),
            "with_update_plugin must store the provided builder"
        );
    }

    #[test]
    fn chaining_component_then_plugin_retains_both() {
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_resources: UpdatePluginResources<LocalStorage>| async {
                Ok(NoOpPlugin)
            });

        let s = Setup::new()
            .with_component(NoOpComponent)
            .with_update_plugin(builder);

        assert_eq!(s.components.len(), 1, "components must survive chaining");
        assert!(
            s.build_update_plugin.is_some(),
            "plugin builder must be stored after chaining"
        );
    }

    #[test]
    fn chaining_plugin_then_component_retains_both() {
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_resources: UpdatePluginResources<LocalStorage>| async {
                Ok(NoOpPlugin)
            });

        let s = Setup::new()
            .with_update_plugin(builder)
            .with_component(NoOpComponent);

        assert_eq!(s.components.len(), 1, "components must survive chaining");
        assert!(
            s.build_update_plugin.is_some(),
            "plugin builder must survive chaining"
        );
    }
}
