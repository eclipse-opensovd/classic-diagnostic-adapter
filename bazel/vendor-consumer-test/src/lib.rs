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

use std::sync::Arc;

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{Json, body::Bytes, http::StatusCode};
use cda_core::EcuManager;
use cda_database::datatypes::DiagService;
use cda_interfaces::{
    DiagServiceError, SecurityAccess, Shutdown,
    communication_control::{
        CommunicationInitMode, CommunicationLifecycle, CommunicationOperationFailure,
        CommunicationState, CommunicationVariantDetection,
        operation::{ActivationCause, DetectionCause},
    },
    runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExecutionMode, LockStateProvider, ReloadError,
        RuntimeFilesQuery, RuntimeFilesUpdatePlugin, RuntimeReloaderPlugin, RuntimeUpdateError,
        RuntimeUpdateSecurityPlugin, UpdateCollections, UpdateExecution, UploadFile,
        VerificationError,
    },
    storage_api::{Collection, DirectFileAccess},
};
use cda_plugin_communication_management::{
    lifecycle::{
        CommunicationHandle,
        disable::{DisableError, DisableLease, DisableReason},
    },
    plugin::{CommunicationPlugin, communication_plugin_fn},
};
use cda_plugin_security::{
    AuthApi, AuthError, AuthorizationRequestHandler, Claims, SecurityApi, SecurityPlugin,
    SecurityPluginInitializer, SecurityPluginLoader,
};
use http::{HeaderMap, request::Parts};
use opensovd_cda_lib::{Setup, update::update_plugin_fn};

static CLAIMS: FancyClaims = FancyClaims;

pub struct FancyClaims;

impl Claims for FancyClaims {
    fn sub(&self) -> &str {
        "fancy-vendor"
    }
}

pub struct FancySecurity;

impl AuthApi for FancySecurity {
    fn claims(&self) -> Box<&dyn Claims> {
        Box::new(&CLAIMS)
    }
}

impl SecurityApi for FancySecurity {
    fn validate_service(&self, _service: &DiagService<'_>) -> Result<(), DiagServiceError> {
        Ok(())
    }
}

impl SecurityPlugin for FancySecurity {
    fn as_auth_plugin(&self) -> &dyn AuthApi {
        self
    }

    fn as_security_plugin(&self) -> &dyn SecurityApi {
        self
    }
}

#[derive(Default)]
pub struct FancySecurityLoader;

#[async_trait]
impl SecurityPluginInitializer for FancySecurityLoader {
    async fn initialize_from_request_parts(
        &self,
        _parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError> {
        Ok(Box::new(FancySecurity))
    }
}

#[async_trait]
impl AuthorizationRequestHandler for FancySecurityLoader {
    async fn authorize(_headers: HeaderMap, _body: Bytes) -> impl IntoApiResponse {
        (StatusCode::OK, Json("fancy-token"))
    }
}

impl SecurityPluginLoader for FancySecurityLoader {}

pub struct FancyCommunication {
    handle: CommunicationHandle,
}

#[async_trait]
impl Shutdown for FancyCommunication {
    async fn shutdown(&self) {
        self.handle.shutdown().await;
    }
}

#[async_trait]
impl CommunicationPlugin for FancyCommunication {
    fn state(&self) -> CommunicationState {
        self.handle.state()
    }

    fn acquire(
        &self,
    ) -> Result<
        cda_interfaces::communication_control::CommunicationGuard,
        cda_interfaces::communication_control::CommunicationError,
    > {
        self.handle.acquire()
    }

    async fn activate(
        &self,
        _cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.handle.enable_and_detect().await
    }

    fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
        self.handle.request_enable_and_detect()
    }

    async fn trigger_detection(
        &self,
        _cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.handle.redetect().await
    }

    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.handle.disable(reason).await
    }

    async fn register_lifecycle_hook(
        &self,
        initializer: Arc<dyn CommunicationLifecycle>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.handle.register_lifecycle_hook(initializer).await
    }

    async fn register_variant_detection(
        &self,
        detector: Arc<dyn CommunicationVariantDetection>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.handle.register_variant_detection(detector).await
    }

    fn variant_detection(&self) -> cda_interfaces::communication_control::VariantDetectionMode {
        self.handle.variant_detection()
    }
}

#[derive(Default)]
pub struct FancyRuntimeUpdate;

pub struct FancyRuntimeReloader;

#[async_trait]
impl RuntimeReloaderPlugin for FancyRuntimeReloader {
    async fn reload_databases(
        &self,
        _mdd_paths: Vec<std::path::PathBuf>,
    ) -> Result<(), ReloadError> {
        Ok(())
    }
}

pub struct FancyRuntimeUpdateSecurity;

#[async_trait]
impl<L, C> RuntimeUpdateSecurityPlugin<L, C> for FancyRuntimeUpdateSecurity
where
    L: LockStateProvider,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
{
    async fn check_apply_allowed(
        &self,
        _lock_state_provider: &L,
        _collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        Ok(())
    }

    async fn check_file_integrity(&self, _path: &std::path::Path) -> Result<(), VerificationError> {
        Ok(())
    }
}

#[async_trait]
impl RuntimeFilesUpdatePlugin for FancyRuntimeUpdate {
    async fn list_current(
        &self,
        _query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        Ok(BulkDataList::default())
    }

    async fn list_nextupdate(
        &self,
        _query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        Ok(BulkDataList::default())
    }

    async fn list_backup(
        &self,
        _query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        Ok(BulkDataList::default())
    }

    async fn upload(
        &self,
        _files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        Ok(BulkDataCreatedList::default())
    }

    async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        Ok(Vec::new())
    }

    async fn delete_nextupdate_by_id(&self, _file_id: &str) -> Result<(), RuntimeUpdateError> {
        Ok(())
    }

    async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        Ok(Vec::new())
    }

    async fn start_execution(&self, _mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        Ok("fancy-execution".to_owned())
    }

    async fn list_executions(&self) -> Vec<UpdateExecution> {
        Vec::new()
    }

    async fn get_execution_status(&self, _execution_id: &str) -> Option<UpdateExecution> {
        None
    }
}

#[override_macros::vendor_override(cda_core::lookup_request_seed_service, erase(ecu_mgr))]
fn fancy_request_seed_override(
    ecu_mgr: &EcuManager<FancySecurity>,
    _level: &str,
) -> Result<SecurityAccess, DiagServiceError> {
    let _ = ecu_mgr;
    Err(DiagServiceError::NotFound("Fancy override".to_owned()))
}

pub async fn run_fancy() -> Result<(), opensovd_cda_lib::AppError> {
    let setup = Setup::<FancySecurity, FancySecurityLoader>::new()
        .with_preload(|router| async move {
            router
                .add_routes(
                    aide::axum::ApiRouter::new()
                        .route("/fancy", aide::axum::routing::get(|| async { "fancy" })),
                )
                .await;
            Ok(())
        })
        .with_update_plugin(update_plugin_fn(|_runtime| async {
            Ok(FancyRuntimeUpdate)
        }))
        .with_communication_plugin(communication_plugin_fn(
            |handle, _mode: CommunicationInitMode| async move {
                Ok::<_, std::convert::Infallible>(FancyCommunication { handle })
            },
        ));

    opensovd_cda_lib::run_with_ext_from_config(opensovd_cda_lib::config::default_config(), setup)
        .await
}
