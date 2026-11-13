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

//! [[ dimpl~openapi-gen-route-skeleton, Generic ECU routes from the CDA route definitions ]]
//!
//! Builds the generic part of the document (locks, modes, faults, collections, ...)
//! by running the unmodified CDA route setup of `cda-sovd` against a UDS layer
//! whose transport never communicates. The handlers are never called; only the
//! `OpenAPI` description aide collects while registering the routes is used.

use std::{sync::Arc, time::Duration};

use aide::openapi::{OpenApi, PathItem, ReferenceOr};
use async_trait::async_trait;
use cda_comm_uds::{EcuStateCoordinator, UdsManager};
use cda_core::EcuManager;
use cda_interfaces::{
    DiagServiceError, EcuAddresses, FunctionalTransport, HashMap, HashMapExtensions as _,
    NetworkTopology, PhysicalTransport, ServicePayload, Shutdown, TransmissionParameters,
    TransportResponse, VariantDetectionReceiver,
    communication_control::{
        ActivationCause, CommunicationAccess, CommunicationError, CommunicationGuard,
        CommunicationState, VariantDetectionMode,
    },
    request_authorization::NoRequestLockProvider,
};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use indexmap::IndexMap;
use opensovd_cda_lib::config::configfile::Configuration;
use tokio::sync::{RwLock, mpsc};

use crate::GeneratorError;

/// Path segments of per-resource routes, replaced by concrete per-resource paths.
const TEMPLATED_RESOURCE_ROUTES: [&str; 4] = [
    "/data/{service}",
    "/configurations/{service}",
    "/operations/{service}",
    "/x-single-ecu-jobs/{job_name}",
];

/// The routes the CDA registers for one ECU.
pub(crate) struct EcuRoutes {
    /// Generic routes and the referenced component schemas.
    pub(crate) api: OpenApi,
    /// Per-resource template routes (e.g. `/data/{service}/docs`), keyed by the path
    /// relative to the ECU base path.
    pub(crate) templates: IndexMap<String, PathItem>,
}

/// Transport that never communicates; every send fails.
#[derive(Clone)]
struct OfflineGateway;

impl PhysicalTransport for OfflineGateway {
    fn send(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        _expect_uds_reply: bool,
    ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send {
        std::future::ready(Err(offline()))
    }

    fn ecu_online<T: EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &RwLock<T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Err(offline()))
    }
}

impl FunctionalTransport for OfflineGateway {
    fn send_functional(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _expected_ecu_logical_addrs: HashMap<u16, String>,
        _timeout: Duration,
        _expect_positive_response: bool,
    ) -> impl Future<
        Output = Result<
            HashMap<String, Result<ServicePayload, DiagServiceError>>,
            DiagServiceError,
        >,
    > + Send {
        std::future::ready(Err(offline()))
    }
}

impl NetworkTopology for OfflineGateway {
    fn get_gateway_network_address(
        &self,
        _logical_address: u16,
    ) -> impl Future<Output = Option<String>> + Send {
        std::future::ready(None)
    }
}

#[async_trait]
impl Shutdown for OfflineGateway {
    async fn shutdown(&self) {}
}

fn offline() -> DiagServiceError {
    DiagServiceError::EcuOffline("Offline OpenAPI generation".to_owned())
}

/// Communication that is never enabled.
struct NoCommunication;

impl CommunicationAccess for NoCommunication {
    fn state(&self) -> CommunicationState {
        CommunicationState::Disabled
    }

    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        Err(CommunicationError::Disabled)
    }

    fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
        CommunicationState::Disabled
    }

    fn variant_detection(&self) -> VariantDetectionMode {
        VariantDetectionMode::default()
    }
}

/// Returns the description of the generic routes the CDA registers for the
/// given ECU, including the referenced component schemas. Per-resource template
/// routes (e.g. `/data/{service}`) are returned separately, as the generator
/// replaces them by concrete paths for every visible resource.
pub(crate) async fn ecu_route_paths(
    ecu_name: &str,
    ecu: EcuManager<DefaultSecurityPluginData>,
    config: &Configuration,
) -> Result<EcuRoutes, GeneratorError> {
    let ecu_key = ecu_name.to_lowercase();
    let runtime_state = ecu.runtime_state();
    let mut databases = HashMap::new();
    databases.insert(ecu_name.to_owned(), RwLock::new(ecu));

    let (_variant_tx, variant_rx) = mpsc::channel(1);
    let mut runtime_states = HashMap::new();
    runtime_states.insert(ecu_name.to_owned(), runtime_state);
    let coordinator = EcuStateCoordinator::new(runtime_states);
    let communication_access: Arc<dyn CommunicationAccess> = Arc::new(NoCommunication);

    let uds = UdsManager::new(
        OfflineGateway,
        Arc::new(databases),
        VariantDetectionReceiver::new(variant_rx),
        coordinator,
        &config.functional_description,
        config.faults.clone(),
        Arc::new(NoRequestLockProvider),
        Arc::clone(&communication_access),
        Duration::ZERO,
    );

    let mut file_managers = HashMap::new();
    file_managers.insert(
        ecu_key.clone(),
        cda_database::FileManager::new(String::new(), Vec::new()),
    );

    let router = cda_sovd::build_vehicle_routes::<_, _, DefaultSecurityPlugin>(
        cda_sovd::VehicleConfig {
            flash_files_path: config.flash_files_path.clone(),
            flash_functional_class_default: config.flash_functional_class_default.clone(),
            functional_group_config: config.functional_description.clone(),
            components_config: config.components.clone(),
        },
        cda_sovd::VehicleResources {
            ecu_uds: uds,
            file_managers,
            locks: Arc::new(cda_sovd::Locks::new()),
            communication_access,
            doip_connect: None,
        },
    )
    .await;

    let mut api = OpenApi::default();
    let _ = router.finish_api(&mut api);

    let base_path = format!("/vehicle/v15/components/{ecu_key}");
    let mut templates = IndexMap::new();
    if let Some(paths) = api.paths.as_mut() {
        paths.paths = std::mem::take(&mut paths.paths)
            .into_iter()
            .filter_map(|(path, item)| {
                let rest = path.strip_prefix(&base_path)?;
                if TEMPLATED_RESOURCE_ROUTES
                    .iter()
                    .any(|t| rest.starts_with(t))
                {
                    if let ReferenceOr::Item(item) = item {
                        templates.insert(rest.to_owned(), item);
                    }
                    return None;
                }
                Some((path, item))
            })
            .collect();
    }
    Ok(EcuRoutes { api, templates })
}
