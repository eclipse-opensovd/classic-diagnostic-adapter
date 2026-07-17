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

use async_trait::async_trait;
// Needed so that `self.load()` is callable inside the EcuVariantProvider impl
use cda_interfaces::{
    Connectivity, DiagComm, DiagServiceError, EcuManager as EcuManagerTrait, EcuState, HashMap,
    VariantDetection, VariantState, diagservices::DiagServiceResponse, dlt_ctx, util::std_ext,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::{EcuManager, VariantData};
use crate::diag_kernel::variant_detection;

impl<S: SecurityPlugin> EcuManager<S> {
    fn clear_variant(&self, variant_state: VariantState, connectivity: Option<Connectivity>) {
        let mut ecu_state = std_ext::lock_write(&self.runtime_state.ecu_state);
        ecu_state.variant_state = variant_state;
        ecu_state.variant_index = None;
        if let Some(connectivity) = connectivity {
            ecu_state.connectivity = connectivity;
        }
        drop(ecu_state);
    }
}

#[async_trait]
impl<S: SecurityPlugin> VariantDetection for EcuManager<S> {
    fn ecu_status(&self) -> EcuState {
        self.runtime_state.status()
    }

    #[tracing::instrument(
        target = "variant detection check",
        skip(self, service_responses),
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
        ),
    )]
    async fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        if !self.diag_database.is_loaded() {
            tracing::debug!(ecu_name = %self.ecu_name, "Loading database for variant detection");
            self.load()?;
        }

        if service_responses.is_empty() {
            // No responses means ECU is unreachable -> set connectivity to Offline.
            // Variant state is intentionally preserved (we still know what variant it was).
            std_ext::lock_write(&self.runtime_state.ecu_state).connectivity = Connectivity::Offline;
            return Ok(());
        }

        match variant_detection::evaluate_variant(service_responses, &self.diag_database) {
            Ok(v) => {
                let variant_data = VariantData::from_variant_and_fallback(&v, false);
                self.set_variant(variant_data).await
            }
            Err(e) => {
                if !self.fallback_to_base_variant {
                    // Connectivity is Online. We got responses but couldn't match a variant.
                    self.clear_variant(VariantState::NotDetected, Some(Connectivity::Online));
                    self.db_cache.reset().await;
                    self.diag_database.unload();
                    tracing::debug!(
                        "No variant detected, fallback to base variant disabled, unloading DB"
                    );
                    return Err(e);
                }

                let base_variant = match self.diag_database.base_variant() {
                    Ok(base_variant) => base_variant,
                    Err(e) => {
                        self.clear_variant(VariantState::NotDetected, Some(Connectivity::Online));
                        self.db_cache.reset().await;
                        self.diag_database.unload();
                        tracing::debug!(
                            "No variant detected, and no base variant found in DB, unloading DB"
                        );
                        return Err(e);
                    }
                };

                let variant_data = VariantData::from_variant_and_fallback(&base_variant, true);
                self.set_variant(variant_data).await
            }
        }
    }

    fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm> {
        &self.variant_detection.diag_service_requests
    }

    async fn mark_as_duplicate(&mut self) {
        self.clear_variant(VariantState::Duplicate, None);
        self.db_cache.reset().await;
        self.diag_database.unload();
    }

    async fn mark_as_no_variant_detected(&mut self) {
        self.clear_variant(VariantState::NotDetected, None);
        self.db_cache.reset().await;
        self.diag_database.unload();
    }
}
