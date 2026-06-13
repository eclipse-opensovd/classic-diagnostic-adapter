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

// Needed so that `self.load()` is callable inside the EcuVariantProvider impl
use cda_interfaces::{
    DiagComm, DiagServiceError, EcuManager as EcuManagerTrait, EcuState, EcuVariant, HashMap,
    VariantDetection, diagservices::DiagServiceResponse, dlt_ctx,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::{EcuManager, VariantData};
use crate::diag_kernel::variant_detection;

impl<S: SecurityPlugin> VariantDetection for EcuManager<S> {
    fn variant(&self) -> EcuVariant {
        self.variant.clone()
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
            let state = if matches!(
                self.variant.state,
                EcuState::Online
                    | EcuState::Duplicate
                    | EcuState::Disconnected
                    | EcuState::NoVariantDetected
            ) {
                EcuState::Disconnected
            } else {
                EcuState::Offline
            };

            self.variant = EcuVariant {
                name: None,
                is_base_variant: false,
                is_fallback: false,
                state,
                logical_address: self.logical_address,
            };
            return Ok(());
        }
        match variant_detection::evaluate_variant(service_responses, &self.diag_database) {
            Ok(v) => {
                let variant_data = VariantData::from_variant_and_fallback(&v, false);
                self.set_variant(variant_data).await
            }
            Err(e) => {
                if !self.fallback_to_base_variant {
                    self.variant = EcuVariant {
                        name: None,
                        is_base_variant: false,
                        is_fallback: false,
                        state: EcuState::NoVariantDetected,
                        logical_address: self.logical_address,
                    };
                    self.diag_database.unload();
                    tracing::debug!(
                        "No variant detected, fallback to base variant disabled, unloading DB"
                    );
                    return Err(e);
                }

                let base_variant = match self.diag_database.base_variant() {
                    Ok(base_variant) => base_variant,
                    Err(e) => {
                        self.variant = EcuVariant {
                            name: None,
                            is_base_variant: false,
                            is_fallback: false,
                            state: EcuState::NoVariantDetected,
                            logical_address: self.logical_address,
                        };
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

    fn mark_as_duplicate(&mut self) {
        self.variant.state = EcuState::Duplicate;
        self.diag_database.unload();
    }

    fn mark_as_no_variant_detected(&mut self) {
        self.variant.state = EcuState::NoVariantDetected;
        self.diag_database.unload();
    }
}
