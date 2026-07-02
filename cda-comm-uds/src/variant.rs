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

use std::time::Duration;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuVariant, HashMap,
    HashMapExtensions, PayloadDecoder, UdsTransport, UdsVariant, dlt_ctx,
};

use crate::UdsManager;

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    pub(crate) fn start_variant_detection_for_ecus(&self, ecus: Vec<String>) {
        for ecu_name in ecus {
            let vd = self.clone();
            cda_interfaces::spawn_named!(&format!("variant-detection-{ecu_name}"), async move {
                match vd.detect_variant(&ecu_name).await {
                    Ok(()) => {
                        tracing::trace!("Variant detection successful");
                    }
                    Err(e) => {
                        tracing::info!(error = %e, "Variant detection failed");
                    }
                }
            });
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsVariant for UdsManager<S, T> {
    #[tracing::instrument(skip(self), err,
        fields(
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    async fn detect_variant(&self, ecu_name: &str) -> Result<(), DiagServiceError> {
        #[derive(Debug)]
        enum VariantDetectionResult<'a> {
            ExactMatch(&'a str),
            AllFallbacks,
            NoOnlineEcu,
            NoDetection,
        }

        let ecu = self.uds_ecu_db(ecu_name)?;

        let requests = ecu
            .read()
            .await
            .get_variant_detection_requests()
            .iter()
            .map(|(name, service)| Ok((name.to_owned(), service.clone())))
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;

        if !ecu.read().await.is_loaded() {
            ecu.write().await.load().map_err(|e| {
                DiagServiceError::ResourceError(format!("Failed to load ECU data: {e:?}"))
            })?;
        }

        // Seed the session/security map before sending detection requests so
        // that check_service_preconditions can validate them. This only
        // works for ECUS whose state charts are defined on the base variant level
        if let Err(e) = ecu.read().await.set_default_states().await {
            tracing::debug!(
                error = %e,
                "Could not pre-initialize ECU default states"
            );
        }

        let mut service_responses = HashMap::new();
        'variant_detection_calls: {
            for (name, service) in requests {
                let response = match self
                    .send_with_timeout(
                        ecu_name,
                        service,
                        &(Box::new(()) as DynamicPlugin),
                        None,
                        true,
                        Duration::from_secs(10),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::debug!(
                            request_name = %name,
                            error = %e,
                            "Failed to send variant detection request"
                        );
                        break 'variant_detection_calls; // no need to continue if one fails
                    }
                };
                service_responses.insert(name, response);
            }
        }

        let Some(mut duplicated_ecus) = ecu
            .read()
            .await
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty())
        else {
            // No duplicated ECUs, proceed with normal variant detection
            return ecu
                .write()
                .await
                .detect_variant(service_responses)
                .await
                .map_err(|e| {
                    DiagServiceError::VariantDetectionError(format!(
                        "Failed to detect variant: {e:?}"
                    ))
                });
        };

        // Detect variants for all duplicated ECUs
        duplicated_ecus.insert(ecu_name.to_owned());

        let detection_result = {
            // First ECU that is online and fell back to base variant (no specific match).
            let mut first_fallback = None;
            let mut any_online = false;

            let mut result = None;
            for ecu_name in &duplicated_ecus {
                let Some(ecu) = self.ecus.get(ecu_name) else {
                    continue;
                };

                if let Err(e) = ecu
                    .write()
                    .await
                    .detect_variant(service_responses.clone())
                    .await
                {
                    tracing::warn!(
                        "Variant detection failed for ECU {ecu_name}: {e:?}, marking as undetected"
                    );
                    continue;
                }

                let variant = ecu.read().await.variant();
                if variant.state != cda_interfaces::EcuState::Online {
                    continue;
                }

                any_online = true;

                if variant.is_fallback {
                    first_fallback.get_or_insert(ecu_name);
                } else {
                    result = Some(VariantDetectionResult::ExactMatch(ecu_name));
                    break;
                }
            }

            let result_fallback_mapper =
                |first_fallback, any_online| match (first_fallback, any_online) {
                    (Some(_), true) => VariantDetectionResult::AllFallbacks,
                    (_, true) => VariantDetectionResult::NoDetection,
                    _ => VariantDetectionResult::NoOnlineEcu,
                };

            result.unwrap_or(result_fallback_mapper(first_fallback, any_online))
        };

        tracing::debug!(?detection_result, "ECU variant detection result");

        match &detection_result {
            VariantDetectionResult::ExactMatch(the_chosen_one) => {
                // Mark all other duplicates, the chosen one keeps its detected variant.
                for ecu_name in &duplicated_ecus {
                    if ecu_name == *the_chosen_one {
                        continue;
                    }
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_duplicate();
                    }
                }
            }
            VariantDetectionResult::AllFallbacks => {
                // No specific variant found despite online ECUs - mark all as undetected.
                // Falling back to base variant is only allowed when there are no duplicates.
                for ecu_name in &duplicated_ecus {
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_no_variant_detected();
                    }
                }
            }
            VariantDetectionResult::NoOnlineEcu | VariantDetectionResult::NoDetection => {}
        }

        Ok(())
    }

    async fn get_variant(&self, ecu_name: &str) -> Result<EcuVariant, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let variant = ecu.read().await.variant();
        Ok(variant)
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn start_variant_detection(&self) {
        let mut ecus = Vec::new();
        for (ecu_name, db) in self.ecus.iter() {
            if !db.read().await.is_physical_ecu() {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Skip variant detection for functional description"
                );
                continue;
            }
            if let Err(DiagServiceError::EcuOffline(_)) =
                self.gateway.ecu_online(ecu_name, db).await
            {
                // empty response means ECU is offline
                if let Err(e) = db
                    .write()
                    .await
                    .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
                    .await
                {
                    tracing::error!(ecu_name = %ecu_name,
                        "Failed to set ECU offline during variant detection: {e:?}");
                }
                continue;
            }

            if db
                .read()
                .await
                .duplicating_ecu_names()
                .is_some_and(|d| ecus.iter().any(|e| d.contains(e)))
            {
                continue; // Only do one variant detection for duplicated ECUs
            }

            ecus.push(ecu_name.to_owned());
        }
        let cloned = self.clone();
        cloned.start_variant_detection_for_ecus(ecus);
    }
}
