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

//! ECU discovery probing: the probe sequence and the bounded per-ECU
//! discovery/re-probe logic of [`CanDiagGateway`].

use std::time::Instant;

use cda_interfaces::dlt_ctx;

use super::{
    CanDiagGateway,
    connection::CanEcuConnection,
    error::{CanError, CanGatewaySetupError},
};
use crate::config::CanConfig;

#[derive(Clone, Debug)]
pub(super) struct ProbeRequest {
    name: String,
    payload: Vec<u8>,
}

impl ProbeRequest {
    pub(super) fn tester_present() -> Self {
        Self {
            name: "tester_present".to_owned(),
            payload: vec![0x3E, 0x00],
        }
    }
}

impl CanDiagGateway {
    pub(super) fn build_probe_sequence(
        config: &CanConfig,
    ) -> Result<Vec<ProbeRequest>, CanGatewaySetupError> {
        let mut probes = vec![ProbeRequest::tester_present()];

        for fallback in &config.probe_fallbacks {
            let payload = fallback
                .payload_bytes()
                .map_err(CanGatewaySetupError::InvalidConfiguration)?;

            if probes.iter().any(|existing| existing.payload == payload) {
                continue;
            }

            let name = fallback
                .name
                .clone()
                .unwrap_or_else(|| format!("probe_{}", hex::encode_upper(&payload)));

            probes.push(ProbeRequest { name, payload });
        }

        Ok(probes)
    }

    async fn probe_connection(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
        discovery_index: usize,
        discovery_total: usize,
    ) -> Result<(), CanError> {
        let mut last_error = None;

        for retry_round in 0..=self.probe_retries {
            if retry_round > 0 {
                // A missed exchange during discovery is often transient (e.g.
                // the ECU still waking up); retry inside the transport so the
                // UDS layer only ever sees settled online/offline states.
                tracing::debug!(
                    ecu = %conn.ecu_name,
                    retry_round,
                    probe_retries = self.probe_retries,
                    "Re-running CAN discovery probe sequence"
                );
                cda_interfaces::util::tokio_ext::sleep_for(self.probe_retry_delay).await;
            }
            if let Ok(()) = self
                .probe_sequence_once(conn, logical_addr, discovery_index, discovery_total)
                .await
                .map_err(|e| last_error = Some(e))
            {
                return Ok(());
            }
        }

        Err(last_error.unwrap_or(CanError::EcuNotResponding(conn.request_id.raw())))
    }

    /// One round through the configured probe sequence; `Ok` on the first
    /// probe the ECU answers.
    async fn probe_sequence_once(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
        discovery_index: usize,
        discovery_total: usize,
    ) -> Result<(), CanError> {
        let mut last_error = None;

        #[allow(
            clippy::arithmetic_side_effects,
            reason = "1-based display index; overflow impossible"
        )]
        for (probe_index_0, probe) in self.probe_sequence.iter().enumerate() {
            let probe_index = probe_index_0 + 1;
            let start = Instant::now();
            tracing::debug!(
                ecu = %conn.ecu_name,
                logical_addr,
                network_addr = %conn.network_address(),
                discovery_index,
                discovery_total,
                probe_index,
                probe_total = self.probe_sequence.len(),
                probe_name = %probe.name,
                probe_payload = %hex::encode_upper(&probe.payload),
                timeout_ms = u32::try_from(self.probe_timeout.as_millis()).unwrap_or(u32::MAX),
                "Starting CAN discovery probe"
            );

            match conn
                .probe_with_payload(&probe.payload, self.probe_timeout)
                .await
            {
                Ok(response) => {
                    let elapsed = start.elapsed();
                    let response_kind = if response.first() == Some(&0x7F) {
                        format!(
                            "negative-response nrc=0x{:02X}",
                            response.get(2).copied().unwrap_or(0)
                        )
                    } else {
                        format!(
                            "positive-response sid=0x{:02X}",
                            response.first().copied().unwrap_or(0)
                        )
                    };

                    tracing::info!(
                        ecu = %conn.ecu_name,
                        logical_addr,
                        network_addr = %conn.network_address(),
                        discovery_index,
                        discovery_total,
                        probe_index,
                        probe_total = self.probe_sequence.len(),
                        probe_name = %probe.name,
                        probe_payload = %hex::encode_upper(&probe.payload),
                        response_kind,
                        response_data = %hex::encode_upper(&response),
                        elapsed_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX),
                        "CAN discovery probe succeeded"
                    );
                    return Ok(());
                }
                Err(error) => {
                    let elapsed = start.elapsed();
                    tracing::debug!(
                        ecu = %conn.ecu_name,
                        logical_addr,
                        network_addr = %conn.network_address(),
                        discovery_index,
                        discovery_total,
                        probe_index,
                        probe_total = self.probe_sequence.len(),
                        probe_name = %probe.name,
                        probe_payload = %hex::encode_upper(&probe.payload),
                        elapsed_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX),
                        error = %error,
                        "CAN discovery probe failed"
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(CanError::EcuNotResponding(conn.request_id.raw())))
    }

    /// Discovers ECUs on the CAN bus by probing with `TesterPresent`.
    ///
    /// Sends a `TesterPresent` (0x3E 0x00) request to each configured ECU
    /// and waits for a response. ECUs that respond are considered online.
    ///
    /// # Returns
    /// A list of ECU names that responded to the probe.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("CAN")))]
    pub async fn discover_ecus(&self) -> Vec<String> {
        let mut discovered = Vec::new();
        let discovery_total = self.connections.len();

        for (discovery_index, (ecu_name, conn)) in self.connections.iter().enumerate() {
            let logical_addr = self.logical_address_for_ecu(ecu_name);

            match self
                .probe_connection(
                    conn,
                    logical_addr,
                    discovery_index.saturating_add(1),
                    discovery_total,
                )
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        ecu = %conn.ecu_name,
                        logical_addr = logical_addr,
                        network_addr = %conn.network_address(),
                        "ECU discovered on CAN"
                    );
                    self.discovered_ecus.write().await.insert(ecu_name.clone());
                    // Push the lowercase map key, not `conn.ecu_name`: for
                    // ECUs from [[can.ecu_mappings]] the latter carries the
                    // config-file casing, which the variant-detection
                    // consumer would not find in its lowercase-keyed ECU map.
                    discovered.push(ecu_name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        ecu = %conn.ecu_name,
                        logical_addr = logical_addr,
                        error = %e,
                        "ECU not responding on CAN"
                    );
                    self.discovered_ecus.write().await.remove(ecu_name);
                }
            }
        }

        discovered
    }

    /// Re-probes a specific ECU to check if it's online.
    ///
    /// # Arguments
    /// * `ecu_name` - Name of the ECU to probe
    ///
    /// # Returns
    /// `true` if the ECU responded, `false` otherwise.
    #[tracing::instrument(skip(self), fields(dlt_context = dlt_ctx!("CAN")))]
    pub(crate) async fn probe_ecu(&self, ecu_name: &str) -> bool {
        let ecu_name = ecu_name.to_lowercase();
        let Some(conn) = self.connections.get(&ecu_name).cloned() else {
            return false;
        };
        let logical_addr = self.logical_address_for_ecu(&ecu_name);

        if self
            .probe_connection(&conn, logical_addr, 1, 1)
            .await
            .is_ok()
        {
            self.discovered_ecus.write().await.insert(ecu_name);
            true
        } else {
            self.discovered_ecus.write().await.remove(&ecu_name);
            false
        }
    }
}
