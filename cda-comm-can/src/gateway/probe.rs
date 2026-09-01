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
            payload: vec![cda_interfaces::service_ids::TESTER_PRESENT, 0x00],
        }
    }
}

impl CanDiagGateway {
    pub(super) fn build_probe_sequence(
        config: &CanConfig,
    ) -> Result<Vec<ProbeRequest>, CanGatewaySetupError> {
        let mut probes = if config.default_probes {
            vec![ProbeRequest::tester_present()]
        } else {
            // With the built-in probe disabled the fallbacks are the whole
            // sequence; empty would make discovery a silent no-op.
            if config.probe_fallbacks.is_empty() {
                return Err(CanGatewaySetupError::InvalidConfiguration(
                    "can.default_probes = false requires at least one [[can.probe_fallbacks]] \
                     entry"
                        .to_owned(),
                ));
            }
            Vec::new()
        };

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

    pub(super) async fn probe_connection(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
    ) -> Result<(), CanError> {
        let mut last_error = None;

        for retry_round in 0..=self.probe_retries {
            if retry_round > 0 {
                // A missed exchange during discovery is often transient (e.g.
                // the ECU still waking up); retry inside the transport so the
                // UDS layer only ever sees settled online/offline states.
                tracing::debug!(
                    ecu = %conn.ecu_name(),
                    retry_round,
                    probe_retries = self.probe_retries,
                    "Re-running CAN discovery probe sequence"
                );
                cda_interfaces::util::tokio_ext::sleep_for(self.probe_retry_delay).await;
            }
            if let Ok(()) = self
                .probe_sequence_once(conn, logical_addr)
                .await
                .map_err(|e| last_error = Some(e))
            {
                return Ok(());
            }
        }

        Err(last_error.unwrap_or(CanError::EcuNotResponding(conn.request_id().raw())))
    }

    /// One round through the configured probe sequence; `Ok` on the first
    /// probe the ECU answers.
    async fn probe_sequence_once(
        &self,
        conn: &CanEcuConnection,
        logical_addr: u16,
    ) -> Result<(), CanError> {
        let mut last_error = None;

        for probe in self.probe_sequence.iter() {
            let start = Instant::now();
            tracing::debug!(
                ecu = %conn.ecu_name(),
                logical_addr,
                network_addr = %conn.network_address(),
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
                            "negative-response nrc={:#04X}",
                            response.get(2).copied().unwrap_or(0)
                        )
                    } else {
                        format!(
                            "positive-response sid={:#04X}",
                            response.first().copied().unwrap_or(0)
                        )
                    };

                    tracing::info!(
                        ecu = %conn.ecu_name(),
                        logical_addr,
                        network_addr = %conn.network_address(),
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
                        ecu = %conn.ecu_name(),
                        logical_addr,
                        network_addr = %conn.network_address(),
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

        Err(last_error.unwrap_or(CanError::EcuNotResponding(conn.request_id().raw())))
    }

    /// Discovers ECUs on the CAN bus by running the configured probe
    /// sequence (`TesterPresent` by default, plus/or the configured
    /// fallbacks) against each configured ECU. ECUs that answer any probe
    /// are considered online.
    ///
    /// # Returns
    /// A list of ECU names that responded to a probe.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("CAN")))]
    pub async fn discover_ecus(&self) -> Vec<String> {
        let topology = self.topology.read().await;
        self.discover_ecus_with_topology(&topology).await
    }

    pub(super) async fn discover_ecus_with_topology(
        &self,
        topology: &super::CanTopology,
    ) -> Vec<String> {
        let futures: Vec<_> = topology
            .connections()
            .iter()
            .map(|(ecu_name, addressing)| {
                let logical_addr = topology
                    .logical_address_for_ecu(ecu_name)
                    .unwrap_or_default();
                let conn = CanEcuConnection::new(std::sync::Arc::clone(addressing));

                async move {
                    let result = self.probe_connection(&conn, logical_addr).await;
                    match &result {
                        Ok(()) => tracing::info!(
                            ecu = %conn.ecu_name(),
                            logical_addr = logical_addr,
                            network_addr = %conn.network_address(),
                            "ECU discovered on CAN"
                        ),
                        Err(e) => tracing::debug!(
                            ecu = %conn.ecu_name(),
                            logical_addr = logical_addr,
                            error = %e,
                            "ECU not responding on CAN"
                        ),
                    }
                    // Return the lowercase map key, not `conn.ecu_name`: for
                    // ECUs from [[can.ecu_mappings]] the latter carries the
                    // config-file casing, which the variant-detection
                    // consumer would not find in its lowercase-keyed ECU map.
                    (ecu_name.clone(), result)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        let mut discovered = Vec::new();
        let mut cache = self.discovered_ecus.write().await;

        for (ecu_name, result) in results {
            match result {
                Ok(()) => {
                    cache.insert(ecu_name.clone());
                    discovered.push(ecu_name);
                }
                Err(_) => {
                    cache.remove(&ecu_name);
                }
            }
        }

        discovered
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[cfg(feature = "can-socketcand")]
    use cda_interfaces::CanId;

    use super::*;
    use crate::config::CanProbeConfig;
    #[cfg(feature = "can-socketcand")]
    use crate::{CanEcuAddressing, gateway::shared_topology};

    #[test]
    fn default_probe_sequence_starts_with_tester_present() {
        let config = CanConfig::default();
        let probes = CanDiagGateway::build_probe_sequence(&config).expect("valid config");
        assert_eq!(probes.len(), 1);
        assert_eq!(
            probes.first().map(|p| p.payload.clone()),
            Some(vec![cda_interfaces::service_ids::TESTER_PRESENT, 0x00])
        );
    }

    #[test]
    fn disabled_default_probes_use_the_fallbacks_verbatim() {
        let config = CanConfig {
            default_probes: false,
            probe_fallbacks: vec![CanProbeConfig {
                name: Some("read-did".to_owned()),
                payload_hex: "22F190".to_owned(),
            }],
            ..CanConfig::default()
        };
        let probes = CanDiagGateway::build_probe_sequence(&config).expect("valid config");
        assert_eq!(probes.len(), 1);
        assert_eq!(
            probes.first().map(|p| p.payload.clone()),
            Some(vec![0x22, 0xF1, 0x90])
        );
    }

    #[test]
    fn disabled_default_probes_without_fallbacks_fail_setup() {
        let config = CanConfig {
            default_probes: false,
            ..CanConfig::default()
        };
        // An empty probe sequence would make discovery a silent no-op.
        assert!(CanDiagGateway::build_probe_sequence(&config).is_err());
    }

    /// Each address has no responder, so all probes must time out together
    /// rather than one after another.
    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    async fn discovery_probes_unresponsive_ecus_concurrently() {
        const INTERFACE: &str = "socketcand:127.0.0.1:29536:vcan0";
        const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

        let mut gateway = CanDiagGateway::test_instance(
            shared_topology(vec![
                (
                    "missing-1",
                    CanEcuAddressing::new(
                        "missing-1".to_owned(),
                        INTERFACE.to_owned(),
                        CanId::try_from(0x600).unwrap(),
                        CanId::try_from(0x608).unwrap(),
                    ),
                ),
                (
                    "missing-2",
                    CanEcuAddressing::new(
                        "missing-2".to_owned(),
                        INTERFACE.to_owned(),
                        CanId::try_from(0x610).unwrap(),
                        CanId::try_from(0x618).unwrap(),
                    ),
                ),
                (
                    "missing-3",
                    CanEcuAddressing::new(
                        "missing-3".to_owned(),
                        INTERFACE.to_owned(),
                        CanId::try_from(0x620).unwrap(),
                        CanId::try_from(0x628).unwrap(),
                    ),
                ),
            ]),
            vec![],
        );
        gateway.probe_timeout = PROBE_TIMEOUT;

        let start = std::time::Instant::now();
        assert_eq!(
            gateway.discover_ecus().await,
            [] as [std::string::String; 0]
        );
        assert!(
            start.elapsed() < PROBE_TIMEOUT * 2,
            "three probes should complete near one timeout, not three: {:?}",
            start.elapsed()
        );
    }
}
