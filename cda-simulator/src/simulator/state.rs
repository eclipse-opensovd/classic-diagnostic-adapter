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

//! Simulator state management.

use std::{collections::HashMap, sync::Arc};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::mdd::{ParameterValue, ServiceDefinition, VariantDetectionPattern};

/// The active variant being simulated
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActiveVariant {
    pub name: String,
    pub is_base: bool,
}

/// Statistics about simulator operation
#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SimulatorStats {
    pub requests_received: u64,
    pub responses_sent: u64,
    pub errors: u64,
    pub unsupported_requests: u64,
}

/// Runtime state of the simulator
pub struct SimulatorState {
    /// ECU name from MDD
    pub ecu_name: String,
    /// Path to the MDD file
    pub mdd_path: String,
    /// The selected variant
    pub variant: ActiveVariant,
    /// CAN interface name
    pub interface: String,
    /// CAN request ID (what we listen on)
    pub request_id: u32,
    /// CAN response ID (what we respond on)
    pub response_id: u32,
    /// Service definitions indexed by (SID, SubFunction)
    pub services: HashMap<(u8, Option<u16>), ServiceDefinition>,
    /// Value overrides: (service_name, param_name) -> overridden value (as physical value)
    pub overrides: Arc<RwLock<HashMap<(String, String), ParameterValue>>>,
    /// Statistics
    pub stats: Arc<RwLock<SimulatorStats>>,
}

impl SimulatorState {
    /// Create a new simulator state
    pub fn new(
        ecu_name: String,
        mdd_path: String,
        variant: ActiveVariant,
        interface: String,
        request_id: u32,
        response_id: u32,
        services: HashMap<(u8, Option<u16>), ServiceDefinition>,
    ) -> Self {
        Self {
            ecu_name,
            mdd_path,
            variant,
            interface,
            request_id,
            response_id,
            services,
            overrides: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SimulatorStats::default())),
        }
    }

    /// Get a service by name
    pub fn get_service_by_name(&self, name: &str) -> Option<&ServiceDefinition> {
        self.services.values().find(|s| s.name == name)
    }

    /// Get a service by key (SID, SubFunction)
    pub fn get_service(&self, sid: u8, sub_function: Option<u16>) -> Option<&ServiceDefinition> {
        // Try exact match first
        if let Some(service) = self.services.get(&(sid, sub_function)) {
            return Some(service);
        }
        // Try SID-only match
        self.services.get(&(sid, None))
    }

    /// Set an override for a parameter (physical value)
    pub async fn set_override(&self, service_name: &str, param_name: &str, value: ParameterValue) {
        let mut overrides = self.overrides.write().await;
        overrides.insert((service_name.to_string(), param_name.to_string()), value);
    }

    /// Remove an override
    pub async fn remove_override(&self, service_name: &str, param_name: &str) -> bool {
        let mut overrides = self.overrides.write().await;
        overrides
            .remove(&(service_name.to_string(), param_name.to_string()))
            .is_some()
    }

    /// Get an override value
    pub async fn get_override(
        &self,
        service_name: &str,
        param_name: &str,
    ) -> Option<ParameterValue> {
        let overrides = self.overrides.read().await;
        overrides
            .get(&(service_name.to_string(), param_name.to_string()))
            .cloned()
    }

    /// Clear all overrides
    pub async fn clear_overrides(&self) {
        let mut overrides = self.overrides.write().await;
        overrides.clear();
    }

    /// Get all overrides
    pub async fn get_all_overrides(&self) -> HashMap<(String, String), ParameterValue> {
        let overrides = self.overrides.read().await;
        overrides.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = SimulatorStats::default();
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> SimulatorStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    /// Increment requests received counter
    pub async fn inc_requests(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_received = stats.requests_received.saturating_add(1);
    }

    /// Increment responses sent counter
    pub async fn inc_responses(&self) {
        let mut stats = self.stats.write().await;
        stats.responses_sent = stats.responses_sent.saturating_add(1);
    }

    /// Increment error counter
    pub async fn inc_errors(&self) {
        let mut stats = self.stats.write().await;
        stats.errors = stats.errors.saturating_add(1);
    }

    /// Increment unsupported requests counter
    pub async fn inc_unsupported(&self) {
        let mut stats = self.stats.write().await;
        stats.unsupported_requests = stats.unsupported_requests.saturating_add(1);
    }

    /// Apply variant detection patterns as initial overrides
    ///
    /// This sets the identification parameters to the values expected by the CDA
    /// for the selected variant, so variant detection works correctly.
    pub async fn apply_variant_patterns(&self, patterns: &[VariantDetectionPattern]) {
        let mut overrides = self.overrides.write().await;
        let mut applied_count = 0;

        for pattern in patterns {
            // Find the service by name
            let service = match self
                .services
                .values()
                .find(|s| s.name == pattern.service_name)
            {
                Some(s) => s,
                None => {
                    tracing::debug!(
                        service = %pattern.service_name,
                        "Service not found for variant pattern"
                    );
                    continue;
                }
            };

            // Find the parameter in the service
            let param = match service
                .response_params
                .iter()
                .find(|p| p.name == pattern.parameter_name)
            {
                Some(p) => p,
                None => {
                    tracing::debug!(
                        service = %pattern.service_name,
                        parameter = %pattern.parameter_name,
                        "Parameter not found for variant pattern"
                    );
                    continue;
                }
            };

            // Convert the expected value to a ParameterValue based on the parameter's bit length
            let value = convert_pattern_value(&pattern.expected_value, param.bit_length);

            tracing::info!(
                service = %pattern.service_name,
                parameter = %pattern.parameter_name,
                expected = %pattern.expected_value,
                value = ?value,
                "Applying variant detection pattern"
            );

            overrides.insert(
                (pattern.service_name.clone(), pattern.parameter_name.clone()),
                value,
            );
            applied_count += 1;
        }

        tracing::info!(
            applied = applied_count,
            total = patterns.len(),
            "Applied variant detection patterns as initial overrides"
        );
    }
}

/// Convert a pattern expected value string to a ParameterValue
///
/// The expected value can be:
/// - Hex string like "0500", "04" (treated as raw hex bytes)
/// - ASCII string like "DA1", "91Y" (treated as ASCII bytes)
fn convert_pattern_value(expected: &str, bit_length: u32) -> ParameterValue {
    let byte_length = ((bit_length + 7) / 8) as usize;

    // Try to parse as hex first (if all characters are hex digits)
    if expected.chars().all(|c| c.is_ascii_hexdigit()) && expected.len().is_multiple_of(2) {
        // It's a hex string like "0500" or "04"
        if let Ok(bytes) = hex::decode(expected) {
            if bytes.len() <= 8 {
                // Convert to u64 for small values
                let mut value: u64 = 0;
                for b in &bytes {
                    value = (value << 8) | (*b as u64);
                }
                return ParameterValue::UInt(value);
            } else {
                // Return as bytes for larger values
                return ParameterValue::Bytes(bytes);
            }
        }
    }

    // Treat as ASCII string (e.g., "DA1", "91Y")
    let bytes = expected.as_bytes().to_vec();
    if bytes.len() <= 8 && byte_length <= 8 {
        // Convert ASCII to u64 (big-endian)
        let mut value: u64 = 0;
        for b in &bytes {
            value = (value << 8) | (*b as u64);
        }
        // Pad to expected length if needed
        let actual_len = bytes.len();
        if actual_len < byte_length {
            value <<= (byte_length - actual_len) * 8;
        }
        ParameterValue::UInt(value)
    } else {
        ParameterValue::Bytes(bytes)
    }
}
