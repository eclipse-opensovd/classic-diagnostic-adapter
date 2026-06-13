/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! MDD file parsing and service extraction.

pub mod defaults;
mod response_gen;
mod service_def;

use cda_database::{DatabaseConfig, datatypes::DiagnosticDatabase};
use cda_interfaces::datatypes::{CanComParams, ComParamValue, FlatbBufConfig};
pub use defaults::{DefaultOverridesFile, apply_default_overrides};
pub use response_gen::extract_services;
pub use service_def::{
    CompuCategory, Conversion, ParameterValue, ResponseParameter, ServiceDefinition, ServiceSource,
};

use crate::error::SimulatorError;

/// Loaded MDD data
pub struct MddData {
    pub ecu_name: String,
    pub database: DiagnosticDatabase,
}

/// Information about a variant
#[derive(Debug, Clone)]
pub struct VariantInfo {
    pub name: String,
    pub is_base: bool,
}

/// A variant detection pattern extracted from the MDD
/// This defines what parameter values identify a specific variant
#[derive(Debug, Clone)]
pub struct VariantDetectionPattern {
    /// The service name that contains the identification parameters
    pub service_name: String,
    /// The parameter name to check
    pub parameter_name: String,
    /// The expected value (as a string, may be hex or ASCII)
    pub expected_value: String,
}

/// Extract variant detection patterns for a specific variant
///
/// These patterns define what parameter values the CDA expects to see
/// when detecting this variant. The simulator should set these values
/// so variant detection works correctly.
pub fn extract_variant_patterns(
    database: &DiagnosticDatabase,
    variant_name: &str,
) -> Vec<VariantDetectionPattern> {
    let ecu_data = match database.ecu_data() {
        Ok(data) => data,
        Err(_) => return vec![],
    };

    let Some(variants) = ecu_data.variants() else {
        return vec![];
    };

    // Find the requested variant
    let variant = match variants.iter().find(|v| {
        v.diag_layer()
            .and_then(|dl| dl.short_name())
            .is_some_and(|n| n == variant_name)
    }) {
        Some(v) => v,
        None => return vec![],
    };

    let mut patterns = Vec::new();

    // Extract patterns from variant_pattern -> matching_parameter
    if let Some(variant_patterns) = variant.variant_pattern() {
        for pattern in variant_patterns {
            if let Some(matching_params) = pattern.matching_parameter() {
                for mp in matching_params {
                    // Get the expected value
                    let expected_value = match mp.expected_value() {
                        Some(v) => v.to_string(),
                        None => continue,
                    };

                    // Get the output parameter name
                    let parameter_name = match mp.out_param().and_then(|op| op.short_name()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    // Get the service name
                    let service_name = match mp
                        .diag_service()
                        .and_then(|ds| ds.diag_comm())
                        .and_then(|dc| dc.short_name())
                    {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    patterns.push(VariantDetectionPattern {
                        service_name,
                        parameter_name,
                        expected_value,
                    });
                }
            }
        }
    }

    // Deduplicate patterns (same service+param may appear multiple times)
    patterns.sort_by(|a, b| {
        (&a.service_name, &a.parameter_name).cmp(&(&b.service_name, &b.parameter_name))
    });
    patterns
        .dedup_by(|a, b| a.service_name == b.service_name && a.parameter_name == b.parameter_name);

    tracing::info!(
        variant = %variant_name,
        pattern_count = patterns.len(),
        "Extracted variant detection patterns"
    );

    for pattern in &patterns {
        tracing::debug!(
            service = %pattern.service_name,
            parameter = %pattern.parameter_name,
            expected = %pattern.expected_value,
            "Variant detection pattern"
        );
    }

    patterns
}

/// Load an MDD file and parse it
pub fn load_mdd(mdd_path: &str) -> Result<MddData, SimulatorError> {
    let (ecu_name, ecu_payload) =
        cda_database::load_ecudata(mdd_path).map_err(|e| SimulatorError::MddLoad(e.to_string()))?;

    let database = DiagnosticDatabase::new_from_vec(
        mdd_path.to_string(),
        ecu_payload.to_vec(),
        FlatbBufConfig::default(),
        DatabaseConfig::default(),
    )
    .map_err(|e| SimulatorError::MddParse(e.to_string()))?;

    Ok(MddData { ecu_name, database })
}

/// Extract available variants from the MDD
pub fn extract_variants(database: &DiagnosticDatabase) -> Vec<VariantInfo> {
    let ecu_data = match database.ecu_data() {
        Ok(data) => data,
        Err(_) => return vec![],
    };

    let Some(variants) = ecu_data.variants() else {
        return vec![];
    };

    variants
        .iter()
        .filter_map(|v| {
            let name = v
                .diag_layer()
                .and_then(|dl| dl.short_name())
                .unwrap_or("unknown")
                .to_string();
            Some(VariantInfo {
                name,
                is_base: v.is_base_variant(),
            })
        })
        .collect()
}

/// Try to extract CAN IDs from MDD COM parameters
///
/// This function attempts to find CAN physical request and response IDs from the MDD.
/// It uses a two-tier approach:
/// 1. First tries to extract from CP_UniqueRespIdTable complex parameter
/// 2. Falls back to direct lookup of CP_CanPhysReqId and CP_CanRespUSDTId
pub fn extract_can_ids(database: &DiagnosticDatabase) -> (Option<u32>, Option<u32>) {
    // Find a CAN-related protocol in the database
    let protocol = match find_can_protocol(database) {
        Some(p) => p,
        None => {
            tracing::debug!("No CAN protocol found in MDD, CAN IDs must be provided via CLI");
            return (None, None);
        }
    };

    let com_params = CanComParams::default();

    // First, try extracting from CP_UniqueRespIdTable (complex value).
    // The table may exist but carry no CAN IDs (e.g. DoIP-centric MDDs that
    // still reference a CAN protocol layer), so treat its two halves
    // independently and fill whatever is missing from the direct scalar
    // com-param lookup instead of returning early.
    let (table_request_id, table_response_id) =
        extract_can_ids_from_unique_resp_table(database, &protocol, &com_params)
            .unwrap_or((None, None));

    let request_id: Option<u32> = table_request_id.or_else(|| {
        database
            .find_com_param(Some(&protocol), &com_params.physical_request_id)
            .ok()
            .and_then(|v| v)
    });
    let response_id: Option<u32> = table_response_id.or_else(|| {
        database
            .find_com_param(Some(&protocol), &com_params.physical_response_id)
            .ok()
            .and_then(|v| v)
    });

    if request_id.is_some() || response_id.is_some() {
        tracing::info!(
            request_id = request_id.map(|id| format!("0x{:03X}", id)),
            response_id = response_id.map(|id| format!("0x{:03X}", id)),
            from_unique_resp_id_table = table_request_id.is_some() || table_response_id.is_some(),
            "Extracted CAN IDs from MDD COM parameters"
        );
    } else {
        tracing::debug!("No CAN IDs found in MDD COM parameters");
    }

    (request_id, response_id)
}

/// Find a CAN-related protocol in the MDD database
fn find_can_protocol(
    database: &DiagnosticDatabase,
) -> Option<cda_database::datatypes::Protocol<'_>> {
    // Common CAN protocol names in MDD files
    const CAN_PROTOCOL_NAMES: &[&str] = &[
        "UDS_CAN",
        "ISO_11898_2_DWCAN",
        "ISO_11898_3_DWFTCAN",
        "CAN",
        "ISO_15765_2",
        "ISO_15765_3",
    ];

    let diag_layers = database.diag_layers().ok()?;

    // Collect all protocols from COM param refs
    let protocols: Vec<_> = diag_layers
        .iter()
        .flat_map(|dl| dl.com_param_refs().into_iter().flatten())
        .filter_map(|cp_ref| cp_ref.protocol())
        .collect();

    // Try to find a CAN protocol by name
    for name in CAN_PROTOCOL_NAMES {
        if let Some(p) = protocols.iter().find(|p| {
            p.diag_layer()
                .and_then(|dl| dl.short_name())
                .is_some_and(|sn| sn == *name)
        }) {
            tracing::debug!(protocol = %name, "Found CAN protocol in MDD");
            return Some(cda_database::datatypes::Protocol(*p));
        }
    }

    // If no named CAN protocol found, use the first available protocol
    if !protocols.is_empty() {
        let protocol_name = protocols[0]
            .diag_layer()
            .and_then(|dl| dl.short_name())
            .unwrap_or("unknown");
        tracing::debug!(
            protocol = %protocol_name,
            "CAN protocol not found by name, using first available protocol"
        );
        return Some(cda_database::datatypes::Protocol(protocols[0]));
    }

    None
}

/// Try to extract CAN IDs from CP_UniqueRespIdTable complex parameter
fn extract_can_ids_from_unique_resp_table(
    database: &DiagnosticDatabase,
    protocol: &cda_database::datatypes::Protocol<'_>,
    com_params: &CanComParams,
) -> Option<(Option<u32>, Option<u32>)> {
    // Use the re-exported lookup function from cda_database::datatypes
    let unique_resp_table =
        cda_database::datatypes::lookup(database, Some(&protocol.0), "CP_UniqueRespIdTable")
            .ok()?;

    if let ComParamValue::Complex(entries) = unique_resp_table {
        let request_id = entries
            .get(&com_params.physical_request_id.name)
            .and_then(|v| {
                if let ComParamValue::Simple(s) = v {
                    parse_can_id_value(&s.value)
                } else {
                    None
                }
            });

        let response_id = entries
            .get(&com_params.physical_response_id.name)
            .and_then(|v| {
                if let ComParamValue::Simple(s) = v {
                    parse_can_id_value(&s.value)
                } else {
                    None
                }
            });

        Some((request_id, response_id))
    } else {
        None
    }
}

/// Parse a CAN ID from string (supports hex with 0x prefix and decimal)
fn parse_can_id_value(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex_str, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}
