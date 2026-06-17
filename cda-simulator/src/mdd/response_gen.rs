/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! Service extraction and default response generation from MDD.

use std::collections::HashMap;

use cda_database::datatypes::{
    CompuCategory as DbCompuCategory, CompuMethod as DbCompuMethod, DataOperation,
    DataOperationVariant, DiagCodedTypeVariant, DiagService, DiagnosticDatabase, Parameter,
};

use super::service_def::{
    Conversion, ParameterValue, ResponseParameter, ServiceDefinition, ServiceSource,
};
use crate::error::SimulatorError;

/// Extract all services for a given variant from the MDD
///
/// This includes services from:
/// 1. The selected variant's diag layer (highest priority - overrides base)
/// 2. The base variant's diag layer (inherited services)
/// 3. Built-in services like TesterPresent (0x3E)
///
/// Service resolution order:
/// - Variant-specific services override base variant services
/// - This matches how CDA resolves services at runtime
pub fn extract_services(
    database: &DiagnosticDatabase,
    variant_name: &str,
) -> Result<HashMap<(u8, Option<u16>), ServiceDefinition>, SimulatorError> {
    let ecu_data = database
        .ecu_data()
        .map_err(|e| SimulatorError::MddParse(e.to_string()))?;

    // Find the selected variant
    let variant = ecu_data
        .variants()
        .and_then(|vars| {
            vars.iter().find(|v| {
                v.diag_layer()
                    .and_then(|dl| dl.short_name())
                    .is_some_and(|n| n == variant_name)
            })
        })
        .ok_or_else(|| SimulatorError::VariantNotFound(variant_name.to_string()))?;

    // Find the base variant (for inherited services)
    let base_variant = ecu_data
        .variants()
        .and_then(|vars| vars.iter().find(|v| v.is_base_variant()));

    let mut services = HashMap::new();
    let mut override_count = 0u32;
    let mut variant_only_count = 0u32;

    // First, add services from the base variant (if different from selected)
    let is_base = variant.is_base_variant();
    if !is_base {
        if let Some(base) = base_variant {
            if let Some(diag_layer) = base.diag_layer() {
                if let Some(diag_services) = diag_layer.diag_services() {
                    for svc in diag_services {
                        let service = DiagService(svc);
                        if let Ok(mut service_def) = parse_service_definition(&service) {
                            service_def.source = ServiceSource::BaseVariant;
                            let key = service_def.key();
                            services.insert(key, service_def);
                        }
                    }
                }
            }
        }
    }

    // Then, add/override with services from the selected variant
    if let Some(diag_layer) = variant.diag_layer() {
        if let Some(diag_services) = diag_layer.diag_services() {
            for svc in diag_services {
                let service = DiagService(svc);
                if let Ok(mut service_def) = parse_service_definition(&service) {
                    service_def.source = ServiceSource::SelectedVariant;
                    let key = service_def.key();

                    // Track if this is an override or a new service
                    if let Some(existing) = services.get(&key) {
                        if existing.source == ServiceSource::BaseVariant {
                            override_count += 1;
                            tracing::debug!(
                                service = %service_def.name,
                                sid = format!("0x{:02X}", service_def.sid),
                                sub = service_def.sub_function.map(|s| format!("0x{:02X}", s)),
                                base_params = existing.response_params.len(),
                                variant_params = service_def.response_params.len(),
                                "Variant overrides base service"
                            );
                        }
                    } else {
                        variant_only_count += 1;
                        tracing::debug!(
                            service = %service_def.name,
                            sid = format!("0x{:02X}", service_def.sid),
                            sub = service_def.sub_function.map(|s| format!("0x{:02X}", s)),
                            "Variant-only service (not in base)"
                        );
                    }

                    services.insert(key, service_def);
                }
            }
        }
    }

    // If this IS the base variant, mark all services as coming from base
    if is_base {
        if let Some(diag_layer) = variant.diag_layer() {
            if let Some(diag_services) = diag_layer.diag_services() {
                for svc in diag_services {
                    let service = DiagService(svc);
                    if let Ok(mut service_def) = parse_service_definition(&service) {
                        service_def.source = ServiceSource::BaseVariant;
                        let key = service_def.key();
                        services.insert(key, service_def);
                    }
                }
            }
        }
    }

    // Extract services from ECU shared data (lowest priority - don't override existing)
    let ecu_shared_count = extract_ecu_shared_services(database, &mut services);

    // Add built-in TesterPresent (0x3E) service if not already present
    add_tester_present_service(&mut services);

    // Count services by source for logging
    let final_base_count = services
        .values()
        .filter(|s| s.source == ServiceSource::BaseVariant)
        .count();
    let final_variant_count = services
        .values()
        .filter(|s| s.source == ServiceSource::SelectedVariant)
        .count();
    let final_builtin_count = services
        .values()
        .filter(|s| s.source == ServiceSource::BuiltIn)
        .count();
    let final_ecu_shared_count = services
        .values()
        .filter(|s| s.source == ServiceSource::EcuShared)
        .count();

    tracing::info!(
        variant = %variant_name,
        is_base = is_base,
        total_services = services.len(),
        from_base = final_base_count,
        from_variant = final_variant_count,
        from_ecu_shared = final_ecu_shared_count,
        from_builtin = final_builtin_count,
        overrides = override_count,
        variant_only = variant_only_count,
        ecu_shared_added = ecu_shared_count,
        "Extracted services with variant-specific overrides"
    );

    Ok(services)
}

/// Add the TesterPresent (0x3E) service if not already defined
fn add_tester_present_service(services: &mut HashMap<(u8, Option<u16>), ServiceDefinition>) {
    use super::service_def::ServiceDefinition;

    // TesterPresent with suppressPositiveResponse = 0 (expects response)
    let key_with_response = (0x3E, Some(0x00));
    if !services.contains_key(&key_with_response) {
        services.insert(
            key_with_response,
            ServiceDefinition {
                name: "TesterPresent".to_string(),
                sid: 0x3E,
                sub_function: Some(0x00),
                sub_function_len: 1,
                description: Some("TesterPresent - Keep session alive".to_string()),
                response_params: vec![
                    ResponseParameter {
                        name: "SID".to_string(),
                        byte_position: 0,
                        bit_position: 0,
                        bit_length: 8,
                        default_value: ParameterValue::UInt(0x7E), // Response SID
                        unit: None,
                        conversion: None,
                    },
                    ResponseParameter {
                        name: "SubFunction".to_string(),
                        byte_position: 1,
                        bit_position: 0,
                        bit_length: 8,
                        default_value: ParameterValue::UInt(0x00),
                        unit: None,
                        conversion: None,
                    },
                ],
                response_length: 2,
                is_multiframe: false,
                source: ServiceSource::BuiltIn,
            },
        );
    }

    // TesterPresent with suppressPositiveResponse = 1 (no response expected, but we handle it)
    let key_suppress = (0x3E, Some(0x80));
    if !services.contains_key(&key_suppress) {
        services.insert(
            key_suppress,
            ServiceDefinition {
                name: "TesterPresent_SuppressResponse".to_string(),
                sid: 0x3E,
                sub_function: Some(0x80),
                sub_function_len: 1,
                description: Some("TesterPresent - Suppress positive response".to_string()),
                response_params: vec![], // No response for suppressed
                response_length: 0,
                is_multiframe: false,
                source: ServiceSource::BuiltIn,
            },
        );
    }
}

/// Extract services from ECU shared data
///
/// ECU shared data is accessed via functional_groups -> parent_refs -> EcuSharedData.
/// These services have lowest priority - we don't override services already extracted
/// from variant or base variant.
fn extract_ecu_shared_services(
    database: &DiagnosticDatabase,
    services: &mut HashMap<(u8, Option<u16>), ServiceDefinition>,
) -> usize {
    use cda_database::datatypes::{ParentRef, ParentRefType};

    let mut added_count = 0;

    // Get functional groups from the database
    let functional_groups = match database.functional_groups() {
        Ok(groups) => groups,
        Err(_) => return 0, // No functional groups - not an error, just no ECU shared data
    };

    // Helper to recursively find ECU shared services from parent refs
    // This mirrors the logic in cda-core's find_ecu_shared_services
    fn find_ecu_shared_services_recursive<'a>(
        parent_refs: impl Iterator<Item = impl Into<ParentRef<'a>>>,
    ) -> Vec<DiagService<'a>> {
        let mut services = Vec::new();

        for parent_ref_raw in parent_refs {
            let parent_ref: ParentRef<'a> = parent_ref_raw.into();

            match parent_ref.ref_type().try_into() {
                Ok(ParentRefType::EcuSharedData) => {
                    // Found ECU shared data - extract its services
                    if let Some(ecu_shared) = parent_ref.ref__as_ecu_shared_data() {
                        if let Some(diag_layer) = ecu_shared.diag_layer() {
                            if let Some(diag_svcs) = diag_layer.diag_services() {
                                for svc in diag_svcs {
                                    services.push(DiagService(svc));
                                }
                            }
                        }
                    }
                }
                Ok(ParentRefType::FunctionalGroup) => {
                    // Recurse into nested functional groups
                    if let Some(fg) = parent_ref.ref__as_functional_group() {
                        if let Some(nested_refs) = fg.parent_refs() {
                            services.extend(find_ecu_shared_services_recursive(
                                nested_refs.iter().map(ParentRef),
                            ));
                        }
                    }
                }
                _ => {} // Other types - ignore
            }
        }

        services
    }

    // Find ECU shared services from all functional groups
    for fg in functional_groups {
        if let Some(parent_refs) = fg.parent_refs() {
            let ecu_shared_services =
                find_ecu_shared_services_recursive(parent_refs.iter().map(ParentRef));

            for service in ecu_shared_services {
                if let Ok(mut service_def) = parse_service_definition(&service) {
                    let key = service_def.key();

                    // Only add if not already present (don't override variant/base services)
                    if !services.contains_key(&key) {
                        service_def.source = ServiceSource::EcuShared;
                        tracing::trace!(
                            service = %service_def.name,
                            sid = format!("0x{:02X}", service_def.sid),
                            sub = service_def.sub_function.map(|s| format!("0x{:02X}", s)),
                            "Adding ECU shared service"
                        );
                        services.insert(key, service_def);
                        added_count += 1;
                    }
                }
            }
        }
    }

    added_count
}

/// Parse a single service definition from MDD
fn parse_service_definition(
    service: &DiagService<'_>,
) -> Result<ServiceDefinition, SimulatorError> {
    let diag_comm = service
        .diag_comm()
        .ok_or_else(|| SimulatorError::InvalidService("Missing diag_comm".into()))?;

    let name = diag_comm.short_name().unwrap_or("unknown").to_string();

    // Get SID from request
    let sid = service
        .request_id()
        .ok_or_else(|| SimulatorError::InvalidService(format!("Missing SID for {name}")))?;

    // Get sub-function (DID/LID) if present - can be 1 or 2 bytes
    let (sub_function, sub_function_len) = match service.request_sub_function_id() {
        Some((id, bit_len)) => {
            let byte_len = ((bit_len as u8).saturating_add(7)) / 8;
            (u16::try_from(id).ok(), byte_len.max(1))
        }
        None => (None, 0),
    };

    // Get description from long_name if available
    let description = diag_comm
        .long_name()
        .and_then(|ln| ln.value())
        .map(String::from);

    // Parse positive responses
    let mut response_params = Vec::new();
    let mut max_byte_end: u32 = 0;

    if let Some(pos_responses) = service.pos_responses() {
        for response in pos_responses {
            if let Some(params) = response.params() {
                for param_raw in params {
                    let param = Parameter(param_raw);
                    if let Ok(resp_param) = parse_response_parameter(&param) {
                        // Track maximum byte position for response length
                        let param_end = resp_param.byte_position + resp_param.byte_length();
                        if param_end > max_byte_end {
                            max_byte_end = param_end;
                        }
                        response_params.push(resp_param);
                    }
                }
            }
        }
    }

    // Response length is the total payload size
    let response_length = max_byte_end as usize;

    // Multi-frame is needed if response (including SID + DID echo) exceeds single frame capacity
    // ISO-TP single frame can carry up to 7 bytes total, with 1 byte for length = 6 bytes payload
    let is_multiframe = response_length > 6;

    Ok(ServiceDefinition {
        name,
        sid,
        sub_function,
        sub_function_len,
        description,
        response_params,
        response_length,
        is_multiframe,
        source: ServiceSource::BaseVariant, // Will be overwritten by caller
    })
}

/// Parse a single response parameter from MDD
fn parse_response_parameter(param: &Parameter<'_>) -> Result<ResponseParameter, SimulatorError> {
    let name = param.short_name().unwrap_or("unknown").to_string();
    let byte_position = param.byte_position();
    let bit_position = param.bit_position();

    // Get bit length and conversion from DOP (Data Operation)
    let (bit_length, unit, conversion) = extract_dop_info(param);

    // Generate default value
    let default_value = generate_default_value(param, &name, bit_length);

    Ok(ResponseParameter {
        name,
        byte_position,
        bit_position,
        bit_length,
        default_value,
        unit,
        conversion,
    })
}

/// Extract information from Data Operation (DOP)
fn extract_dop_info(param: &Parameter<'_>) -> (u32, Option<String>, Option<Conversion>) {
    let mut bit_length = 8u32; // Default to 1 byte
    let unit = None; // Unit extraction is complex, skip for now
    let mut conversion = None;

    // Try to get DOP from Value parameter
    if let Some(value) = param.specific_data_as_value() {
        if let Some(dop_ref) = value.dop() {
            let dop = DataOperation(dop_ref);
            if let Ok(variant) = dop.variant() {
                match variant {
                    DataOperationVariant::Normal(normal_dop) => {
                        // Get bit length from DiagCodedType
                        if let Ok(diag_type) = normal_dop.diag_coded_type() {
                            match diag_type.type_() {
                                DiagCodedTypeVariant::StandardLength(slt) => {
                                    bit_length = slt.bit_length;
                                }
                                DiagCodedTypeVariant::MinMaxLength(mmlt) => {
                                    // Use minimum length as default
                                    bit_length = mmlt.min_length().saturating_mul(8);
                                }
                                DiagCodedTypeVariant::LeadingLengthInfo(ll) => {
                                    // Leading length - use the length info bits
                                    bit_length = *ll;
                                }
                                DiagCodedTypeVariant::ParamLengthInfo(_) => {
                                    // Runtime-resolved byte length: not known statically.
                                    // Use a sensible default (1 byte) for the simulator.
                                    bit_length = 8;
                                }
                            }
                        }

                        // Extract conversion from CompuMethod
                        conversion = extract_conversion_from_dop(&normal_dop);
                    }
                    DataOperationVariant::Structure(_) => {
                        // Structure - would need recursive handling
                        bit_length = 8;
                    }
                    _ => {
                        // Other types - use default
                        bit_length = 8;
                    }
                }
            }
        }
    }

    // If we have a reserved parameter, get bit length from there
    if let Some(reserved) = param.0.specific_data_as_reserved() {
        bit_length = reserved.bit_length();
    }

    (bit_length, unit, conversion)
}

/// Extract conversion from NormalDOP's CompuMethod
fn extract_conversion_from_dop(
    normal_dop: &cda_database::datatypes::NormalDop<'_>,
) -> Option<Conversion> {
    // Access the underlying FlatBuffer NormalDOP to get compu_method
    let compu_method_fb = normal_dop.0.compu_method()?;

    // Convert FlatBuffer CompuMethod to datatypes CompuMethod
    let compu_method: DbCompuMethod = compu_method_fb.into();

    match compu_method.category {
        DbCompuCategory::Identical => Some(Conversion::identity()),
        DbCompuCategory::Linear | DbCompuCategory::RatFunc => {
            // Extract from first scale's rational_coefficients
            let scale = compu_method.internal_to_phys.scales.first()?;
            let coeffs = scale.rational_coefficients.as_ref()?;

            // Linear formula from cda-core: physical = (num0 + raw * num1) / denom
            // Where: num0 = offset, num1 = multiplier factor, denom = divisor
            // So: physical = offset/denom + raw * (num1/denom)
            // Our Conversion: physical = raw * multiplier + offset
            let denom = coeffs.denominator.first().copied().unwrap_or(1.0);
            let num0 = coeffs.numerator.first().copied().unwrap_or(0.0); // offset term
            let num1 = coeffs.numerator.get(1).copied().unwrap_or(1.0); // multiplier term

            let multiplier = num1 / denom;
            let offset = num0 / denom;

            Some(Conversion::linear(multiplier, offset))
        }
        DbCompuCategory::ScaleLinear => {
            // ScaleLinear: physical = raw * (num0 / denom0)
            let scale = compu_method.internal_to_phys.scales.first()?;
            let coeffs = scale.rational_coefficients.as_ref()?;

            let num0 = coeffs.numerator.first().copied().unwrap_or(1.0);
            let denom0 = coeffs.denominator.first().copied().unwrap_or(1.0);

            let multiplier = num0 / denom0;
            Some(Conversion::linear(multiplier, 0.0))
        }
        DbCompuCategory::TextTable => {
            // Text table - treat as identity for raw value purposes
            Some(Conversion::identity())
        }
        _ => {
            // Other categories (CompuCode, TabIntp, etc.) - use identity for now
            Some(Conversion::identity())
        }
    }
}

/// Generate a sensible default value for a parameter
fn generate_default_value(param: &Parameter<'_>, _name: &str, bit_length: u32) -> ParameterValue {
    // Check for coded const value
    if let Some(coded_const) = param.specific_data_as_coded_const() {
        if let Some(value_str) = coded_const.coded_value() {
            // Try to parse as hex or decimal
            let value = value_str
                .strip_prefix("0x")
                .or_else(|| value_str.strip_prefix("0X"))
                .map(|s| u64::from_str_radix(s, 16).ok())
                .unwrap_or_else(|| value_str.parse().ok());

            if let Some(v) = value {
                return ParameterValue::UInt(v);
            }
        }
    }

    // Default to 0 for the appropriate size
    let byte_length = (bit_length.saturating_add(7)) / 8;
    if byte_length > 8 {
        // Large values as bytes
        ParameterValue::Bytes(vec![0u8; byte_length as usize])
    } else {
        ParameterValue::UInt(0)
    }
}
