/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! Request handling and response generation.

use std::sync::Arc;

use super::state::SimulatorState;
use crate::{
    error::SimulatorError,
    mdd::{ParameterValue, ServiceDefinition},
};

/// Handles diagnostic requests and generates responses
pub struct RequestHandler {
    state: Arc<SimulatorState>,
}

impl RequestHandler {
    /// Create a new request handler
    pub fn new(state: Arc<SimulatorState>) -> Self {
        Self { state }
    }

    /// Process an incoming UDS request and generate a response
    ///
    /// Returns `Ok(Some(response))` for normal responses, `Ok(None)` when no response
    /// should be sent (e.g., TesterPresent with suppressPositiveResponse).
    pub async fn handle_request(&self, request: &[u8]) -> Result<Option<Vec<u8>>, SimulatorError> {
        // Validate minimum length
        if request.is_empty() {
            return Err(SimulatorError::InvalidRequest("Empty request".into()));
        }

        let sid = request[0];

        // Try to find service with different sub-function lengths:
        // 1. Try 2-byte DID first (if request has enough bytes)
        // 2. Try 1-byte sub-function
        // 3. Try no sub-function
        let service = self.find_service_smart(sid, request)?;

        let sub_function_display = service.sub_function.map(|s| {
            if service.sub_function_len == 2 {
                format!("0x{:04X}", s)
            } else {
                format!("0x{:02X}", s)
            }
        });

        tracing::debug!(
            sid = format!("0x{:02X}", sid),
            sub_function = sub_function_display,
            "Processing request"
        );

        // Check for suppress positive response (bit 7 of sub-function)
        // For TesterPresent (0x3E) with sub-function 0x80, no response is sent
        if service.response_length == 0 {
            tracing::debug!(
                service = %service.name,
                "Suppressing positive response"
            );
            return Ok(None);
        }

        // Generate response based on service definition
        let response = self.generate_response(service).await?;

        Ok(Some(response))
    }

    /// Find a service by SID, trying different sub-function lengths
    ///
    /// This handles both 1-byte LIDs and 2-byte DIDs:
    /// 1. Try 2-byte DID if request has 3+ bytes
    /// 2. Try 1-byte sub-function if request has 2+ bytes
    /// 3. Try no sub-function
    fn find_service_smart(
        &self,
        sid: u8,
        request: &[u8],
    ) -> Result<&ServiceDefinition, SimulatorError> {
        // Try 2-byte DID first (e.g., 0x22 ReadDataByIdentifier)
        if request.len() >= 3 {
            let did = u16::from_be_bytes([request[1], request[2]]);
            if let Some(service) = self.state.get_service(sid, Some(did)) {
                return Ok(service);
            }
        }

        // Try 1-byte sub-function (e.g., 0x21 ReadDataByLocalIdentifier)
        if request.len() >= 2 {
            let sub_func = request[1] as u16;
            if let Some(service) = self.state.get_service(sid, Some(sub_func)) {
                return Ok(service);
            }
        }

        // Try no sub-function
        if let Some(service) = self.state.get_service(sid, None) {
            return Ok(service);
        }

        // No match found - report with 2-byte DID if available for better error messages
        let sub_function = if request.len() >= 3 {
            Some(u16::from_be_bytes([request[1], request[2]]))
        } else if request.len() >= 2 {
            Some(request[1] as u16)
        } else {
            None
        };
        Err(SimulatorError::UnsupportedService(sid, sub_function))
    }

    /// Generate a response for a service
    async fn generate_response(
        &self,
        service: &ServiceDefinition,
    ) -> Result<Vec<u8>, SimulatorError> {
        // Start building response
        // Response SID = request SID + 0x40
        let response_sid = service
            .sid
            .checked_add(0x40)
            .ok_or_else(|| SimulatorError::InvalidService("SID overflow".into()))?;

        // Calculate total response size
        // The response_length from MDD includes everything from byte 0
        // But we need to build: [response_sid, sub_function?, ...data]
        let mut response = Vec::with_capacity(service.response_length.saturating_add(2));

        // Add response SID
        response.push(response_sid);

        // Add sub-function echo if present (1 or 2 bytes based on sub_function_len)
        if let Some(sub_func) = service.sub_function {
            if service.sub_function_len == 2 {
                // 2-byte DID (big-endian)
                response.extend_from_slice(&sub_func.to_be_bytes());
            } else {
                // 1-byte sub-function/LID
                response.push(sub_func as u8);
            }
        }

        // Initialize the rest of the response with zeros
        // The response_length from MDD should cover the total payload
        let data_start = response.len();
        let _data_needed = service.response_length.saturating_sub(data_start);
        response.resize(service.response_length.max(data_start), 0x00);

        // Get current overrides
        let overrides = self.state.overrides.read().await;

        // Fill in parameter values
        for param in &service.response_params {
            // Skip parameters at positions 0 and 1 (SID and DID echo) - they're already set
            if param.byte_position < 2 {
                continue;
            }

            // Get the value to use (override or default)
            let value = if let Some(override_value) =
                overrides.get(&(service.name.clone(), param.name.clone()))
            {
                // Numeric overrides are in physical units; convert through
                // the parameter's compu-method to get the raw value.
                // Raw-bytes overrides (Bytes / String) bypass the conversion:
                // the caller already provided the bit-exact payload, and
                // `as_f64` is meaningless for them.
                match override_value {
                    ParameterValue::Bytes(_) | ParameterValue::String(_) => override_value.clone(),
                    ParameterValue::Float(f) => {
                        if let Some(ref conversion) = param.conversion {
                            let raw = conversion.physical_to_raw(*f);
                            ParameterValue::UInt(raw as u64)
                        } else {
                            ParameterValue::Float(*f)
                        }
                    }
                    ParameterValue::Int(i) => {
                        if let Some(ref conversion) = param.conversion {
                            let raw = conversion.physical_to_raw(*i as f64);
                            ParameterValue::UInt(raw as u64)
                        } else {
                            ParameterValue::Int(*i)
                        }
                    }
                    ParameterValue::UInt(u) => {
                        if let Some(ref conversion) = param.conversion {
                            let raw = conversion.physical_to_raw(*u as f64);
                            ParameterValue::UInt(raw as u64)
                        } else {
                            ParameterValue::UInt(*u)
                        }
                    }
                }
            } else {
                param.default_value.clone()
            };

            // Encode the value into the response at the correct position
            self.encode_parameter(&mut response, param, &value)?;
        }

        tracing::debug!(
            service = %service.name,
            response_len = response.len(),
            response_hex = %hex::encode(&response),
            "Generated response"
        );

        Ok(response)
    }

    /// Encode a parameter value into the response buffer
    fn encode_parameter(
        &self,
        response: &mut [u8],
        param: &crate::mdd::ResponseParameter,
        value: &ParameterValue,
    ) -> Result<(), SimulatorError> {
        let byte_pos = param.byte_position as usize;
        let bit_length = param.bit_length;
        let byte_length = ((bit_length.saturating_add(7)) / 8) as usize;

        // Check bounds
        if byte_pos.saturating_add(byte_length) > response.len() {
            // Silently skip - parameter extends beyond response buffer
            // This can happen with optional/variable-length responses
            return Ok(());
        }

        // Get raw bytes from value
        let raw_bytes = value.to_raw_bytes(bit_length, param.conversion.as_ref());

        // Handle bit-level positioning if needed
        if param.bit_position == 0 && bit_length.is_multiple_of(8) {
            // Byte-aligned, simple copy
            let copy_len = raw_bytes.len().min(byte_length);
            response[byte_pos..byte_pos.saturating_add(copy_len)]
                .copy_from_slice(&raw_bytes[..copy_len]);
        } else {
            // Bit-level positioning needed
            // This is more complex - for now, just do byte-aligned copy
            // TODO: Implement proper bit-level encoding if needed
            let copy_len = raw_bytes.len().min(byte_length);
            response[byte_pos..byte_pos.saturating_add(copy_len)]
                .copy_from_slice(&raw_bytes[..copy_len]);
        }

        Ok(())
    }
}
