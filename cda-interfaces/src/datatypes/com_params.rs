/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

use crate::{HashMap, datatypes::Unit};

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ComParams {
    pub uds: UdsComParams,
    pub doip: DoipComParams,
}

pub type ComParamName = String;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ComParamConfig<T: Serialize + Debug> {
    pub name: ComParamName,
    pub default: T,
}

pub trait DeserializableCompParam: Sized {
    /// Parse the com parameter from a database string representation
    /// # Errors
    /// Returns `String` if parsing fails, this might happen if the database
    /// does not provide the expected type.
    fn parse_from_db(input: &str, unit: Option<&Unit>) -> Result<Self, String>;
}

/// Custom boolean type for com parameters, to support (de)serialization from different
/// kinds of string representations.
#[derive(Clone, Debug, PartialEq)]
pub enum ComParamBool {
    True,
    False,
}

impl TryFrom<String> for ComParamBool {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "enabled" | "true" | "yes" | "on" | "1" | "active" | "open" | "valid" => {
                Ok(ComParamBool::True)
            }
            "disabled" | "false" | "no" | "off" | "0" | "inactive" | "closed" | "invalid" => {
                Ok(ComParamBool::False)
            }
            _ => Err(format!("Invalid MultiValueBool '{value}'")),
        }
    }
}

impl TryFrom<&str> for ComParamBool {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl<'de> Deserialize<'de> for ComParamBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mvb: Result<ComParamBool, String> = s.try_into();
        match mvb {
            Ok(value) => Ok(value),
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}

impl Serialize for ComParamBool {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            ComParamBool::True => "true",
            ComParamBool::False => "false",
        };
        serializer.serialize_str(s)
    }
}

impl From<bool> for ComParamBool {
    fn from(b: bool) -> Self {
        if b {
            ComParamBool::True
        } else {
            ComParamBool::False
        }
    }
}

impl From<ComParamBool> for bool {
    fn from(mvb: ComParamBool) -> Self {
        match mvb {
            ComParamBool::True => true,
            ComParamBool::False => false,
        }
    }
}

/// Defines the default values for the Communication
/// parameters which are used in the UDS communication
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct UdsComParams {
    // todo use this in #53
    /// Define Tester Present generation
    pub tester_present_retry_policy: ComParamConfig<ComParamBool>,

    // todo use this in #53
    /// Addressing mode for sending Tester Present
    /// Only relevant in case no function messages are sent
    pub tester_present_addr_mode: ComParamConfig<AddressingMode>,

    // todo use this in #53
    /// Define expectation for Tester Present responses
    pub tester_present_response_expected: ComParamConfig<ComParamBool>,

    // todo use this in #53
    /// Define condition for sending tester present
    /// When bus has been idle (Interval defined by `TesterPresentTime`)
    pub tester_present_send_type: ComParamConfig<TesterPresentSendType>,

    // todo use this in #53
    /// Message to be sent for tester present
    pub tester_present_message: ComParamConfig<Vec<u8>>,

    // todo use this in #53
    /// Expected positive response (if required)
    pub tester_present_exp_pos_resp: ComParamConfig<Vec<u8>>,

    // todo use this in #53
    /// Expected negative response (if required)
    /// A tester present error should be reported in the log, tester present s
    /// ending should be continued
    pub tester_present_exp_neg_resp: ComParamConfig<Vec<u8>>,

    /// Timing interval for tester present messages in µs
    pub tester_present_time: ComParamConfig<Duration>,

    /// Repetition of last request in case of timeout, transmission or receive error
    /// Only applies to application layer messages
    pub repeat_req_count_app: ComParamConfig<u32>,

    /// `RetryPolicy` in case of NRC 0x21 (busy repeat request)
    pub rc_21_retry_policy: ComParamConfig<RetryPolicy>,

    /// Time period the tester accepts for repeated NRC 0x21 (busy repeat request) and retries,
    /// while waiting for a positive response in µS
    pub rc_21_completion_timeout: ComParamConfig<Duration>,

    /// Time between a NRC 0x21 (busy repeat request) and the retransmission of the same request
    pub rc_21_repeat_request_time: ComParamConfig<Duration>,

    /// `RetryPolicy` in case of NRC 0x78 (response pending)
    pub rc_78_retry_policy: ComParamConfig<RetryPolicy>,

    /// Time period the tester accepts for repeated NRC 0x78 (response pending),
    /// and waits for a positive response
    pub rc_78_completion_timeout: ComParamConfig<Duration>,

    /// Enhanced timeout after receiving a NRC 0x78 (response pending) to wait for the
    /// complete reception of the response message
    pub rc_78_timeout: ComParamConfig<Duration>,

    /// `RetryPolicy` in case of NRC 0x94 (temporarily not available)
    pub rc_94_retry_policy: ComParamConfig<RetryPolicy>,

    /// Time period the tester accepts for repeated NRC 0x94 (temporarily not available),
    /// and waits for a positive response
    pub rc_94_completion_timeout: ComParamConfig<Duration>,

    /// Time between a NRC 0x94 (temporarily not available)
    /// and the retransmission of the same request
    pub rc_94_repeat_request_time: ComParamConfig<Duration>,

    /// Timeout after sending a successful request, for
    /// the complete reception of the response message
    pub timeout_default: ComParamConfig<Duration>,
}

/// Defines the Communication parameters which are used in the `DoIP` communication
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DoipComParams {
    /// Logical address of a `DoIP` entity.
    /// In case of directly reachable `DoIP` entity it's equal to the
    /// `LogicalEcuAddress`, otherwise data will be sent via this address to the `LogicalEcuAddress`
    pub logical_gateway_address: ComParamConfig<u16>,

    /// Only the ID of this com param is needed right now
    pub logical_response_id_table_name: String,

    /// Logical/Physical address of the ECU
    pub logical_ecu_address: ComParamConfig<u16>,

    /// Functional address of the ECU
    pub logical_functional_address: ComParamConfig<u16>,

    /// Logical address of the tester
    pub logical_tester_address: ComParamConfig<u16>,

    // todo use this in #22
    /// Number of retries for specific NACKs
    /// The key must be a string, because parsing from toml requires keys to be strings,
    /// no other types are supported.
    pub nack_number_of_retries: ComParamConfig<HashMap<String, u32>>,

    // todo use this n #22
    /// Maximum time the tester waits for an ACK or NACK of the `DoIP` entity
    pub diagnostic_ack_timeout: ComParamConfig<Duration>,

    // todo use this n #22
    /// Period between retries, after specific NACK conditions are encountered
    pub retry_period: ComParamConfig<Duration>,

    /// Maximum time allowed for the ECUs routing activation
    pub routing_activation_timeout: ComParamConfig<Duration>,

    /// Number of retries in case a transmission error,
    /// a reception error, or transport layer timeout is encountered
    pub repeat_request_count_transmission: ComParamConfig<u32>,

    /// Timeout after which a connection attempt should've been successful
    pub connection_timeout: ComParamConfig<Duration>,

    /// Delay before attempting to reconnect
    pub connection_retry_delay: ComParamConfig<Duration>,

    /// Attempts to retry connection before giving up
    pub connection_retry_attempts: ComParamConfig<u32>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum RetryPolicy {
    Disabled,
    ContinueUntilTimeout,
    ContinueUnlimited,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum AddressingMode {
    Physical,
    Functional,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum TesterPresentSendType {
    FixedPeriod,
    OnIdle,
}

// make this configurable?
impl TryFrom<String> for RetryPolicy {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let lc = value.to_lowercase();
        if lc.contains("timeout") {
            Ok(RetryPolicy::ContinueUntilTimeout)
        } else if lc.contains("unlimited") {
            Ok(RetryPolicy::ContinueUnlimited)
        } else {
            Err(format!("Invalid RetryPolicy '{value}'"))
        }
    }
}

impl TryFrom<String> for AddressingMode {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let lc = value.to_lowercase();
        if lc.contains("functional") {
            Ok(AddressingMode::Functional)
        } else if lc.contains("physical") {
            Ok(AddressingMode::Physical)
        } else {
            Err(format!("Invalid AddressingMode '{value}'"))
        }
    }
}

impl TryFrom<String> for TesterPresentSendType {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let lc = value.to_lowercase();
        if lc.contains("idle") {
            Ok(TesterPresentSendType::OnIdle)
        } else if lc.contains("fixed") {
            Ok(TesterPresentSendType::FixedPeriod)
        } else {
            Err(format!("Invalid TesterPresentMode '{value}'"))
        }
    }
}

impl Default for UdsComParams {
    fn default() -> Self {
        Self {
            tester_present_retry_policy: ComParamConfig {
                name: "CP_TesterPresentHandling".to_owned(),
                default: true.into(),
            },
            tester_present_addr_mode: ComParamConfig {
                name: "CP_TesterPresentAddrMode".to_owned(),
                default: AddressingMode::Physical,
            },
            tester_present_response_expected: ComParamConfig {
                name: "CP_TesterPresentReqResp".to_owned(),
                default: true.into(),
            },
            tester_present_send_type: ComParamConfig {
                name: "CP_TesterPresentSendType".to_owned(),
                default: TesterPresentSendType::OnIdle,
            },
            tester_present_message: ComParamConfig {
                name: "CP_TesterPresentMessage".to_owned(),
                default: vec![0x3E, 0x00],
            },
            tester_present_exp_pos_resp: ComParamConfig {
                name: "CP_TesterPresentExpPosResp".to_owned(),
                default: vec![0x7E, 0x00],
            },
            tester_present_exp_neg_resp: ComParamConfig {
                name: "CP_TesterPresentExpNegResp".to_owned(),
                default: vec![0x7F, 0x3E],
            },
            tester_present_time: ComParamConfig {
                name: "CP_TesterPresentTime".to_owned(),
                default: Duration::from_secs(2),
            },
            repeat_req_count_app: ComParamConfig {
                name: "CP_RepeatReqCountApp".to_owned(),
                default: 2,
            },
            rc_21_retry_policy: ComParamConfig {
                name: "CP_RC21Handling".to_owned(),
                default: RetryPolicy::ContinueUntilTimeout,
            },
            rc_21_completion_timeout: ComParamConfig {
                name: "CP_RC21CompletionTimeout".to_owned(),
                default: Duration::from_secs(25),
            },
            rc_21_repeat_request_time: ComParamConfig {
                name: "CP_RC21RequestTime".to_owned(),
                default: Duration::from_millis(200),
            },
            rc_78_retry_policy: ComParamConfig {
                name: "CP_RC78Handling".to_owned(),
                default: RetryPolicy::ContinueUntilTimeout,
            },
            rc_78_completion_timeout: ComParamConfig {
                name: "CP_RC78CompletionTimeout".to_owned(),
                default: Duration::from_secs(25),
            },
            rc_78_timeout: ComParamConfig {
                name: "CP_P6Star".to_owned(),
                default: Duration::from_secs(1),
            },
            rc_94_retry_policy: ComParamConfig {
                name: "CP_RC94Handling".to_owned(),
                default: RetryPolicy::ContinueUntilTimeout,
            },
            rc_94_completion_timeout: ComParamConfig {
                name: "CP_RC94CompletionTimeout".to_owned(),
                default: Duration::from_secs(25),
            },
            rc_94_repeat_request_time: ComParamConfig {
                name: "CP_RC94RequestTime".to_owned(),
                default: Duration::from_millis(200),
            },
            timeout_default: ComParamConfig {
                name: "CP_P6Max".to_owned(),
                default: Duration::from_secs(1),
            },
        }
    }
}

impl Default for DoipComParams {
    fn default() -> Self {
        Self {
            logical_gateway_address: ComParamConfig {
                name: "CP_DoIPLogicalGatewayAddress".to_owned(),
                default: 0,
            },
            logical_response_id_table_name: "CP_UniqueRespIdTable".to_owned(),
            logical_ecu_address: ComParamConfig {
                name: "CP_DoIPLogicalEcuAddress".to_owned(),
                default: 0,
            },
            logical_functional_address: ComParamConfig {
                name: "CP_DoIPLogicalFunctionalAddress".to_owned(),
                default: 0,
            },
            logical_tester_address: ComParamConfig {
                name: "CP_DoIPLogicalTesterAddress".to_owned(),
                default: 0,
            },
            nack_number_of_retries: ComParamConfig {
                name: "CP_DoIPNumberOfRetries".to_owned(),
                default: [
                    ("0x03".to_owned(), 3), // Out of memory
                ]
                .into_iter()
                .collect(),
            },
            diagnostic_ack_timeout: ComParamConfig {
                name: "CP_DoIPDiagnosticAckTimeout".to_owned(),
                default: Duration::from_secs(1),
            },
            retry_period: ComParamConfig {
                name: "CP_DoIPRetryPeriod".to_owned(),
                default: Duration::from_millis(200),
            },
            routing_activation_timeout: ComParamConfig {
                name: "CP_DoIPRoutingActivationTimeout".to_owned(),
                default: Duration::from_secs(30),
            },
            repeat_request_count_transmission: ComParamConfig {
                name: "CP_RepeatReqCountTrans".to_owned(),
                default: 3,
            },
            connection_timeout: ComParamConfig {
                name: "CP_DoIPConnectionTimeout".to_owned(),
                default: Duration::from_secs(30),
            },
            connection_retry_delay: ComParamConfig {
                name: "CP_DoIPConnectionRetryDelay".to_owned(),
                default: Duration::from_secs(5),
            },
            connection_retry_attempts: ComParamConfig {
                name: "CP_DoIPConnectionRetryAttempts".to_owned(),
                default: 100,
            },
        }
    }
}

impl DeserializableCompParam for ComParamBool {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        ComParamBool::try_from(input)
    }
}

impl DeserializableCompParam for u32 {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        input.parse::<u32>().map_err(|e| format!("{e:?}"))
    }
}

impl DeserializableCompParam for u16 {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        input.parse::<u16>().map_err(|e| format!("{e:?}"))
    }
}

// type alias does not allow specifying hasher, we set the hasher globally.
#[allow(clippy::implicit_hasher)]
impl<T: DeserializeOwned> DeserializableCompParam for HashMap<String, T> {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        serde_json::from_str(input).map_err(|e| e.to_string())
    }
}

impl DeserializableCompParam for Vec<u8> {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        let r = serde_json::from_str(input).map_err(|e| e.to_string());
        if r.is_ok() {
            return r;
        }

        Ok(hex::decode(input).map_err(|e| format!("{e:?}"))?.clone())
    }
}

impl DeserializableCompParam for AddressingMode {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        AddressingMode::try_from(input.to_owned()).map_err(|e| e.clone())
    }
}

impl DeserializableCompParam for RetryPolicy {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        RetryPolicy::try_from(input.to_owned()).map_err(|e| e.clone())
    }
}

impl DeserializableCompParam for TesterPresentSendType {
    fn parse_from_db(input: &str, _unit: Option<&Unit>) -> Result<Self, String> {
        TesterPresentSendType::try_from(input.to_owned()).map_err(|e| e.clone())
    }
}

impl DeserializableCompParam for Duration {
    fn parse_from_db(input: &str, unit: Option<&Unit>) -> Result<Self, String> {
        let value = input
            .parse::<f64>()
            .map_err(|e| e.clone())
            .map_err(|e| e.to_string())?;
        if value <= 0.0 {
            return Err(format!("Invalid Duration '{value}'"));
        }

        let factor = unit
            .as_ref()
            .and_then(|u| u.factor_to_si_unit)
            .unwrap_or(0.000_001);
        // base unit would be seconds, but internally use microseconds for better precision
        let result = std::panic::catch_unwind(|| {
            // Warning allowed because the truncated value is still large
            // enough to represent durations accurately.
            // Losing the sign is not an issue here,
            // because value is already checked to be positive.
            #[allow(clippy::cast_possible_truncation)]
            #[allow(clippy::cast_sign_loss)]
            Duration::from_micros((value * factor * 1_000_000f64) as u64)
        });

        result.map_err(|_| "Unit conversion from micros failed".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_value_bool() {
        let value = "\"Enabled\"";
        let result: ComParamBool = serde_json::from_str(value).unwrap();
        assert_eq!(result, ComParamBool::True);

        let value = "Disabled";
        let result: ComParamBool = value.try_into().unwrap();
        assert_eq!(result, ComParamBool::False);
    }
}
