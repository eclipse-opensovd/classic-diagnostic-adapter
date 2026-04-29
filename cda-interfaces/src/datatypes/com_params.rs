/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

use crate::{HashMap, datatypes::Unit};

/// Trait for looking up a previously resolved com param value by its fallback name.
///
/// Structs that accumulate resolved parameter values implement this trait so that
/// [`ComParamConfig::resolve_fallback`] and [`AddressComParamConfig::resolve_fallback`]
/// can find the value of a named sibling field.
pub trait FallbackLookup<T> {
    fn lookup(&self, name: &str) -> Option<T>;
}

/// Backward-compatible implementation: look up in a slice of `(&str, T)` pairs.
impl<T: Clone> FallbackLookup<T> for [(&str, T)] {
    fn lookup(&self, name: &str) -> Option<T> {
        self.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }
}

/// Backward-compatible implementation: look up in a `Vec` of `(&str, T)` pairs.
impl<T: Clone> FallbackLookup<T> for Vec<(&str, T)> {
    fn lookup(&self, name: &str) -> Option<T> {
        self.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }
}

/// Configuration for communication protocol settings.
/// Protocol names are used to match against database protocol layer names.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CommunicationConfig {
    /// Protocol name for `DoIP` communication
    pub doip_protocol_name: String,
    /// Protocol name for `DoIP` with DOBT communication
    pub doip_dobt_protocol_name: String,
}

impl Default for CommunicationConfig {
    fn default() -> Self {
        Self {
            doip_protocol_name: "UDS_Ethernet_DoIP".to_owned(),
            doip_dobt_protocol_name: "UDS_Ethernet_DoIP_DOBT".to_owned(),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ComParams {
    pub uds: UdsComParams,
    pub doip: DoipComParams,
}

impl ComParams {
    /// Returns a new `ComParams` with any values from `ecu_config` applied on top of
    /// the global defaults. Fields that are `None` in the ECU config remain unchanged.
    #[must_use]
    pub fn with_ecu_config(&self, ecu_config: &EcuConfig) -> Self {
        Self {
            uds: self.uds.with_overrides(&ecu_config.com_params.uds),
            doip: self.doip.with_overrides(&ecu_config.com_params.doip),
        }
    }
}

/// Per-ECU configuration. Values specified here take precedence over the global defaults.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuConfig {
    /// Per-ECU communication parameter overrides.
    #[serde(default)]
    pub com_params: EcuComParams,
}

/// Per-ECU communication parameter overrides. Only the fields that are `Some`
/// will override the corresponding global defaults.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuComParams {
    #[serde(default)]
    pub uds: EcuUdsComParams,
    #[serde(default)]
    pub doip: EcuDoipComParams,
}

/// Per-ECU overrides for UDS communication parameters.
/// Each field, when `Some`, replaces the `default` value in the corresponding global
/// `ComParamConfig`.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuUdsComParams {
    pub tester_present_retry_policy: Option<ComParamOverride<ComParamBool>>,
    pub tester_present_addr_mode: Option<ComParamOverride<AddressingMode>>,
    pub tester_present_response_expected: Option<ComParamOverride<ComParamBool>>,
    pub tester_present_send_type: Option<ComParamOverride<TesterPresentSendType>>,
    pub tester_present_message: Option<ComParamOverride<Vec<u8>>>,
    pub tester_present_exp_pos_resp: Option<ComParamOverride<Vec<u8>>>,
    pub tester_present_exp_neg_resp: Option<ComParamOverride<Vec<u8>>>,
    pub tester_present_time: Option<ComParamOverride<Duration>>,
    pub repeat_req_count_app: Option<ComParamOverride<u32>>,
    pub rc_21_retry_policy: Option<ComParamOverride<RetryPolicy>>,
    pub rc_21_completion_timeout: Option<ComParamOverride<Duration>>,
    pub rc_21_repeat_request_time: Option<ComParamOverride<Duration>>,
    pub rc_78_retry_policy: Option<ComParamOverride<RetryPolicy>>,
    pub rc_78_completion_timeout: Option<ComParamOverride<Duration>>,
    pub rc_78_timeout: Option<ComParamOverride<Duration>>,
    pub rc_94_retry_policy: Option<ComParamOverride<RetryPolicy>>,
    pub rc_94_completion_timeout: Option<ComParamOverride<Duration>>,
    pub rc_94_repeat_request_time: Option<ComParamOverride<Duration>>,
    pub timeout_default: Option<ComParamOverride<Duration>>,
}

/// Per-ECU overrides for `DoIP` communication parameters.
/// Each field, when `Some`, replaces the `default` value in the corresponding global
/// `ComParamConfig`.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuDoipComParams {
    pub logical_gateway_address: Option<AddressOverride>,
    pub logical_response_id_table_name: Option<String>,
    pub comparam_ignore_protocol_in_lookup: Option<bool>,
    pub logical_ecu_address: Option<AddressOverride>,
    pub logical_functional_address: Option<AddressOverride>,
    pub logical_tester_address: Option<AddressOverride>,
    pub nack_number_of_retries: Option<ComParamOverride<HashMap<String, u32>>>,
    pub diagnostic_ack_timeout: Option<ComParamOverride<Duration>>,
    pub retry_period: Option<ComParamOverride<Duration>>,
    pub routing_activation_timeout: Option<ComParamOverride<Duration>>,
    pub repeat_request_count_transmission: Option<ComParamOverride<u32>>,
    pub connection_timeout: Option<ComParamOverride<Duration>>,
    pub connection_retry_delay: Option<ComParamOverride<Duration>>,
    pub connection_retry_attempts: Option<ComParamOverride<u32>>,
}

pub type ComParamName = String;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct ComParamConfig<T: Serialize + Debug> {
    pub name: ComParamName,
    pub default: T,
    /// If the value is not found in the database, use the resolved value of
    /// another field (of the same type) instead of `default`.
    #[serde(default)]
    pub fallback: Option<String>,
    /// When set, this value is used directly and the database lookup is skipped
    /// entirely.  Useful when the MDD does not contain a matching `ComParamRef`.
    #[serde(default)]
    pub value: Option<T>,
}

impl<T: Serialize + Debug + Clone> ComParamConfig<T> {
    /// Creates a new `ComParamConfig` with the given name and default.
    pub fn new(name: impl Into<String>, default: T) -> Self {
        Self {
            name: name.into(),
            default,
            fallback: None,
            value: None,
        }
    }

    /// Resolves the fallback value: if `fallback` names a previously resolved
    /// sibling field, return that; otherwise return `default`.
    #[must_use]
    pub fn resolve_fallback<L: FallbackLookup<T> + ?Sized>(&self, resolved: &L) -> T {
        self.fallback
            .as_deref()
            .and_then(|key| resolved.lookup(key))
            .unwrap_or_else(|| self.default.clone())
    }
}

/// Configuration for a `DoIP` address comparam with optional fallback reference.
/// When the address cannot be found in the database, the `fallback` field
/// (if set) names another address field whose resolved value should be used
/// instead of `default`.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AddressComParamConfig {
    pub name: ComParamName,
    pub default: u16,
    /// If the address is not found in the database, use the resolved value of
    /// another address field instead of `default`.  Valid values:
    /// `logical_gateway_address`, `logical_ecu_address`,
    /// `logical_functional_address`, `logical_tester_address`.
    #[serde(default)]
    pub fallback: Option<String>,
    /// When set, this value is used directly and the database lookup is skipped
    /// entirely.  Useful when the MDD does not contain a matching `ComParamRef`.
    #[serde(default)]
    pub value: Option<u16>,
}

impl AddressComParamConfig {
    /// Creates a new `AddressComParamConfig` with no fallback reference.
    pub fn new(name: impl Into<String>, default: u16) -> Self {
        Self {
            name: name.into(),
            default,
            fallback: None,
            value: None,
        }
    }

    /// Returns a `ComParamConfig<u16>` view (without fallback) for use with
    /// `find_com_param`.
    #[must_use]
    pub fn as_com_param_config(&self) -> ComParamConfig<u16> {
        ComParamConfig {
            name: self.name.clone(),
            default: self.default,
            fallback: None,
            value: self.value,
        }
    }

    /// Resolves the fallback value: if `fallback` names a previously resolved
    /// address, return that; otherwise return `default`.
    #[must_use]
    pub fn resolve_fallback<L: FallbackLookup<u16> + ?Sized>(&self, resolved: &L) -> u16 {
        self.fallback
            .as_deref()
            .and_then(|key| resolved.lookup(key))
            .unwrap_or(self.default)
    }
}

/// Previously resolved `DoIP` address values, used for fallback resolution
/// in [`AddressComParamConfig::resolve_fallback`].
#[derive(Default, Debug)]
pub struct ResolvedAddresses {
    pub logical_gateway_address: Option<u16>,
    pub logical_ecu_address: Option<u16>,
    pub logical_functional_address: Option<u16>,
}

impl FallbackLookup<u16> for ResolvedAddresses {
    fn lookup(&self, name: &str) -> Option<u16> {
        match name {
            "logical_gateway_address" => self.logical_gateway_address,
            "logical_ecu_address" => self.logical_ecu_address,
            "logical_functional_address" => self.logical_functional_address,
            _ => None,
        }
    }
}

/// Previously resolved `DoIP` communication parameter values, used for
/// fallback resolution in [`ComParamConfig::resolve_fallback`].
#[derive(Default)]
pub struct ResolvedDoipParams {
    pub diagnostic_ack_timeout: Option<Duration>,
    pub retry_period: Option<Duration>,
    pub routing_activation_timeout: Option<Duration>,
    pub connection_timeout: Option<Duration>,
    pub connection_retry_delay: Option<Duration>,
    pub repeat_request_count_transmission: Option<u32>,
    pub connection_retry_attempts: Option<u32>,
}

impl FallbackLookup<Duration> for ResolvedDoipParams {
    fn lookup(&self, name: &str) -> Option<Duration> {
        match name {
            "diagnostic_ack_timeout" => self.diagnostic_ack_timeout,
            "retry_period" => self.retry_period,
            "routing_activation_timeout" => self.routing_activation_timeout,
            "connection_timeout" => self.connection_timeout,
            "connection_retry_delay" => self.connection_retry_delay,
            _ => None,
        }
    }
}

impl FallbackLookup<u32> for ResolvedDoipParams {
    fn lookup(&self, name: &str) -> Option<u32> {
        match name {
            "repeat_request_count_transmission" => self.repeat_request_count_transmission,
            "connection_retry_attempts" => self.connection_retry_attempts,
            _ => None,
        }
    }
}

/// Previously resolved UDS communication parameter values, used for
/// fallback resolution in [`ComParamConfig::resolve_fallback`].
#[derive(Default)]
pub struct ResolvedUdsParams {
    pub tester_present_time: Option<Duration>,
    pub rc_21_completion_timeout: Option<Duration>,
    pub rc_21_repeat_request_time: Option<Duration>,
    pub rc_78_completion_timeout: Option<Duration>,
    pub rc_78_timeout: Option<Duration>,
    pub rc_94_completion_timeout: Option<Duration>,
    pub rc_94_repeat_request_time: Option<Duration>,
    pub timeout_default: Option<Duration>,
    pub repeat_req_count_app: Option<u32>,
    pub tester_present_retry_policy: Option<ComParamBool>,
    pub tester_present_response_expected: Option<ComParamBool>,
    pub rc_21_retry_policy: Option<RetryPolicy>,
    pub rc_78_retry_policy: Option<RetryPolicy>,
    pub rc_94_retry_policy: Option<RetryPolicy>,
    pub tester_present_addr_mode: Option<AddressingMode>,
    pub tester_present_send_type: Option<TesterPresentSendType>,
    pub tester_present_message: Option<Vec<u8>>,
    pub tester_present_exp_pos_resp: Option<Vec<u8>>,
    pub tester_present_exp_neg_resp: Option<Vec<u8>>,
}

impl FallbackLookup<Duration> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<Duration> {
        match name {
            "tester_present_time" => self.tester_present_time,
            "rc_21_completion_timeout" => self.rc_21_completion_timeout,
            "rc_21_repeat_request_time" => self.rc_21_repeat_request_time,
            "rc_78_completion_timeout" => self.rc_78_completion_timeout,
            "rc_78_timeout" => self.rc_78_timeout,
            "rc_94_completion_timeout" => self.rc_94_completion_timeout,
            "rc_94_repeat_request_time" => self.rc_94_repeat_request_time,
            "timeout_default" => self.timeout_default,
            _ => None,
        }
    }
}

impl FallbackLookup<u32> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<u32> {
        match name {
            "repeat_req_count_app" => self.repeat_req_count_app,
            _ => None,
        }
    }
}

impl FallbackLookup<ComParamBool> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<ComParamBool> {
        match name {
            "tester_present_retry_policy" => self.tester_present_retry_policy.clone(),
            "tester_present_response_expected" => self.tester_present_response_expected.clone(),
            _ => None,
        }
    }
}

impl FallbackLookup<RetryPolicy> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<RetryPolicy> {
        match name {
            "rc_21_retry_policy" => self.rc_21_retry_policy.clone(),
            "rc_78_retry_policy" => self.rc_78_retry_policy.clone(),
            "rc_94_retry_policy" => self.rc_94_retry_policy.clone(),
            _ => None,
        }
    }
}

impl FallbackLookup<AddressingMode> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<AddressingMode> {
        match name {
            "tester_present_addr_mode" => self.tester_present_addr_mode.clone(),
            _ => None,
        }
    }
}

impl FallbackLookup<TesterPresentSendType> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<TesterPresentSendType> {
        match name {
            "tester_present_send_type" => self.tester_present_send_type.clone(),
            _ => None,
        }
    }
}

impl FallbackLookup<Vec<u8>> for ResolvedUdsParams {
    fn lookup(&self, name: &str) -> Option<Vec<u8>> {
        match name {
            "tester_present_message" => self.tester_present_message.clone(),
            "tester_present_exp_pos_resp" => self.tester_present_exp_pos_resp.clone(),
            "tester_present_exp_neg_resp" => self.tester_present_exp_neg_resp.clone(),
            _ => None,
        }
    }
}

/// Per-ECU override for an address field.
///
/// In TOML this is either a plain integer (`logical_tester_address = 42`) or a
/// table with optional `default` and/or `fallback`:
///
/// ```toml
/// logical_functional_address = { fallback = "logical_gateway_address" }
/// logical_ecu_address = { default = 100, fallback = "logical_gateway_address" }
/// ```
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum AddressOverride {
    /// A literal address value.
    Value(u16),
    /// A structured override with optional default, fallback, and/or value.
    Config {
        #[serde(default)]
        default: Option<u16>,
        #[serde(default)]
        fallback: Option<String>,
        /// When set, this value is used directly and the database lookup is
        /// skipped entirely.
        #[serde(default)]
        value: Option<u16>,
    },
}

/// Per-ECU override for a communication parameter field.
///
/// In TOML this is either a plain value (`timeout_default = { secs = 5, nanos = 0 }`)
/// or a table with optional `default` and/or `fallback`:
///
/// ```toml
/// [ecu.MyEcu.com_params.uds.timeout_default]
/// default = { secs = 5, nanos = 0 }
/// fallback = "rc_78_timeout"
/// ```
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
pub enum ComParamOverride<T> {
    /// A literal value.
    Value(T),
    /// A structured override with optional default, fallback, and/or value.
    Config {
        default: Option<T>,
        fallback: Option<String>,
        /// When set, this value is used directly and the database lookup is
        /// skipped entirely.
        value: Option<T>,
    },
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
    pub logical_gateway_address: AddressComParamConfig,

    /// Only the ID of this com param is needed right now
    pub logical_response_id_table_name: String,

    /// When `true`, com param lookups that fail under the configured protocol
    /// are retried without a protocol filter.  This is useful for com params
    /// (e.g. `CP_UniqueRespIdTable`) that exist in the database without a
    /// protocol reference.  Defaults to `false`.
    #[serde(default)]
    pub comparam_ignore_protocol_in_lookup: bool,

    /// Logical/Physical address of the ECU
    pub logical_ecu_address: AddressComParamConfig,

    /// Functional address of the ECU
    pub logical_functional_address: AddressComParamConfig,

    /// Logical address of the tester
    pub logical_tester_address: AddressComParamConfig,

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
            tester_present_retry_policy: ComParamConfig::new(
                "CP_TesterPresentHandling",
                true.into(),
            ),
            tester_present_addr_mode: ComParamConfig::new(
                "CP_TesterPresentAddrMode",
                AddressingMode::Physical,
            ),
            tester_present_response_expected: ComParamConfig::new(
                "CP_TesterPresentReqResp",
                true.into(),
            ),
            tester_present_send_type: ComParamConfig::new(
                "CP_TesterPresentSendType",
                TesterPresentSendType::OnIdle,
            ),
            tester_present_message: ComParamConfig::new(
                "CP_TesterPresentMessage",
                vec![0x3E, 0x00],
            ),
            tester_present_exp_pos_resp: ComParamConfig::new(
                "CP_TesterPresentExpPosResp",
                vec![0x7E, 0x00],
            ),
            tester_present_exp_neg_resp: ComParamConfig::new(
                "CP_TesterPresentExpNegResp",
                vec![0x7F, 0x3E],
            ),
            tester_present_time: ComParamConfig::new(
                "CP_TesterPresentTime",
                Duration::from_secs(2),
            ),
            repeat_req_count_app: ComParamConfig::new("CP_RepeatReqCountApp", 2),
            rc_21_retry_policy: ComParamConfig::new(
                "CP_RC21Handling",
                RetryPolicy::ContinueUntilTimeout,
            ),
            rc_21_completion_timeout: ComParamConfig::new(
                "CP_RC21CompletionTimeout",
                Duration::from_secs(25),
            ),
            rc_21_repeat_request_time: ComParamConfig::new(
                "CP_RC21RequestTime",
                Duration::from_millis(200),
            ),
            rc_78_retry_policy: ComParamConfig::new(
                "CP_RC78Handling",
                RetryPolicy::ContinueUntilTimeout,
            ),
            rc_78_completion_timeout: ComParamConfig::new(
                "CP_RC78CompletionTimeout",
                Duration::from_secs(25),
            ),
            rc_78_timeout: ComParamConfig::new("CP_P6Star", Duration::from_secs(1)),
            rc_94_retry_policy: ComParamConfig::new(
                "CP_RC94Handling",
                RetryPolicy::ContinueUntilTimeout,
            ),
            rc_94_completion_timeout: ComParamConfig::new(
                "CP_RC94CompletionTimeout",
                Duration::from_secs(25),
            ),
            rc_94_repeat_request_time: ComParamConfig::new(
                "CP_RC94RequestTime",
                Duration::from_millis(200),
            ),
            timeout_default: ComParamConfig::new("CP_P6Max", Duration::from_secs(1)),
        }
    }
}

impl Default for DoipComParams {
    fn default() -> Self {
        Self {
            logical_gateway_address: AddressComParamConfig::new("CP_DoIPLogicalGatewayAddress", 0),
            logical_response_id_table_name: "CP_UniqueRespIdTable".to_owned(),
            comparam_ignore_protocol_in_lookup: false,
            logical_ecu_address: AddressComParamConfig::new("CP_DoIPLogicalEcuAddress", 0),
            logical_functional_address: AddressComParamConfig::new(
                "CP_DoIPLogicalFunctionalAddress",
                0,
            ),
            logical_tester_address: AddressComParamConfig::new("CP_DoIPLogicalTesterAddress", 0),
            nack_number_of_retries: ComParamConfig::new(
                "CP_DoIPNumberOfRetries",
                [
                    ("0x03".to_owned(), 3), // Out of memory
                ]
                .into_iter()
                .collect(),
            ),
            diagnostic_ack_timeout: ComParamConfig::new(
                "CP_DoIPDiagnosticAckTimeout",
                Duration::from_secs(1),
            ),
            retry_period: ComParamConfig::new("CP_DoIPRetryPeriod", Duration::from_millis(200)),
            routing_activation_timeout: ComParamConfig::new(
                "CP_DoIPRoutingActivationTimeout",
                Duration::from_secs(30),
            ),
            repeat_request_count_transmission: ComParamConfig::new("CP_RepeatReqCountTrans", 3),
            connection_timeout: ComParamConfig::new(
                "CP_DoIPConnectionTimeout",
                Duration::from_secs(30),
            ),
            connection_retry_delay: ComParamConfig::new(
                "CP_DoIPConnectionRetryDelay",
                Duration::from_secs(5),
            ),
            connection_retry_attempts: ComParamConfig::new("CP_DoIPConnectionRetryAttempts", 100),
        }
    }
}

/// Helper: apply a `ComParamOverride<T>` to a `ComParamConfig<T>`.
fn apply_override<T: Serialize + Debug + Clone>(
    base: &ComParamConfig<T>,
    override_val: Option<&ComParamOverride<T>>,
) -> ComParamConfig<T> {
    match override_val {
        None => base.clone(),
        Some(ComParamOverride::Value(v)) => ComParamConfig {
            name: base.name.clone(),
            default: v.clone(),
            fallback: base.fallback.clone(),
            value: base.value.clone(),
        },
        Some(ComParamOverride::Config {
            default,
            fallback,
            value,
        }) => ComParamConfig {
            name: base.name.clone(),
            default: default.clone().unwrap_or_else(|| base.default.clone()),
            fallback: fallback.clone().or_else(|| base.fallback.clone()),
            value: value.clone().or_else(|| base.value.clone()),
        },
    }
}

/// Helper: apply an `AddressOverride` to an `AddressComParamConfig`.
fn apply_address_override(
    base: &AddressComParamConfig,
    override_val: Option<&AddressOverride>,
) -> AddressComParamConfig {
    match override_val {
        None => base.clone(),
        Some(AddressOverride::Value(v)) => AddressComParamConfig {
            name: base.name.clone(),
            default: *v,
            fallback: base.fallback.clone(),
            value: base.value,
        },
        Some(AddressOverride::Config {
            default,
            fallback,
            value,
        }) => AddressComParamConfig {
            name: base.name.clone(),
            default: default.unwrap_or(base.default),
            fallback: fallback.clone().or_else(|| base.fallback.clone()),
            value: value.or(base.value),
        },
    }
}

impl UdsComParams {
    /// Returns a copy with any `Some` fields from the ECU config applied.
    #[must_use]
    pub fn with_overrides(&self, o: &EcuUdsComParams) -> Self {
        Self {
            tester_present_retry_policy: apply_override(
                &self.tester_present_retry_policy,
                o.tester_present_retry_policy.as_ref(),
            ),
            tester_present_addr_mode: apply_override(
                &self.tester_present_addr_mode,
                o.tester_present_addr_mode.as_ref(),
            ),
            tester_present_response_expected: apply_override(
                &self.tester_present_response_expected,
                o.tester_present_response_expected.as_ref(),
            ),
            tester_present_send_type: apply_override(
                &self.tester_present_send_type,
                o.tester_present_send_type.as_ref(),
            ),
            tester_present_message: apply_override(
                &self.tester_present_message,
                o.tester_present_message.as_ref(),
            ),
            tester_present_exp_pos_resp: apply_override(
                &self.tester_present_exp_pos_resp,
                o.tester_present_exp_pos_resp.as_ref(),
            ),
            tester_present_exp_neg_resp: apply_override(
                &self.tester_present_exp_neg_resp,
                o.tester_present_exp_neg_resp.as_ref(),
            ),
            tester_present_time: apply_override(
                &self.tester_present_time,
                o.tester_present_time.as_ref(),
            ),
            repeat_req_count_app: apply_override(
                &self.repeat_req_count_app,
                o.repeat_req_count_app.as_ref(),
            ),
            rc_21_retry_policy: apply_override(
                &self.rc_21_retry_policy,
                o.rc_21_retry_policy.as_ref(),
            ),
            rc_21_completion_timeout: apply_override(
                &self.rc_21_completion_timeout,
                o.rc_21_completion_timeout.as_ref(),
            ),
            rc_21_repeat_request_time: apply_override(
                &self.rc_21_repeat_request_time,
                o.rc_21_repeat_request_time.as_ref(),
            ),
            rc_78_retry_policy: apply_override(
                &self.rc_78_retry_policy,
                o.rc_78_retry_policy.as_ref(),
            ),
            rc_78_completion_timeout: apply_override(
                &self.rc_78_completion_timeout,
                o.rc_78_completion_timeout.as_ref(),
            ),
            rc_78_timeout: apply_override(&self.rc_78_timeout, o.rc_78_timeout.as_ref()),
            rc_94_retry_policy: apply_override(
                &self.rc_94_retry_policy,
                o.rc_94_retry_policy.as_ref(),
            ),
            rc_94_completion_timeout: apply_override(
                &self.rc_94_completion_timeout,
                o.rc_94_completion_timeout.as_ref(),
            ),
            rc_94_repeat_request_time: apply_override(
                &self.rc_94_repeat_request_time,
                o.rc_94_repeat_request_time.as_ref(),
            ),
            timeout_default: apply_override(&self.timeout_default, o.timeout_default.as_ref()),
        }
    }
}

impl DoipComParams {
    /// Returns a copy with any `Some` fields from the ECU config applied.
    #[must_use]
    pub fn with_overrides(&self, o: &EcuDoipComParams) -> Self {
        Self {
            logical_gateway_address: apply_address_override(
                &self.logical_gateway_address,
                o.logical_gateway_address.as_ref(),
            ),
            logical_response_id_table_name: o
                .logical_response_id_table_name
                .clone()
                .unwrap_or_else(|| self.logical_response_id_table_name.clone()),
            comparam_ignore_protocol_in_lookup: o
                .comparam_ignore_protocol_in_lookup
                .unwrap_or(self.comparam_ignore_protocol_in_lookup),
            logical_ecu_address: apply_address_override(
                &self.logical_ecu_address,
                o.logical_ecu_address.as_ref(),
            ),
            logical_functional_address: apply_address_override(
                &self.logical_functional_address,
                o.logical_functional_address.as_ref(),
            ),
            logical_tester_address: apply_address_override(
                &self.logical_tester_address,
                o.logical_tester_address.as_ref(),
            ),
            nack_number_of_retries: apply_override(
                &self.nack_number_of_retries,
                o.nack_number_of_retries.as_ref(),
            ),
            diagnostic_ack_timeout: apply_override(
                &self.diagnostic_ack_timeout,
                o.diagnostic_ack_timeout.as_ref(),
            ),
            retry_period: apply_override(&self.retry_period, o.retry_period.as_ref()),
            routing_activation_timeout: apply_override(
                &self.routing_activation_timeout,
                o.routing_activation_timeout.as_ref(),
            ),
            repeat_request_count_transmission: apply_override(
                &self.repeat_request_count_transmission,
                o.repeat_request_count_transmission.as_ref(),
            ),
            connection_timeout: apply_override(
                &self.connection_timeout,
                o.connection_timeout.as_ref(),
            ),
            connection_retry_delay: apply_override(
                &self.connection_retry_delay,
                o.connection_retry_delay.as_ref(),
            ),
            connection_retry_attempts: apply_override(
                &self.connection_retry_attempts,
                o.connection_retry_attempts.as_ref(),
            ),
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

    #[test]
    fn address_fallback_resolves_to_named_address() {
        let config = AddressComParamConfig {
            name: "CP_DoIPLogicalFunctionalAddress".into(),
            default: 0,
            fallback: Some("logical_gateway_address".into()),
            value: None,
        };
        let resolved = vec![("logical_gateway_address", 0x3000u16)];
        assert_eq!(config.resolve_fallback(&resolved), 0x3000);
    }

    #[test]
    fn address_fallback_returns_default_when_no_match() {
        let config = AddressComParamConfig {
            name: "CP_DoIPLogicalFunctionalAddress".into(),
            default: 42,
            fallback: Some("nonexistent_address".into()),
            value: None,
        };
        assert_eq!(config.resolve_fallback(&ResolvedAddresses::default()), 42);
    }

    #[test]
    fn address_fallback_returns_default_when_none() {
        let config = AddressComParamConfig::new("CP_DoIPLogicalTesterAddress", 0xFD00);
        assert_eq!(
            config.resolve_fallback(&ResolvedAddresses::default()),
            0xFD00
        );
    }

    #[test]
    fn ecu_override_replaces_tester_address_with_literal() {
        let global = DoipComParams::default();
        let ecu_overrides = EcuDoipComParams {
            logical_tester_address: Some(AddressOverride::Value(88)),
            ..Default::default()
        };
        let merged = global.with_overrides(&ecu_overrides);
        assert_eq!(merged.logical_tester_address.default, 88);
    }

    #[test]
    fn ecu_override_preserves_global_when_none() {
        let global = DoipComParams {
            logical_tester_address: AddressComParamConfig::new(
                "CP_DoIPLogicalTesterAddress",
                0xFD00,
            ),
            ..Default::default()
        };
        let ecu_overrides = EcuDoipComParams::default(); // all None
        let merged = global.with_overrides(&ecu_overrides);
        assert_eq!(merged.logical_tester_address.default, 0xFD00);
    }

    #[test]
    fn ecu_override_structured_sets_default_and_fallback() {
        let global = DoipComParams::default();
        let ecu_overrides = EcuDoipComParams {
            logical_functional_address: Some(AddressOverride::Config {
                default: Some(0x1234),
                fallback: Some("logical_gateway_address".into()),
                value: None,
            }),
            ..Default::default()
        };
        let merged = global.with_overrides(&ecu_overrides);
        assert_eq!(merged.logical_functional_address.default, 0x1234);
        assert_eq!(
            merged.logical_functional_address.fallback.as_deref(),
            Some("logical_gateway_address")
        );
    }

    #[test]
    fn ecu_override_uds_timeout() {
        let global = UdsComParams::default();
        let ecu_overrides = EcuUdsComParams {
            timeout_default: Some(ComParamOverride::Value(Duration::from_secs(5))),
            ..Default::default()
        };
        let merged = global.with_overrides(&ecu_overrides);
        assert_eq!(merged.timeout_default.default, Duration::from_secs(5));
        // other fields unchanged
        assert_eq!(
            merged.tester_present_time.default,
            global.tester_present_time.default
        );
    }

    /// Simulates the DMCL3000 scenario: database has no tester or functional address,
    /// global config provides a tester default, functional falls back to gateway,
    /// and the ECU overrides the tester address.
    #[test]
    fn delorean_scenario_full_override_chain() {
        let global = ComParams {
            doip: DoipComParams {
                logical_tester_address: AddressComParamConfig::new(
                    "CP_DoIPLogicalTesterAddress",
                    0xFD00,
                ),
                logical_functional_address: AddressComParamConfig {
                    name: "CP_DoIPLogicalFunctionalAddress".into(),
                    default: 0,
                    fallback: Some("logical_gateway_address".into()),
                    value: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        // ECU override: DMCL3000 sets tester address to 88
        let ecu_config = EcuConfig {
            com_params: EcuComParams {
                doip: EcuDoipComParams {
                    logical_tester_address: Some(AddressOverride::Value(88)),
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let resolved = global.with_ecu_config(&ecu_config);

        // (1) Functional address still has fallback to gateway
        assert_eq!(
            resolved.doip.logical_functional_address.fallback.as_deref(),
            Some("logical_gateway_address")
        );
        // Simulate database miss: functional resolves to gateway value
        let resolved_addrs = vec![("logical_gateway_address", 0x3000u16)];
        assert_eq!(
            resolved
                .doip
                .logical_functional_address
                .resolve_fallback(&resolved_addrs),
            0x3000
        );

        // (2) Global default was 0xFD00, but (3) ECU override replaced it with 88
        assert_eq!(resolved.doip.logical_tester_address.default, 88);
    }
}
