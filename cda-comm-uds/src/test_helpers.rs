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

//! Shared test doubles for `cda-comm-uds` tests.

use std::time::Duration;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DoipComParams, EcuAddresses, EcuState, EcuStateManager, HashMap,
    HashMapExtensions, UdsComParams, VariantDetection,
    datatypes::{AddressingMode, RetryPolicy, TesterPresentSendType},
    diagservices::DiagServiceResponse,
};

/// Minimal test double satisfying `UdsEcuDb + VariantDetection`.
pub(crate) struct TestEcuDb {
    service_states: tokio::sync::Mutex<std::collections::HashMap<u8, String>>,
    /// Configurable `CP_P6Max`-backed timeout, so tests can verify that
    /// callers fall back to this comparam-derived value instead of using a
    /// hardcoded literal. Defaults to 5s to match the previous fixed value.
    timeout_default: Duration,
    /// Configurable `CP_RepeatReqCountApp`, so tests can verify the exact
    /// number of application-layer retries performed on timeout/transmission/
    /// receive errors. Defaults to 3 to match the previous fixed value.
    repeat_req_count_app: u32,
}

impl TestEcuDb {
    pub fn new() -> Self {
        Self {
            service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_default: Duration::from_secs(5),
            repeat_req_count_app: 3,
        }
    }

    /// Create a test double with a custom `timeout_default` (`CP_P6Max`).
    pub fn with_timeout_default(timeout_default: Duration) -> Self {
        Self {
            service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_default,
            repeat_req_count_app: 3,
        }
    }

    /// Create a test double with a custom `timeout_default` (`CP_P6Max`) and
    /// `repeat_req_count_app` (`CP_RepeatReqCountApp`).
    pub fn with_timeout_default_and_repeat_req_count_app(
        timeout_default: Duration,
        repeat_req_count_app: u32,
    ) -> Self {
        Self {
            service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_default,
            repeat_req_count_app,
        }
    }
}

impl Default for TestEcuDb {
    fn default() -> Self {
        Self::new()
    }
}

impl EcuAddresses for TestEcuDb {
    fn tester_address(&self) -> u16 {
        0x0E00
    }
    fn logical_address(&self) -> u16 {
        0x0001
    }
    fn logical_gateway_address(&self) -> u16 {
        0x0000
    }
    fn logical_functional_address(&self) -> u16 {
        0xFFFF
    }
    fn ecu_name(&self) -> String {
        "TestECU".to_string()
    }
    fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
        self.logical_address() == other.logical_address()
    }
}

impl DoipComParams for TestEcuDb {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        static EMPTY: std::sync::OnceLock<HashMap<u8, u32>> = std::sync::OnceLock::new();
        EMPTY.get_or_init(HashMap::new)
    }
    fn diagnostic_ack_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }
    fn retry_period(&self) -> Duration {
        Duration::from_millis(100)
    }
    fn routing_activation_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn repeat_request_count_transmission(&self) -> u32 {
        3
    }
    fn connection_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn connection_retry_delay(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn connection_retry_attempts(&self) -> u32 {
        3
    }
}

impl UdsComParams for TestEcuDb {
    fn tester_present_retry_policy(&self) -> bool {
        false
    }
    fn tester_present_addr_mode(self) -> AddressingMode {
        unimplemented!()
    }
    fn tester_present_response_expected(self) -> bool {
        unimplemented!()
    }
    fn tester_present_send_type(self) -> TesterPresentSendType {
        unimplemented!()
    }
    fn tester_present_message(self) -> Vec<u8> {
        unimplemented!()
    }
    fn tester_present_exp_pos_resp(self) -> Vec<u8> {
        unimplemented!()
    }
    fn tester_present_exp_neg_resp(self) -> Vec<u8> {
        unimplemented!()
    }
    fn tester_present_time(&self) -> Duration {
        Duration::from_secs(2)
    }
    fn repeat_req_count_app(&self) -> u32 {
        self.repeat_req_count_app
    }
    fn rc_21_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::ContinueUntilTimeout
    }
    fn rc_21_completion_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn rc_21_repeat_request_time(&self) -> Duration {
        Duration::from_millis(10)
    }
    fn rc_78_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::ContinueUntilTimeout
    }
    fn rc_78_completion_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn rc_78_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn rc_94_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::ContinueUntilTimeout
    }
    fn rc_94_completion_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn rc_94_repeat_request_time(&self) -> Duration {
        Duration::from_millis(10)
    }
    fn timeout_default(&self) -> Duration {
        self.timeout_default
    }
}

impl EcuStateManager for TestEcuDb {
    fn set_service_state(&self, sid: u8, value: String) -> impl Future<Output = ()> + Send {
        let states = &self.service_states;
        async move {
            states.lock().await.insert(sid, value);
        }
    }

    fn get_service_state(&self, sid: u8) -> impl Future<Output = Option<String>> + Send {
        let states = &self.service_states;
        async move { states.lock().await.get(&sid).cloned() }
    }

    fn session(&self) -> impl Future<Output = Result<String, DiagServiceError>> + Send {
        std::future::ready(Ok("default".to_string()))
    }

    fn default_session(&self) -> Result<String, DiagServiceError> {
        Ok("default".to_string())
    }

    fn security_access(&self) -> impl Future<Output = Result<String, DiagServiceError>> + Send {
        std::future::ready(Ok("locked".to_string()))
    }

    async fn lookup_session_change(&self, _session: &str) -> Result<DiagComm, DiagServiceError> {
        unimplemented!()
    }

    fn set_default_states(&self) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Ok(()))
    }
}

#[async_trait]
impl VariantDetection for TestEcuDb {
    fn ecu_status(&self) -> EcuState {
        unimplemented!()
    }

    async fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        _service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        unimplemented!()
    }

    fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm> {
        unimplemented!()
    }

    async fn mark_as_duplicate(&mut self) {
        unimplemented!()
    }

    async fn mark_as_no_variant_detected(&mut self) {
        unimplemented!()
    }
}
