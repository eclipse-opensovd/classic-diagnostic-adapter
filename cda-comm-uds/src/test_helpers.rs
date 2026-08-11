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
    ComponentInfos, Connectivity, DiagComm, DiagCommLookup, DiagCommType, DiagServiceError,
    DoipComParams, Dtc, DynamicPlugin, EcuAddresses, EcuRuntimeState, EcuSchemas, EcuSecurity,
    EcuState, EcuStateManager, HashMap, HashMapExtensions, HashSet, MuxCaseInfo, PayloadDecoder,
    PayloadEncoder, Protocol, ResponseParameterInfo, SchemaDescription, SecurityAccess,
    ServiceParameterMetadata, ServicePayload, UDS_ID_RESPONSE_BITMASK, UdsComParams,
    VariantDetection, VariantState,
    datatypes::{
        AddressingMode, ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
        ComponentOperationsInfo, DtcLookup, DtcReadInformationFunction, RetryPolicy,
        RoutineSubfunctions, SdSdg, TesterPresentSendType, single_ecu,
    },
    diagservices::{
        DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType, MappedNRC,
        UdsPayloadData,
    },
    service_ids,
};

/// Decoded response produced by [`TestEcuDb`]'s [`PayloadDecoder`].
///
/// Classifies itself as negative purely from the raw bytes, so tests drive the
/// positive/negative distinction by choosing what their gateway replies.
#[derive(Clone, Debug)]
pub(crate) struct TestResponse {
    service: DiagComm,
    data: Vec<u8>,
}

impl DiagServiceResponse for TestResponse {
    fn empty_positive(service: DiagComm) -> Self {
        Self {
            service,
            data: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn service_name(&self) -> String {
        self.service.name.clone()
    }

    fn response_type(&self) -> DiagServiceResponseType {
        if self.data.first() == Some(&service_ids::NEGATIVE_RESPONSE) {
            DiagServiceResponseType::Negative
        } else {
            DiagServiceResponseType::Positive
        }
    }

    fn get_raw(&self) -> &[u8] {
        &self.data
    }

    fn into_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError> {
        unimplemented!()
    }

    fn as_nrc(&self) -> Result<MappedNRC, DiagServiceError> {
        unimplemented!()
    }

    fn get_dtcs(
        &self,
    ) -> Result<
        Vec<(
            cda_interfaces::datatypes::DtcField,
            cda_interfaces::datatypes::DtcRecord,
        )>,
        DiagServiceError,
    > {
        unimplemented!()
    }
}

/// Minimal test double satisfying `UdsEcuDb + VariantDetection`.
pub(crate) struct TestEcuDb {
    service_states: tokio::sync::Mutex<std::collections::HashMap<u8, String>>,
    /// Configurable `CP_P6Max`-backed timeout, so tests can verify that
    /// callers fall back to this comparam-derived value instead of using a
    /// hardcoded literal. Defaults to 5s to match the previous fixed value.
    timeout_default: Duration,
    /// Configurable `CP_RepeatReqCountApp`, so tests can verify the exact
    /// number of application-layer retries performed on timeout/transmission/
    /// receive errors. Defaults to 2 to match the `CP_RepeatReqCountApp`
    /// comparam default.
    repeat_req_count_app: u32,
}

impl TestEcuDb {
    pub fn new() -> Self {
        Self {
            service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_default: Duration::from_secs(5),
            repeat_req_count_app: 2,
        }
    }

    /// Create a test double with a custom `timeout_default` (`CP_P6Max`).
    pub fn with_timeout_default(timeout_default: Duration) -> Self {
        Self {
            service_states: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            timeout_default,
            repeat_req_count_app: 2,
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

    fn lookup_session_change(
        &self,
        session: &str,
    ) -> impl Future<Output = Result<DiagComm, DiagServiceError>> {
        std::future::ready(Ok(DiagComm {
            name: session.to_owned(),
            type_: DiagCommType::Modes,
            lookup_name: Some(session.to_owned()),
            subfunction_id: Some(SESSION_SUBFUNCTION),
        }))
    }

    fn set_default_states(&self) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Ok(()))
    }
}

#[async_trait]
impl VariantDetection for TestEcuDb {
    fn ecu_status(&self) -> EcuState {
        // Online with a detected variant, so senders skip the pre-send variant
        // detection guard (see `transport::needs_variant_detection`).
        EcuState {
            connectivity: Connectivity::Online,
            variant_state: VariantState::Detected {
                name: "TestVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            },
            variant_index: Some(0),
        }
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

/// Subfunction byte used for every session change encoded by [`TestEcuDb`].
const SESSION_SUBFUNCTION: u8 = 0x02;

impl PayloadEncoder for TestEcuDb {
    async fn check_genericservice(
        &self,
        _security_plugin: &DynamicPlugin,
        _rawdata: Vec<u8>,
    ) -> Result<ServicePayload, DiagServiceError> {
        unimplemented!()
    }

    fn create_uds_payload(
        &self,
        diag_service: &DiagComm,
        _security_plugin: &DynamicPlugin,
        _data: Option<UdsPayloadData>,
        _functional_group_name: Option<&str>,
    ) -> impl Future<Output = Result<ServicePayload, DiagServiceError>> + Send {
        // This double has no database to encode against, so it only knows how
        // to build session-control frames. Fail loudly rather than silently
        // mis-encoding some other service as `10 xx`.
        assert!(
            matches!(diag_service.type_, DiagCommType::Modes),
            "TestEcuDb only encodes session-control requests, got {diag_service:?}; extend it if \
             you need another service"
        );
        std::future::ready(Ok(ServicePayload {
            data: vec![
                service_ids::SESSION_CONTROL,
                diag_service.subfunction_id.unwrap_or(SESSION_SUBFUNCTION),
            ],
            source_address: self.tester_address(),
            target_address: self.logical_address(),
            // Left unset on purpose: the real encoder only fills this in when
            // the state chart has a transition whose *source* is the currently
            // active state, which is exactly what fails when the ECU is not in
            // its default session. Callers must not depend on the transport
            // layer's `new_session` fallback to track the session.
            new_session: None,
            new_security: None,
        }))
    }
}

impl PayloadDecoder for TestEcuDb {
    type Response = TestResponse;

    fn convert_from_uds(
        &self,
        diag_service: &DiagComm,
        payload: &ServicePayload,
        _map_to_json: bool,
        _functional_group_name: Option<&str>,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send {
        std::future::ready(Ok(TestResponse {
            service: diag_service.clone(),
            data: payload.data.clone(),
        }))
    }

    async fn convert_request_from_uds(
        &self,
        _diag_service: &DiagComm,
        _payload: &ServicePayload,
        _map_to_json: bool,
    ) -> Result<Self::Response, DiagServiceError> {
        unimplemented!()
    }

    fn convert_service_14_response(
        _diag_comm: DiagComm,
        _response: ServicePayload,
    ) -> Result<Self::Response, DiagServiceError> {
        unimplemented!()
    }
}

impl EcuSecurity for TestEcuDb {
    async fn lookup_security_access_change(
        &self,
        _level: &str,
        _has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        unimplemented!()
    }

    async fn get_send_key_param_name(
        &self,
        _diag_service: &DiagComm,
    ) -> Result<String, DiagServiceError> {
        unimplemented!()
    }

    fn default_security_access(&self) -> Result<String, DiagServiceError> {
        Ok("locked".to_owned())
    }

    fn is_service_allowed(
        &self,
        _service: &DiagComm,
        _security_plugin: &DynamicPlugin,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Ok(()))
    }
}

impl ComponentInfos for TestEcuDb {
    fn get_components_data_info(&self, _security_plugin: &DynamicPlugin) -> Vec<ComponentDataInfo> {
        unimplemented!()
    }

    fn get_functional_group_data_info(
        &self,
        _security_plugin: &DynamicPlugin,
        _functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        unimplemented!()
    }

    fn get_components_configurations_info(
        &self,
        _security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        unimplemented!()
    }

    fn get_components_operations_info(
        &self,
        _security_plugin: &DynamicPlugin,
    ) -> Vec<ComponentOperationsInfo> {
        unimplemented!()
    }

    fn get_routine_subfunctions(
        &self,
        _service_name: &str,
        _security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        unimplemented!()
    }

    fn get_functional_group_operations_info(
        &self,
        _security_plugin: &DynamicPlugin,
        _functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        unimplemented!()
    }

    fn get_functional_group_routine_subfunctions(
        &self,
        _security_plugin: &DynamicPlugin,
        _functional_group_name: &str,
        _service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        unimplemented!()
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        unimplemented!()
    }

    fn get_request_parameter_metadata(
        &self,
        _service_name: &str,
    ) -> Result<Vec<ServiceParameterMetadata>, DiagServiceError> {
        unimplemented!()
    }

    fn get_response_parameter_metadata(
        &self,
        _service_name: &str,
    ) -> Result<Vec<ResponseParameterInfo>, DiagServiceError> {
        unimplemented!()
    }

    fn get_mux_cases_for_service(
        &self,
        _service_name: &str,
    ) -> Result<Vec<MuxCaseInfo>, DiagServiceError> {
        unimplemented!()
    }

    fn functional_groups(&self) -> Vec<String> {
        unimplemented!()
    }
}

impl Dtc for TestEcuDb {
    fn lookup_dtc_services(
        &self,
        _service_types: &[DtcReadInformationFunction],
    ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError> {
        unimplemented!()
    }
}

impl DiagCommLookup for TestEcuDb {
    fn lookup_single_ecu_job(&self, _job_name: &str) -> Result<single_ecu::Job, DiagServiceError> {
        unimplemented!()
    }

    fn lookup_service_through_func_class(
        &self,
        _func_class_name: &str,
        _service_id: u8,
    ) -> Result<DiagComm, DiagServiceError> {
        unimplemented!()
    }

    fn lookup_diagcomms_by_request_prefix(
        &self,
        _service_bytes: &[u8],
    ) -> Result<Vec<DiagComm>, DiagServiceError> {
        unimplemented!()
    }

    fn lookup_service_by_sid_and_name(
        &self,
        _service_id: u8,
        _name: &str,
        _functional_group_name: Option<&str>,
    ) -> Result<DiagComm, DiagServiceError> {
        unimplemented!()
    }
}

impl EcuSchemas for TestEcuDb {
    async fn schema_for_request(
        &self,
        _service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        unimplemented!()
    }

    async fn schema_for_responses(
        &self,
        _service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        unimplemented!()
    }

    async fn schema_for_fg_request(
        &self,
        _service: &DiagComm,
        _functional_group_name: &str,
    ) -> Result<SchemaDescription, DiagServiceError> {
        unimplemented!()
    }
}

impl cda_interfaces::EcuManager for TestEcuDb {
    type Response = TestResponse;

    fn is_physical_ecu(&self) -> bool {
        true
    }

    fn protocol(&self) -> &Protocol {
        unimplemented!()
    }

    fn is_loaded(&self) -> bool {
        true
    }

    fn load(&mut self) -> Result<(), DiagServiceError> {
        Ok(())
    }

    fn comparams(&self) -> Result<ComplexComParamValue, DiagServiceError> {
        unimplemented!()
    }

    async fn sdgs(&self, _service: Option<&DiagComm>) -> Result<Vec<SdSdg>, DiagServiceError> {
        unimplemented!()
    }

    fn set_duplicating_ecu_names(&mut self, _duplicate_ecus: HashSet<String>) {
        unimplemented!()
    }

    fn duplicating_ecu_names(&self) -> Option<&HashSet<String>> {
        None
    }

    fn revision(&self) -> String {
        unimplemented!()
    }

    fn runtime_state(&self) -> EcuRuntimeState {
        unimplemented!()
    }
}

/// Builds the positive response an ECU sends for a session change request.
pub(crate) fn positive_session_response() -> Vec<u8> {
    vec![
        service_ids::SESSION_CONTROL | UDS_ID_RESPONSE_BITMASK,
        SESSION_SUBFUNCTION,
    ]
}

/// Builds a negative response (NRC 0x22 `conditionsNotCorrect`) for a session
/// change request.
pub(crate) fn negative_session_response() -> Vec<u8> {
    vec![
        service_ids::NEGATIVE_RESPONSE,
        service_ids::SESSION_CONTROL,
        0x22,
    ]
}
