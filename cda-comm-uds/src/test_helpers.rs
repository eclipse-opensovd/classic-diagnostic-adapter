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
    ecu_name: String,
    logical_address: u16,
    runtime_state: cda_interfaces::EcuRuntimeState,
    detection_requests: HashMap<String, DiagComm>,
    duplicate_ecus: cda_interfaces::HashSet<String>,
    detection_mutations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    mutation_entered: Option<std::sync::Arc<tokio::sync::Notify>>,
    mutation_release: Option<std::sync::Arc<tokio::sync::Notify>>,
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
            ecu_name: "TestECU".to_owned(),
            logical_address: 0x0001,
            runtime_state: cda_interfaces::EcuRuntimeState::new(),
            detection_requests: HashMap::new(),
            duplicate_ecus: cda_interfaces::HashSet::default(),
            detection_mutations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            mutation_entered: None,
            mutation_release: None,
            timeout_default: Duration::from_secs(5),
            repeat_req_count_app: 2,
        }
    }

    pub fn with_identity(ecu_name: impl Into<String>, logical_address: u16) -> Self {
        Self {
            ecu_name: ecu_name.into(),
            logical_address,
            ..Self::new()
        }
    }

    pub fn for_detection() -> Self {
        let runtime_state = cda_interfaces::EcuRuntimeState::new();
        {
            let mut state = runtime_state.ecu_state.write().unwrap();
            state.connectivity = cda_interfaces::Connectivity::Online;
        }
        Self {
            runtime_state,
            detection_requests: HashMap::from_iter([(
                "variant-request".to_owned(),
                DiagComm::new("variant-request", cda_interfaces::DiagCommType::Data),
            )]),
            timeout_default: Duration::from_millis(20),
            repeat_req_count_app: 0,
            ..Self::new()
        }
    }

    pub fn for_detection_with_identity(ecu_name: impl Into<String>, logical_address: u16) -> Self {
        Self {
            ecu_name: ecu_name.into(),
            logical_address,
            ..Self::for_detection()
        }
    }

    pub fn detection_mutations(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::clone(&self.detection_mutations)
    }

    pub fn set_mutation_gate(
        &mut self,
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
    ) {
        self.mutation_entered = Some(entered);
        self.mutation_release = Some(release);
    }

    /// Create a test double with a custom `timeout_default` (`CP_P6Max`).
    pub fn with_timeout_default(timeout_default: Duration) -> Self {
        Self {
            timeout_default,
            ..Self::new()
        }
    }

    /// Create a test double with a custom `timeout_default` (`CP_P6Max`) and
    /// `repeat_req_count_app` (`CP_RepeatReqCountApp`).
    pub fn with_timeout_default_and_repeat_req_count_app(
        timeout_default: Duration,
        repeat_req_count_app: u32,
    ) -> Self {
        Self {
            timeout_default,
            repeat_req_count_app,
            ..Self::new()
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
        self.logical_address
    }
    fn logical_gateway_address(&self) -> u16 {
        0x0000
    }
    fn logical_functional_address(&self) -> u16 {
        0xFFFF
    }
    fn ecu_name(&self) -> String {
        self.ecu_name.clone()
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
        self.runtime_state.status()
    }

    async fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        if let Some(entered) = &self.mutation_entered {
            entered.notify_one();
        }
        if let Some(release) = &self.mutation_release {
            release.notified().await;
        }
        self.detection_mutations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if service_responses.is_empty() {
            self.runtime_state.ecu_state.write().unwrap().connectivity =
                cda_interfaces::Connectivity::Offline;
        }
        Ok(())
    }

    fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm> {
        &self.detection_requests
    }

    async fn mark_as_duplicate(&mut self) {
        self.runtime_state.ecu_state.write().unwrap().variant_state =
            cda_interfaces::VariantState::Duplicate;
    }

    async fn mark_as_no_variant_detected(&mut self) {
        self.runtime_state.ecu_state.write().unwrap().variant_state =
            cda_interfaces::VariantState::NotDetected;
    }
}

#[derive(Clone)]
pub(crate) struct TestResponse;

impl DiagServiceResponse for TestResponse {
    fn empty_positive(_service: DiagComm) -> Self {
        Self
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn service_name(&self) -> String {
        String::new()
    }

    fn response_type(&self) -> cda_interfaces::diagservices::DiagServiceResponseType {
        cda_interfaces::diagservices::DiagServiceResponseType::Positive
    }

    fn get_raw(&self) -> &[u8] {
        &[]
    }

    fn into_json(
        self,
    ) -> Result<cda_interfaces::diagservices::DiagServiceJsonResponse, DiagServiceError> {
        unimplemented!()
    }

    fn as_nrc(&self) -> Result<cda_interfaces::diagservices::MappedNRC, DiagServiceError> {
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

impl cda_interfaces::PayloadEncoder for TestEcuDb {
    fn check_genericservice(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
        _rawdata: Vec<u8>,
    ) -> impl Future<Output = Result<cda_interfaces::ServicePayload, DiagServiceError>> + Send {
        std::future::ready(Err(DiagServiceError::NotFound(String::new())))
    }

    fn create_uds_payload(
        &self,
        _diag_service: &DiagComm,
        _security_plugin: &cda_interfaces::DynamicPlugin,
        _data: Option<cda_interfaces::diagservices::UdsPayloadData>,
        _functional_group_name: Option<&str>,
    ) -> impl Future<Output = Result<cda_interfaces::ServicePayload, DiagServiceError>> + Send {
        std::future::ready(Ok(cda_interfaces::ServicePayload {
            data: vec![cda_interfaces::service_ids::READ_DATA_BY_IDENTIFIER],
            source_address: self.tester_address(),
            target_address: self.logical_address(),
            new_session: None,
            new_security: None,
        }))
    }
}

impl cda_interfaces::PayloadDecoder for TestEcuDb {
    type Response = TestResponse;

    fn convert_from_uds(
        &self,
        _diag_service: &DiagComm,
        _payload: &cda_interfaces::ServicePayload,
        _map_to_json: bool,
        _functional_group_name: Option<&str>,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send {
        std::future::ready(Ok(TestResponse))
    }

    fn convert_request_from_uds(
        &self,
        _diag_service: &DiagComm,
        _payload: &cda_interfaces::ServicePayload,
        _map_to_json: bool,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send {
        std::future::ready(Ok(TestResponse))
    }

    fn convert_service_14_response(
        _diag_comm: DiagComm,
        _response: cda_interfaces::ServicePayload,
    ) -> Result<Self::Response, DiagServiceError> {
        Ok(TestResponse)
    }
}

impl cda_interfaces::EcuSecurity for TestEcuDb {
    async fn lookup_security_access_change(
        &self,
        _level: &str,
        _has_key: bool,
    ) -> Result<cda_interfaces::SecurityAccess, DiagServiceError> {
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
        _security_plugin: &cda_interfaces::DynamicPlugin,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
        std::future::ready(Ok(()))
    }
}

impl cda_interfaces::ComponentInfos for TestEcuDb {
    fn get_components_data_info(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
    ) -> Vec<cda_interfaces::datatypes::ComponentDataInfo> {
        Vec::new()
    }

    fn get_functional_group_data_info(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
        _functional_group_name: &str,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn get_components_configurations_info(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentConfigurationsInfo>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn get_components_operations_info(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
    ) -> Vec<cda_interfaces::datatypes::ComponentOperationsInfo> {
        Vec::new()
    }

    fn get_routine_subfunctions(
        &self,
        _service_name: &str,
        _security_plugin: &cda_interfaces::DynamicPlugin,
    ) -> Result<cda_interfaces::datatypes::RoutineSubfunctions, DiagServiceError> {
        unimplemented!()
    }

    fn get_functional_group_operations_info(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
        _functional_group_name: &str,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentOperationsInfo>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn get_functional_group_routine_subfunctions(
        &self,
        _security_plugin: &cda_interfaces::DynamicPlugin,
        _functional_group_name: &str,
        _service_name: &str,
    ) -> Result<cda_interfaces::datatypes::RoutineSubfunctions, DiagServiceError> {
        unimplemented!()
    }

    fn get_components_single_ecu_jobs_info(
        &self,
    ) -> Vec<cda_interfaces::datatypes::ComponentDataInfo> {
        Vec::new()
    }

    fn get_request_parameter_metadata(
        &self,
        _service_name: &str,
    ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn get_response_parameter_metadata(
        &self,
        _service_name: &str,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn get_mux_cases_for_service(
        &self,
        _service_name: &str,
    ) -> Result<Vec<cda_interfaces::MuxCaseInfo>, DiagServiceError> {
        Ok(Vec::new())
    }

    fn functional_groups(&self) -> Vec<String> {
        Vec::new()
    }
}

impl cda_interfaces::Dtc for TestEcuDb {
    fn lookup_dtc_services(
        &self,
        _service_types: &[cda_interfaces::datatypes::DtcReadInformationFunction],
    ) -> Result<
        HashMap<
            cda_interfaces::datatypes::DtcReadInformationFunction,
            cda_interfaces::datatypes::DtcLookup,
        >,
        DiagServiceError,
    > {
        Ok(HashMap::new())
    }
}

impl cda_interfaces::DiagCommLookup for TestEcuDb {
    fn lookup_single_ecu_job(
        &self,
        _job_name: &str,
    ) -> Result<cda_interfaces::datatypes::single_ecu::Job, DiagServiceError> {
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
        Ok(Vec::new())
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

impl cda_interfaces::EcuSchemas for TestEcuDb {
    async fn schema_for_request(
        &self,
        _service: &DiagComm,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        unimplemented!()
    }

    async fn schema_for_responses(
        &self,
        _service: &DiagComm,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        unimplemented!()
    }

    async fn schema_for_fg_request(
        &self,
        _service: &DiagComm,
        _functional_group_name: &str,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        unimplemented!()
    }
}

impl cda_interfaces::file_manager::EmbeddedFiles for TestEcuDb {
    fn list(
        &self,
    ) -> impl Future<Output = HashMap<String, cda_interfaces::file_manager::ChunkMetaData>> + Send
    {
        std::future::ready(HashMap::new())
    }

    async fn get(
        &self,
        _id: &str,
    ) -> Result<
        (cda_interfaces::file_manager::ChunkMetaData, Vec<u8>),
        cda_interfaces::file_manager::MddError,
    > {
        unimplemented!()
    }
}

impl cda_interfaces::EcuManager for TestEcuDb {
    type Response = TestResponse;

    fn is_physical_ecu(&self) -> bool {
        true
    }

    fn protocol(&self) -> &cda_interfaces::Protocol {
        static PROTOCOL: std::sync::OnceLock<cda_interfaces::Protocol> = std::sync::OnceLock::new();
        PROTOCOL.get_or_init(cda_interfaces::Protocol::default)
    }

    fn is_loaded(&self) -> bool {
        true
    }

    fn load(&mut self) -> Result<(), DiagServiceError> {
        Ok(())
    }

    fn comparams(
        &self,
    ) -> Result<cda_interfaces::datatypes::ComplexComParamValue, DiagServiceError> {
        unimplemented!()
    }

    fn sdgs(
        &self,
        _service: Option<&DiagComm>,
    ) -> impl Future<Output = Result<Vec<cda_interfaces::datatypes::SdSdg>, DiagServiceError>> + Send
    {
        std::future::ready(Ok(Vec::new()))
    }

    fn set_duplicating_ecu_names(&mut self, duplicate_ecus: cda_interfaces::HashSet<String>) {
        self.duplicate_ecus = duplicate_ecus;
    }

    fn duplicating_ecu_names(&self) -> Option<&cda_interfaces::HashSet<String>> {
        Some(&self.duplicate_ecus)
    }

    fn revision(&self) -> String {
        "0.0.0".to_owned()
    }

    fn runtime_state(&self) -> cda_interfaces::EcuRuntimeState {
        self.runtime_state.clone()
    }
}
