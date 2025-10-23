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

use std::time::Duration;

use hashbrown::HashMap;

use crate::{
    DiagComm, DiagServiceError, DynamicPlugin, SecurityAccess, TesterPresentType,
    datatypes::{
        ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo, DataTransferMetaData,
        DtcCode, DtcExtendedInfo, DtcRecordAndStatus, NetworkStructure, SdSdg, single_ecu,
    },
    diagservices::{DiagServiceResponse, UdsPayloadData},
};

pub struct FlashTransferStartParams<'a> {
    pub file_path: &'a str,
    pub offset: u64,
    pub length: u64,
    pub transfer_meta_data: DataTransferMetaData,
}

/// UDS communication interface
pub trait UdsEcu: Send + Sync + 'static {
    type Response: DiagServiceResponse;
    /// Returns a list of loaded ECUs.
    /// They are not necessarily online, but have been loaded from the database.
    fn get_ecus(&self) -> impl Future<Output = Vec<String>> + Send;
    /// Fetches the network structure of the ECUs, including their connections and addresses.
    fn get_network_structure(&self) -> impl Future<Output = NetworkStructure> + Send;
    /// Retrieve the Special Data Groups (SDGs) for the given ECU.
    /// SDGs provide textual information.
    /// For example, they are used to provide meta information about the ECU, like the bus interface
    /// or the AUTOSAR version.
    /// # Errors
    /// Will return `Err` if the ECU does not exist or if the service is not available.
    fn get_sdgs(
        &self,
        ecu: &str,
        service: Option<&DiagComm>,
    ) -> impl Future<Output = Result<Vec<SdSdg>, DiagServiceError>> + Send;
    /// Retrieves the communication parameters for a specific ECU.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    fn get_comparams(
        &self,
        ecu: &str,
    ) -> impl Future<Output = Result<ComplexComParamValue, DiagServiceError>> + Send;
    /// Retrieve all `read` services for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    fn get_components_data_info(
        &self,
        ecu: &str,
    ) -> impl Future<Output = Result<Vec<ComponentDataInfo>, DiagServiceError>> + Send;
    /// Retrieve all configuration type services for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist
    fn get_components_configuration_info(
        &self,
        ecu: &str,
    ) -> impl Future<Output = Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>> + Send;
    /// Retrieve all single ecu jobs for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    fn get_components_single_ecu_jobs_info(
        &self,
        ecu: &str,
    ) -> impl Future<Output = Result<Vec<ComponentDataInfo>, DiagServiceError>> + Send;
    /// Retrieve a specific single ecu job for the given ECU.
    fn get_single_ecu_job(
        &self,
        ecu: &str,
        job_name: &str,
    ) -> impl Future<Output = Result<single_ecu::Job, DiagServiceError>> + Send;
    /// Send a message via the given `DiagComm` and Payload to the ECU.
    /// The timeout is set to the given duration, instead of the default timeout.
    /// Can be used to override the default timeout for a specific request, especially
    /// for requests which expect to take longer.
    fn send_with_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Duration,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;
    /// Send a message via the given `DiagComm` and Payload to the ECU.
    /// The default timeouts of the ECU, read from the communication parameters, will be used.
    /// # Error
    /// Will return `Err` if the ECU does not exist or if the request fails.
    fn send(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;
    /// Send a raw uds packet to the ECU
    /// The initial bytes of the packet are analyzed to resolve the diag-service,
    /// but the rest of the data is not validated / checked for consistency
    /// # Error
    /// Will return `Err` if the ECU does not exist, the diag-service cannot be
    /// resolved or if the request fails.
    fn send_genericservice(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<Vec<u8>, DiagServiceError>> + Send;
    /// Set the session for the given ECU.
    /// No authentication is done by the implementation itself, it is assumed that the
    /// caller has already set the appropriate security access if required.
    /// If not the ECU will return a negative response
    /// Expiration is used to reset the ECU to the default session after the given duration.
    /// Upon positive response, the internally tracked session is updated.
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    ///
    /// Forwards errors from the `send` function.
    fn set_ecu_session(
        &self,
        ecu_name: &str,
        session: &str,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;
    /// Set the security access for the given ECU.
    /// The returned `SecurityAccess` defines whether further authentication is required
    /// `SecurityAccess::RequestSeed` means that the reply contains a seed to calculate a key,
    ///  `SecurityAccess::SendKey` sends the key calculated by the seed, to the ECU.
    /// On a positive response after sending the key, the internally tracked session is updated.
    ///
    /// Expiration is used to reset the ECU to the default security access after the given duration
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    ///
    /// Forwards errors from the `send` function.
    fn set_ecu_security_access(
        &self,
        ecu_name: &str,
        level: &str,
        seed_service: Option<&String>,
        authentication_data: Option<UdsPayloadData>,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> impl Future<Output = Result<(SecurityAccess, Self::Response), DiagServiceError>> + Send;
    /// Get the name of the parameter used to send the key for the given ECU and security level.
    /// # Errors
    /// Returns an error if the ECU or security level is not found.
    fn get_send_key_param_name(
        &self,
        ecu_name: &str,
        level: &str,
    ) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Retrieve service to reset the ECU.
    fn get_ecu_reset_services(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<Vec<String>, DiagServiceError>> + Send;
    /// Get the current session of the ECU.
    fn ecu_session(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Get the current security access level of the ECU.
    fn ecu_security_access(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Lookup the service id on the ECU and restrict the result to the function class.
    /// After the successful lookup, the found service will be executed with the given payload.
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    ///
    /// Furthermore, errors from the `send` function are forwarded.
    fn ecu_exec_service_from_function_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
        security_plugin: &DynamicPlugin,
        data: UdsPayloadData,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;
    /// Lookup a service on the ECU by a given function class name and service id.
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    fn ecu_lookup_service_through_func_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
    ) -> impl Future<Output = Result<DiagComm, DiagServiceError>> + Send;

    /// Start a flash transfer for the given ECU.
    /// Setting the ECU into the appropriate session and security access must be done
    /// before calling this function, otherwise the ECU will not accept the transfer.
    /// # Errors
    /// * `DiagServiceError::InvalidRequest`
    ///   * A transfer is already in progress for the given ECU.
    ///   * The given file path does not exist or is not readable.
    ///   * The offset and length do not match the file size.
    /// * `DiagServiceError::NotFound`
    ///   * The ECU with the given name does not exist.
    fn ecu_flash_transfer_start(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        security_plugin: &DynamicPlugin,
        parameters: FlashTransferStartParams<'_>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
    /// Once the transfer has finished transfer exit must be called to finalize the transfer.
    /// No new transfer can be started before this is called.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///  * The ECU with the given name does not exist.
    ///  * The transfer with the given ID does not exist.
    /// * `DiagServiceError::InvalidRequest`
    ///   * The transfer is not in a state where it can be exited, e.g. it is still in progress.
    ///   * Failures on retrieving the transfer exit status.
    fn ecu_flash_transfer_exit(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
    /// Fetch all flash transfers for the given ECU.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///   * The ECU with the given name does not exist.
    fn ecu_flash_transfer_status(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<Vec<DataTransferMetaData>, DiagServiceError>> + Send;
    /// Fetch the status of a specific flash transfer by its ID.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///   * The ECU with the given name does not exist.
    ///   * The transfer with the given ID does not exist.
    fn ecu_flash_transfer_status_id(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> impl Future<Output = Result<DataTransferMetaData, DiagServiceError>> + Send;

    /// Trigger variant detection for the given ECU.
    /// # Errors
    /// Will return `Err` if the variant detection cannot be triggered, e.g. if the given ECU
    /// does not exist or no service for variant detection is available.
    fn detect_variant(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Get the name of the variant for the given ECU.
    /// # Errors
    /// Will return Err if the ECU does not exist.
    /// If the variant is cannot be resolved, "Unknown" will be returned.
    fn get_variant(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<String, DiagServiceError>> + Send;

    /// trigger the variant detection process for all ECUs.
    /// Main work will be done in the background, there is no result returned,
    /// as the data is internally stored and used in `EcuUds`
    fn start_variant_detection(&self) -> impl Future<Output = ()> + Send;

    /// Start sending periodic tester present messages to keep the session alive.
    /// The interval is defined per ECU in the communication parameters.
    fn start_tester_present(
        &self,
        type_: TesterPresentType,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Stop sending periodic tester present messages.
    fn stop_tester_present(
        &self,
        type_: TesterPresentType,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Check if a tester present is active for the given type.
    fn check_tester_present_active(
        &self,
        type_: &TesterPresentType,
    ) -> impl Future<Output = bool> + Send;

    // Retrieve all faults for the given ECU, with optional filtering by status, severity and scope.
    // W/o fmt::skip 'impl Future...' is put on the same line by rustfmt,
    // then it complains about the line being too long...
    #[rustfmt::skip]
    fn ecu_dtc_by_mask(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        status: Option<HashMap<String, serde_json::Value>>,
        severity: Option<u32>,
        scope: Option<String>,
    ) -> impl
        Future<Output = Result<HashMap<DtcCode, DtcRecordAndStatus>, DiagServiceError>> + Send;

    fn ecu_dtc_extended(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        sae_dtc: &str,
        include_extended_data: bool,
        include_snapshot: bool,
        include_schema: bool,
    ) -> impl Future<Output = Result<DtcExtendedInfo, DiagServiceError>> + Send;

    /// Get the functional groups an ECU belongs to.
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the ECU is not found.
    fn ecu_functional_groups(
        &self,
        ecu_name: &str,
    ) -> impl Future<Output = Result<Vec<String>, DiagServiceError>> + Send;
}
