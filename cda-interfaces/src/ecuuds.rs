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

use async_trait::async_trait;

use crate::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuVariant, HashMap, SecurityAccess,
    TesterPresentType,
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
#[async_trait]
pub trait UdsEcu: Send + Sync + 'static {
    type Response: DiagServiceResponse;
    /// Returns a list of loaded ECUs.
    /// They are not necessarily online, but have been loaded from the database.
    async fn get_ecus(&self) -> Vec<String>;
    /// Returns a list of loaded ECUs, filtering out the functional description.
    /// The same constraints as [get_ecus](UdsEcu::get_ecus) apply.
    async fn get_physical_ecus(&self) -> Vec<String>;
    /// Fetches the network structure of the ECUs, including their connections and addresses.
    async fn get_network_structure(&self) -> NetworkStructure;
    /// Retrieve the Special Data Groups (SDGs) for the given ECU.
    /// SDGs provide textual information.
    /// For example, they are used to provide meta information about the ECU, like the bus interface
    /// or the AUTOSAR version.
    /// # Errors
    /// Will return `Err` if the ECU does not exist or if the service is not available.
    async fn get_sdgs(
        &self,
        ecu: &str,
        service: Option<&DiagComm>,
    ) -> Result<Vec<SdSdg>, DiagServiceError>;
    /// Retrieves the communication parameters for a specific ECU.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    async fn get_comparams(&self, ecu: &str) -> Result<ComplexComParamValue, DiagServiceError>;
    /// Retrieve all `read` services for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    async fn get_components_data_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError>;
    /// Retrieve all configuration type services for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist
    async fn get_components_configuration_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>;
    /// Retrieve all single ecu jobs for the given ECU on the detected variant.
    /// # Errors
    /// Will return `Err` if the ECU does not exist.
    async fn get_components_single_ecu_jobs_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError>;
    /// Retrieve a specific single ecu job for the given ECU.
    async fn get_single_ecu_job(
        &self,
        ecu: &str,
        job_name: &str,
    ) -> Result<single_ecu::Job, DiagServiceError>;
    /// Send a message via the given `DiagComm` and Payload to the ECU.
    /// The timeout is set to the given duration, instead of the default timeout.
    /// Can be used to override the default timeout for a specific request, especially
    /// for requests which expect to take longer.
    async fn send_with_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Duration,
    ) -> Result<Self::Response, DiagServiceError>;
    /// Send a message via the given `DiagComm` and Payload to the ECU.
    /// The default timeouts of the ECU, read from the communication parameters, will be used.
    /// # Error
    /// Will return `Err` if the ECU does not exist or if the request fails.
    async fn send(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> Result<Self::Response, DiagServiceError>;
    /// Send a raw uds packet to the ECU
    /// The initial bytes of the packet are analyzed to resolve the diag-service,
    /// but the rest of the data is not validated / checked for consistency
    /// # Error
    /// Will return `Err` if the ECU does not exist, the diag-service cannot be
    /// resolved or if the request fails.
    async fn send_genericservice(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, DiagServiceError>;
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
    async fn set_ecu_session(
        &self,
        ecu_name: &str,
        session: &str,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> Result<Self::Response, DiagServiceError>;
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
    async fn set_ecu_security_access(
        &self,
        ecu_name: &str,
        level: &str,
        seed_service: Option<&String>,
        authentication_data: Option<UdsPayloadData>,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> Result<(SecurityAccess, Self::Response), DiagServiceError>;
    /// Get the name of the parameter used to send the key for the given ECU and security level.
    /// # Errors
    /// Returns an error if the ECU or security level is not found.
    async fn get_send_key_param_name(
        &self,
        ecu_name: &str,
        level: &str,
    ) -> Result<String, DiagServiceError>;
    /// Retrieve service to reset the ECU.
    async fn get_ecu_reset_services(&self, ecu_name: &str)
    -> Result<Vec<String>, DiagServiceError>;
    /// Get the current session of the ECU.
    async fn ecu_session(&self, ecu_name: &str) -> Result<String, DiagServiceError>;
    /// Get the current security access level of the ECU.
    async fn ecu_security_access(&self, ecu_name: &str) -> Result<String, DiagServiceError>;
    /// Lookup the service id on the ECU and restrict the result to the function class.
    /// After the successful lookup, the found service will be executed with the given payload.
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    ///
    /// Furthermore, errors from the `send` function are forwarded.
    async fn ecu_exec_service_from_function_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
        security_plugin: &DynamicPlugin,
        data: UdsPayloadData,
    ) -> Result<Self::Response, DiagServiceError>;
    /// Lookup a service on the ECU by a given function class name and service id.
    /// # Errors
    /// * `DiagServiceError::NotFound` if the ECU or service lookup failed.
    async fn ecu_lookup_service_through_func_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<DiagComm, DiagServiceError>;

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
    async fn ecu_flash_transfer_start(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        security_plugin: &DynamicPlugin,
        parameters: FlashTransferStartParams<'_>,
    ) -> Result<(), DiagServiceError>;
    /// Once the transfer has finished transfer exit must be called to finalize the transfer.
    /// No new transfer can be started before this is called.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///  * The ECU with the given name does not exist.
    ///  * The transfer with the given ID does not exist.
    /// * `DiagServiceError::InvalidRequest`
    ///   * The transfer is not in a state where it can be exited, e.g. it is still in progress.
    ///   * Failures on retrieving the transfer exit status.
    async fn ecu_flash_transfer_exit(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<(), DiagServiceError>;
    /// Fetch all flash transfers for the given ECU.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///   * The ECU with the given name does not exist.
    async fn ecu_flash_transfer_status(
        &self,
        ecu_name: &str,
    ) -> Result<Vec<DataTransferMetaData>, DiagServiceError>;
    /// Fetch the status of a specific flash transfer by its ID.
    /// # Errors
    /// * `DiagServiceError::NotFound`
    ///   * The ECU with the given name does not exist.
    ///   * The transfer with the given ID does not exist.
    async fn ecu_flash_transfer_status_id(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<DataTransferMetaData, DiagServiceError>;

    /// Trigger variant detection for the given ECU.
    /// # Errors
    /// Will return `Err` if the variant detection cannot be triggered, e.g. if the given ECU
    /// does not exist or no service for variant detection is available.
    async fn detect_variant(&self, ecu_name: &str) -> Result<(), DiagServiceError>;

    /// Get the name of the variant for the given ECU.
    /// # Errors
    /// Will return Err if the ECU does not exist.
    /// If the variant is cannot be resolved, "Unknown" will be returned.
    async fn get_variant(&self, ecu_name: &str) -> Result<EcuVariant, DiagServiceError>;

    /// trigger the variant detection process for all ECUs.
    /// Main work will be done in the background, there is no result returned,
    /// as the data is internally stored and used in `EcuUds`
    async fn start_variant_detection(&self);

    /// Start sending periodic tester present messages to keep the session alive.
    /// The interval is defined per ECU in the communication parameters.
    async fn start_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError>;

    /// Stop sending periodic tester present messages.
    async fn stop_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError>;

    /// Check if a tester present is active for the given type.
    async fn check_tester_present_active(&self, type_: &TesterPresentType) -> bool;

    /// Retrieve all faults for the given ECU,
    /// with optional filtering by status, severity and scope.
    async fn ecu_dtc_by_mask(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        status: Option<HashMap<String, serde_json::Value>>,
        severity: Option<u32>,
        scope: Option<String>,
    ) -> Result<HashMap<DtcCode, DtcRecordAndStatus>, DiagServiceError>;

    async fn ecu_dtc_extended(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        sae_dtc: &str,
        include_extended_data: bool,
        include_snapshot: bool,
        include_schema: bool,
    ) -> Result<DtcExtendedInfo, DiagServiceError>;

    /// Get the functional groups an ECU belongs to.
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the ECU is not found.
    async fn ecu_functional_groups(&self, ecu_name: &str) -> Result<Vec<String>, DiagServiceError>;

    /// Send a functional group request using functional communication.
    /// This method groups ECUs by their gateway and sends one request per gateway using
    /// the functional address. It then waits for responses from all ECUs in the group.
    ///
    /// # Arguments
    /// * `functional_group` - Name of the functional group
    /// * `service` - The diagnostic service to execute
    /// * `security_plugin` - Security plugin to validate the request against
    /// * `payload` - Optional payload data for the service
    /// * `map_to_json` - Whether to map the response to JSON format
    ///
    /// # Returns
    /// A map of ECU names to their responses (or errors if the request failed)
    ///
    /// # Errors
    /// Returns error if the functional group doesn't exist or if all ECUs fail to respond
    async fn send_functional_group(
        &self,
        functional_group: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> HashMap<String, Result<Self::Response, DiagServiceError>>;
}

#[cfg(feature = "test-utils")]
pub mod mock {
    use std::time::Duration;

    use async_trait::async_trait;

    use super::FlashTransferStartParams;
    use crate::{
        DiagComm, DiagServiceError, DynamicPlugin, EcuVariant, HashMap, SecurityAccess,
        TesterPresentType, UdsEcu,
        datatypes::{
            ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
            DataTransferMetaData, DtcCode, DtcExtendedInfo, DtcRecordAndStatus, NetworkStructure,
            SdSdg, single_ecu,
        },
        diagservices::UdsPayloadData,
    };

    mockall::mock! {
        pub UdsEcu {}

        impl Clone for UdsEcu {
            fn clone(&self) -> Self;
        }

        #[async_trait]
            // allowed because the mock! macro generates references to Option types
    #[allow(clippy::ref_option_ref)]
        impl UdsEcu for UdsEcu {
            type Response = crate::diagservices::mock::MockDiagServiceResponse;

            async fn get_ecus(&self) -> Vec<String>;
            async fn get_physical_ecus(&self) -> Vec<String>;
            async fn get_network_structure(&self) -> NetworkStructure;
            #[mockall::concretize]
            async fn get_sdgs(
                &self,
                ecu: &str,
                service: Option<&DiagComm>,
            ) -> Result<Vec<SdSdg>, DiagServiceError>;
            async fn get_comparams(
                &self,
                ecu: &str,
            ) -> Result<ComplexComParamValue, DiagServiceError>;
            async fn get_components_data_info(
                &self,
                ecu: &str,
            ) -> Result<Vec<ComponentDataInfo>, DiagServiceError>;
            async fn get_components_configuration_info(
                &self,
                ecu: &str,
            ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>;
            async fn get_components_single_ecu_jobs_info(
                &self,
                ecu: &str,
            ) -> Result<Vec<ComponentDataInfo>, DiagServiceError>;
            async fn get_single_ecu_job(
                &self,
                ecu: &str,
                job_name: &str,
            ) -> Result<single_ecu::Job, DiagServiceError>;
            async fn send_with_timeout(
                &self,
                ecu_name: &str,
                service: DiagComm,
                security_plugin: &DynamicPlugin,
                payload: Option<UdsPayloadData>,
                map_to_json: bool,
                timeout: Duration,
            ) -> Result<<MockUdsEcu as UdsEcu>::Response, DiagServiceError>;
            async fn send(
                &self,
                ecu_name: &str,
                service: DiagComm,
                security_plugin: &DynamicPlugin,
                payload: Option<UdsPayloadData>,
                map_to_json: bool,
            ) -> Result<<MockUdsEcu as UdsEcu>::Response, DiagServiceError>;
            async fn send_genericservice(
                &self,
                ecu_name: &str,
                security_plugin: &DynamicPlugin,
                payload: Vec<u8>,
                timeout: Option<Duration>,
            ) -> Result<Vec<u8>, DiagServiceError>;
            async fn set_ecu_session(
                &self,
                ecu_name: &str,
                session: &str,
                security_plugin: &DynamicPlugin,
                expiration: Duration,
            ) -> Result<<MockUdsEcu as UdsEcu>::Response, DiagServiceError>;
            #[mockall::concretize]
            async fn set_ecu_security_access(
                &self,
                ecu_name: &str,
                level: &str,
                seed_service: Option<&String>,
                authentication_data: Option<UdsPayloadData>,
                security_plugin: &DynamicPlugin,
                expiration: Duration,
            ) -> Result<(SecurityAccess, <MockUdsEcu as UdsEcu>::Response), DiagServiceError>;
            async fn get_send_key_param_name(
                &self,
                ecu_name: &str,
                level: &str,
            ) -> Result<String, DiagServiceError>;
            async fn get_ecu_reset_services(
                &self,
                ecu_name: &str,
            ) -> Result<Vec<String>, DiagServiceError>;
            async fn ecu_session(
                &self,
                ecu_name: &str,
            ) -> Result<String, DiagServiceError>;
            async fn ecu_security_access(
                &self,
                ecu_name: &str,
            ) -> Result<String, DiagServiceError>;
            async fn ecu_exec_service_from_function_class(
                &self,
                ecu_name: &str,
                func_class_name: &str,
                service_id: u8,
                security_plugin: &DynamicPlugin,
                data: UdsPayloadData,
            ) -> Result<<MockUdsEcu as UdsEcu>::Response, DiagServiceError>;
            async fn ecu_lookup_service_through_func_class(
                &self,
                ecu_name: &str,
                func_class_name: &str,
                service_id: u8,
            ) -> Result<DiagComm, DiagServiceError>;
            #[mockall::concretize]
            async fn ecu_flash_transfer_start(
                &self,
                ecu_name: &str,
                func_class_name: &str,
                security_plugin: &DynamicPlugin,
                parameters: FlashTransferStartParams<'_>,
            ) -> Result<(), DiagServiceError>;
            async fn ecu_flash_transfer_exit(
                &self,
                ecu_name: &str,
                id: &str,
            ) -> Result<(), DiagServiceError>;
            async fn ecu_flash_transfer_status(
                &self,
                ecu_name: &str,
            ) -> Result<Vec<DataTransferMetaData>, DiagServiceError>;
            async fn ecu_flash_transfer_status_id(
                &self,
                ecu_name: &str,
                id: &str,
            ) -> Result<DataTransferMetaData, DiagServiceError>;
            async fn detect_variant(
                &self,
                ecu_name: &str,
            ) -> Result<(), DiagServiceError>;
            async fn get_variant(
                &self,
                ecu_name: &str,
            ) -> Result<EcuVariant, DiagServiceError>;
            async fn start_variant_detection(&self);
            async fn start_tester_present(
                &self,
                type_: TesterPresentType,
            ) -> Result<(), DiagServiceError>;
            async fn stop_tester_present(
                &self,
                type_: TesterPresentType,
            ) -> Result<(), DiagServiceError>;
            async fn check_tester_present_active(
                &self,
                type_: &TesterPresentType,
            ) -> bool;
            async fn ecu_dtc_by_mask(
                &self,
                ecu_name: &str,
                security_plugin: &DynamicPlugin,
                status: Option<HashMap<String, serde_json::Value>>,
                severity: Option<u32>,
                scope: Option<String>,
            ) -> Result<HashMap<DtcCode, DtcRecordAndStatus>, DiagServiceError>;
            async fn ecu_dtc_extended(
                &self,
                ecu_name: &str,
                security_plugin: &DynamicPlugin,
                sae_dtc: &str,
                include_extended_data: bool,
                include_snapshot: bool,
                include_schema: bool,
            ) -> Result<DtcExtendedInfo, DiagServiceError>;
            async fn ecu_functional_groups(
                &self,
                ecu_name: &str,
            ) -> Result<Vec<String>, DiagServiceError>;
            async fn send_functional_group(
                &self,
                functional_group: &str,
                service: DiagComm,
                security_plugin: &DynamicPlugin,
                payload: Option<UdsPayloadData>,
                map_to_json: bool,
            ) -> HashMap<String, Result<<MockUdsEcu as UdsEcu>::Response, DiagServiceError>>;
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::{UdsEcu, mock::MockUdsEcu};

    #[tokio::test]
    async fn test_get_ecus() {
        let mut mock = MockUdsEcu::new();

        mock.expect_get_ecus()
            .times(1)
            .returning(|| vec!["ECU1".to_string(), "ECU2".to_string()]);

        let ecus = mock.get_ecus().await;
        assert_eq!(ecus.len(), 2);
    }

    #[tokio::test]
    async fn test_ecu_session() {
        let mut mock = MockUdsEcu::new();

        mock.expect_ecu_session()
            .with(mockall::predicate::eq("ECU1"))
            .times(1)
            .returning(|_| Ok("DefaultSession".to_string()));

        let session = mock.ecu_session("ECU1").await.unwrap();
        assert_eq!(session, "DefaultSession");
    }
}
