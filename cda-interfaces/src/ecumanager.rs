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
use serde::Serialize;

use crate::{
    DiagComm, DiagServiceError, DoipComParamProvider, DynamicPlugin, EcuSchemaProvider, HashMap,
    HashSet, SecurityAccess, UdsComParamProvider,
    datatypes::{
        ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo, DtcLookup,
        DtcReadInformationFunction, SdSdg, single_ecu,
    },
    diagservices::{DiagServiceResponse, UdsPayloadData},
};

/// Metadata for a service parameter, including constant values for discovery
#[derive(Debug, Clone, Serialize)]
pub struct ServiceParameterMetadata {
    /// Parameter short name (e.g., "`RDBI_DID`", "SESSION")
    pub name: String,
    /// Parameter semantic (e.g., "DATA-IDENTIFIER", "SESSION")
    pub semantic: Option<String>,
    /// Parameter type and constant value if applicable
    pub param_type: ParameterTypeMetadata,
}

/// Parameter type with constant value metadata
#[derive(Debug, Clone, Serialize)]
pub enum ParameterTypeMetadata {
    /// CODED-CONST parameter with fixed value from MDD
    CodedConst { coded_value: String },
    /// PHYS-CONST parameter with constant value from MDD
    PhysConst { phys_constant_value: String },
    /// VALUE or other dynamic parameter types
    Value,
}

/// MUX case information for service response routing
#[derive(Debug, Clone, Serialize)]
pub struct MuxCaseInfo {
    /// Case short name (e.g., "`RDBI_DID_VIN`", "`RDBI_DID_FTP`")
    pub short_name: String,
    /// Case long name (e.g., "VIN", "flashTimingParameter")
    pub long_name: Option<String>,
    /// Lower limit value for this case (DID value for `ReadDataByIdentifier`)
    pub lower_limit: Option<String>,
    /// Upper limit value for this case
    pub upper_limit: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub enum EcuState {
    Online,
    Offline,
    NotTested,
    Duplicate,
    Disconnected,
    NoVariantDetected,
}

#[derive(Clone, Serialize)]
pub struct EcuVariant {
    pub name: Option<String>,
    pub is_base_variant: bool,
    pub state: EcuState,
    pub logical_address: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    DoIp,
    DoIpDobt,
    // todo: other protocols
}

#[derive(Debug, Clone)]
pub struct ServicePayload {
    pub data: Vec<u8>,
    pub source_address: u16,
    pub target_address: u16,
    pub new_session: Option<String>,
    pub new_security: Option<String>,
}

/// Trait to provide communication parameters for an ECU.
/// It might be the case, that no all functions are needed for
/// every protocol. (I.e. gateway address for CAN).
pub trait EcuAddressProvider: Send + Sync + 'static {
    #[must_use]
    fn tester_address(&self) -> u16;
    #[must_use]
    fn logical_address(&self) -> u16;
    #[must_use]
    fn logical_gateway_address(&self) -> u16;
    #[must_use]
    fn logical_functional_address(&self) -> u16;
    #[must_use]
    fn ecu_name(&self) -> String;
    #[must_use]
    fn logical_address_eq<T: EcuAddressProvider>(&self, other: &T) -> bool;
}

pub trait EcuManager:
    DoipComParamProvider
    + UdsComParamProvider
    + EcuAddressProvider
    + EcuSchemaProvider
    + Send
    + Sync
    + 'static
{
    type Response: DiagServiceResponse;
    /// This indicates whether the `EcuManager` is representing an ECU or
    /// a functional description only.
    #[must_use]
    fn is_physical_ecu(&self) -> bool;

    #[must_use]
    fn variant(&self) -> EcuVariant;

    #[must_use]
    fn state(&self) -> EcuState;

    #[must_use]
    fn protocol(&self) -> Protocol;

    #[must_use]
    fn is_loaded(&self) -> bool;

    #[must_use]
    fn functional_groups(&self) -> Vec<String>;

    /// Set the list of ECU names that share the same logical address.
    fn set_duplicating_ecu_names(&mut self, duplicate_ecus: HashSet<String>);
    /// Get the list of ECU names that share the same logical address.
    #[must_use]
    fn duplicating_ecu_names(&self) -> Option<&HashSet<String>>;
    /// Mark this ECU as duplicate. Call this when a Variant was detected for another ECU
    /// with the same logical address.
    /// Sets the state to `EcuState::Duplicate` and unload the database.
    /// Database will be reloaded before next variant detection.
    fn mark_as_duplicate(&mut self);

    /// This allows to (re)load a database after unloading it during runtime, which could happen
    /// if initially the ECU wasn´t responding but later another request
    /// for reprobing the ECU happens.
    ///
    /// # Errors
    /// Will return `Err` if during runtime the ECU file has been removed or changed
    /// in a way that the error causes mentioned in `Self::new` occur.
    fn load(&mut self) -> Result<(), DiagServiceError>;
    fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
    fn get_variant_detection_requests(&self) -> &HashSet<String>;
    /// Communication parameters for the ECU.
    /// # Errors
    /// Will return `DiagServiceError` if the communication
    /// parameters cannot be found in the database.
    fn comparams(&self) -> Result<ComplexComParamValue, DiagServiceError>;
    fn sdgs(
        &self,
        service: Option<&DiagComm>,
    ) -> impl Future<Output = Result<Vec<SdSdg>, DiagServiceError>> + Send;
    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn´t match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    fn convert_from_uds(
        &self,
        diag_service: &DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;

    /// Creates a `ServicePayload` and processes transitions based on raw UDS data,
    /// as received from a generic data endpoint.
    ///
    /// Returns the `ServicePayload` with resolved transitions.
    ///
    /// # Errors
    /// Returns `Err` if the payload cannot be matched to any diagnostic service.
    fn check_genericservice(
        &self,
        security_plugin: &DynamicPlugin,
        rawdata: Vec<u8>,
    ) -> impl Future<Output = Result<ServicePayload, DiagServiceError>> + Send;
    /// Converts given `UdsPayloadData` into a UDS request payload for the given `DiagService`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the `UdsPayloadData` doesn´t provide required parameters
    /// for the `DiagService` request or if elements of the `UdsPayloadData` cannot be mapped to
    /// the raw UDS bytestream.
    fn create_uds_payload(
        &self,
        diag_service: &DiagComm,
        security_plugin: &DynamicPlugin,
        data: Option<UdsPayloadData>,
    ) -> impl Future<Output = Result<ServicePayload, DiagServiceError>> + Send;
    /// Convert a UDS REQUEST payload into a `DiagServiceResponse` using the
    /// REQUEST definition in MDD. This function parses incoming REQUEST payloads
    /// (not responses) for bidirectional UDS-to-SOVD conversion scenarios.
    ///
    /// # Errors
    /// Returns `Err` in the following cases:
    /// - **Service not supported**: The service has no REQUEST definition in the database
    ///   (returns `RequestNotSupported`). This indicates the MDD database doesn't define
    ///   how to parse request payloads for this service.
    /// - **Invalid database**: Required parameter metadata (short names) is missing from
    ///   the database structure (returns `InvalidDatabase`). This is a database integrity issue.
    /// - **Data mapping errors**: Individual parameters cannot be decoded from the raw UDS bytes
    ///   due to type mismatches, invalid values, or insufficient payload length
    ///   (returns `DataError`).
    ///   These errors are collected and included in the response structure for debugging.
    fn convert_request_from_uds(
        &self,
        diag_service: &DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send;
    /// Looks up a single ECU job by name for the current ECU variant.
    /// # Errors
    /// Will return `Err` if the job cannot be found in the database
    /// Unlikely other case is that neither a lookup in the current nor the base variant succeeded.
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError>;

    /// Sets the service state for a given service identifier.
    ///
    /// This method stores the current state associated with a diagnostic service,
    /// identified by its service ID (SID). The state value is typically used to
    /// track the value of `/modes` after executing a service.
    ///
    /// # Parameters
    /// * `sid` - The service identifier (SID) as a byte value
    /// * `value` - The state value to associate with this service
    ///   (e.g., session name, security level)
    fn set_service_state(&self, sid: u8, value: String) -> impl Future<Output = ()> + Send;

    /// Retrieves the current service state for a given service identifier.
    ///
    /// This method returns the previously stored state for a diagnostic service,
    /// identified by its service ID (SID). Returns `None` if no state has been
    /// set for the given service identifier.
    ///
    /// # Parameters
    /// * `sid` - The service identifier (SID) as a byte value
    ///
    /// # Returns
    /// * `Some(String)` - The stored state value if it exists
    /// * `None` - If no state has been set for this service identifier
    fn get_service_state(&self, sid: u8) -> impl Future<Output = Option<String>> + Send;

    /// Lookup the transition between the active session and the requested one.
    /// # Errors
    /// * `DiagServiceError::AccessDenied` if no transition exists
    /// * `DiagServiceError::NotFound` on various lookup errors.
    fn lookup_session_change(
        &self,
        session: &str,
    ) -> impl Future<Output = Result<DiagComm, DiagServiceError>> + Send;
    /// Lookup the transition from the current security state to the given one.
    /// As switching to a new security state might need authentication.
    /// * `RequestSeed(DiagComm)`: A seeds needs to be requested via the provided diag comm.
    /// * `SendKey((Id, DiagComm))`: Send the key calculated by the previously requested seed.
    ///   The diag comm has to be used to authenticate against the ECU, the target security
    ///   state is given in the Id.
    ///
    /// # Errors
    /// * `DiagServiceError::AccessDenied` if no transition exists
    /// * `DiagServiceError::NotFound` on various lookup errors.
    fn lookup_security_access_change(
        &self,
        level: &str,
        seed_service: Option<&String>,
        has_key: bool,
    ) -> impl Future<Output = Result<SecurityAccess, DiagServiceError>> + Send;
    /// Retrieves the name of the parameter used to send the key for security access.
    /// # Errors
    /// Will return `DiagServiceError` if the parameter cannot be found in the database
    fn get_send_key_param_name(
        &self,
        diag_service: &DiagComm,
    ) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Retrieves the name of the current ecu session, i.e. 'extended', 'programming' or 'default'.
    /// The examples above differ depending on the parameterization of the ECU.
    /// # Errors
    /// Will return `DiagServiceError` if the session cannot be found in the database
    /// or no session is currently set or no variant is loaded.
    fn session(&self) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Retrieves the name of the default ecu session
    /// # Errors
    /// Will return `DiagServiceError` if no default session is found in the database
    fn default_session(&self) -> Result<String, DiagServiceError>;
    /// Retrieves the name of the current ecu security level,
    /// i.e. `level_42`
    /// The exact values depends on the ECU parameterization.
    /// # Errors
    /// Will return `DiagServiceError` if the security access cannot be found in the database
    /// or no security access is currently set or no variant is loaded.
    fn security_access(&self) -> impl Future<Output = Result<String, DiagServiceError>> + Send;
    /// Retrieves the name of the default ecu security level,
    /// # Errors
    /// Will return `DiagServiceError` if no default session is found in the database
    fn default_security_access(&self) -> Result<String, DiagServiceError>;
    /// Lookup a service by a given function class name and service id.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_through_func_class(
        &self,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<DiagComm, DiagServiceError>;
    /// Lookup a service by its service id for the current ECU variant.
    /// This will first look up the service in the current variant, then in the base variant
    /// # Errors
    /// Will return `Err` if either the variant or base variant cannot be resolved.
    fn lookup_service_names_by_sid(&self, service_id: u8) -> Result<Vec<String>, DiagServiceError>;
    /// Lookup a service by its service id and name for the current ECU variant.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_by_sid_and_name(
        &self,
        service_id: u8,
        name: &str,
    ) -> Result<DiagComm, DiagServiceError>;

    /// Get parameter metadata for a specific service, including constant values for PHYS-CONST and
    /// CODED-CONST parameters.
    /// This is useful for discovering which DIDs are handled by which services.
    /// # Errors
    /// Will return `Err` if the service cannot be found or parameter metadata cannot be extracted.
    fn get_service_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<ServiceParameterMetadata>, DiagServiceError>;
    /// Get MUX case information for services using multiplexed responses
    /// (e.g., `ReadDataByIdentifier` with different DIDs).
    /// The MUX cases contain the actual DID values in their `lower_limit/upper_limit` fields.
    /// # Errors
    /// Will return `Err` if MUX case information cannot be retrieved.
    fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<MuxCaseInfo>, DiagServiceError>;

    /// Retrieve all `read` services for the current ECU variant.
    fn get_components_data_info(&self) -> Vec<ComponentDataInfo>;
    /// Retrieve all configuration type services for the current ECU variant.
    /// # Errors
    /// Returns `DiagServiceError` if the lookup failed.
    fn get_components_configurations_info(
        &self,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>;
    /// Retrieve all 'single ecu' jobs for the current ECU variant.
    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo>;
    /// Lookup DTC services for the given service types in the current ECU variant.
    /// # Errors
    /// Returns `DiagServiceError` if the lookup failed.
    fn lookup_dtc_services(
        &self,
        service_types: Vec<DtcReadInformationFunction>,
    ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError>;
    fn is_service_allowed(
        &self,
        service: &DiagComm,
        security_plugin: &DynamicPlugin,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
    /// Retrieve the revision of the ECU variant if available,
    /// otherwise return 0.0.0
    fn revision(&self) -> String;

    /// Convert a response to service 0x14 according to
    /// ISO-14229-1 12.2.3 and 12.2.4
    /// # Errors
    /// - `DiagServiceError::UnexpectedResponse` if the SID for the positive response doesn't
    ///   match 0x54
    /// - `DiagServiceError::BadPayload` if the SID is missing
    fn convert_service_14_response(
        &self,
        diag_comm: DiagComm,
        response: ServicePayload,
    ) -> Result<Self::Response, DiagServiceError>;
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum EcuManagerType {
    Ecu,
    FunctionalDescription,
}

impl Protocol {
    #[must_use]
    pub const fn value(&self) -> &'static str {
        match self {
            Protocol::DoIp => "UDS_Ethernet_DoIP",
            Protocol::DoIpDobt => "UDS_Ethernet_DoIP_DOBT",
        }
    }
}

impl std::fmt::Display for EcuState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcuState::Online => write!(f, "Online"),
            EcuState::Offline => write!(f, "Offline"),
            EcuState::NotTested => write!(f, "NotTested"),
            EcuState::Duplicate => write!(f, "Duplicate"),
            EcuState::Disconnected => write!(f, "Disconnected"),
            EcuState::NoVariantDetected => write!(f, "NoVariantDetected"),
        }
    }
}
