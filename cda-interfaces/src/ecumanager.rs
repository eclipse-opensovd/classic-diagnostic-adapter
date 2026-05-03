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
use serde::Serialize;

use crate::{
    DiagComm, DiagServiceError, DoipComParamProvider, DynamicPlugin, EcuSchemaProvider, HashMap,
    HashSet, SecurityAccess, UDS_ID_RESPONSE_BITMASK, UdsComParamProvider,
    datatypes::{
        ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
        ComponentOperationsInfo, DtcLookup, DtcReadInformationFunction, RoutineSubfunctions, SdSdg,
        single_ecu,
    },
    diagservices::{DiagServiceResponse, UdsPayloadData},
    service_ids,
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

/// Metadata for a POS-RESPONSE parameter, including byte layout information
/// needed for encoding response payloads.
#[derive(Debug, Clone, Serialize)]
pub struct ResponseParameterInfo {
    /// Parameter short name
    pub name: String,
    /// Parameter semantic (e.g., "DATA", "SERVICEIDRQ", "DATA-IDENTIFIER")
    pub semantic: Option<String>,
    /// Parameter type and constant value
    pub param_type: ParameterTypeMetadata,
    /// Byte offset in the response payload (0-based)
    pub byte_position: u32,
    /// Bit offset within the byte (0-based)
    pub bit_position: u32,
    /// Fixed byte size for `StandardLength` parameters, `None` for variable-length
    pub byte_size: Option<u32>,
}

/// Information about a single scale in a DOP `CompuMethod`.
///
/// For TEXTTABLE DOPs the lower/upper limits define the coded (internal)
/// value range that maps to the label in `compu_const_vt`.
#[derive(Debug, Clone, Serialize)]
pub struct CompuScaleInfo {
    /// Short label for this scale
    pub short_label: Option<String>,
    /// Lower coded limit (closed bound)
    pub lower_limit: Option<u64>,
    /// Upper coded limit (closed bound); equals `lower_limit` for single-value scales.
    pub upper_limit: Option<u64>,
    /// COMPU-CONST textual value (VT or VT-TI)
    pub compu_const_vt: Option<String>,
}

/// Parameter type with constant value metadata
#[derive(Debug, Clone, Serialize)]
pub enum ParameterTypeMetadata {
    /// CODED-CONST parameter with fixed value from MDD
    CodedConst { coded_value: String },
    /// PHYS-CONST parameter with constant value from MDD.
    /// If the DOP uses a TEXTTABLE `CompuMethod`, `coded_value` contains
    /// the numeric (internal/coded) value resolved from the text table.
    PhysConst {
        phys_constant_value: String,
        coded_value: Option<u64>,
    },
    /// MATCHING-REQUEST-PARAM: value copied from the corresponding request parameter.
    /// `byte_length` is the number of bytes to copy from the request.
    MatchingRequestParam { byte_length: u32 },
    /// VALUE or other dynamic parameter types.
    ///
    /// When the DOP is available, `physical_default_value` carries the ODX
    /// default, `coded_default_value` is its resolved coded equivalent, and
    /// `compu_scales` lists the TEXTTABLE / LINEAR scales from the DOP
    /// `CompuMethod` (empty for IDENTICAL DOPs).
    Value {
        /// ODX `PHYSICAL-DEFAULT-VALUE` (textual)
        physical_default_value: Option<String>,
        /// Coded (internal) form of the default value, resolved via the DOP
        coded_default_value: Option<u64>,
        /// Scales from the DOP `CompuMethod` (TEXTTABLE entries with limits)
        compu_scales: Vec<CompuScaleInfo>,
    },
}

impl Default for ParameterTypeMetadata {
    fn default() -> Self {
        Self::Value {
            physical_default_value: None,
            coded_default_value: None,
            compu_scales: Vec::new(),
        }
    }
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
    /// Indicates whether this variant was selected as a fallback when no specific variant matched.
    /// When true, this is a fallback scenario.
    /// When false, it's an exact match (even if `is_base_variant` is true).
    pub is_fallback: bool,
    pub state: EcuState,
    pub logical_address: u16,
}

#[derive(Debug, Clone)]
pub struct Protocol(String);

impl Protocol {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn str(&self) -> &str {
        &self.0
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self("UDS_Ethernet_DoIP_DOBT".to_owned())
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct ServicePayload {
    pub data: Vec<u8>,
    pub source_address: u16,
    pub target_address: u16,
    pub new_session: Option<String>,
    pub new_security: Option<String>,
}

impl ServicePayload {
    #[must_use]
    pub fn is_positive_response_for_sid(&self, sent_sid: u8) -> bool {
        self.data.first() == Some(&sent_sid.saturating_add(UDS_ID_RESPONSE_BITMASK))
    }

    #[must_use]
    pub fn is_negative_response_for_sid(&self, sent_sid: u8) -> bool {
        self.data.first() == Some(&service_ids::NEGATIVE_RESPONSE)
            && self.data.get(1) == Some(&sent_sid)
    }

    #[must_use]
    pub fn is_response_for_sid(&self, sent_sid: u8) -> bool {
        self.is_negative_response_for_sid(sent_sid) || self.is_positive_response_for_sid(sent_sid)
    }

    /// Returns `true` if the UDS subfunction byte (byte index 1) has bit 7 set,
    /// indicating the `suppressPosRspMsgIndicationBit` (SPRMIB) is active.
    /// When this bit is set, the ECU is not expected to send a positive response, so callers
    /// should not treat the absence of a positive response as an error.
    #[must_use]
    pub fn is_suppress_positive_response(&self) -> bool {
        self.data.get(1).is_some_and(|&b| b & 0x80 != 0)
    }

    /// Validates that a positive response echoes back the expected identifier bytes
    /// from the original request, as required by ISO 14229-1.
    ///
    /// Per ISO 14229-1, a positive response "parameter is an echo of [the identifier]
    /// from the request message." Specifically:
    /// - `ReadDataByIdentifier` (0x22): 2-byte `dataIdentifier` echo (Table 189)
    /// - `WriteDataByIdentifier` (0x2E): 2-byte `dataIdentifier` echo (Table 280)
    /// - `InputOutputControlByIdentifier` (0x2F): 2-byte `dataIdentifier` echo (Table 401)
    /// - `RoutineControl` (0x31): 1-byte `routineControlType` (bits 6-0 of `SubFunction`,
    ///   suppress-positive-response bit masked out) + 2-byte `routineIdentifier` (Table 428)
    ///
    /// Returns `true` if:
    /// - The service does not require echo validation (no echo bytes defined), or
    /// - The echoed bytes in the response match those in the request.
    ///
    /// Returns `false` if the echoed bytes do not match.
    #[must_use]
    pub fn has_matching_echo_bytes(&self, request_data: &[u8]) -> bool {
        let Some(&sent_sid) = request_data.first() else {
            return true;
        };

        // Only validate positive responses; negative responses are handled separately.
        if !self.is_positive_response_for_sid(sent_sid) {
            return true;
        }

        let echo_len = Self::echo_byte_count(sent_sid);
        if echo_len == 0 {
            return true;
        }

        // Check that we have enough bytes in both request and response.
        // Echo bytes start at index 1 (after SID/response SID byte).
        let Some(request_echo) = request_data.get(1..1usize.saturating_add(echo_len)) else {
            return true; // Request too short to have echo bytes; skip validation.
        };
        let Some(response_echo) = self.data.get(1..1usize.saturating_add(echo_len)) else {
            return false; // Response too short to contain expected echo bytes.
        };

        // For RoutineControl, the subfunction byte (index 1 of the request) may have the
        // suppress-positive-response bit (0x80) set; the response never includes this bit.
        // We mask it out for comparison.
        if sent_sid == service_ids::ROUTINE_CONTROL {
            let request_subfn =
                request_echo.first().copied().unwrap_or(0) & crate::DEFAULT_SUBFUNCTION_MASK;
            let response_subfn = response_echo.first().copied().unwrap_or(0);
            if request_subfn != response_subfn {
                return false;
            }
            // Compare remaining bytes (routine identifier) directly.
            return request_echo.get(1..) == response_echo.get(1..);
        }

        request_echo == response_echo
    }

    /// Returns the number of echo bytes (after the response SID) that a positive response
    /// for the given request SID must echo back from the request, per ISO 14229-1.
    ///
    /// The echo byte counts are derived from the positive response message definitions in
    /// ISO 14229-1 (Tables 188, 279, 401, 428). Returns 0 for services where the spec does
    /// not define echoed identifier bytes.
    #[must_use]
    pub const fn echo_byte_count(sent_sid: u8) -> usize {
        match sent_sid {
            // ReadDataByIdentifier, WriteDataByIdentifier,
            // InputOutputControlByIdentifier: 2-byte DID
            service_ids::READ_DATA_BY_IDENTIFIER
            | service_ids::WRITE_DATA_BY_IDENTIFIER
            | service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER => 2,
            // RoutineControl: 1-byte subfunction + 2-byte RoutineIdentifier
            service_ids::ROUTINE_CONTROL => 3,
            _ => 0,
        }
    }
}

/// Trait to provide communication parameters for an ECU.
/// It might be the case, that not all functions are needed for
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
    fn protocol(&self) -> &Protocol;

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

    /// Mark this ECU as having no variant detected. Call this when variant detection fails
    /// or when all duplicated ECUs only fall back to base variant without finding a specific match.
    /// Sets the state to `EcuState::NoVariantDetected` and unload the database.
    /// Database will be reloaded before next variant detection.
    fn mark_as_no_variant_detected(&mut self);

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
    fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm>;
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
    /// When `functional_group_name` is `Some`, the service is looked up in the
    /// named functional group instead of the ECU variant.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn´t match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    fn convert_from_uds(
        &self,
        diag_service: &DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
        functional_group_name: Option<&str>,
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
    /// When `functional_group_name` is `Some`, the service is looked up in the
    /// named functional group instead of the ECU variant.
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
        functional_group_name: Option<&str>,
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
    /// Lookup services by matching a service request prefix.
    ///
    /// Finds diagnostic services where the request parameters match a sequence of bytes.
    /// This is useful for finding services based on their complete service identifier,
    /// including service ID, subfunction, and additional coded constant parameters.
    /// Partial parameters won't match and that the prefix must be aligned to parameter boundaries.
    ///
    /// # Parameters
    /// * `service_bytes` - A byte slice containing the service identifier and parameters.
    ///   The first byte is the service ID (SID), followed by any coded constant parameters
    ///   in their sequential byte positions (e.g., `[0x31, 0x01, 0x02, 0x46]`
    ///
    /// # Returns
    /// A vector of service short names that match the criteria
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if no services match the given request prefix,
    /// or `DiagServiceError::InvalidParameter` if the `service_bytes` slice is empty.
    fn lookup_diagcomms_by_request_prefix(
        &self,
        service_bytes: &[u8],
    ) -> Result<Vec<DiagComm>, DiagServiceError>;

    /// Lookup a service by its service id and name.
    ///
    /// When `functional_group_name` is `Some`, the search is scoped to the
    /// given functional group (and its parent refs) instead of the ECU variant.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_by_sid_and_name(
        &self,
        service_id: u8,
        name: &str,
        functional_group_name: Option<&str>,
    ) -> Result<DiagComm, DiagServiceError>;

    /// Get parameter metadata for a specific service, including constant values for PHYS-CONST and
    /// CODED-CONST parameters.
    /// This is useful for discovering which DIDs are handled by which services.
    /// # Errors
    /// Will return `Err` if the service cannot be found or parameter metadata cannot be extracted.
    fn get_request_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<ServiceParameterMetadata>, DiagServiceError>;
    /// Get parameter metadata for the POS-RESPONSE of a service.
    /// Includes byte layout and type information for response payload construction.
    /// # Errors
    /// Will return `Err` if the service cannot be found or metadata cannot be extracted.
    fn get_response_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<ResponseParameterInfo>, DiagServiceError>;
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
    fn get_components_data_info(&self, security_plugin: &DynamicPlugin) -> Vec<ComponentDataInfo>;
    /// Retrieve all `read` services for a specific functional group's diag layer.
    /// # Errors
    /// Will return `Err` if the functional group cannot be found.
    fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError>;
    /// Retrieve all configuration type services for the current ECU variant.
    /// # Errors
    /// Returns `DiagServiceError` if the lookup failed.
    fn get_components_configurations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>;
    /// Retrieve all `RoutineControl` (SID 0x31) operations for the current ECU variant,
    /// with flags indicating available subfunctions (Stop/RequestResults).
    fn get_components_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Vec<ComponentOperationsInfo>;
    /// Check which `RoutineControl` subfunctions (Stop 0x02, `RequestResults` 0x03) are defined
    /// for the given routine service name.
    ///
    /// Returns `Ok(RoutineSubfunctions)` if the Start (0x01) service exists.
    /// `has_stop` and `has_request_results` indicate whether those subfunctions are also defined.
    ///
    /// # Errors
    /// Returns `Err(DiagServiceError::NotFound)` if the Start service for the given name is not
    /// found in the ECU description.
    fn get_routine_subfunctions(
        &self,
        service_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError>;
    /// Retrieve all `RoutineControl` (SID 0x31) operations for a specific functional group,
    /// with flags indicating available subfunctions (Stop/RequestResults).
    /// # Errors
    /// Returns `DiagServiceError` if the functional group cannot be found.
    fn get_functional_group_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError>;
    /// Check which `RoutineControl` subfunctions (Stop 0x02, `RequestResults` 0x03) are defined
    /// for a specific routine within a functional group.
    ///
    /// Returns `Ok(RoutineSubfunctions)` if the Start (0x01) subfunction for the given service
    /// name is found within the functional group.
    /// `has_stop` and `has_request_results` indicate whether those subfunctions are also defined.
    ///
    /// # Errors
    /// Returns `Err(DiagServiceError::NotFound)` if the functional group does not exist or if the
    /// Start service for the given name is not found within it.
    fn get_functional_group_routine_subfunctions(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_ids;

    fn make_payload(data: Vec<u8>) -> ServicePayload {
        ServicePayload {
            data,
            source_address: 0x1000,
            target_address: 0x0001,
            new_session: None,
            new_security: None,
        }
    }

    // echo_byte_count

    #[test]
    fn echo_byte_count_read_data_by_identifier() {
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::READ_DATA_BY_IDENTIFIER),
            2
        );
    }

    #[test]
    fn echo_byte_count_write_data_by_identifier() {
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::WRITE_DATA_BY_IDENTIFIER),
            2
        );
    }

    #[test]
    fn echo_byte_count_io_control_by_identifier() {
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER),
            2
        );
    }

    #[test]
    fn echo_byte_count_routine_control() {
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::ROUTINE_CONTROL),
            3
        );
    }

    #[test]
    fn echo_byte_count_other_services_returns_zero() {
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::SESSION_CONTROL),
            0
        );
        assert_eq!(ServicePayload::echo_byte_count(service_ids::ECU_RESET), 0);
        assert_eq!(
            ServicePayload::echo_byte_count(service_ids::TESTER_PRESENT),
            0
        );
    }

    // has_matching_echo_bytes: ReadDataByIdentifier

    #[test]
    fn rdbi_matching_did_returns_true() {
        // Request: ReadDataByIdentifier DID 0xF190
        let request = vec![0x22, 0xF1, 0x90];
        // Response: positive (0x62) with matching DID
        let response = make_payload(vec![0x62, 0xF1, 0x90, 0x01, 0x02, 0x03]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn rdbi_mismatched_did_returns_false() {
        // Request: ReadDataByIdentifier DID 0xF190
        let request = vec![0x22, 0xF1, 0x90];
        // Response: positive (0x62) with WRONG DID (0xF200 instead of 0xF190)
        let response = make_payload(vec![0x62, 0xF2, 0x00, 0x01, 0x02, 0x03]);
        assert!(!response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn rdbi_mismatched_did_single_byte_difference_returns_false() {
        // Request: ReadDataByIdentifier DID 0xF190
        let request = vec![0x22, 0xF1, 0x90];
        // Response: DID 0xF191 (off by one)
        let response = make_payload(vec![0x62, 0xF1, 0x91, 0xAA]);
        assert!(!response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn rdbi_response_too_short_for_echo_returns_false() {
        // Request: ReadDataByIdentifier DID 0xF190
        let request = vec![0x22, 0xF1, 0x90];
        // Response: only has SID + 1 byte (missing second DID byte)
        let response = make_payload(vec![0x62, 0xF1]);
        assert!(!response.has_matching_echo_bytes(&request));
    }

    // has_matching_echo_bytes: negative response passthrough

    #[test]
    fn negative_response_always_returns_true() {
        // Negative responses are validated by is_negative_response_for_sid, not echo bytes.
        let request = vec![0x22, 0xF1, 0x90];
        // Negative response: 0x7F, original SID, NRC
        let response = make_payload(vec![0x7F, 0x22, 0x31]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    // has_matching_echo_bytes: services without echo validation

    #[test]
    fn session_control_no_echo_validation() {
        let request = vec![0x10, 0x03]; // DiagnosticSessionControl - extendedSession
        // Response has different subfunction - but no echo validation for this SID
        let response = make_payload(vec![0x50, 0x01, 0x00, 0x19]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    // has_matching_echo_bytes: RoutineControl

    #[test]
    fn routine_control_matching_returns_true() {
        // Request: RoutineControl Start (0x01) + RoutineID 0x1001
        let request = vec![0x31, 0x01, 0x10, 0x01];
        // Response: positive (0x71) with matching subfunction and RoutineID
        let response = make_payload(vec![0x71, 0x01, 0x10, 0x01, 0xAA]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn routine_control_suppress_positive_response_bit_masked() {
        // Request: RoutineControl Start with suppressPosRsp (0x81) + RoutineID 0x1001
        let request = vec![0x31, 0x81, 0x10, 0x01];
        // Response: positive (0x71) with subfunction 0x01 (bit 7 cleared)
        let response = make_payload(vec![0x71, 0x01, 0x10, 0x01]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn routine_control_wrong_routine_id_returns_false() {
        // Request: RoutineControl Start + RoutineID 0x1001
        let request = vec![0x31, 0x01, 0x10, 0x01];
        // Response: correct subfunction but wrong RoutineID (0x2002)
        let response = make_payload(vec![0x71, 0x01, 0x20, 0x02]);
        assert!(!response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn routine_control_wrong_subfunction_returns_false() {
        // Request: RoutineControl Start (0x01) + RoutineID 0x1001
        let request = vec![0x31, 0x01, 0x10, 0x01];
        // Response: subfunction 0x02 (Stop) with correct RoutineID
        let response = make_payload(vec![0x71, 0x02, 0x10, 0x01]);
        assert!(!response.has_matching_echo_bytes(&request));
    }

    // has_matching_echo_bytes: edge cases

    #[test]
    fn empty_request_data_returns_true() {
        let response = make_payload(vec![0x62, 0xF1, 0x90, 0x01]);
        assert!(response.has_matching_echo_bytes(&[]));
    }

    #[test]
    fn request_too_short_for_echo_returns_true() {
        // Request has SID but no DID bytes (malformed, but we don't fail)
        let request = vec![0x22];
        let response = make_payload(vec![0x62, 0xF1, 0x90, 0x01]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    // has_matching_echo_bytes: WriteDataByIdentifier

    #[test]
    fn wdbi_matching_did_returns_true() {
        // Request: WriteDataByIdentifier DID 0xF190 + data
        let request = vec![0x2E, 0xF1, 0x90, 0xAA, 0xBB];
        // Response: positive (0x6E) with matching DID
        let response = make_payload(vec![0x6E, 0xF1, 0x90]);
        assert!(response.has_matching_echo_bytes(&request));
    }

    #[test]
    fn wdbi_mismatched_did_returns_false() {
        // Request: WriteDataByIdentifier DID 0xF190
        let request = vec![0x2E, 0xF1, 0x90, 0xAA];
        // Response: positive with wrong DID
        let response = make_payload(vec![0x6E, 0xF2, 0x00]);
        assert!(!response.has_matching_echo_bytes(&request));
    }
}
