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

use hashbrown::{HashMap, HashSet};

use crate::{
    DiagComm, DiagServiceError, DoipComParamProvider, EcuSchemaProvider, Id, SecurityAccess,
    UdsComParamProvider,
    datatypes::{
        ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo, SdSdg, single_ecu,
    },
    diagservices::{DiagServiceResponse, UdsPayloadData},
};

#[derive(Clone, Copy)]
pub enum EcuState {
    Online,
    Offline,
    NotTested,
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
    pub new_session_id: Option<Id>,
    pub new_security_access_id: Option<Id>,
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
    #[must_use]
    fn variant_name(&self) -> Option<String>;

    #[must_use]
    fn state(&self) -> EcuState;

    #[must_use]
    fn protocol(&self) -> Protocol;

    #[must_use]
    fn is_loaded(&self) -> bool;

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
    ) -> Result<(), DiagServiceError>;
    fn get_variant_detection_requests(&self) -> &HashSet<String>;
    /// Communication parameters for the ECU.
    fn comparams(&self) -> ComplexComParamValue;
    fn sdgs(&self, service: Option<&DiagComm>) -> Result<Vec<SdSdg>, DiagServiceError>;
    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn´t match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    fn convert_from_uds(
        &self,
        diag_service: &DiagComm,
        raw_payload: &[u8],
        map_to_json: bool,
    ) -> Result<Self::Response, DiagServiceError>;
    /// Creates a `ServicePayload` and processes transitions based on raw UDS data,
    /// as received from a generic data endpoint.
    ///
    /// Returns the `ServicePayload` with resolved transitions.
    ///
    /// # Errors
    /// Returns `Err` if the payload cannot be matched to any diagnostic service.
    fn check_genericservice(&self, rawdata: Vec<u8>) -> Result<ServicePayload, DiagServiceError>;
    /// Converts given `UdsPayloadData` into a UDS request payload for the given `DiagService`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the `UdsPayloadData` doesn´t provide required parameters
    /// for the `DiagService` request or if elements of the `UdsPayloadData` cannot be mapped to
    /// the raw UDS bytestream.
    fn create_uds_payload(
        &self,
        diag_service: &DiagComm,
        data: Option<UdsPayloadData>,
    ) -> Result<ServicePayload, DiagServiceError>;
    /// Looks up a single ECU job by name for the current ECU variant.
    /// # Errors
    /// Will return `Err` if the job cannot be found in the database
    /// Unlikely other case is that neither a lookup in the current nor the base variant succeeded.
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError>;
    /// Update the internally tracked ecu session.
    /// Has to be called after changing the session, to make sure the transition lookup keep working
    /// # Errors
    /// This is also (re)starting the reset task that is
    /// setting the session and security access back to the default value.
    /// To do this the defaults have to looked up which might fail.
    /// In that case the error is forwarded
    fn set_session(&self, session: Id, expiration: Duration) -> Result<(), DiagServiceError>;
    /// Update the internally tracked ecu security access.
    /// Has to be called after changing the session, to make sure the transition lookup keep working
    /// # Errors
    /// This is also (re)starting the reset task that is setting the session and security
    /// access back to the default value.
    /// To do this the defaults have to looked up which might fail.
    /// In that case the error is forwarded
    fn set_security_access(
        &self,
        security_access: Id,
        expiration: Duration,
    ) -> Result<(), DiagServiceError>;
    /// Lookup the transition between the active session and the requested one.
    /// # Errors
    /// * `DiagServiceError::AccessDenied` if no transition exists
    /// * `DiagServiceError::NotFound` on various lookup errors.
    fn lookup_session_change(&self, session: &str) -> Result<(Id, DiagComm), DiagServiceError>;
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
    ) -> Result<SecurityAccess, DiagServiceError>;
    /// Retrieves the name of the current ecu session, i.e. 'extended', 'programming' or 'default'.
    /// The examples above differ depending on the parameterization of the ECU.
    fn session(&self) -> String;
    /// Retrieves the name of the current ecu security level,
    /// i.e. 'level_42'
    /// The exact values depends on the ECU parameterization.
    fn security_access(&self) -> String;
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
    fn lookup_service_by_sid(&self, service_id: u8) -> Result<Vec<String>, DiagServiceError>;
    /// Retrieve all `read` services for the current ECU variant.
    fn get_components_data_info(&self) -> Vec<ComponentDataInfo>;
    /// Retrieve all configuration type services for the current ECU variant.
    fn get_components_configurations_info(
        &self,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError>;
    /// Retrieve all 'single ecu' jobs for the current ECU variant.
    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo>;
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
        }
    }
}
