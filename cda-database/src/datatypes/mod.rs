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

use std::fmt::Debug;

use cda_interfaces::{
    DiagComm, DiagCommAction, DiagCommType, DiagServiceError, Id, STRINGS, StringId,
    datatypes::{ComParamConfig, ComParamValue, DeserializableCompParam},
    get_string_with_default,
};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;
use serde::Serialize;

use crate::{
    mdd_data::{load_ecudata, read_ecudata},
    proto::dataformat::EcuData,
};

const LOG_TARGET: &str = "ECU-Db-Mapping";

pub use comparam::*;
pub use data_operation::*;
pub use diag_coded_type::*;
pub use functional_classes::*;
pub use jobs::*;
pub use parameter::*;
pub use sd_sdg::*;
pub use service::*;
pub use state_charts::*;
pub use variant::*;

pub(crate) mod comparam;
pub(crate) mod data_operation;
pub(crate) mod diag_coded_type;
pub(crate) mod functional_classes;
pub(crate) mod jobs;
pub(crate) mod parameter;
pub(crate) mod sd_sdg;
pub(crate) mod service;
pub(crate) mod state_charts;
pub(crate) mod variant;

pub type DiagnosticServiceMap = HashMap<Id, DiagnosticService>;
pub type RequestMap = HashMap<Id, Request>;
pub type ResponseMap = HashMap<Id, Response>;
pub type ParameterMap = HashMap<Id, Parameter>;
pub type ComParamMap = HashMap<Id, ComParam>;
pub type DiagCodedTypeMap = HashMap<Id, DiagCodedType>;
pub type DOPMap = HashMap<Id, DataOperation>;
pub type VariantMap = HashMap<Id, Variant>;
pub type ProtocolMap = HashMap<Id, Protocol>;
pub type BaseServiceMap = HashMap<String, Id>;
pub type SdgMap = HashMap<Id, Sdg>;
pub type SdMap = HashMap<Id, Sd>;

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagnosticDatabase {
    ecu_database_path: String,
    pub ecu_name: String,
    pub services: DiagnosticServiceMap,
    pub requests: RequestMap,
    pub responses: ResponseMap,
    pub params: ParameterMap,
    pub com_params: ComParamMap,
    pub diag_coded_types: DiagCodedTypeMap,
    pub data_operations: DOPMap,
    pub variants: VariantMap,
    pub base_variant_id: Id,
    pub base_service_lookup: BaseServiceMap,
    pub protocols: ProtocolMap,
    pub sdgs: SdgMap,
    pub sds: SdMap,
    pub single_ecu_jobs: SingleEcuJobMap,
    pub base_single_ecu_job_lookup: BaseSingleEcuJobMap,
    pub state_charts: StateChartMap,
    pub state_chart_lookup: HashMap<String, Id>,
    pub base_state_chart_lookup: BaseStateChartMap,
    pub functional_classes: HashMap<String, FunctClass>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Protocol {
    pub short_name: StringId,
}

#[derive(Clone)]
pub enum LogicalAddressType {
    /// Lookup for the ECU address.
    /// Looking up the ECU address usually consists of two parts.
    /// The first element in this tuple is the name for response ID table,
    /// the second is the name for the ECU address.
    /// Both names are used to look up the address in the com params.
    Ecu(String, String),
    /// Lookup for the gateway address. The value is the name of the gateway address com param.
    Gateway(String),
    /// Lookup for the functional address.
    /// The value is the name of the functional address com param.
    Functional(String),
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DbDiagComm {
    action: DiagCommAction,
    type_: DiagCommType,
    pub(crate) lookup_name: StringId,
}

impl From<&DbDiagComm> for DiagComm {
    fn from(db_diag_comm: &DbDiagComm) -> Self {
        let name = get_string_with_default!(db_diag_comm.lookup_name);
        DiagComm {
            name: name.clone(),
            action: db_diag_comm.action.clone(),
            type_: db_diag_comm.type_.clone(),
            lookup_name: Some(name),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct LongName {
    pub value: Option<StringId>,
    pub ti: Option<StringId>,
}

const REF_OPTIONAL_NONE_MSG: &str = "ID Reference is not set";
fn ref_optional_none(ctx: &str) -> DiagServiceError {
    DiagServiceError::InvalidDatabase(format!("{REF_OPTIONAL_NONE_MSG} in {ctx}"))
}

fn option_str_to_string(opt: Option<&String>) -> Option<StringId> {
    opt.map(|s| STRINGS.get_or_insert(s))
}

impl DiagnosticDatabase {
    pub fn new(ecu_database_path: String, ecu_data_blob: &[u8]) -> Result<Self, DiagServiceError> {
        let ecu_data = read_ecudata(ecu_data_blob).map_err(DiagServiceError::InvalidDatabase)?;

        let requests = get_requests(&ecu_data)?;
        let params = get_parameters(&ecu_data, &ecu_database_path);

        let services = get_services(&ecu_data, &requests, &params)?;
        let dops = get_data_operations(&ecu_data);

        let com_params = get_comparams(&ecu_data);
        let diag_coded_types = get_diag_coded_types(&ecu_data);

        let single_ecu_jobs = get_single_ecu_jobs(&ecu_data)?;
        let (state_charts, state_chart_lookup) = get_state_charts(&ecu_data, &services)?;

        let (variants, base_variant_id) =
            create_variant_map(&ecu_data, &services, &single_ecu_jobs, &state_charts)?;

        if base_variant_id == 0 {
            return Err(DiagServiceError::InvalidDatabase(
                "No base variant found.".to_owned(),
            ));
        }
        let base_service_lookup: BaseServiceMap = variants
            .get(&base_variant_id)
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
            })?
            .service_lookup
            .clone();

        let base_single_ecu_job_lookup: BaseSingleEcuJobMap = variants
            .get(&base_variant_id)
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
            })?
            .single_ecu_job_lookup
            .clone();

        let base_state_chart_lookup: BaseStateChartMap = variants
            .get(&base_variant_id)
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
            })?
            .state_charts_lookup
            .clone();

        let responses = get_responses(&ecu_data)?;
        let protocols = get_protocols(&ecu_data)?;

        let sdgs = get_sdgs(
            &ecu_data,
            &ecu_database_path,
            variants.get(&base_variant_id).map_or(&[], |v| &v.sdgs),
        );
        let sds = get_sds(&ecu_data);

        let functional_classes = get_functional_classes(&ecu_data, &services);

        Ok(DiagnosticDatabase {
            ecu_database_path,
            ecu_name: ecu_data.ecu_name.to_string(),
            services,
            requests,
            responses,
            params,
            com_params,
            diag_coded_types,
            data_operations: dops,
            variants,
            base_variant_id,
            base_service_lookup,
            protocols,
            sdgs,
            sds,
            single_ecu_jobs,
            base_single_ecu_job_lookup,
            state_charts,
            state_chart_lookup,
            base_state_chart_lookup,
            functional_classes,
        })
    }

    pub fn is_loaded(&self) -> bool {
        !self.services.is_empty() // todo: add more checks
    }

    pub fn unload(&mut self) {
        self.services = HashMap::new();
        self.requests = HashMap::new();
        self.responses = HashMap::new();
        self.params = HashMap::new();
        self.com_params = HashMap::new();
        self.diag_coded_types = HashMap::new();
        self.data_operations = HashMap::new();
        self.variants = HashMap::new();
        self.protocols = HashMap::new();
        self.single_ecu_jobs = HashMap::new();
        self.base_single_ecu_job_lookup = HashMap::new();
    }

    pub fn load_variant_sdgs(&mut self, variant_id: Id) -> Result<(), DiagServiceError> {
        let (_, ecu_data_blob) = load_ecudata(&self.ecu_database_path)
            .map_err(|e| DiagServiceError::InvalidDatabase(e.to_string()))?;
        // let mut ecu_data_reader = quick_protobuf::BytesReader::from_bytes(&ecu_data_blob);
        let ecu_data = read_ecudata(&ecu_data_blob).map_err(DiagServiceError::InvalidDatabase)?;

        let sdgs = get_sdgs(
            &ecu_data,
            &self.ecu_database_path,
            self.variants.get(&variant_id).map_or(&[], |v| &v.sdgs),
        );

        self.sdgs.extend(sdgs);
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), DiagServiceError> {
        let ecu_data = load_ecudata(&self.ecu_database_path)
            .map_err(|e| DiagServiceError::InvalidDatabase(e.to_string()))?;
        *self = DiagnosticDatabase::new(self.ecu_database_path.clone(), &ecu_data.1)?;
        Ok(())
    }

    pub fn find_logical_address(
        &self,
        type_: LogicalAddressType,
        protocol: &Protocol,
    ) -> Result<u16, DiagServiceError> {
        let (param_name, additional_param_name) = match type_ {
            LogicalAddressType::Ecu(response_id_table, ecu_address) => {
                (response_id_table, Some(ecu_address))
            }
            LogicalAddressType::Gateway(p) => (p, None),
            LogicalAddressType::Functional(p) => (p, None),
        };
        let logical_address_lookup_result = comparam::lookup(self, protocol, &param_name)?;

        match logical_address_lookup_result {
            ComParamValue::Simple(simple_value) => {
                let val_as_u16 = simple_value.value.parse::<u16>().map_err(|e| {
                    DiagServiceError::ParameterConversionError(format!("Invalid address: {e}"))
                })?;
                Ok(val_as_u16)
            }
            ComParamValue::Complex(complex) => {
                match complex.get(&additional_param_name.ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "{param_name:?} not found in complex value"
                    ))
                })?) {
                    None => Err(DiagServiceError::InvalidDatabase(format!(
                        "{param_name} not found in complex value"
                    ))),
                    Some(ComParamValue::Simple(address)) => {
                        let val_as_u16 = address.value.parse::<u16>().map_err(|e| {
                            DiagServiceError::ParameterConversionError(format!(
                                "Invalid address: {e}"
                            ))
                        })?;
                        Ok(val_as_u16)
                    }
                    _ => Err(DiagServiceError::InvalidDatabase(format!(
                        "{param_name} is not a simple value"
                    ))),
                }
            }
        }
    }

    pub fn find_com_param<T: DeserializableCompParam + Serialize + Debug + Clone>(
        &self,
        protocol: &Protocol,
        com_param: &ComParamConfig<T>,
    ) -> T {
        let lookup_result = comparam::lookup(self, protocol, &com_param.name);
        match lookup_result {
            Ok(ComParamValue::Simple(simple)) => {
                match T::parse_from_db(&simple.value, simple.unit.as_ref()) {
                    Ok(value) => value,
                    Err(_) => {
                        log::warn!(
                            "Failed to deserialize Simple Value for com param {} with value {}",
                            com_param.name,
                            simple.value,
                        );
                        com_param.default.clone()
                    }
                }
            }
            Ok(ComParamValue::Complex(_)) => {
                log::warn!(
                    "using fallback for {}, error: unexpected Complex value",
                    com_param.name
                );
                com_param.default.clone()
            }
            Err(e) => {
                if let DiagServiceError::DatabaseEntryNotFound(e) = &e {
                    log::debug!("using fallback for {}, error: {e}", com_param.name);
                } else {
                    log::warn!("using fallback for {}, error: {e}", com_param.name);
                }
                com_param.default.clone()
            }
        }
    }
}

fn get_protocols(ecu_data: &EcuData) -> Result<ProtocolMap, DiagServiceError> {
    ecu_data
        .protocols
        .iter()
        .map(|p| {
            let short_name_id = STRINGS.get_or_insert(
                &p.diag_layer
                    .as_ref()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("Protocol has no DiagLayer.".to_owned())
                    })?
                    .short_name,
            );
            Ok((
                p.id.as_ref()
                    .ok_or_else(|| ref_optional_none("Protocol.id"))?
                    .value,
                Protocol {
                    short_name: short_name_id,
                },
            ))
        })
        .collect::<Result<ProtocolMap, DiagServiceError>>()
}
