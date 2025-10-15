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

use std::{fmt::Debug, ops::Deref};

use cda_interfaces::{
    DiagServiceError, Id, STRINGS, StringId,
    datatypes::{ComParamConfig, ComParamValue, DeserializableCompParam},
};
pub use comparam::*;
pub use data_operation::*;
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
pub use diag_coded_type::*;
use ouroboros::self_referencing;
// pub use dtc::*;
// pub use functional_classes::*;
// use hashbrown::HashMap;
// pub use jobs::*;
// pub use parameter::*;
// pub use sd_sdg::*;
use serde::Serialize;

// pub use service::*;
// pub use state_charts::*;
// pub use variant::*;
use crate::{
    datatypes,
    mdd_data::{load_ecudata, read_ecudata},
    proto::diagnostic_description::dataformat,
};

pub(crate) mod comparam;
pub(crate) mod data_operation;
pub(crate) mod diag_coded_type;
pub(crate) mod dtc;
pub(crate) mod functional_classes;
pub(crate) mod jobs;
pub(crate) mod parameter;
pub(crate) mod sd_sdg;
pub(crate) mod service;
pub(crate) mod state_charts;
pub(crate) mod variant;

// pub type DiagnosticServiceMap = HashMap<Id, DiagnosticService>;
// pub type RequestMap = HashMap<Id, Request>;
// pub type ResponseMap = HashMap<Id, Response>;
// pub type ParameterMap = HashMap<Id, Parameter>;
// pub type ComParamMap = HashMap<Id, ComParam>;
// pub type DiagCodedTypeMap = HashMap<Id, DiagCodedType>;
// pub type DOPMap = HashMap<Id, DataOperation>;
// pub type VariantMap = HashMap<StringId, Variant>;
// pub type ProtocolMap = HashMap<Id, Protocol>;
// pub type BaseServiceMap = HashMap<String, Id>;
// pub type SdgMap = HashMap<Id, Sdg>;
// pub type SdMap = HashMap<Id, Sd>;
// pub type DtcMap = HashMap<Id, Dtc>;

macro_rules! dataformat_wrapper {
    ($name:ident, $inner:ty) => {
        #[repr(transparent)]
        pub struct $name(pub $inner);

        impl Deref for $name {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
    ($name:ident<$lt:lifetime>, $inner:ty) => {
        #[repr(transparent)]
        pub struct $name<$lt>(pub $inner);

        impl<$lt> Deref for $name<$lt> {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

dataformat_wrapper!(Protocol<'a>, dataformat::Protocol<'a>);

dataformat_wrapper!(State<'a>, dataformat::State<'a>);
dataformat_wrapper!(StateChart<'a>, dataformat::StateChart<'a>);

dataformat_wrapper!(Variant<'a>, dataformat::Variant<'a>);
dataformat_wrapper!(SdOrSdg<'a>, dataformat::SDOrSDG<'a>);
dataformat_wrapper!(Sdgs<'a>, dataformat::SDGS<'a>);

dataformat_wrapper!(DiagService<'a>, dataformat::DiagService<'a>);
dataformat_wrapper!(DiagComm<'a>, dataformat::DiagComm<'a>);
dataformat_wrapper!(DiagLayer<'a>, dataformat::DiagLayer<'a>);

dataformat_wrapper!(Field<'a>, dataformat::Field<'a>);
dataformat_wrapper!(DataOperation<'a>, dataformat::DOP<'a>);
dataformat_wrapper!(DataOperationVariant, dataformat::SpecificDOPData);
dataformat_wrapper!(StructureDop<'a>, dataformat::Structure<'a>);
dataformat_wrapper!(MuxDop<'a>, dataformat::MUXDOP<'a>);
dataformat_wrapper!(CompuMethod<'a>, dataformat::CompuMethod<'a>); // todo alexmohr, might need the internal type back.
dataformat_wrapper!(CompuCategory, dataformat::CompuCategory); // todo alexmohr, might need the internal type back.
dataformat_wrapper!(CompuScale<'a>, dataformat::CompuScale<'a>); // todo alexmohr, might need the internal type back.

dataformat_wrapper!(DbDataType, dataformat::DataType);

dataformat_wrapper!(Parameter<'a>, dataformat::Param<'a>);
dataformat_wrapper!(ResponseType, dataformat::ResponseType);
dataformat_wrapper!(ParamType, dataformat::ParamType);

impl DiagService<'_> {
    pub fn request_id(&self) -> Option<(u16, StandardLengthType)> {
        let request = self.0.request()?;
        let params = request.params()?;
        let sid = params.iter().map(Parameter).find_map(|p| {
            if p.byte_pos() == 0 && p.bit_pos() == 0 {
                p.specific_data_as_coded_const()
            } else {
                None
            }
        })?;

        if sid
            .diag_coded_type()
            .is_none_or(|t| t.base_data_type().0 != (*(datatypes::DbDataType::A_UINT_32)).0)
        {
            return None;
        }

        let standard_length_type = sid
            .diag_coded_type()
            .and_then(|t| t.specific_data_as_standard_length_type())?;

        // SIDRQ should not be condensed, or contain a bitmask
        if standard_length_type.condensed() || standard_length_type.bit_mask().is_some() {
            return None;
        }

        // according to ISO_14229 SIDRQ is defined as XX16 eg, max 2 bytes
        if let Some(sid) = sid.coded_value().and_then(|v| v.parse::<u16>().ok()) {
            Some((sid, standard_length_type.into()))
        } else {
            None
        }
    }
}

impl TryInto<cda_interfaces::DiagComm> for DiagService {
    type Error = DiagServiceError;

    fn try_into(self) -> Result<cda_interfaces::DiagComm, Self::Error> {
        let diag_comm = self.diag_comm().ok_or(DiagServiceError::InvalidDatabase(
            "DiagService missing diag_comm".to_owned(),
        ))?;
        let name = diag_comm
            .short_name()
            .ok_or(DiagServiceError::InvalidDatabase(
                "DiagService missing name".to_owned(),
            ))?
            .to_owned();
        let service_prefix = if let Some((id, _)) = self.request_id() {
            (id >> 8) as u8
        } else {
            return Err(DiagServiceError::InvalidDatabase(
                "DiagService missing service_prefix".to_owned(),
            ));
        };

        Ok(cda_interfaces::DiagComm {
            name,
            type_: service_prefix.try_into()?,
            lookup_name: None,
        })
    }
}

#[allow(non_upper_case_globals)] // allowed in auto generated code too, to keep it consistent
impl DataOperationVariant {
    pub const NONE: Self = Self(dataformat::SpecificDOPData::NONE);
    pub const NormalDOP: Self = Self(dataformat::SpecificDOPData::NormalDOP);
    pub const EndOfPduField: Self = Self(dataformat::SpecificDOPData::EndOfPduField);
    pub const StaticField: Self = Self(dataformat::SpecificDOPData::StaticField);
    pub const EnvDataDesc: Self = Self(dataformat::SpecificDOPData::EnvDataDesc);
    pub const EnvData: Self = Self(dataformat::SpecificDOPData::EnvData);
    pub const DTCDOP: Self = Self(dataformat::SpecificDOPData::DTCDOP);
    pub const Structure: Self = Self(dataformat::SpecificDOPData::Structure);
    pub const MUXDOP: Self = Self(dataformat::SpecificDOPData::MUXDOP);
    pub const DynamicLengthField: Self = Self(dataformat::SpecificDOPData::DynamicLengthField);
}

impl DbDataType {
    pub const A_INT_32: Self = Self(dataformat::DataType::A_INT_32);
    pub const A_UINT_32: Self = Self(dataformat::DataType::A_UINT_32);
    pub const A_FLOAT_32: Self = Self(dataformat::DataType::A_FLOAT_32);
    pub const A_ASCIISTRING: Self = Self(dataformat::DataType::A_ASCIISTRING);
    pub const A_UTF_8_STRING: Self = Self(dataformat::DataType::A_UTF_8_STRING);
    pub const A_UNICODE_2_STRING: Self = Self(dataformat::DataType::A_UNICODE_2_STRING);
    pub const A_BYTEFIELD: Self = Self(dataformat::DataType::A_BYTEFIELD);
    pub const A_FLOAT_64: Self = Self(dataformat::DataType::A_FLOAT_64);
}

impl ParamType {
    pub const CODED_CONST: Self = Self(dataformat::ParamType::CODED_CONST);
    pub const DYNAMIC: Self = Self(dataformat::ParamType::DYNAMIC);
    pub const LENGTH_KEY: Self = Self(dataformat::ParamType::LENGTH_KEY);
    pub const MATCHING_REQUEST_PARAM: Self = Self(dataformat::ParamType::MATCHING_REQUEST_PARAM);
    pub const NRC_CONST: Self = Self(dataformat::ParamType::NRC_CONST);
    pub const PHYS_CONST: Self = Self(dataformat::ParamType::PHYS_CONST);
    pub const RESERVED: Self = Self(dataformat::ParamType::RESERVED);
    pub const SYSTEM: Self = Self(dataformat::ParamType::SYSTEM);
    pub const TABLE_ENTRY: Self = Self(dataformat::ParamType::TABLE_ENTRY);
    pub const TABLE_KEY: Self = Self(dataformat::ParamType::TABLE_KEY);
    pub const TABLE_STRUCT: Self = Self(dataformat::ParamType::TABLE_STRUCT);
    pub const VALUE: Self = Self(dataformat::ParamType::VALUE);
}

impl ResponseType {
    pub const POS_RESPONSE: Self = Self(dataformat::ResponseType::POS_RESPONSE);
    pub const NEG_RESPONSE: Self = Self(dataformat::ResponseType::NEG_RESPONSE);
    pub const GLOBAL_NEG_RESPONSE: Self = Self(dataformat::ResponseType::GLOBAL_NEG_RESPONSE);
}

impl CompuCategory {
    pub const IDENTICAL: Self = Self(dataformat::CompuCategory::IDENTICAL);
    pub const LINEAR: Self = Self(dataformat::CompuCategory::LINEAR);
    pub const SCALE_LINEAR: Self = Self(dataformat::CompuCategory::SCALE_LINEAR);
    pub const TEXT_TABLE: Self = Self(dataformat::CompuCategory::TEXT_TABLE);
    pub const COMPU_CODE: Self = Self(dataformat::CompuCategory::COMPU_CODE);
    pub const TAB_INTP: Self = Self(dataformat::CompuCategory::TAB_INTP);
    pub const RAT_FUNC: Self = Self(dataformat::CompuCategory::RAT_FUNC);
    pub const SCALE_RAT_FUNC: Self = Self(dataformat::CompuCategory::SCALE_RAT_FUNC);
}

impl Parameter {
    pub fn byte_pos(&self) -> u32 {
        self.0.byte_position().unwrap_or(0)
    }
    pub fn bit_pos(&self) -> u32 {
        self.0.bit_position().unwrap_or(0)
    }
}

#[self_referencing]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
#[derive(Debug)]
struct EcuData {
    blob: Vec<u8>,

    #[borrows(blob)]
    #[covariant]
    pub data: dataformat::EcuData<'this>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagnosticDatabase {
    ecu_database_path: String,
    pub ecu_name: String,
    ecu_data: Option<EcuData>,
    // pub variants: VariantMap,
    // pub services: DiagnosticServiceMap,
    // pub requests: RequestMap,
    // pub responses: ResponseMap,
    // pub params: ParameterMap,
    // pub com_params: ComParamMap,
    // pub diag_coded_types: DiagCodedTypeMap,
    // pub data_operations: DOPMap,
    //
    // pub base_variant_id: Id,
    // pub base_service_lookup: BaseServiceMap,
    // pub protocols: ProtocolMap,
    // pub sdgs: SdgMap,
    // pub sds: SdMap,
    // pub single_ecu_jobs: SingleEcuJobMap,
    // pub base_single_ecu_job_lookup: BaseSingleEcuJobMap,
    // pub state_charts: StateChartMap,
    // pub state_chart_lookup: HashMap<String, Id>,
    // pub base_state_chart_lookup: BaseStateChartMap,
    // pub functional_classes_lookup: FunctionalClassesLookupMap,
    // pub functional_classes: HashMap<Id, String>,
    // pub dtcs: DtcMap,
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

// impl From<&DbDiagComm> for DiagComm {
//     fn from(db_diag_comm: &DbDiagComm) -> Self {
//         let name = get_string_with_default!(db_diag_comm.lookup_name);
//         DiagComm {
//             name: name.clone(),
//             action: db_diag_comm.action.clone(),
//             type_: db_diag_comm.type_.clone(),
//             lookup_name: Some(name),
//         }
//     }
// }

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

// todo ????
// impl Default for DiagnosticDatabase {
//     fn default() -> Self {
//         DiagnosticDatabase {
//             ecu_database_path: String::new(),
//             ecu_name: String::new(),
//             ecu_data: dataformat::EcuData {
//                 _tab: proto::Message::default(),
//             },
//         }
//     }
// }

impl DiagnosticDatabase {
    pub fn new(
        ecu_database_path: String,
        ecu_data_blob: Vec<u8>,
    ) -> Result<Self, DiagServiceError> {
        let ecu_data = read_ecudata(&ecu_data_blob).map_err(DiagServiceError::InvalidDatabase)?;
        let ecu_name = ecu_data
            .ecu_name()
            .ok_or(DiagServiceError::InvalidDatabase(
                "ECU name is missing in ECU data".to_owned(),
            ))?
            .to_string();

        Ok(DiagnosticDatabase {
            ecu_database_path,
            ecu_name,
            ecu_data: Some(
                EcuDataBuilder {
                    blob: ecu_data_blob,
                    data_builder: |ecu_data_blob| read_ecudata(ecu_data_blob).unwrap(),
                }
                .build(),
            ),
        })

        // let params = get_parameters(&ecu_data, &ecu_database_path);
        //
        // let services = get_services(&ecu_data, &requests, &params)?;
        // let dops = get_data_operations(&ecu_data);
        //
        // let com_params = get_comparams(&ecu_data);
        // let diag_coded_types = get_diag_coded_types(&ecu_data);
        //
        // let single_ecu_jobs = get_single_ecu_jobs(&ecu_data)?;
        // let (state_charts, state_chart_lookup) = get_state_charts(&ecu_data, &services)?;
        //
        // let (variants, base_variant_id) =
        //     create_variant_map(&ecu_data, &services, &single_ecu_jobs, &state_charts)?;
        //
        // if base_variant_id == 0 {
        //     return Err(DiagServiceError::InvalidDatabase(
        //         "No base variant found.".to_owned(),
        //     ));
        // }
        // let base_service_lookup: BaseServiceMap = variants
        //     .get(&base_variant_id)
        //     .ok_or_else(|| {
        //         DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
        //     })?
        //     .service_lookup
        //     .clone();
        //
        // let base_single_ecu_job_lookup: BaseSingleEcuJobMap = variants
        //     .get(&base_variant_id)
        //     .ok_or_else(|| {
        //         DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
        //     })?
        //     .single_ecu_job_lookup
        //     .clone();
        //
        // let base_state_chart_lookup: BaseStateChartMap = variants
        //     .get(&base_variant_id)
        //     .ok_or_else(|| {
        //         DiagServiceError::InvalidDatabase("Base variant not found in variants.".to_owned())
        //     })?
        //     .state_charts_lookup
        //     .clone();
        //
        // let responses = get_responses(&ecu_data)?;
        // let protocols = get_protocols(&ecu_data)?;
        //
        // let sdgs = get_sdgs(
        //     &ecu_data,
        //     &ecu_database_path,
        //     variants.get(&base_variant_id).map_or(&[], |v| &v.sdgs),
        // );
        // let sds = get_sds(&ecu_data);
        // let functional_classes: HashMap<Id, String> = ecu_data
        //     .funct_classes
        //     .iter()
        //     .filter_map(|fc| {
        //         fc.id
        //             .as_ref()
        //             .map(|id| (id.value, fc.short_name.to_string()))
        //     })
        //     .collect();
        // let functional_classes_lookup = get_functional_classes_lookup(&ecu_data, &services);
        //
        // let dtc_records = get_dtcs(&ecu_data, &ecu_database_path);
    }

    pub fn is_loaded(&self) -> bool {
        self.ecu_data.is_some()
    }

    pub fn unload(&mut self) {
        self.ecu_data = None;
    }

    //  todo alexmohr
    pub fn load_variant_sdgs(&mut self, _variant: &Variant) -> Result<(), DiagServiceError> {
        // let (_, ecu_data_blob) = load_ecudata(&self.ecu_database_path)
        //     .map_err(|e| DiagServiceError::InvalidDatabase(e.to_string()))?;
        // let ecu_data = read_ecudata(&ecu_data_blob).map_err(DiagServiceError::InvalidDatabase)?;
        //
        // let sdgs = get_sdgs(
        //     &ecu_data,
        //     &self.ecu_database_path,
        //     self.variants.get(&variant_id).map_or(&[], |v| &v.sdgs),
        // );
        //
        // self.sdgs.extend(sdgs);
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), DiagServiceError> {
        let ecu_data = load_ecudata(&self.ecu_database_path)
            .map_err(|e| DiagServiceError::InvalidDatabase(e.to_string()))?;
        *self = DiagnosticDatabase::new(self.ecu_database_path.clone(), ecu_data.1)?;
        Ok(())
    }

    pub fn find_logical_address(
        &self,
        type_: LogicalAddressType,
        protocol: &dataformat::Protocol,
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

    pub fn ecu_data(&self) -> Result<&dataformat::EcuData<'_>, DiagServiceError> {
        self.ecu_data
            .as_ref()
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU data not loaded".to_owned()))
            .map(|ecu_data| ecu_data.borrow_data())
    }

    pub fn base_variant(&'_ self) -> Result<Variant<'_>, DiagServiceError> {
        let ecu_data = self.ecu_data()?;
        ecu_data
            .variants()
            .and_then(|variants| variants.iter().find(|v| v.is_base_variant()))
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("No base variant found in ECU data.".to_owned())
            })
            .map(Variant)
    }

    #[tracing::instrument(
        skip(self),
        fields(
            protocol = ?protocol,
            param_name = %com_param.name
        )
    )]
    pub fn find_com_param<T: DeserializableCompParam + Serialize + Debug + Clone>(
        &self,
        protocol: &dataformat::Protocol,
        com_param: &ComParamConfig<T>,
    ) -> T {
        let lookup_result = comparam::lookup(self, protocol, &com_param.name);
        match lookup_result {
            Ok(ComParamValue::Simple(simple)) => {
                match T::parse_from_db(&simple.value, simple.unit.as_ref()) {
                    Ok(value) => value,
                    Err(_) => {
                        tracing::warn!(
                            param_name = %com_param.name,
                            param_value = %simple.value,
                            unit = ?simple.unit,
                            "Failed to deserialize Simple Value for com param, using default"
                        );
                        com_param.default.clone()
                    }
                }
            }
            Ok(ComParamValue::Complex(_)) => {
                tracing::warn!(
                    param_name = %com_param.name,
                    "Using fallback for complex value - unexpected Complex value type"
                );
                com_param.default.clone()
            }
            Err(e) => {
                if let DiagServiceError::DatabaseEntryNotFound(e) = &e {
                    tracing::debug!(
                        param_name = %com_param.name,
                        error = %e,
                        "Using fallback - database entry not found"
                    );
                } else {
                    tracing::warn!(
                        param_name = %com_param.name,
                        error = %e,
                        "Using fallback - lookup error"
                    );
                }
                com_param.default.clone()
            }
        }
    }
}

// fn get_protocols(ecu_data: &EcuData) -> Result<ProtocolMap, DiagServiceError> {
//     ecu_data
//         .protocols
//         .iter()
//         .map(|p| {
//             let short_name_id = STRINGS.get_or_insert(
//                 &p.diag_layer
//                     .as_ref()
//                     .ok_or_else(|| {
//                         DiagServiceError::InvalidDatabase("Protocol has no DiagLayer.".to_owned())
//                     })?
//                     .short_name,
//             );
//             Ok((
//                 p.id.as_ref()
//                     .ok_or_else(|| ref_optional_none("Protocol.id"))?
//                     .value,
//                 Protocol {
//                     short_name: short_name_id,
//                 },
//             ))
//         })
//         .collect::<Result<ProtocolMap, DiagServiceError>>()
// }
