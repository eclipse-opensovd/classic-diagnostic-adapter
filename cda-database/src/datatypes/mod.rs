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
    DiagServiceError,
    datatypes::{ComParamConfig, ComParamValue, DeserializableCompParam, FlatbBufConfig},
};
pub use comparam::*;
pub use data_operation::*;
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
pub use diag_coded_type::*;
use ouroboros::self_referencing;
use serde::Serialize;
pub use service::*;

use crate::{
    datatypes,
    flatbuf::diagnostic_description::dataformat,
    mdd_data::{load_ecudata, read_ecudata},
};

#[cfg(feature = "database-builder")]
pub mod database_builder;

pub(crate) mod comparam;
pub(crate) mod data_operation;
pub(crate) mod diag_coded_type;
pub(crate) mod dtc;
pub(crate) mod jobs;
pub(crate) mod service;

#[macro_export]
macro_rules! dataformat_wrapper {
    ($name:ident, $inner:ty) => {
        #[repr(transparent)]
        #[derive(Clone, Debug)]
        pub struct $name(pub $inner);

        impl std::ops::Deref for $name {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                $name(inner)
            }
        }
    };
    ($name:ident<$lt:lifetime>, $inner:ty) => {
        #[repr(transparent)]
        #[derive(Clone, Debug)]
        pub struct $name<$lt>(pub $inner);

        impl<$lt> std::ops::Deref for $name<$lt> {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<$lt> From<$inner> for $name<$lt> {
            fn from(inner: $inner) -> Self {
                $name(inner)
            }
        }
    };
}

macro_rules! impl_diag_coded_type {
    ($type_name:ident) => {
        impl $type_name<'_> {
            /// Get the `DiagCodedType` of the type and convert into the cda interface type
            /// # Errors
            /// Returns `DiagServiceError` if the `DiagCodedType`
            /// is not found or cannot be converted
            pub fn diag_coded_type(&self) -> Result<DiagCodedType, DiagServiceError> {
                if let Some(dc) = self.0.diag_coded_type() {
                    dc.try_into()
                } else {
                    Err(DiagServiceError::InvalidDatabase(format!(
                        "Expected DiagCodedType for {}",
                        stringify!($type_name)
                    )))
                }
            }
        }
    };
}

dataformat_wrapper!(EcuDb<'a>, dataformat::EcuData<'a>);
dataformat_wrapper!(ParentRef<'a>, dataformat::ParentRef<'a>);
dataformat_wrapper!(Variant<'a>, dataformat::Variant<'a>);
dataformat_wrapper!(Protocol<'a>, dataformat::Protocol<'a>);
dataformat_wrapper!(State<'a>, dataformat::State<'a>);
dataformat_wrapper!(StateChart<'a>, dataformat::StateChart<'a>);

// Requests, Responses...
dataformat_wrapper!(DiagService<'a>, dataformat::DiagService<'a>);
dataformat_wrapper!(DiagComm<'a>, dataformat::DiagComm<'a>);
dataformat_wrapper!(DiagLayer<'a>, dataformat::DiagLayer<'a>);
dataformat_wrapper!(Parameter<'a>, dataformat::Param<'a>);
dataformat_wrapper!(Request<'a>, dataformat::Request<'a>);
dataformat_wrapper!(Response<'a>, dataformat::Response<'a>);

// DOPS
dataformat_wrapper!(DopField<'a>, dataformat::Field<'a>);
dataformat_wrapper!(DataOperation<'a>, dataformat::DOP<'a>);
dataformat_wrapper!(StructureDop<'a>, dataformat::Structure<'a>);
dataformat_wrapper!(MuxDop<'a>, dataformat::MUXDOP<'a>);
dataformat_wrapper!(DtcDop<'a>, dataformat::DTCDOP<'a>);
dataformat_wrapper!(NormalDop<'a>, dataformat::NormalDOP<'a>);
dataformat_wrapper!(EndOfPdu<'a>, dataformat::EndOfPduField<'a>);
dataformat_wrapper!(DynamicLengthField<'a>, dataformat::DynamicLengthField<'a>);
dataformat_wrapper!(EnvDataDescDop<'a>, dataformat::EnvDataDesc<'a>);
dataformat_wrapper!(EnvDataDop<'a>, dataformat::EnvData<'a>);
dataformat_wrapper!(StaticFieldDop<'a>, dataformat::StaticField<'a>);
dataformat_wrapper!(DynamicLengthDop<'a>, dataformat::DynamicLengthField<'a>);
dataformat_wrapper!(SdOrSdg<'a>, dataformat::SDOrSDG<'a>);
dataformat_wrapper!(Sdgs<'a>, dataformat::SDGS<'a>);

impl_diag_coded_type!(DtcDop);
impl_diag_coded_type!(NormalDop);

// Multiplexer
dataformat_wrapper!(Case<'a>, dataformat::Case<'a>);
dataformat_wrapper!(DefaultCase<'a>, dataformat::DefaultCase<'a>);

dataformat_wrapper!(DbDataType, dataformat::DataType);

impl DefaultCase<'_> {
    #[must_use]
    pub fn case_struct_dop(&self) -> Option<StructureDop<'_>> {
        self.0
            .structure()
            .and_then(|s| s.specific_data_as_structure().map(Into::into))
    }
}

impl DiagService<'_> {
    #[must_use]
    pub fn request_id(&self) -> Option<u8> {
        // allow the truncation, so we can re-use the same conversion function
        // for the sub-function id which is u16
        // per ISO 14229-1 the SID is 1 byte
        #[allow(clippy::cast_possible_truncation)]
        self.find_request_sid_or_sub_func_param(0, 0)
            .map(|(sid, _)| sid as u8)
    }

    #[must_use]
    pub fn request_sub_function_id(&self) -> Option<(u16, u32)> {
        self.find_request_sid_or_sub_func_param(1, 0)
    }

    #[must_use]
    fn find_request_sid_or_sub_func_param(
        &self,
        byte_pos: u32,
        bit_pos: u32,
    ) -> Option<(u16, u32)> {
        let request = self.0.request()?;
        let params = request.params()?;

        params.iter().find_map(|p| {
            if p.byte_position().unwrap_or(0) != byte_pos
                || p.bit_position().unwrap_or(0) != bit_pos
            {
                return None;
            }

            let coded_const = p.specific_data_as_coded_const()?;
            let diag_coded_type = coded_const.diag_coded_type()?;
            if diag_coded_type.base_data_type() != (*DbDataType::A_UINT_32) {
                return None;
            }

            let standard_length_type = diag_coded_type.specific_data_as_standard_length_type()?;

            // SIDRQ validation
            if standard_length_type.condensed() || standard_length_type.bit_mask().is_some() {
                return None;
            }

            // Parse value
            let value = coded_const.coded_value()?.parse::<u16>().ok()?;
            Some((value, standard_length_type.bit_length()))
        })
    }
}

impl TryInto<cda_interfaces::DiagComm> for DiagService<'_> {
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

        let service_id = self.request_id().ok_or(DiagServiceError::InvalidDatabase(
            "DiagService missing request_id".to_owned(),
        ))?;

        Ok(cda_interfaces::DiagComm {
            name,
            type_: service_id.try_into()?,
            lookup_name: self
                .diag_comm()
                .and_then(|dc| dc.short_name())
                .map(ToOwned::to_owned),
        })
    }
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

impl From<DataType> for dataformat::DataType {
    fn from(value: DataType) -> Self {
        match value {
            DataType::Int32 => dataformat::DataType::A_INT_32,
            DataType::UInt32 => dataformat::DataType::A_UINT_32,
            DataType::Float32 => dataformat::DataType::A_FLOAT_32,
            DataType::Float64 => dataformat::DataType::A_FLOAT_64,
            DataType::AsciiString => dataformat::DataType::A_ASCIISTRING,
            DataType::Utf8String => dataformat::DataType::A_UTF_8_STRING,
            DataType::Unicode2String => dataformat::DataType::A_UNICODE_2_STRING,
            DataType::ByteField => dataformat::DataType::A_BYTEFIELD,
        }
    }
}

impl From<CompuCategory> for dataformat::CompuCategory {
    fn from(value: CompuCategory) -> Self {
        match value {
            CompuCategory::Identical => dataformat::CompuCategory::IDENTICAL,
            CompuCategory::Linear => dataformat::CompuCategory::LINEAR,
            CompuCategory::ScaleLinear => dataformat::CompuCategory::SCALE_LINEAR,
            CompuCategory::TextTable => dataformat::CompuCategory::TEXT_TABLE,
            CompuCategory::CompuCode => dataformat::CompuCategory::COMPU_CODE,
            CompuCategory::TabIntp => dataformat::CompuCategory::TAB_INTP,
            CompuCategory::RatFunc => dataformat::CompuCategory::RAT_FUNC,
            CompuCategory::ScaleRatFunc => dataformat::CompuCategory::SCALE_RAT_FUNC,
        }
    }
}

pub enum ParamType {
    CodedConst,
    Dynamic,
    LengthKey,
    MatchingRequestParam,
    NrcConst,
    PhysConst,
    Reserved,
    System,
    TableEntry,
    TableKey,
    TableStruct,
    Value,
}

#[derive(PartialEq, Eq, Debug)]
pub enum ParentRefType {
    NONE,
    Variant,
    Protocol,
    FunctionalGroup,
    TableDop,
    EcuSharedData,
}

impl TryFrom<dataformat::ParamType> for ParamType {
    type Error = DiagServiceError;

    fn try_from(value: dataformat::ParamType) -> Result<Self, Self::Error> {
        match value {
            dataformat::ParamType::CODED_CONST => Ok(ParamType::CodedConst),
            dataformat::ParamType::DYNAMIC => Ok(ParamType::Dynamic),
            dataformat::ParamType::LENGTH_KEY => Ok(ParamType::LengthKey),
            dataformat::ParamType::MATCHING_REQUEST_PARAM => Ok(ParamType::MatchingRequestParam),
            dataformat::ParamType::NRC_CONST => Ok(ParamType::NrcConst),
            dataformat::ParamType::PHYS_CONST => Ok(ParamType::PhysConst),
            dataformat::ParamType::RESERVED => Ok(ParamType::Reserved),
            dataformat::ParamType::SYSTEM => Ok(ParamType::System),
            dataformat::ParamType::TABLE_ENTRY => Ok(ParamType::TableEntry),
            dataformat::ParamType::TABLE_KEY => Ok(ParamType::TableKey),
            dataformat::ParamType::TABLE_STRUCT => Ok(ParamType::TableStruct),
            dataformat::ParamType::VALUE => Ok(ParamType::Value),
            _ => Err(DiagServiceError::InvalidDatabase(format!(
                "Unknown ParamType: {value:?}",
            ))),
        }
    }
}

impl TryFrom<dataformat::ParentRefType> for ParentRefType {
    type Error = DiagServiceError;

    fn try_from(value: dataformat::ParentRefType) -> Result<Self, Self::Error> {
        match value {
            dataformat::ParentRefType::NONE => Ok(ParentRefType::NONE),
            dataformat::ParentRefType::Variant => Ok(ParentRefType::Variant),
            dataformat::ParentRefType::Protocol => Ok(ParentRefType::Protocol),
            dataformat::ParentRefType::FunctionalGroup => Ok(ParentRefType::FunctionalGroup),
            dataformat::ParentRefType::TableDop => Ok(ParentRefType::TableDop),
            dataformat::ParentRefType::EcuSharedData => Ok(ParentRefType::EcuSharedData),
            _ => Err(DiagServiceError::InvalidDatabase(format!(
                "Unknown ParentRefType: {value:?}",
            ))),
        }
    }
}

impl Parameter<'_> {
    #[must_use]
    pub fn byte_position(&self) -> u32 {
        self.0.byte_position().unwrap_or(0)
    }
    #[must_use]
    pub fn bit_position(&self) -> u32 {
        self.0.bit_position().unwrap_or(0)
    }
    /// Get the `ParamType` of the Parameter
    /// # Errors
    /// Returns if the `ParamType` cannot be converted i.e. the flatbuf type
    /// has an unknown value.
    pub fn param_type(&self) -> Result<ParamType, DiagServiceError> {
        self.0.param_type().try_into()
    }
}

impl From<dataformat::LongName<'_>> for LongName {
    fn from(val: dataformat::LongName<'_>) -> Self {
        LongName {
            value: val.value().map(ToOwned::to_owned),
            ti: val.ti().map(ToOwned::to_owned),
        }
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
    ecu_data: Option<EcuData>,
    flatbuf_config: FlatbBufConfig,
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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct LongName {
    pub value: Option<String>,
    pub ti: Option<String>,
}

impl DiagnosticDatabase {
    /// Create a new `DiagnosticDatabase` from the given ECU database path and ECU data blob.
    /// # Errors
    /// Returns an error if the ECU data blob cannot be read.
    /// # Panics
    /// When `FlatBufConfig::verify` is disabled and an invalid ECU data blob is provided.
    pub fn new(
        ecu_database_path: String,
        ecu_data_blob: Vec<u8>,
        flatbuf_config: FlatbBufConfig,
    ) -> Result<Self, DiagServiceError> {
        let ecu_data = EcuDataTryBuilder {
            blob: ecu_data_blob,
            data_builder: |ecu_data_blob| {
                read_ecudata(ecu_data_blob, &flatbuf_config).map_err(|e| {
                    DiagServiceError::InvalidDatabase(format!(
                        "Failed to read ECU data from blob: {e}"
                    ))
                })
            },
        }
        .try_build()?;

        Ok(DiagnosticDatabase {
            ecu_database_path,
            ecu_data: Some(ecu_data),
            flatbuf_config,
        })
    }

    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.ecu_data.is_some()
    }

    pub fn unload(&mut self) {
        self.ecu_data = None;
    }

    /// Load the ECU data from the ECU database path.
    /// # Errors
    /// Returns an error if the ECU data cannot be loaded.
    /// # Panics
    /// If the ECU data is invalid and `FlatbBufConfig::verify` is disabled.
    pub fn load(&mut self) -> Result<(), DiagServiceError> {
        let ecu_data = load_ecudata(&self.ecu_database_path)
            .map_err(|e| DiagServiceError::InvalidDatabase(e.to_string()))?;
        *self = DiagnosticDatabase::new(
            self.ecu_database_path.clone(),
            ecu_data.1,
            self.flatbuf_config.clone(),
        )?;
        Ok(())
    }

    /// Find the logical address of the given type in
    /// the diagnostic database for the given protocol.
    /// # Errors
    /// * `DiagServiceError::DatabaseEntryNotFound` if the com param is not found or is invalid.
    /// * `DiagServiceError::ParameterConversionError` if the com param value cannot be converted
    pub fn find_logical_address(
        &self,
        type_: LogicalAddressType,
        diag_database: &DiagnosticDatabase,
        protocol: &dataformat::Protocol,
    ) -> Result<u16, DiagServiceError> {
        let (param_name, additional_param_name) = match type_ {
            LogicalAddressType::Ecu(response_id_table, ecu_address) => {
                (response_id_table, Some(ecu_address))
            }
            LogicalAddressType::Gateway(p) | LogicalAddressType::Functional(p) => (p, None),
        };

        match comparam::lookup(diag_database, protocol, &param_name)? {
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

    /// Get the ECU data, which is the root of the database
    /// # Errors
    /// `DiagServiceError::InvalidDatabase` if ECU data is not loaded
    pub fn ecu_data(&self) -> Result<&dataformat::EcuData<'_>, DiagServiceError> {
        self.ecu_data
            .as_ref()
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU data not loaded".to_owned()))
            .map(|ecu_data| ecu_data.borrow_data())
    }

    /// Get the ECU name from the ECU data
    /// # Errors
    /// `DiagServiceError::InvalidDatabase` if ECU data is not loaded or ECU name not found
    pub fn ecu_name(&self) -> Result<String, DiagServiceError> {
        self.ecu_data()?
            .ecu_name()
            .map(ToOwned::to_owned)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU name not found".to_owned()))
    }

    /// Get all diagnostic layers from the ECU data
    /// # Errors
    /// `DiagServiceError::InvalidDatabase` if ECU data is not loaded
    pub fn diag_layers(&self) -> Result<Vec<datatypes::DiagLayer<'_>>, DiagServiceError> {
        Ok(self
            .ecu_data()?
            .variants()
            .into_iter()
            .flat_map(|vars| vars.iter())
            .filter_map(|variant| variant.diag_layer())
            .map(datatypes::DiagLayer)
            .collect::<Vec<_>>())
    }

    /// Get the base variant from the ECU data
    /// # Errors
    /// `DiagServiceError::InvalidDatabase` if no base variant is found
    pub fn base_variant(&'_ self) -> Result<Variant<'_>, DiagServiceError> {
        let ecu_data = self.ecu_data()?;
        ecu_data
            .variants()
            .and_then(|variants| variants.iter().find(dataformat::Variant::is_base_variant))
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
                if let Ok(value) = T::parse_from_db(&simple.value, simple.unit.as_ref()) {
                    value
                } else {
                    tracing::warn!(
                        param_name = %com_param.name,
                        param_value = %simple.value,
                        unit = ?simple.unit,
                        "Failed to deserialize Simple Value for com param, using default"
                    );
                    com_param.default.clone()
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

    /// Get all functional groups from the ECU data
    /// # Errors
    /// `DiagServiceError::InvalidDatabase` if ECU data is not loaded or no functional groups found
    pub fn functional_groups(
        &self,
    ) -> Result<Vec<dataformat::FunctionalGroup<'_>>, DiagServiceError> {
        let ecu_data = self.ecu_data()?;
        ecu_data
            .functional_groups()
            .map(|groups| groups.iter().collect())
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "No functional groups found in ECU data.".to_owned(),
                )
            })
    }
}
