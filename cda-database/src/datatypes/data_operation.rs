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

//
use cda_interfaces::{DiagServiceError, util::decode_hex};

// #[cfg(feature = "deepsize")]
// use deepsize::DeepSizeOf;
//
use crate::{
    datatypes::{DataType, Id, LongName},
    proto::diagnostic_description::dataformat,
};
// use crate::proto::diagnostic_description::dataformat::SpecificDOPData;
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum DOPType {
//     Regular,
//     EnvDataDesc,
//     Mux,
//     DynamicEndMarkerField,
//     DynamicLengthField,
//     EndOfPduField,
//     StaticField,
//     EnvData,
//     Structure,
//     Dtc,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DataOperation {
//     pub type_: DOPType,
//     pub short_name: String,
//     pub variant: DataOperationVariant,
// }
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum DataOperationVariant {
//     Normal(NormalDop),
//     EndOfPdu(EndOfPduDop),
//     Structure(StructureDop),
//     EnvDataDesc(EnvDataDescDop),
//     EnvData(EnvDataDop),
//     Dtc(DtcDop),
//     StaticField(StaticFieldDop),
//     Mux(MuxDop),
//     DynamicLengthField(DynamicLengthDop),
// }
//
// impl TryFrom<dataformat::DOP<'_>> for DataOperationVariant {
//     type Error = DiagServiceError;
//
//     fn try_from(value: dataformat::DOP) -> Result<Self, Self::Error> {
//         match value.specific_data_type() {
//             SpecificDOPData::NormalDOP(_) => {
//                 let n = value
//                     .specific_data_as_normal_dop()
//                     .ok_or_else(|| {
//                         DiagServiceError::InvalidDatabase(
//                             "Expected NormalDOP specific data".to_owned(),
//                         )
//                     })?;
//                 DataOperationVariant::Normal(NormalDop{
//                     diag_type: n.d,
//                     compu_method: CompuMethod {},
//                     unit: None,
//                 })
//             }
//             SpecificDOPData::EndOfPduField(_) => {
//                 DataOperationVariant::EndOfPdu(
//                     EndOfPduDop{
//
//                     }
//                 )
//             }
//             SpecificDOPData::StaticField(_) => {
//
//             }
//             SpecificDOPData::EnvDataDesc(_) => {
//
//             }
//             SpecificDOPData::EnvData(_) => {
//
//             }
//             SpecificDOPData::DTCDOP(_) => {
//
//             }
//             SpecificDOPData::Structure(_) => {
//
//             }
//             SpecificDOPData::MUXDOP(_) => {
//
//             }
//             SpecificDOPData::DynamicLengthField(_) => {
//
//             }
//         }
//     }
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct EndOfPduDop {
//     pub min_items: u32,
//     pub max_items: Option<u32>,
//     pub field: DopField,
// }
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct NormalDop {
//     pub diag_type: Id,
//     pub compu_method: CompuMethod,
//     pub unit: Option<Unit>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct StructureDop {
//     pub params: Vec<Id>,
//     pub byte_size: u32,
//     pub visible: bool,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct EnvDataDescDop {
//     pub param_short_name: Option<StringId>,
//     pub param_path_short_name: Option<StringId>,
//     pub env_data_dops: Vec<Id>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct EnvDataDop {
//     pub dtc_values: Vec<u32>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct StaticFieldDop {
//     pub fixed_number_of_items: u32,
//     pub item_byte_size: u32,
//     pub field: DopField,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DtcDop {
//     pub diag_coded_type: Id,
//     pub physical_type: Option<PhysicalType>,
//     pub compu_method: CompuMethod,
//     pub dtc_refs: Vec<Id>,
//     pub is_visible: bool,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct MuxDop {
//     pub byte_position: u32,
//     pub switch_key: Option<SwitchKey>,
//     pub default_case: Option<Case>,
//     pub cases: Vec<Case>,
//     pub is_visible: bool,
// }
//
// #[derive(Debug, Clone)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct Case {
//     pub short_name: StringId,
//     pub long_name: Option<LongName>,
//     pub structure: Option<Id>,
//     pub lower_limit: Option<Limit>,
//     pub upper_limit: Option<Limit>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct SwitchKey {
//     pub byte_position: u32,
//     pub bit_position: u32,
//     pub dop: Option<Id>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DynamicLengthDop {
//     pub num_items_byte_pos: u32,
//     pub num_items_bit_pos: u32,
//     pub num_items_dop: Id,
//
//     /// Determines the offset from the start of the param to where the repeated
//     /// data begins.
//     pub first_element_offset: usize,
//     pub repeated_dop_id: Id,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct PhysicalType {
//     pub precision: u32,
//     pub base_data_type: DataType,
//     pub display_radix: Option<Radix>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum Radix {
//     Hex,
//     Dec,
//     Bin,
//     Oct,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DopFieldBasicStruct {
//     pub struct_id: Id,
//     pub name: Option<StringId>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DopFieldEnvDataDesc {
//     pub env_data_desc: Id,
//     pub name: Option<StringId>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum DopFieldValue {
//     BasicStruct(DopFieldBasicStruct),
//     EnvDataDesc(DopFieldEnvDataDesc),
// }
//
// /// A dop field may either reference a basic structure or an env data desc.
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct DopField {
//     pub value: DopFieldValue,
//     pub is_visible: bool,
// }
//
// #[derive(Copy, Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum CompuCategory {
//     Identical,
//     Linear,
//     ScaleLinear,
//     TextTable,
//     CompuCode,
//     TabIntp,
//     RatFunc,
//     ScaleRatFunc,
// }
//
// #[derive(Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct CompuMethod {
//     pub category: CompuCategory,
//     pub internal_to_phys: CompuFunction,
// }
// #[derive(Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct CompuFunction {
//     pub scales: Vec<CompuScale>,
// }
// #[derive(Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct CompuScale {
//     pub lower_limit: Option<Limit>,
//     pub upper_limit: Option<Limit>,
//     pub rational_coefficients: Option<CompuRationalCoefficients>,
//     pub consts: Option<CompuValues>,
// }
// #[derive(Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct CompuValues {
//     pub v: f64,
//     pub vt: Option<StringId>,
//     pub vt_ti: Option<StringId>,
// }
//
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum IntervalType {
    Open,
    Closed,
    Infinite,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Limit {
    /// A limit can be a numeric type, a string or a byte field.
    /// Numeric types are compared numerically
    /// For strings only the equals operator is supported
    /// For byte fields comparison works like this:
    /// * Values are padded with 0x00 until they are the same length
    /// * Right most byte is least significant (Big endian order)
    /// * Read large unsigned int from the limit and the comparison target
    ///   and compare numerically.
    pub value: String,
    pub interval_type: IntervalType,
}

impl TryInto<u32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<u32, Self::Error> {
        let f: f64 = self.try_into()?;
        Ok(f as u32)
    }
}

impl TryInto<i32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<i32, Self::Error> {
        let f: f64 = self.try_into()?;
        Ok(f as i32)
    }
}

impl TryInto<f32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<f32, Self::Error> {
        if self.value.is_empty() {
            // treat empty string as 0
            return Ok(f32::default());
        }
        self.value.parse().map_err(|e| {
            DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into f32, {e:?}",
                self.value
            ))
        })
    }
}

impl TryInto<f64> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<f64, Self::Error> {
        if self.value.is_empty() {
            // treat empty string as 0
            return Ok(f64::default());
        }
        self.value.parse().map_err(|e| {
            DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into f64, {e:?}",
                self.value
            ))
        })
    }
}

impl TryInto<Vec<u8>> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.value
            .split_whitespace()
            .map(|value| {
                if value.chars().all(|c| c.is_ascii_digit()) {
                    value
                        .parse::<u8>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for ByteField".to_owned(),
                            )
                        })
                } else if value.contains('.') {
                    let float_value = value.parse::<f64>().map_err(|e| {
                        DiagServiceError::ParameterConversionError(format!(
                            "Invalid value for float, error={e}"
                        ))
                    })?;
                    Ok((float_value as u8).to_be_bytes().to_vec())
                } else if let Some(stripped) = value.to_lowercase().strip_prefix("0x") {
                    decode_hex(stripped)
                } else {
                    decode_hex(value)
                }
            })
            .collect::<Result<Vec<_>, DiagServiceError>>()
            .map(|vecs| vecs.into_iter().flatten().collect())
    }
}

impl Into<Limit> for dataformat::Limit {
    fn into(self) -> Limit {
        Limit {
            value: self.value().unwrap_or_default().to_owned(),
            interval_type: self.interval_type().into(),
        }
    }
}

impl Into<IntervalType> for dataformat::IntervalType {
    fn into(self) -> IntervalType {
        match self {
            dataformat::IntervalType::OPEN => IntervalType::Open,
            dataformat::IntervalType::CLOSED => IntervalType::Closed,
            dataformat::IntervalType::INFINITE => IntervalType::Infinite,
            _ => IntervalType::Infinite,
        }
    }
}

//
// #[derive(Clone, Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct CompuRationalCoefficients {
//     pub numerator: Vec<f64>,
//     pub denominator: Vec<f64>,
// }
//
// fn fallback_factors(u: &dataformat::Unit) -> Option<f64> {
//     // guess some factors
//     let name = u.short_name()?.to_lowercase();
//     if name.starts_with("giga") {
//         Some(1_000_000_000.0)
//     } else if name.starts_with("mega") {
//         Some(1_000_000.0)
//     } else if name.starts_with("kilo") || name == "km" {
//         Some(1000.0)
//     } else if name.starts_with("centi") || name == "cm" {
//         Some(100.0)
//     } else if name.starts_with("deca") {
//         Some(10.0)
//     } else if name.starts_with("deci") {
//         Some(0.1)
//     } else if name.starts_with("milli") || name == "ms" || name == "mv" {
//         Some(0.001)
//     } else if name.starts_with("micro") {
//         Some(0.000_001)
//     } else if name.starts_with("nano") {
//         Some(0.000_000_001)
//     } else {
//         None
//     }
// }
// //
// // fn get_compu_method(
// //     compu_method: Option<&dataformat::CompuMethod>,
// // ) -> Result<CompuMethod, DiagServiceError> {
// //     if compu_method.is_none() {
// //         return Err(DiagServiceError::InvalidDatabase(
// //             "CompuMethod not set".to_owned(),
// //         ));
// //     }
// //
// //     Ok(CompuMethod {
// //         category: compu_method
// //             .unwrap()
// //             .category
// //             .ok_or_else(|| {
// //                 DiagServiceError::InvalidDatabase("CompuMethod has no category".to_owned())
// //             })?
// //             .try_into()?,
// //         internal_to_phys: CompuFunction {
// //             scales: compu_method
// //                 .unwrap()
// //                 .internal_to_phys
// //                 .as_ref()
// //                 .map_or_else(
// //                     || Ok(Vec::new()),
// //                     |tophys| {
// //                         tophys
// //                             .compu_scales
// //                             .iter()
// //                             .map(|s| {
// //                                 let lower_limit = get_limit(s.lower_limit.as_ref())?;
// //                                 let upper_limit = get_limit(s.upper_limit.as_ref())?;
// //
// //                                 let consts = s.consts.as_ref().map(|c| CompuValues {
// //                                     v: c.v(),
// //                                     vt: option_str_to_string(c.vt.as_ref()),
// //                                     vt_ti: option_str_to_string(c.vt_ti.as_ref()),
// //                                 });
// //
// //                                 Ok(CompuScale {
// //                                     lower_limit,
// //                                     upper_limit,
// //                                     rational_coefficients: s.rational_co_effs.as_ref().map(|r| {
// //                                         CompuRationalCoefficients {
// //                                             numerator: r.numerator.clone(),
// //                                             denominator: r.denominator.clone(),
// //                                         }
// //                                     }),
// //                                     consts,
// //                                 })
// //                             })
// //                             .collect::<Result<Vec<_>, DiagServiceError>>()
// //                     },
// //                 )?,
// //         },
// //     })
// // }
//
// // fn get_limit(limit: Option<&dataformat::Limit>) -> Result<Option<Limit>, DiagServiceError> {
// //     limit
// //         .map(|l| {
// //             l.interval_type.try_into().map(|interval_type| Limit {
// //                 value: l.value.clone(),
// //                 interval_type,
// //             })
// //         })
// //         .transpose()
// // }
// //
// // fn get_dop_field(f: &dop::Field) -> Result<DopField, DiagServiceError> {
// //     fn create_dop_field_from_basic_structure(
// //         f: &dop::Field,
// //         dop_ref: &dop::Ref,
// //     ) -> Result<DopField, DiagServiceError> {
// //         let ref_value = dop_ref
// //             .r#ref
// //             .as_ref()
// //             .ok_or_else(|| {
// //                 DiagServiceError::InvalidDatabase(
// //                     "DopField.basicStructure.ref_pb is missing".to_owned(),
// //                 )
// //             })?
// //             .value;
// //
// //         Ok(DopField {
// //             value: DopFieldValue::BasicStruct(DopFieldBasicStruct {
// //                 struct_id: ref_value,
// //                 name: option_str_to_string(f.basic_structure_short_name_ref.as_ref()),
// //             }),
// //             is_visible: f.is_visible(),
// //         })
// //     }
// //
// //     fn create_dop_field_from_env_data_desc(
// //         f: &dop::Field,
// //         dop_ref: &dop::Ref,
// //     ) -> Result<DopField, DiagServiceError> {
// //         let ref_value = dop_ref
// //             .r#ref
// //             .as_ref()
// //             .ok_or_else(|| {
// //                 DiagServiceError::InvalidDatabase(
// //                     "DopField.envDataDesc.ref_pb is missing".to_owned(),
// //                 )
// //             })?
// //             .value;
// //
// //         Ok(DopField {
// //             value: DopFieldValue::EnvDataDesc(DopFieldEnvDataDesc {
// //                 env_data_desc: ref_value,
// //                 name: option_str_to_string(f.env_data_desc_short_name_ref.as_ref()),
// //             }),
// //             is_visible: f.is_visible(),
// //         })
// //     }
// //
// //     match (&f.basic_structure, &f.env_data_desc) {
// //         (Some(dop_ref), None) => create_dop_field_from_basic_structure(f, dop_ref),
// //         (None, Some(dop_ref)) => create_dop_field_from_env_data_desc(f, dop_ref),
// //         (Some(_), Some(_)) => Err(DiagServiceError::InvalidDatabase(
// //             "DopField has both basicStructure and envDataDesc".to_owned(),
// //         )),
// //         (None, None) => Err(DiagServiceError::InvalidDatabase(
// //             "DopField has neither basicStructure nor envDataDesc".to_owned(),
// //         )),
// //     }
// // }
// //
// // impl From<dop::DopType> for DOPType {
// //     fn from(dop_type: dop::DopType) -> Self {
// //         match dop_type {
// //             dop::DopType::Regular => DOPType::Regular,
// //             dop::DopType::EnvDataDesc => DOPType::EnvDataDesc,
// //             dop::DopType::Mux => DOPType::Mux,
// //             dop::DopType::DynamicEndMarkerField => DOPType::DynamicEndMarkerField,
// //             dop::DopType::DynamicLengthField => DOPType::DynamicLengthField,
// //             dop::DopType::EndOfPduField => DOPType::EndOfPduField,
// //             dop::DopType::StaticField => DOPType::StaticField,
// //             dop::DopType::EnvData => DOPType::EnvData,
// //             dop::DopType::Structure => DOPType::Structure,
// //             dop::DopType::Dtc => DOPType::Dtc,
// //         }
// //     }
// // }
// //
// // impl TryFrom<i32> for DOPType {
// //     type Error = DiagServiceError;
// //
// //     fn try_from(value: i32) -> Result<Self, Self::Error> {
// //         dop::DopType::try_from(value)
// //             .map_err(|_| {
// //                 DiagServiceError::InvalidDatabase(format!("Invalid DOPType value: {value}"))
// //             })
// //             .map(Self::from)
// //     }
// // }
// //
// // impl From<dataformat::compu_method::CompuCategory> for CompuCategory {
// //     fn from(cat: dataformat::compu_method::CompuCategory) -> Self {
// //         match cat {
// //             dataformat::compu_method::CompuCategory::Identical => CompuCategory::Identical,
// //             dataformat::compu_method::CompuCategory::Linear => CompuCategory::Linear,
// //             dataformat::compu_method::CompuCategory::ScaleLinear => CompuCategory::ScaleLinear,
// //             dataformat::compu_method::CompuCategory::TextTable => CompuCategory::TextTable,
// //             dataformat::compu_method::CompuCategory::CompuCode => CompuCategory::CompuCode,
// //             dataformat::compu_method::CompuCategory::TabIntp => CompuCategory::TabIntp,
// //             dataformat::compu_method::CompuCategory::RatFunc => CompuCategory::RatFunc,
// //             dataformat::compu_method::CompuCategory::ScaleRatFunc => CompuCategory::ScaleRatFunc,
// //         }
// //     }
// // }
// //
// // impl TryFrom<i32> for CompuCategory {
// //     type Error = DiagServiceError;
// //
// //     fn try_from(value: i32) -> Result<Self, Self::Error> {
// //         dataformat::compu_method::CompuCategory::try_from(value)
// //             .map_err(|_| {
// //                 DiagServiceError::InvalidDatabase(format!("Invalid CompuCategory value: {value}"))
// //             })
// //             .map(Self::from)
// //     }
// // }
// //
// // impl From<limit::IntervalType> for IntervalType {
// //     fn from(interval_type: limit::IntervalType) -> Self {
// //         match interval_type {
// //             limit::IntervalType::Open => IntervalType::Open,
// //             limit::IntervalType::Closed => IntervalType::Closed,
// //             limit::IntervalType::Infinite => IntervalType::Infinite,
// //         }
// //     }
// // }
// //
// // impl TryFrom<i32> for IntervalType {
// //     type Error = DiagServiceError;
// //
// //     fn try_from(value: i32) -> Result<Self, Self::Error> {
// //         limit::IntervalType::try_from(value)
// //             .map_err(|_| {
// //                 DiagServiceError::InvalidDatabase(format!("Invalid IntervalType value: {value}"))
// //             })
// //             .map(Self::from)
// //     }
// // }
// //
// // impl From<dataformat::physical_type::Radix> for Radix {
// //     fn from(radix: dataformat::physical_type::Radix) -> Self {
// //         match radix {
// //             dataformat::physical_type::Radix::Hex => Radix::Hex,
// //             dataformat::physical_type::Radix::Dec => Radix::Dec,
// //             dataformat::physical_type::Radix::Bin => Radix::Bin,
// //             dataformat::physical_type::Radix::Oct => Radix::Oct,
// //         }
// //     }
// // }
// //
// // impl TryFrom<i32> for Radix {
// //     type Error = DiagServiceError;
// //
// //     fn try_from(value: i32) -> Result<Self, Self::Error> {
// //         dataformat::physical_type::Radix::try_from(value)
// //             .map_err(|_| DiagServiceError::InvalidDatabase(format!("Invalid Radix value: {value}")))
// //             .map(Self::from)
// //     }
// // }
// //
// // #[cfg(test)]
// // mod tests {
// //     use super::*;
// //
// //     #[test]
// //     fn test_limit_try_into_f32_empty_string() {
// //         let limit = Limit {
// //             value: "".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<f32, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), 0.0_f32);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_f64_empty_string() {
// //         let limit = Limit {
// //             value: "".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<f64, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), 0.0_f64);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_u32_empty_string() {
// //         let limit = Limit {
// //             value: "".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<u32, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), 0_u32);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_hex_values() {
// //         let limit = Limit {
// //             value: "0x01 0x02 0x03".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_hex_without_prefix() {
// //         let limit = Limit {
// //             value: "AB CD EF".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_mixed_case_hex() {
// //         let limit = Limit {
// //             value: "0xAa 0xBb 0xCc".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0xAA, 0xBB, 0xCC]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_numeric_values() {
// //         let limit = Limit {
// //             value: "1 2 255".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![1, 2, 255]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_float_values() {
// //         let limit = Limit {
// //             value: "1.5 2.7 255.9".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![1, 2, 255]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_mixed_values() {
// //         let limit = Limit {
// //             value: "0x01 2 3.5 0xFF".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![1, 2, 3, 255]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_single_value() {
// //         let limit = Limit {
// //             value: "0x42".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0x42]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_empty_string() {
// //         let limit = Limit {
// //             value: "".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), Vec::<u8>::new());
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_whitespace_only() {
// //         let limit = Limit {
// //             value: "   ".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), Vec::<u8>::new());
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_numeric_overflow() {
// //         let limit = Limit {
// //             value: "256".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert!(result.is_err());
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_invalid_hex() {
// //         let limit = Limit {
// //             value: "0xGG".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert!(result.is_err());
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_invalid_float() {
// //         let limit = Limit {
// //             value: "not.a.number".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert!(result.is_err());
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_multi_byte_hex() {
// //         let limit = Limit {
// //             value: "0x1234 0x5678".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0x12, 0x34, 0x56, 0x78]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_zero_values() {
// //         let limit = Limit {
// //             value: "0x00 0 0.0".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![0, 0, 0]);
// //     }
// //
// //     #[test]
// //     fn test_limit_try_into_vec_u8_extra_whitespace() {
// //         let limit = Limit {
// //             value: "  0x01   0x02  0x03  ".to_string(),
// //             interval_type: IntervalType::Closed,
// //         };
// //
// //         let result: Result<Vec<u8>, _> = (&limit).try_into();
// //         assert_eq!(result.unwrap(), vec![1, 2, 3]);
// //     }
// // }
