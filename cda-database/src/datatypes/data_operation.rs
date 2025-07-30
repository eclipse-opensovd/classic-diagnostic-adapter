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

use cda_interfaces::{DiagServiceError, STRINGS, StringId, datatypes::Unit, get_string};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{
        DOPMap, DataType, Id, LOG_TARGET, LongName, option_str_to_string, ref_optional_none,
    },
    proto::dataformat::{
        self, EcuData,
        dop::{self},
        limit,
    },
};

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DOPType {
    Regular,
    EnvDataDesc,
    Mux,
    DynamicEndMarkerField,
    DynamicLengthField,
    EndOfPduField,
    StaticField,
    EnvData,
    Structure,
    Dtc,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DataOperation {
    pub type_: DOPType,
    pub short_name: String,
    pub variant: DataOperationVariant,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DataOperationVariant {
    Normal(NormalDop),
    EndOfPdu(EndOfPduDop),
    Structure(StructureDop),
    EnvDataDesc(EnvDataDescDop),
    EnvData(EnvDataDop),
    Dtc(DtcDop),
    StaticField(StaticFieldDop),
    Mux(MuxDop),
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct EndOfPduDop {
    pub min_items: u32,
    pub max_items: u32,
    pub field: DopField,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct NormalDop {
    pub diag_type: Id,
    pub compu_method: CompuMethod,
    pub unit: Option<Unit>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StructureDop {
    pub params: Vec<Id>,
    pub byte_size: u32,
    pub visible: bool,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct EnvDataDescDop {
    pub param_short_name: Option<StringId>,
    pub param_path_short_name: Option<StringId>,
    pub env_data_dops: Vec<Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct EnvDataDop {
    pub dtc_values: Vec<u32>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StaticFieldDop {
    pub fixed_number_of_items: u32,
    pub item_byte_size: u32,
    pub field: DopField,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DtcDop {
    pub diag_coded_type: Id,
    pub physical_type: Option<PhysicalType>,
    pub compu_method: CompuMethod,
    pub dtc_refs: Vec<Id>,
    pub is_visible: bool,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MuxDop {
    pub byte_position: u32,
    pub switch_key: Option<SwitchKey>,
    pub default_case: Option<Case>,
    pub cases: Vec<Case>,
    pub is_visible: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Case {
    pub short_name: StringId,
    pub long_name: Option<LongName>,
    pub structure: Option<Id>,
    pub lower_limit: Result<Limit, DiagServiceError>,
    pub upper_limit: Result<Limit, DiagServiceError>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct SwitchKey {
    pub byte_position: u32,
    pub bit_position: u32,
    pub dop: Option<Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct PhysicalType {
    pub precision: u32,
    pub base_data_type: DataType,
    pub display_radix: Option<Radix>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum Radix {
    Hex,
    Dec,
    Bin,
    Oct,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DopField {
    pub basic_structure: Id,
    pub basic_structure_short_name: Option<StringId>,
    pub env_data_desc: Option<Id>,
    pub env_data_desc_short_name: Option<StringId>,
    pub is_visible: bool,
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum CompuCategory {
    Identical,
    Linear,
    ScaleLinear,
    TextTable,
    CompuCode,
    TabIntp,
    RatFunc,
    ScaleRatFunc,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CompuMethod {
    pub category: CompuCategory,
    pub internal_to_phys: CompuFunction,
}
#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CompuFunction {
    pub scales: Vec<CompuScale>,
}
#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CompuScale {
    pub lower_limit: Result<Limit, DiagServiceError>,
    pub upper_limit: Result<Limit, DiagServiceError>,
    pub rational_coefficients: Option<CompuRationalCoefficients>,
    pub consts: Option<CompuValues>,
}
#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CompuValues {
    pub v: f64,
    pub vt: Option<StringId>,
    pub vt_ti: Option<StringId>,
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum IntervalType {
    Open,
    Closed,
    Infinite,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Limit {
    pub value: f64,
    pub interval_type: IntervalType,
}
#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CompuRationalCoefficients {
    pub numerator: Vec<f64>,
    pub denominator: Vec<f64>,
}

pub(super) fn get_data_operations(ecu_data: &EcuData) -> DOPMap {
    ecu_data
        .dops
        .iter()
        .map(|d| {
            let dop_id =
                d.id.as_ref()
                    .ok_or_else(|| ref_optional_none("DOP.id"))?
                    .value;

            let variant = get_dop_variant(d, dop_id, ecu_data)?;

            Ok((
                dop_id,
                DataOperation {
                    type_: d.dop_type.try_into()?,
                    short_name: d.short_name.to_string(),
                    variant,
                },
            ))
        })
        .filter_map(|res: Result<_, DiagServiceError>| match res {
            Ok(res) => Some(res),
            Err(e) => {
                log::debug!(target: LOG_TARGET, "Error processing DOP: {e:?}");
                None
            }
        })
        .collect::<DOPMap>()
}

// TODO: Refactor this function an split it into smaller functions
// for each DOP type
#[allow(clippy::too_many_lines)]
fn get_dop_variant(
    d: &dataformat::Dop,
    dop_id: u32,
    ecu_data: &EcuData,
) -> Result<DataOperationVariant, DiagServiceError> {
    let variant = match &d.specific_data {
        Some(dop::SpecificData::NormalDop(n)) => {
            if n.diag_coded_type.is_none() {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "Normal DOP id[{dop_id}] has no diag type."
                )));
            }
            if n.compu_method.is_none() {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "Normal DOP id[{dop_id}] has no compu method."
                )));
            }

            DataOperationVariant::Normal(NormalDop {
                diag_type: n
                    .diag_coded_type
                    .as_ref()
                    .unwrap()
                    .r#ref
                    .as_ref()
                    .ok_or_else(|| {
                        ref_optional_none(&format!("id[{dop_id}] NormalDOP.diagCodedType.ref_pb"))
                    })?
                    .value,

                compu_method: get_compu_method(n.compu_method.as_ref())?,
                unit: n.unit_ref.and_then(|u_ref| {
                    ecu_data
                        .units
                        .iter()
                        .find(|u| u.id == u_ref.r#ref)
                        .map(|u| {
                            let factor = if u.factorsitounit.is_some() {
                                u.factorsitounit
                            } else {
                                fallback_factors(u)
                            };

                            Unit {
                                factor_to_si_unit: factor,
                                offset_to_si_unit: u.offsetitounit,
                            }
                        })
                }),
            })
        }
        Some(dop::SpecificData::EndOfPduField(eop)) => {
            let field = eop
                .field
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "EndOfPduDop id[{dop_id}] without field"
                    ))
                })
                .and_then(get_dop_field)?;
            DataOperationVariant::EndOfPdu(EndOfPduDop {
                min_items: eop.min_number_of_items(),
                max_items: eop.max_number_of_items(),
                field,
            })
        }
        Some(dop::SpecificData::Structure(structure)) => {
            DataOperationVariant::Structure(StructureDop {
                params: structure
                    .params
                    .iter()
                    .map(|p| {
                        p.r#ref
                            .as_ref()
                            .ok_or_else(|| {
                                ref_optional_none(&format!(
                                    "id[{dop_id}] Structure.params[].ref_pb"
                                ))
                            })
                            .map(|p| p.value)
                    })
                    .collect::<Result<Vec<_>, DiagServiceError>>()?,
                byte_size: structure.byte_size(),
                visible: structure.is_visible,
            })
        }
        Some(dop::SpecificData::EnvDataDesc(env_data_desc)) => {
            DataOperationVariant::EnvDataDesc(EnvDataDescDop {
                param_short_name: option_str_to_string(env_data_desc.param_short_name.as_ref()),
                param_path_short_name: option_str_to_string(
                    env_data_desc.param_path_short_name.as_ref(),
                ),
                env_data_dops: env_data_desc
                    .env_datas
                    .iter()
                    .map(|d: &dop::Ref| {
                        d.r#ref
                            .as_ref()
                            .ok_or_else(|| {
                                ref_optional_none(&format!(
                                    "id[{dop_id}] EnvDataDesc.envDataDops[].ref_pb"
                                ))
                            })
                            .map(|d| d.value)
                    })
                    .collect::<Result<Vec<_>, DiagServiceError>>()?,
            })
        }
        Some(dop::SpecificData::EnvData(env_data)) => DataOperationVariant::EnvData(EnvDataDop {
            dtc_values: env_data.dtc_values.clone(),
        }),
        Some(dop::SpecificData::DtcDop(dtc_dop)) => DataOperationVariant::Dtc(DtcDop {
            diag_coded_type: dtc_dop
                .diag_coded_type
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "DTC DOP id[{dop_id}] without diag coded type"
                    ))
                })?
                .r#ref
                .as_ref()
                .ok_or_else(|| {
                    ref_optional_none(&format!("id[{dop_id}] DTC DOP diag coded type ref_pb"))
                })?
                .value,
            physical_type: dtc_dop
                .physical_type
                .as_ref()
                .map(|p| {
                    Ok(PhysicalType {
                        precision: p.precision(),
                        base_data_type: p.base_data_type.try_into()?,
                        display_radix: if let Some(radix) = p.display_radix {
                            Some(radix.try_into()?)
                        } else {
                            None
                        },
                    })
                })
                .transpose()?,
            compu_method: get_compu_method(dtc_dop.compu_method.as_ref())?,
            dtc_refs: dtc_dop
                .dtcs
                .iter()
                .map(|d| {
                    d.r#ref
                        .as_ref()
                        .ok_or_else(|| {
                            ref_optional_none(&format!("id[{dop_id}] DTC DOP dtc_refs[].ref_pb"))
                        })
                        .map(|d| d.value)
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?,
            is_visible: dtc_dop.is_visible(),
        }),
        Some(dop::SpecificData::StaticField(static_field)) => {
            let field = static_field
                .field
                .as_ref()
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "EndOfPduDop id[{dop_id}] without field"
                    ))
                })
                .and_then(get_dop_field)?;
            DataOperationVariant::StaticField(StaticFieldDop {
                fixed_number_of_items: static_field.fixed_number_of_items,
                item_byte_size: static_field.item_byte_size,
                field,
            })
        }
        Some(dop::SpecificData::MuxDop(mux)) => {
            let cases = mux
                .cases
                .iter()
                .map(|case| {
                    Ok(Case {
                        short_name: STRINGS.get_or_insert(&case.short_name),
                        long_name: case.long_name.as_ref().map(|name| LongName {
                            value: option_str_to_string(name.value.as_ref()),
                            ti: option_str_to_string(name.ti.as_ref()),
                        }),
                        structure: case
                            .structure
                            .as_ref()
                            .and_then(|s| s.r#ref.as_ref())
                            .map(|s| s.value),
                        lower_limit: get_limit(case.lower_limit.as_ref()),
                        upper_limit: get_limit(case.upper_limit.as_ref()),
                    })
                })
                .collect::<Result<Vec<_>, DiagServiceError>>()?;

            DataOperationVariant::Mux(MuxDop {
                byte_position: mux.byte_position,
                switch_key: mux
                    .switch_key
                    .as_ref()
                    .map(|s| {
                        Ok(SwitchKey {
                            byte_position: s.byte_position,
                            bit_position: s.bit_position(),
                            dop: s
                                .dop
                                .as_ref()
                                .and_then(|d| d.r#ref.as_ref())
                                .map(|d| d.value),
                        })
                    })
                    .transpose()?,
                default_case: cases
                    .iter()
                    .find(|case| {
                        mux.default_case.as_ref().is_some_and(|d| {
                            get_string!(case.short_name).is_ok_and(|s| s == d.short_name)
                        })
                    })
                    .cloned(),

                cases,
                is_visible: mux.is_visible(),
            })
        }
        Some(dop::SpecificData::DynamicLengthField(_)) => {
            return Err(DiagServiceError::ParameterConversionError(
                "dynamicLengthField not implemented yet".into(),
            ));
        }
        None => {
            // log::debug!(target: LOG_TARGET, "DOP without SpecificData: {d:?}");
            return Err(DiagServiceError::InvalidDatabase(format!(
                "DOP id[{dop_id}] {} has no Variant set",
                d.short_name
            )));
        }
    };
    Ok(variant)
}

fn fallback_factors(u: &dataformat::Unit) -> Option<f64> {
    // guess some factors
    let name = u.short_name.to_lowercase();
    if name.starts_with("giga") {
        Some(1_000_000_000.0)
    } else if name.starts_with("mega") {
        Some(1_000_000.0)
    } else if name.starts_with("kilo") || name == "km" {
        Some(1000.0)
    } else if name.starts_with("centi") || name == "cm" {
        Some(100.0)
    } else if name.starts_with("deca") {
        Some(10.0)
    } else if name.starts_with("deci") {
        Some(0.1)
    } else if name.starts_with("milli") || name == "ms" || name == "mv" {
        Some(0.001)
    } else if name.starts_with("micro") {
        Some(0.000_001)
    } else if name.starts_with("nano") {
        Some(0.000_000_001)
    } else {
        None
    }
}

fn get_compu_method(
    compu_method: Option<&dataformat::CompuMethod>,
) -> Result<CompuMethod, DiagServiceError> {
    if compu_method.is_none() {
        return Err(DiagServiceError::InvalidDatabase(
            "CompuMethod not set".to_owned(),
        ));
    }

    Ok(CompuMethod {
        category: compu_method
            .unwrap()
            .category
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("CompuMethod has no category".to_owned())
            })?
            .try_into()?,
        internal_to_phys: CompuFunction {
            scales: compu_method
                .unwrap()
                .internal_to_phys
                .as_ref()
                .map_or_else(
                    || Ok(Vec::new()),
                    |tophys| {
                        tophys
                            .compu_scales
                            .iter()
                            .map(|s| {
                                let lower_limit = get_limit(s.lower_limit.as_ref());
                                let upper_limit = get_limit(s.upper_limit.as_ref());

                                let consts = s.consts.as_ref().map(|c| CompuValues {
                                    v: c.v(),
                                    vt: option_str_to_string(c.vt.as_ref()),
                                    vt_ti: option_str_to_string(c.vt_ti.as_ref()),
                                });

                                Ok(CompuScale {
                                    lower_limit,
                                    upper_limit,
                                    rational_coefficients: s.rational_co_effs.as_ref().map(|r| {
                                        CompuRationalCoefficients {
                                            numerator: r.numerator.clone(),
                                            denominator: r.denominator.clone(),
                                        }
                                    }),
                                    consts,
                                })
                            })
                            .collect::<Result<Vec<_>, DiagServiceError>>()
                    },
                )?,
        },
    })
}

fn get_limit(limit: Option<&dataformat::Limit>) -> Result<Limit, DiagServiceError> {
    // Even a valid database contains empty limits, we just assume INFINITE for them
    let default = dataformat::Limit {
        value: String::new(),
        interval_type: limit::IntervalType::Infinite as i32,
    };
    let l = limit.unwrap_or(&default);

    let val = if l.value.is_empty() {
        Ok(0.0f64)
    } else {
        l.value.parse::<f64>().map_err(|_| {
            DiagServiceError::InvalidDatabase(format!(
                "failed to parse lower limit {} as f64",
                l.value
            ))
        })
    }?;
    Ok(Limit {
        value: val,
        interval_type: l.interval_type.try_into()?,
    })
}

fn get_dop_field(f: &dop::Field) -> Result<DopField, DiagServiceError> {
    Ok(DopField {
        basic_structure: f
            .basic_structure
            .as_ref()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Dop basic structure ref not set.".to_owned())
            })?
            .r#ref
            .as_ref()
            .ok_or_else(|| ref_optional_none("Field.basicStructure.ref_pb"))?
            .value,
        basic_structure_short_name: option_str_to_string(f.basic_structure_short_name_ref.as_ref()),
        env_data_desc: f
            .env_data_desc
            .as_ref()
            .and_then(|e| e.r#ref.as_ref())
            .map(|e| e.value),
        env_data_desc_short_name: option_str_to_string(f.env_data_desc_short_name_ref.as_ref()),
        is_visible: f.is_visible(),
    })
}

impl From<dop::DopType> for DOPType {
    fn from(dop_type: dop::DopType) -> Self {
        match dop_type {
            dop::DopType::Regular => DOPType::Regular,
            dop::DopType::EnvDataDesc => DOPType::EnvDataDesc,
            dop::DopType::Mux => DOPType::Mux,
            dop::DopType::DynamicEndMarkerField => DOPType::DynamicEndMarkerField,
            dop::DopType::DynamicLengthField => DOPType::DynamicLengthField,
            dop::DopType::EndOfPduField => DOPType::EndOfPduField,
            dop::DopType::StaticField => DOPType::StaticField,
            dop::DopType::EnvData => DOPType::EnvData,
            dop::DopType::Structure => DOPType::Structure,
            dop::DopType::Dtc => DOPType::Dtc,
        }
    }
}

impl TryFrom<i32> for DOPType {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        dop::DopType::try_from(value)
            .map_err(|_| {
                DiagServiceError::InvalidDatabase(format!("Invalid DOPType value: {value}"))
            })
            .map(Self::from)
    }
}

impl From<dataformat::compu_method::CompuCategory> for CompuCategory {
    fn from(cat: dataformat::compu_method::CompuCategory) -> Self {
        match cat {
            dataformat::compu_method::CompuCategory::Identical => CompuCategory::Identical,
            dataformat::compu_method::CompuCategory::Linear => CompuCategory::Linear,
            dataformat::compu_method::CompuCategory::ScaleLinear => CompuCategory::ScaleLinear,
            dataformat::compu_method::CompuCategory::TextTable => CompuCategory::TextTable,
            dataformat::compu_method::CompuCategory::CompuCode => CompuCategory::CompuCode,
            dataformat::compu_method::CompuCategory::TabIntp => CompuCategory::TabIntp,
            dataformat::compu_method::CompuCategory::RatFunc => CompuCategory::RatFunc,
            dataformat::compu_method::CompuCategory::ScaleRatFunc => CompuCategory::ScaleRatFunc,
        }
    }
}

impl TryFrom<i32> for CompuCategory {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        dataformat::compu_method::CompuCategory::try_from(value)
            .map_err(|_| {
                DiagServiceError::InvalidDatabase(format!("Invalid CompuCategory value: {value}"))
            })
            .map(Self::from)
    }
}

impl From<limit::IntervalType> for IntervalType {
    fn from(interval_type: limit::IntervalType) -> Self {
        match interval_type {
            limit::IntervalType::Open => IntervalType::Open,
            limit::IntervalType::Closed => IntervalType::Closed,
            limit::IntervalType::Infinite => IntervalType::Infinite,
        }
    }
}

impl TryFrom<i32> for IntervalType {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        limit::IntervalType::try_from(value)
            .map_err(|_| {
                DiagServiceError::InvalidDatabase(format!("Invalid IntervalType value: {value}"))
            })
            .map(Self::from)
    }
}

impl From<dataformat::physical_type::Radix> for Radix {
    fn from(radix: dataformat::physical_type::Radix) -> Self {
        match radix {
            dataformat::physical_type::Radix::Hex => Radix::Hex,
            dataformat::physical_type::Radix::Dec => Radix::Dec,
            dataformat::physical_type::Radix::Bin => Radix::Bin,
            dataformat::physical_type::Radix::Oct => Radix::Oct,
        }
    }
}

impl TryFrom<i32> for Radix {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        dataformat::physical_type::Radix::try_from(value)
            .map_err(|_| DiagServiceError::InvalidDatabase(format!("Invalid Radix value: {value}")))
            .map(Self::from)
    }
}
