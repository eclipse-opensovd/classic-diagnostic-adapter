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

//
use cda_interfaces::{DiagServiceError, dlt_ctx, util::decode_hex};

use crate::{datatypes, flatbuf::diagnostic_description::dataformat};

pub enum DataOperationVariant<'a> {
    Normal(datatypes::NormalDop<'a>),
    EndOfPdu(datatypes::EndOfPdu<'a>),
    Structure(datatypes::StructureDop<'a>),
    EnvDataDesc(datatypes::EnvDataDescDop<'a>),
    EnvData(datatypes::EnvDataDop<'a>),
    Dtc(datatypes::DtcDop<'a>),
    StaticField(datatypes::StaticFieldDop<'a>),
    Mux(datatypes::MuxDop<'a>),
    DynamicLengthField(datatypes::DynamicLengthDop<'a>),
}

#[derive(Copy, Clone, Debug)]
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
pub struct CompuMethod {
    pub category: CompuCategory,
    pub internal_to_phys: CompuFunction,
}

#[derive(Clone, Debug)]
pub struct CompuFunction {
    pub scales: Vec<CompuScale>,
}
#[derive(Clone, Debug)]
pub struct CompuScale {
    pub lower_limit: Option<Limit>,
    pub upper_limit: Option<Limit>,
    pub rational_coefficients: Option<CompuRationalCoefficients>,
    pub consts: Option<CompuValues>,
    pub inverse_values: Option<CompuValues>,
}
#[derive(Clone, Debug)]
pub struct CompuValues {
    pub v: f64,
    pub vt: Option<String>,
    pub vt_ti: Option<String>,
}
#[derive(Clone, Debug)]
pub struct CompuRationalCoefficients {
    pub numerator: Vec<f64>,
    pub denominator: Vec<f64>,
}

impl From<dataformat::CompuCategory> for CompuCategory {
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("DB"),
        )
    )]
    fn from(value: dataformat::CompuCategory) -> Self {
        match value {
            dataformat::CompuCategory::IDENTICAL => CompuCategory::Identical,
            dataformat::CompuCategory::LINEAR => CompuCategory::Linear,
            dataformat::CompuCategory::SCALE_LINEAR => CompuCategory::ScaleLinear,
            dataformat::CompuCategory::TEXT_TABLE => CompuCategory::TextTable,
            dataformat::CompuCategory::COMPU_CODE => CompuCategory::CompuCode,
            dataformat::CompuCategory::TAB_INTP => CompuCategory::TabIntp,
            dataformat::CompuCategory::RAT_FUNC => CompuCategory::RatFunc,
            dataformat::CompuCategory::SCALE_RAT_FUNC => CompuCategory::ScaleRatFunc,
            _ => {
                tracing::error!("Compu Category {:?} not recognized", value);
                CompuCategory::Identical
            }
        }
    }
}

impl From<dataformat::CompuValues<'_>> for CompuValues {
    fn from(value: dataformat::CompuValues) -> Self {
        CompuValues {
            v: value.v().unwrap_or(0.0),
            vt: value.vt().map(ToOwned::to_owned),
            vt_ti: value.vt_ti().map(ToOwned::to_owned),
        }
    }
}

impl<'a> From<dataformat::CompuMethod<'a>> for CompuMethod {
    fn from(value: dataformat::CompuMethod<'a>) -> Self {
        CompuMethod {
            category: value.category().into(),
            internal_to_phys: value
                .internal_to_phys()
                .map_or(CompuFunction { scales: vec![] }, Into::into),
        }
    }
}

impl<'a> From<dataformat::CompuInternalToPhys<'a>> for CompuFunction {
    fn from(value: dataformat::CompuInternalToPhys<'a>) -> Self {
        CompuFunction {
            scales: value
                .compu_scales()
                .map(|scales_vec| {
                    scales_vec
                        .iter()
                        .map(Into::into)
                        .collect::<Vec<CompuScale>>()
                })
                .unwrap_or_default(),
        }
    }
}

impl<'a> From<dataformat::CompuScale<'a>> for CompuScale {
    fn from(value: dataformat::CompuScale<'a>) -> Self {
        CompuScale {
            lower_limit: value.lower_limit().map(Into::into),
            upper_limit: value.upper_limit().map(Into::into),
            rational_coefficients: value
                .rational_co_effs()
                .map(|rc| CompuRationalCoefficients {
                    numerator: rc
                        .numerator()
                        .map(|nums| nums.iter().collect())
                        .unwrap_or_default(),
                    denominator: rc
                        .denominator()
                        .map(|dens| dens.iter().collect())
                        .unwrap_or_default(),
                }),
            consts: value.consts().map(Into::into),
            inverse_values: value.inverse_values().map(Into::into),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum IntervalType {
    Open,
    Closed,
    Infinite,
}

#[derive(Clone, Debug)]
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
        if f < f64::from(u32::MIN) || f > f64::from(u32::MAX) || !f.is_finite() {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into u32, value is negative",
                self.value
            )));
        }
        // checked above
        #[allow(clippy::cast_possible_truncation)]
        #[allow(clippy::cast_sign_loss)]
        Ok(f as u32)
    }
}

impl TryInto<i32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<i32, Self::Error> {
        let f: f64 = self.try_into()?;
        if f < f64::from(i32::MIN) || f > f64::from(i32::MAX) || !f.is_finite() {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into i32, value out of range",
                self.value
            )));
        }

        // checked above
        #[allow(clippy::cast_possible_truncation)]
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
                    // this is expected behavior when converting from a float.
                    #[allow(clippy::cast_possible_truncation)]
                    #[allow(clippy::cast_sign_loss)]
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

impl From<dataformat::Limit<'_>> for Limit {
    fn from(val: dataformat::Limit<'_>) -> Self {
        Limit {
            value: val.value().unwrap_or_default().to_owned(),
            interval_type: val.interval_type().into(),
        }
    }
}

impl From<dataformat::IntervalType> for IntervalType {
    fn from(val: dataformat::IntervalType) -> Self {
        match val {
            dataformat::IntervalType::OPEN => IntervalType::Open,
            dataformat::IntervalType::CLOSED => IntervalType::Closed,
            _ => IntervalType::Infinite,
        }
    }
}

impl datatypes::DataOperation<'_> {
    /// Get the specific data variant of the `DataOperation`.
    /// # Errors
    /// Returns an error if the specific data type is not recognized or if the specific data is
    /// missing.
    pub fn variant(&self) -> Result<DataOperationVariant<'_>, DiagServiceError> {
        macro_rules! get_specific_data {
            ($method:ident, $variant:ident, $type_name:literal) => {
                self.0
                    .$method()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(
                            concat!("Failed to get ", $type_name, " specific data").to_owned(),
                        )
                    })
                    .map(|dop| DataOperationVariant::$variant(dop.into()))
            };
        }

        match self.specific_data_type() {
            dataformat::SpecificDOPData::NONE => Err(DiagServiceError::ParameterConversionError(
                "DataOperation has no specific data type".to_owned(),
            )),
            dataformat::SpecificDOPData::NormalDOP => {
                get_specific_data!(specific_data_as_normal_dop, Normal, "NormalDOP")
            }
            dataformat::SpecificDOPData::EndOfPduField => {
                get_specific_data!(specific_data_as_end_of_pdu_field, EndOfPdu, "EndOfPduField")
            }
            dataformat::SpecificDOPData::Structure => {
                get_specific_data!(specific_data_as_structure, Structure, "Structure")
            }
            dataformat::SpecificDOPData::EnvDataDesc => {
                get_specific_data!(specific_data_as_env_data_desc, EnvDataDesc, "EnvDataDesc")
            }
            dataformat::SpecificDOPData::EnvData => {
                get_specific_data!(specific_data_as_env_data, EnvData, "EnvData")
            }
            dataformat::SpecificDOPData::DTCDOP => {
                get_specific_data!(specific_data_as_dtcdop, Dtc, "DTCDOP")
            }
            dataformat::SpecificDOPData::StaticField => {
                get_specific_data!(specific_data_as_static_field, StaticField, "StaticField")
            }
            dataformat::SpecificDOPData::MUXDOP => {
                get_specific_data!(specific_data_as_muxdop, Mux, "MUXDOP")
            }
            dataformat::SpecificDOPData::DynamicLengthField => {
                get_specific_data!(
                    specific_data_as_dynamic_length_field,
                    DynamicLengthField,
                    "DynamicLengthField"
                )
            }
            _ => Err(DiagServiceError::ParameterConversionError(
                "Unknown DataOperation specific data type".to_owned(),
            )),
        }
    }
}
