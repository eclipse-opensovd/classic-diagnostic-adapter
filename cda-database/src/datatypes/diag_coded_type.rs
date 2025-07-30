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

use bitvec::order::Msb0;
use cda_interfaces::DiagServiceError;
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{DiagCodedTypeMap, ref_optional_none},
    proto::dataformat::{self, diag_coded_type},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DataType {
    Int32,
    UInt32,
    Float32,
    AsciiString,
    Utf8String,
    Unicode2String,
    ByteField,
    Float64,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagCodedType {
    pub base_datatype: DataType,
    pub type_: DiagCodedTypeVariant,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCodedTypeVariant {
    LeadingLengthInfo(BitLength),
    MinMaxLength(MinMaxLengthType),
    StandardLength(StandardLengthType),
}

pub type BitLength = u32;
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MinMaxLengthType {
    pub min_length: u32,
    pub max_length: u32,
    pub termination: Termination,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StandardLengthType {
    pub bit_length: u32,
    pub bitmask: Option<Vec<u8>>,
    pub condensed: bool,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum Termination {
    EndOfPdu,
    Zero,
    HexFF,
}

pub(super) fn get_diag_coded_types(ecu_data: &dataformat::EcuData) -> DiagCodedTypeMap {
    ecu_data
        .diag_coded_types
        .iter()
        .map(|dct| {
            let base_datatype = dct.base_data_type.try_into()?;
            let type_ = match &dct.specific_data {
                Some(diag_coded_type::SpecificData::LeadingLengthInfoType(l)) => {
                    DiagCodedTypeVariant::LeadingLengthInfo(l.bit_length)
                }
                Some(diag_coded_type::SpecificData::MinMaxLengthType(m)) => {
                    DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                        min_length: m.min_length,
                        max_length: m.max_length(),
                        termination: match m.termination.try_into().ok() {
                            Some(diag_coded_type::min_max_length_type::Termination::EndOfPdu) => {
                                Termination::EndOfPdu
                            }
                            Some(diag_coded_type::min_max_length_type::Termination::Zero) => {
                                Termination::Zero
                            }
                            Some(diag_coded_type::min_max_length_type::Termination::HexFf) => {
                                Termination::HexFF
                            }
                            None => {
                                return Err(DiagServiceError::InvalidDatabase(
                                    "DiagCodedType SpecificData termination not found".to_owned(),
                                ));
                            }
                        },
                    })
                }
                Some(diag_coded_type::SpecificData::StandardLengthType(l)) => {
                    DiagCodedTypeVariant::StandardLength(StandardLengthType {
                        bit_length: l.bit_length,
                        bitmask: l.bit_mask.clone(),
                        condensed: l.condensed(),
                    })
                }
                Some(diag_coded_type::SpecificData::ParamLengthInfoType(_)) => {
                    // todo! implement
                    return Err(DiagServiceError::InvalidDatabase(
                        "DiagCodedType SpecificData ParamLengthInfoType not supported".to_owned(),
                    ));
                }
                None => {
                    return Err(DiagServiceError::InvalidDatabase(
                        "DiagCodedType SpecificData not found".to_owned(),
                    ));
                }
            };
            Ok((
                dct.id
                    .as_ref()
                    .ok_or_else(|| ref_optional_none("DiagCodedType.id"))?
                    .value,
                DiagCodedType {
                    base_datatype,
                    type_,
                },
            ))
        })
        .filter_map(Result::ok)
        .collect::<DiagCodedTypeMap>()
}

impl From<dataformat::diag_coded_type::DataType> for DataType {
    fn from(data_type: dataformat::diag_coded_type::DataType) -> Self {
        match data_type {
            dataformat::diag_coded_type::DataType::AInt32 => DataType::Int32,
            dataformat::diag_coded_type::DataType::AUint32 => DataType::UInt32,
            dataformat::diag_coded_type::DataType::AFloat32 => DataType::Float32,
            dataformat::diag_coded_type::DataType::AAsciistring => DataType::AsciiString,
            dataformat::diag_coded_type::DataType::AUtf8String => DataType::Utf8String,
            dataformat::diag_coded_type::DataType::AUnicode2String => DataType::Unicode2String,
            dataformat::diag_coded_type::DataType::ABytefield => DataType::ByteField,
            dataformat::diag_coded_type::DataType::AFloat64 => DataType::Float64,
        }
    }
}

impl TryFrom<i32> for DataType {
    type Error = DiagServiceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        dataformat::diag_coded_type::DataType::try_from(value)
            .map_err(|_| {
                DiagServiceError::InvalidDatabase(format!(
                    "DiagCodedType base_data_type {value:?} not found"
                ))
            })
            .map(Self::from)
    }
}

impl DiagCodedTypeVariant {
    pub fn apply(&self, input_data: &[u8]) -> Vec<u8> {
        match self {
            DiagCodedTypeVariant::LeadingLengthInfo(l) => {
                // calculate the maximum bytes we can store in `l` bits.
                let max_len = if *l >= 64 {
                    // this clamps the maximum length to 64 bits
                    // it is not specified by UDS and in theory the length could be > 64 bits
                    // But it is highly unlikely because 64 bits allow addressing 18.45 exabytes
                    // which is more than enough for any ECU
                    u64::MAX
                } else {
                    // basically this is the same as 2^l - 1
                    // which is the maximum length that can be encoded in l bits
                    // The bit shift is better for performance than calculating 2^l - 1
                    (1_u64 << *l) - 1
                };

                // If the input data is larger than the maximum length,
                // we truncate it to the maximum length
                // this ensures no trailing data is included
                let limited_len = (input_data.len() as u64).min(max_len);
                let mut bits = bitvec::bitvec![u8, Msb0;];

                // iterate over the bits of the length and push them into the bit vector
                for i in (0..*l).rev() {
                    bits.push((limited_len >> i) & 1 == 1);
                }

                // write the payload in the same bit vector, limited to the maximum length
                bits.extend_from_raw_slice(&input_data[0..limited_len as usize]);
                bits.into_vec()
            }
            DiagCodedTypeVariant::MinMaxLength(_min_max_length_type) => todo!(),
            DiagCodedTypeVariant::StandardLength(slt) => {
                let mapped_bytes =
                    Self::get_bytes_from_bit_length(input_data, slt.bit_length as usize);

                if let Some(masks) = &slt.bitmask {
                    // apply masks sequentially
                    mapped_bytes
                        .iter()
                        .zip(masks.iter())
                        .map(|(&b, &mask)| b & mask)
                        .collect()
                } else {
                    mapped_bytes
                }
            }
        }
    }

    fn get_bytes_from_bit_length(input_data: &[u8], bit_len: usize) -> Vec<u8> {
        if bit_len >= 8 {
            let mut bytes = bit_len / 8;
            let remainder = bit_len % 8;
            let mask = if remainder > 0 {
                bytes += 1;
                (0xFF << (8 - remainder)) as u8
            } else {
                0xFF
            };

            let mut mapped_data = if bytes > input_data.len() {
                let mut padded_data = vec![0; bytes - input_data.len()];
                padded_data.extend_from_slice(input_data);
                padded_data
            } else {
                input_data[input_data.len() - bytes..].to_vec()
            };

            if let Some(val) = mapped_data.last_mut() {
                *val &= mask;
            }
            mapped_data
        } else {
            let mask = ((1 << bit_len) - 1) as u8;
            let mut mapped_data = if input_data.is_empty() {
                vec![0]
            } else {
                input_data[input_data.len() - 1..].to_vec()
            };

            if let Some(val) = mapped_data.last_mut() {
                *val &= mask;
            }
            mapped_data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_type_variant_mapping() {
        let mut input_data = vec![0x12, 0x34, 0x56, 0x7A];
        let variant = DiagCodedTypeVariant::LeadingLengthInfo(8);
        let result = variant.apply(&input_data);
        input_data.insert(0, 0x04); // insert length byte
        assert_eq!(result, input_data);

        let mut input_data = vec![0x12, 0x34, 0x56, 0x7A]; // make sure extra byte is cut off
        let variant = DiagCodedTypeVariant::LeadingLengthInfo(2); // 2 bit -> 3 max elements
        let result = variant.apply(&input_data);
        input_data.insert(0, 0x03); // insert length byte
        // the length info is only 2 bits,
        // this means the remaining data is not written on exact byte borders
        // the last byte 0x7a is ignored because it does not fit into our length
        // data bits: 000100100011010001010110
        // length:    11
        // combined:  11000100100011010001010110
        // + 6 bits padding to get full bytes
        // 11000100100011010001010110000000
        // converted to base is the value below
        // inclusive range, to account for the length byte
        assert_eq!(result, [0xc4, 0x8d, 0x15, 0x80]);

        let mut input_data = Vec::new();
        for i in 0..=u32::from(u16::MAX) {
            // deliberately provide too much data that fully fills the length byte
            input_data.push(i as u8);
        }
        let variant = DiagCodedTypeVariant::LeadingLengthInfo(16);
        let result = variant.apply(&input_data);
        // insert both length bytes.
        input_data.splice(..0, [0xFF, 0xFF]);
        assert_eq!(result, input_data[0..=u16::MAX as usize + 1]);

        let input_data = vec![0x12, 0x34, 0x56, 0x7A];
        let variant = DiagCodedTypeVariant::StandardLength(StandardLengthType {
            bit_length: 16,
            bitmask: Some(vec![0xFF, 0x0F]),
            condensed: false,
        });
        let result = variant.apply(&input_data);
        assert_eq!(result, vec![0x56, 0x0A]);
    }
}
