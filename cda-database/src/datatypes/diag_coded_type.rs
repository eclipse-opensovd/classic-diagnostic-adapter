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

impl DataType {
    fn validate_bit_len(&self, bit_len: BitLength) -> Result<(), DiagServiceError> {
        if bit_len == 0 {
            return Err(DiagServiceError::BadPayload(
                "Cannot extract data with length 0".to_owned(),
            ));
        }

        if [DataType::Int32, DataType::UInt32].contains(self) && bit_len > 32 {
            return Err(DiagServiceError::BadPayload(format!(
                "Length must be a at most 32 bit for {:?}, got {bit_len} bit",
                &self
            )));
        }

        if &DataType::Float32 == self && bit_len != 32 {
            return Err(DiagServiceError::BadPayload(format!(
                "Length must be exactly 32 bit for {:?}, got {bit_len} bit",
                &self
            )));
        }

        if &DataType::Float64 == self && bit_len != 64 {
            return Err(DiagServiceError::BadPayload(format!(
                "Length must be exactly 64 bit for {:?}, got {bit_len} bit",
                &self
            )));
        }

        if &DataType::Unicode2String == self && bit_len % 16 != 0 {
            return Err(DiagServiceError::BadPayload(format!(
                "Length must be a multiple of 16 bit for {:?}, got {bit_len} bit",
                &self
            )));
        }

        Ok(())
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagCodedType {
    base_datatype: DataType,
    type_: DiagCodedTypeVariant,
    /// Indicates if the byte order is high-low (Big Endian, default) or low-high (Little Endian).
    is_high_low_byte_order: bool,
}

enum ByteOrder {
    /// Byte order is not changed
    Keep,

    /// Byte order is reversed but acting in pairs of bytes
    /// Needed for Unicode2String
    ReorderPairs,

    /// Byte order is reversed
    Reverse,
}

impl DiagCodedType {
    pub fn new_with_default_byte_order(
        base_datatype: DataType,
        type_: DiagCodedTypeVariant,
    ) -> Result<Self, DiagServiceError> {
        Self::new(base_datatype, type_, true)
    }

    pub fn new(
        base_datatype: DataType,
        type_: DiagCodedTypeVariant,
        is_high_low_byte_order: bool,
    ) -> Result<Self, DiagServiceError> {
        match type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(_) | DiagCodedTypeVariant::MinMaxLength(_) => {
                if ![
                    DataType::ByteField,
                    DataType::AsciiString,
                    DataType::Unicode2String,
                    DataType::Utf8String,
                ]
                .contains(&base_datatype)
                {
                    return Err(DiagServiceError::InvalidDatabase(format!(
                        "LeadingLengthInfo and MinMaxLength are only allowed for ByteField, \
                         AsciiString, Unicode2String, and Utf8String, got {base_datatype:?}"
                    )));
                }
            }
            _ => {}
        }
        Ok(Self {
            base_datatype,
            type_,
            is_high_low_byte_order,
        })
    }

    pub fn base_datatype(&self) -> &DataType {
        &self.base_datatype
    }
    pub fn type_(&self) -> &DiagCodedTypeVariant {
        &self.type_
    }

    pub fn decode(
        &self,
        uds_payload: &[u8],
        byte_pos: usize,
        bit_pos: u32,
    ) -> Result<Vec<u8>, DiagServiceError> {
        let byte_reordering = if self.is_high_low_byte_order {
            ByteOrder::Keep
        } else {
            match self.base_datatype {
                DataType::Unicode2String => ByteOrder::ReorderPairs,
                DataType::ByteField | DataType::AsciiString | DataType::Utf8String => {
                    // ISO 22901-1:2008, 7.3.6.3.3 b) states that the byte order
                    // for these types is to be ignored
                    ByteOrder::Keep
                }
                _ => ByteOrder::Reverse,
            }
        };

        // Bit offset for these datatypes are not allowed.
        if [
            DataType::Unicode2String,
            DataType::ByteField,
            DataType::AsciiString,
            DataType::Utf8String,
        ]
        .contains(&self.base_datatype)
            && bit_pos != 0
        {
            return Err(DiagServiceError::BadPayload(format!(
                "Bit position must be 0 for {:?}, got {bit_pos}",
                self.base_datatype
            )));
        }

        let res = match self.type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(bits) => {
                self.base_datatype.validate_bit_len(bits)?;

                // The leading length parameter must be extracted separately
                let length_info_bytes = extract_bits(
                    bits as usize,
                    bit_pos,
                    byte_pos,
                    None,
                    uds_payload,
                    byte_reordering,
                )?;

                let len = match length_info_bytes.len() {
                    1 => length_info_bytes[0] as usize,
                    2 => u16::from_be_bytes([length_info_bytes[0], length_info_bytes[1]]) as usize,
                    3 => u32::from_be_bytes([
                        0,
                        length_info_bytes[0],
                        length_info_bytes[1],
                        length_info_bytes[2],
                    ]) as usize,
                    4 => u32::from_be_bytes([
                        length_info_bytes[0],
                        length_info_bytes[1],
                        length_info_bytes[2],
                        length_info_bytes[3],
                    ]) as usize,
                    n @ 5..=8 => {
                        let mut bytes = [0u8; 8];
                        match n {
                            5 => bytes[3..].copy_from_slice(&length_info_bytes[0..5]),
                            6 => bytes[2..].copy_from_slice(&length_info_bytes[0..6]),
                            7 => bytes[1..].copy_from_slice(&length_info_bytes[0..7]),
                            8 => bytes.copy_from_slice(&length_info_bytes[0..8]),
                            _ => unreachable!(),
                        }
                        u64::from_be_bytes(bytes) as usize
                    }
                    _ => {
                        return Err(DiagServiceError::BadPayload(
                            "unsupported leading length size".to_owned(),
                        ));
                    }
                };

                // The bits of the leading length are not part of the result.
                // The data bytes start at the byte edge to the length.
                let start_byte = byte_pos + (bit_pos % 8 != 0) as usize + length_info_bytes.len();
                let end_byte = start_byte + len;
                if end_byte > uds_payload.len() {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Not enough data in payload: need {} bytes, but only {} bytes available",
                        end_byte,
                        uds_payload.len()
                    )));
                }
                uds_payload[start_byte..end_byte].to_vec()
            }
            DiagCodedTypeVariant::MinMaxLength(ref e) => {
                if e.max_length == 0 {
                    return Err(DiagServiceError::BadPayload(
                        "MinMaxLengthType max_length cannot be 0".to_owned(),
                    ));
                }
                if e.max_length < e.min_length {
                    return Err(DiagServiceError::BadPayload(format!(
                        "MinMaxLengthType max_length {} cannot be less than min_length {}",
                        e.max_length, e.min_length
                    )));
                }
                if self.base_datatype == DataType::Unicode2String
                    && (!e.min_length.is_multiple_of(2) || !e.max_length.is_multiple_of(2))
                {
                    return Err(DiagServiceError::BadPayload(format!(
                        "DataType {:?} needs an even amount of min/max bytes",
                        self.base_datatype
                    )));
                }

                let max_end = usize::min(byte_pos + e.max_length as usize, uds_payload.len());
                let mut end_pos = byte_pos;

                let res = match e.termination {
                    Termination::EndOfPdu => {
                        // Read until end of pdu or max size, whatever comes first.
                        uds_payload[byte_pos..max_end].to_vec()
                    }
                    Termination::Zero => {
                        match self.base_datatype {
                            DataType::Unicode2String => {
                                while end_pos < max_end {
                                    if end_pos - byte_pos >= e.min_length as usize
                                        && end_pos + 1 < uds_payload.len()
                                        && uds_payload[end_pos] == 0
                                        && uds_payload[end_pos + 1] == 0
                                    {
                                        break; // Found UTF-16 null terminator
                                    }

                                    end_pos += 2; // Unicode2String is 2 bytes per character
                                }
                            }
                            _ => {
                                while end_pos < max_end {
                                    if end_pos - byte_pos >= e.min_length as usize
                                        && uds_payload[end_pos] == 0
                                    {
                                        break; // Found ASCII/UTF-8 null terminator
                                    }
                                    end_pos += 1;
                                }
                            }
                        }

                        if end_pos > uds_payload.len() {
                            return Err(DiagServiceError::BadPayload(format!(
                                "Not enough data in payload, needed {end_pos} bytes, got {} bytes",
                                uds_payload.len()
                            )));
                        }

                        uds_payload[byte_pos..end_pos].to_vec()
                    }
                    Termination::HexFF => {
                        match self.base_datatype {
                            DataType::Unicode2String => {
                                while end_pos < max_end {
                                    if end_pos + 1 < uds_payload.len()
                                        && (end_pos - byte_pos) >= e.min_length as usize
                                        && uds_payload[end_pos] == 0xff
                                        && uds_payload[end_pos + 1] == 0xff
                                    {
                                        break; // Found UTF-16 null terminator
                                    }

                                    end_pos += 2; // Unicode2String is 2 bytes per character
                                }
                            }
                            _ => {
                                while end_pos < max_end {
                                    if (end_pos - byte_pos) >= e.min_length as usize
                                        && uds_payload[end_pos] == 0xff
                                    {
                                        break; // Found ASCII/UTF-8 null terminator
                                    }
                                    end_pos += 1;
                                }
                            }
                        }

                        uds_payload[byte_pos..end_pos].to_vec()
                    }
                };

                if res.len() < e.min_length as usize {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Reached termination or end of PDU before reading {} min bytes",
                        e.min_length
                    )));
                }
                res
            }

            DiagCodedTypeVariant::StandardLength(ref v) => {
                self.base_datatype.validate_bit_len(v.bit_length)?;
                let mask = v.bitmask.as_ref().map(|m| Mask {
                    data: m,
                    condensed: v.condensed,
                });

                extract_bits(
                    v.bit_length as usize,
                    bit_pos,
                    byte_pos,
                    mask.as_ref(),
                    uds_payload,
                    byte_reordering,
                )?
            }
        };

        if res.is_empty() {
            return Err(DiagServiceError::BadPayload(
                "Decoding did not find any payload".to_owned(),
            ));
        }

        Ok(res)
    }

    pub fn encode(&self, input_data: &[u8]) -> Result<Vec<u8>, DiagServiceError> {
        let res = match &self.type_ {
            // todo this is not implemented (yet) according to the spec
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
                Ok(bits.into_vec())
            }
            DiagCodedTypeVariant::MinMaxLength(_min_max_length_type) => todo!(),
            DiagCodedTypeVariant::StandardLength(slt) => {
                let mask = slt.bitmask.as_ref().map(|mask| Mask {
                    data: mask,
                    condensed: slt.condensed,
                });
                extract_bits(
                    slt.bit_length as usize,
                    0,
                    0,
                    mask.as_ref(),
                    input_data,
                    // todo this needs to be changed as soon as data extraction is implemented
                    ByteOrder::Keep,
                )
            }
        }?;

        Ok(res)
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCodedTypeVariant {
    LeadingLengthInfo(BitLength),
    MinMaxLength(MinMaxLengthType),
    StandardLength(StandardLengthType),
}

pub type BitLength = u32;
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MinMaxLengthType {
    pub min_length: u32,
    pub max_length: u32,
    pub termination: Termination,
}
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct StandardLengthType {
    pub bit_length: u32,
    pub bitmask: Option<Vec<u8>>,
    pub condensed: bool,
}

#[derive(Debug, PartialEq)]
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
            let is_high_low_byte_order = dct.is_high_low_byte_order.unwrap_or(true);
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
                DiagCodedType::new(base_datatype, type_, is_high_low_byte_order)?,
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

struct Mask<'a> {
    data: &'a Vec<u8>,
    condensed: bool,
}

fn extract_bits(
    bits: usize,
    bit_pos: u32,
    byte_pos: usize,
    mask: Option<&Mask>,
    uds_payload: &[u8],
    byte_order: ByteOrder,
) -> Result<Vec<u8>, DiagServiceError> {
    // Validate inputs
    if bit_pos > 7 {
        return Err(DiagServiceError::BadPayload(format!(
            "BitPosition range is 0..=7, got {bit_pos}",
        )));
    }

    if byte_pos >= uds_payload.len() {
        return Err(DiagServiceError::BadPayload(format!(
            "BytePosition {byte_pos} is out of bounds for payload length {}",
            uds_payload.len()
        )));
    }

    if bits == 0 {
        return Err(DiagServiceError::BadPayload(
            "Cannot extract 0 bits".to_owned(),
        ));
    }

    // Step N: Corresponds with the steps defined in ISO 22901-1:2008 7.3.6.3.2
    // Step 1: Calculate ByteCount using ceiling function
    let byte_count = (bit_pos + bits as u32).div_ceil(8) as usize;

    if byte_pos + byte_count > uds_payload.len() {
        return Err(DiagServiceError::BadPayload(format!(
            "Input too short: need {byte_count} bytes starting at byte {byte_pos}, but payload \
             has {} bytes total",
            uds_payload.len()
        )));
    }

    // Step 2: Extract ByteCount bytes starting at byte_pos
    let mut extracted_bytes: Vec<u8> = uds_payload[byte_pos..byte_pos + byte_count].to_vec();

    // Step 3: Normalization of data
    match byte_order {
        ByteOrder::Keep => {}
        ByteOrder::ReorderPairs => {
            // Reverse the byte order in pairs for Unicode2String
            for i in (0..extracted_bytes.len()).step_by(2) {
                if i + 1 < extracted_bytes.len() {
                    extracted_bytes.swap(i, i + 1);
                }
            }
        }
        ByteOrder::Reverse => {
            // Reverse the byte order
            extracted_bytes.reverse();
        }
    }

    // Step 4: Extract bits starting from bit_pos
    let total_bits_needed = bits;
    let mut result_bits = Vec::new();

    // Convert bytes to a bit array for easier manipulation
    let mut bit_array = Vec::new();
    for byte in &extracted_bytes {
        for i in 0..8 {
            bit_array.push((byte >> i) & 1_u8);
        }
    }

    // Extract the required bits starting from bit_pos
    let start_bit = bit_pos as usize;
    if start_bit + total_bits_needed > bit_array.len() {
        return Err(DiagServiceError::BadPayload(format!(
            "Not enough bits available: requested {total_bits_needed} bits starting at bit \
             position {start_bit}, but only {} bits available",
            bit_array.len()
        )));
    }

    for i in 0..total_bits_needed {
        if start_bit + i < bit_array.len() {
            result_bits.push(bit_array[start_bit + i]);
        }
    }

    // Step 5: Apply the mask if provided
    if let Some(mask_info) = mask {
        // Convert mask bytes to bit array
        let mut mask_bits = Vec::new();
        for byte in mask_info.data {
            for i in 0..8 {
                mask_bits.push((byte >> i) & 1_u8);
            }
        }

        let mask_bit_count = std::cmp::min(mask_bits.len(), result_bits.len());
        if mask_info.condensed {
            // Remove bits that are 0 in the mask
            // This removes non-continuous bits and shifts higher bits to lower positions
            let mut condensed_bits = Vec::new();
            for i in 0..mask_bit_count {
                if mask_bits[i] == 1_u8 {
                    condensed_bits.push(result_bits[i]);
                }
            }
            result_bits = condensed_bits;
        } else {
            // Apply mask normally without condensing
            for i in 0..mask_bit_count {
                if mask_bits[i] == 0_u8 {
                    result_bits[i] = 0;
                }
            }
        }
    }

    // Convert bit array back to bytes
    let mut result_bytes = Vec::new();
    let mut current_byte = 0u8;
    let mut bit_count = 0;

    for bit in result_bits {
        current_byte |= bit << bit_count;
        bit_count += 1;

        if bit_count == 8 {
            result_bytes.push(current_byte);
            current_byte = 0;
            bit_count = 0;
        }
    }

    // Add the last partial byte if there are remaining bits
    if bit_count > 0 {
        result_bytes.push(current_byte);
    }

    Ok(result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_type_variant_mapping() {
        let mut input_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1];
        let coded_type = DiagCodedType::new_with_default_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(8),
        )
        .unwrap();
        let result = coded_type.encode(&input_data);
        input_data.insert(0, 0x08); // insert length byte
        assert_eq!(result.unwrap(), input_data);

        // make sure extra byte is cut off
        let mut input_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0xab];
        let coded_type = DiagCodedType::new_with_default_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(2), // 2 bit -> 3 max elements
        )
        .unwrap();

        let result = coded_type.encode(&input_data);
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
        assert_eq!(result.unwrap(), [0xc4, 0x8d, 0x15, 0x80]);

        let mut input_data = Vec::new();
        for i in 0..=u32::from(u16::MAX) {
            // deliberately provide too much data that fully fills the length byte
            input_data.push(i as u8);
        }
        let coded_type = DiagCodedType::new_with_default_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(16),
        )
        .unwrap();

        let result = coded_type.encode(&input_data);
        // insert both length bytes.
        input_data.splice(..0, [0xFF, 0xFF]);
        assert_eq!(result.unwrap(), input_data[0..=u16::MAX as usize + 1]);

        let input_data = vec![0x12, 0x34, 0x56, 0x7A];
        let coded_type = DiagCodedType::new_with_default_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(vec![0xFF, 0x0F]),
                condensed: false,
            }),
        )
        .unwrap();
        let result = coded_type.encode(&input_data);
        // 0x12 & 0xFF = 0x12
        // 0x34 & 0x0F = 0x04
        assert_eq!(result.unwrap(), vec![0x12, 0x04]);
    }

    #[test]
    fn test_extract_bits_masked() {
        let mask = Mask {
            data: &vec![0b11110000],
            condensed: false,
        };
        let payload: Vec<u8> = vec![0b10101010];
        // 10101010 -- payload
        // 11110000 -- mask
        // ----------
        // 10100000
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b10100000]);
    }

    #[test]
    fn test_extract_bits_condensed() {
        let mask = Mask {
            data: &vec![0b11110000],
            condensed: true,
        };
        let payload: Vec<u8> = vec![0b10101010];
        // 10101010 -- payload
        // 11110000 -- mask
        // ----------> apply mask
        // 10100000 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1010     --> pad msb
        // 00001010 --> result byte
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b00001010]);
    }

    #[test]
    fn test_extract_bits_condensed_complex() {
        let mask = Mask {
            data: &vec![0b10101010, 0b01010101],
            condensed: true,
        };

        // 11111111 -- payload
        // 10101010 -- mask
        // ----------> apply mask
        // 10101010 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1-1-1-1-

        let payload: Vec<u8> = vec![0b11111111, 0b11111111];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b1111]);
    }

    #[test]
    fn test_extract_bits_condensed_all_zeros() {
        let mask = Mask {
            data: &vec![0b00000000, 0b00000000],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b11111111, 0b11111111];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        // If condensed is set to true, bits are only added to the result if the mask bit is 1.
        // As the mask is all zeros and the length of the result is equal to the count of
        // '1's in the mask, the result should be empty.
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_bits_condensed_sparse() {
        let mask = Mask {
            data: &vec![0b10000001],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b10000001];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b00000011]);
    }

    #[test]
    fn test_extract_bits_standard_length_cases() {
        // Test standard length with byte alignment
        // 16 bits from 2 bytes, no offset
        // Should extract bytes as is since we're starting at bit 0
        let result = extract_bits(16, 0, 0, None, &[0xab, 0xcd], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0xab, 0xcd]);

        // Extracting 18 bits starting from bit position 0 in byte 0
        // Need 18 bits from 0xff, 0xff, 0xff
        // All bits from first 2 bytes (16 bits) + first 2 bits from third byte
        // 0xff = 11111111, 0xff = 11111111, 0xff = 11111111
        // Taking 18 bits: 11111111 11111111 11 -> requires 3 bytes to store
        // Result: [0xff, 0xff, 0x03] (last byte has only 2 bits set)
        let result = extract_bits(18, 0, 0, None, &[0xff, 0xff, 0xff], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0xff, 0xff, 0x03]);

        // Extracting 13 bits starting from bit position 5 in byte 0
        // Byte 0: 0xab = 10101011
        // Byte 1: 0xcd = 11001101
        // Byte 2: 0x42 = 01000010
        //
        // Byte 0: -----101  --> take bits 5-7 from first byte  (total bits 3)
        //         01101---  --> take bits 0-4 from second byte (total bits 8)
        //         01101101  --> Result Byte 0
        // Byte 1: -----110  --> take bits 5-7 from byte 1      (total bits 11)
        //         ---10---  --> take bits 0-1 from byte 2      (total bits 13)
        //         00010110  --> Result Byte 1
        let result = extract_bits(13, 5, 0, None, &[0xab, 0xcd, 0x42], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b01101101, 0b00010110]);

        // Extracting 3 bits starting from bit position 5 in byte 0
        // Byte 0: 0xab = 10101011
        //
        // Byte 0: -----101  --> take bits 5-7 from first byte  (total bits 3)
        let result = extract_bits(3, 5, 0, None, &[0xab], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b101]);

        // Extracting 4 bits starting from bit position 6 in byte 0
        // Byte 0: 0xf0 = 11110000
        // Byte 1: 0x0f = 00001111
        //
        // Byte 0: ------11  --> take bits 6-7 from first byte  (total bits 2)
        //         ----11--  --> take bits 0-1 from second byte (total bits 4)
        //         00001111  --> Result Byte 0
        let result = extract_bits(4, 6, 0, None, &[0xf0, 0x0f], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b1111]);

        // Extracting 7 bits starting from bit position 3 in byte 1
        // Byte 0: 0x01 = 00000001
        // Byte 1: 0xff = 11111111
        // Byte 2: 0x03 = 00000011
        // Extracting bits sequentially starting from byte 1, bit 3:
        // Byte 0: 00011111 --> take bits 3-7 from first byte (total bits 5)
        //         011      --> take 3 bits from second byte  (total bits 8)
        //         01111111 --> Result Byte 0
        let result = extract_bits(7, 3, 1, None, &[0x01, 0xff, 0x03], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b1111111]);
    }

    #[test]
    fn test_extract_bits_byte_position_cases() {
        // Test byte position with different bit lengths
        let result = extract_bits(8, 0, 1, None, &[0x00, 0xff, 0x00], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0xff]);

        // Test byte position with bit position and longer length
        let result = extract_bits(16, 0, 1, None, &[0x00, 0xab, 0xcd], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0xab, 0xcd]);

        // Test byte position with 3 bytes of data
        let result =
            extract_bits(24, 0, 1, None, &[0x00, 0x11, 0x22, 0x33], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0x11, 0x22, 0x33]);
    }

    #[test]
    fn test_extract_bits_error_cases() {
        // Test insufficient data
        assert!(extract_bits(16, 0, 0, None, &[0xab], ByteOrder::Keep).is_err());

        // Test invalid bit position
        assert!(extract_bits(8, 8, 0, None, &[0xff], ByteOrder::Keep).is_err());

        // Test zero bits
        assert!(extract_bits(0, 0, 0, None, &[0xff], ByteOrder::Keep).is_err());

        // Test data too short for byte position
        assert!(extract_bits(8, 0, 2, None, &[0xff], ByteOrder::Keep).is_err());
    }

    #[test]
    fn test_extract_bits_byte_order_cases() {
        let result = extract_bits(16, 0, 0, None, &[0x12, 0x34], ByteOrder::Reverse).unwrap();
        assert_eq!(result, vec![0x34, 0x12]);

        let result = extract_bits(
            32,
            0,
            0,
            None,
            &[0x12, 0x34, 0x56, 0x78],
            ByteOrder::Reverse,
        )
        .unwrap();
        assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12]);

        // Test Unicode2String byte pair reversal
        let result = extract_bits(
            32,
            0,
            0,
            None,
            &[0x12, 0x34, 0x56, 0x78],
            ByteOrder::ReorderPairs,
        )
        .unwrap();
        assert_eq!(result, vec![0x34, 0x12, 0x78, 0x56]);

        // Test Unicode2String byte pair reversal with odd number of bytes
        let result =
            extract_bits(24, 0, 0, None, &[0x12, 0x34, 0x56], ByteOrder::ReorderPairs).unwrap();
        assert_eq!(result, vec![0x34, 0x12, 0x56]);

        // Test byte reversal with masking
        let mask = Mask {
            data: &vec![0xFF, 0x0F],
            condensed: false,
        };
        let result =
            extract_bits(16, 0, 0, Some(&mask), &[0x12, 0x34], ByteOrder::Reverse).unwrap();
        // First reverse bytes: [0x34, 0x12]
        // Then apply mask:     [0xFF, 0x0F]
        // Result:             [0x34, 0x02]
        assert_eq!(result, vec![0x34, 0x02]);

        // Test byte reversal with condensed masking
        let mask = Mask {
            data: &vec![0b_1111_0000, 0b_1111_0000],
            condensed: true,
        };
        let result = extract_bits(
            16,
            0,
            0,
            Some(&mask),
            &[0b_1100_1100, 0b_0011_0011],
            ByteOrder::Reverse,
        )
        .unwrap();
        // First reverse bytes, then apply mask:
        // 1100_1100 0011_0011
        // 1111_0000 1111_0000
        // ---------------
        // 1100_0000 0011_0000
        // condense
        // 1100_xxxx 0011_xxxx -> all bits removed where mask is 0
        assert_eq!(result, vec![0b_1100_0011]);
    }

    fn test_min_max_length(
        min_length: u32,
        max_length: u32,
        payload: Vec<u8>,
        expected: Vec<u8>,
        base_datatype: DataType,
        termination: Termination,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_with_default_byte_order(
            base_datatype,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length,
                max_length,
                termination,
            }),
        )?;

        let result = diag_type.decode(&payload, 0, 0)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_min_max_length_ascii_zero_termination() {
        // Test normal case with zero termination
        assert!(
            test_min_max_length(
                2,                            // min length
                10,                           // max length
                vec![b'a', b'b', 0x00, 0xFF], // payload with zero termination after min length
                vec![b'a', b'b'],             // expected: only ab without termination
                DataType::AsciiString,
                Termination::Zero,
            )
            .is_ok()
        );

        // Test reaching max length without termination
        assert!(
            test_min_max_length(
                2,
                4,
                vec![b'a', b'b', b'c', b'd', 0x00], // payload longer than max_length
                vec![b'a', b'b', b'c', b'd'],       // expected: only up to max_length
                DataType::AsciiString,
                Termination::Zero,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_min_max_length_utf8_ff_termination() {
        // Test normal case with FF termination
        assert!(
            test_min_max_length(
                2,
                10,
                vec![0x68, 0x69, 0xFF, 0x00], // "hi" followed by FF termination
                vec![0x68, 0x69],             // expected: only "hi"
                DataType::Utf8String,
                Termination::HexFF,
            )
            .is_ok()
        );

        // Test reaching end of PDU after min length
        assert!(
            test_min_max_length(
                2,
                10,
                vec![0x68, 0x69, 0x6F], // "hio" without termination
                vec![0x68, 0x69, 0x6F], // expected: entire payload
                DataType::Utf8String,
                Termination::HexFF,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_min_max_length_unicode2_requirements() {
        // Test valid Unicode2String with even lengths
        test_min_max_length(
            4, // min length in bytes, must be even
            8,
            vec![0x00, 0x61, 0x00, 0x62, 0x00, 0x00], // "ab" followed by 0x0000
            vec![0x00, 0x61, 0x00, 0x62],             // expected: only "ab"
            DataType::Unicode2String,
            Termination::Zero,
        )
        .unwrap();

        assert!(
            test_min_max_length(
                3, // odd min length - should fail
                8,
                vec![0x00, 0x61, 0x00, 0x62],
                vec![],
                DataType::Unicode2String,
                Termination::Zero,
            )
            .is_err()
        );

        assert!(
            test_min_max_length(
                4,
                7, // odd max length - should fail
                vec![0x00, 0x61, 0x00, 0x62],
                vec![],
                DataType::Unicode2String,
                Termination::Zero,
            )
            .is_err()
        );
    }

    #[test]
    fn test_min_max_length_termination_cases() {
        // Test termination after min_length but before max_length
        test_min_max_length(
            2,
            6,
            vec![0x61, 0x62, 0x00, 0x63, 0x64], // "ab\0cd"
            vec![0x61, 0x62],                   // should only include "ab"
            DataType::AsciiString,
            Termination::Zero,
        )
        .unwrap();

        // Test zero byte in content should not terminate when max_length reached
        test_min_max_length(
            2,
            4,
            vec![0x61, 0x00, 0x63, 0x64], // "a\0cd"
            vec![0x61, 0x00, 0x63, 0x64], // should include full content
            DataType::AsciiString,
            Termination::Zero,
        )
        .unwrap();

        // Test FF termination not included when max_length reached
        test_min_max_length(
            2,
            3,
            vec![0x61, 0x62, 0x63, 0xFF], // "abc\xFF"
            vec![0x61, 0x62, 0x63],       // should not include FF
            DataType::AsciiString,
            Termination::HexFF,
        )
        .unwrap();

        // Test end of PDU before reaching min_length
        assert!(
            test_min_max_length(
                4,
                6,
                vec![0x61, 0x62],
                vec![0x61, 0x62], // not reached, expect error
                DataType::AsciiString,
                Termination::HexFF,
            )
            .is_err()
        );
    }

    #[test]
    fn test_min_max_length_validation() {
        // Test error when max_length < min_length
        assert!(
            test_min_max_length(
                4,
                2, // max < min should fail
                vec![0x01, 0x02],
                vec![],
                DataType::ByteField,
                Termination::EndOfPdu,
            )
            .is_err()
        );

        // Test exact min_length payload
        test_min_max_length(
            2,
            4,
            vec![0x01, 0x02], // exactly min_length
            vec![0x01, 0x02],
            DataType::ByteField,
            Termination::EndOfPdu,
        )
        .unwrap();

        // Test exact max_length payload
        test_min_max_length(
            2,
            4,
            vec![0x01, 0x02, 0x03, 0x04], // exactly max_length
            vec![0x01, 0x02, 0x03, 0x04],
            DataType::ByteField,
            Termination::EndOfPdu,
        )
        .unwrap();
    }

    fn test_leading_length(
        bit_length: u32,
        byte_pos: usize,
        bit_pos: u32,
        payload: Vec<u8>,
        expected: Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_with_default_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(bit_length),
        )?;

        let result = diag_type.decode(&payload, byte_pos, bit_pos)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_leading_length_8bit() {
        test_leading_length(
            8,
            0,
            0,
            vec![0x03, 0xab, 0xcd, 0xef], // First byte (0x03) indicates 3 bytes follow
            vec![0xab, 0xcd, 0xef],       // Expected: 3 bytes after length byte
        )
        .unwrap();
    }

    #[test]
    fn test_leading_length_16bit() {
        test_leading_length(
            16,
            0,
            0,
            vec![0x00, 0x02, 0xcd, 0xef], // First two bytes (0x0002) indicate 2 bytes follow
            vec![0xcd, 0xef],             // Expected: 2 bytes after length bytes
        )
        .unwrap();
    }

    #[test]
    fn test_leading_length_32bit() {
        test_leading_length(
            32,
            0,
            0,
            vec![0x00, 0x00, 0x00, 0x02, 0xcd, 0xef], // First four bytes indicate 2 bytes follow
            vec![0xcd, 0xef],                         // Expected: 2 bytes after length bytes
        )
        .unwrap();
    }

    #[test]
    fn test_leading_length_64bit() {
        test_leading_length(
            64,
            0,
            0,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xcd, 0xef],
            vec![0xcd, 0xef],
        )
        .unwrap();
    }

    #[test]
    fn test_leading_length_4bit() {
        test_leading_length(
            4,
            0,
            0,
            vec![0b10100011, 0x01, 0x02, 0x03, 0x04], // First 4 bits (1010) indicate 3 bytes
            vec![0x01, 0x02, 0x03],                   // Expected: 3 bytes after length
        )
        .unwrap();
    }

    #[test]
    fn test_leading_length_3bit() {
        test_leading_length(
            3,
            0,
            0,
            vec![0x03, 0xab, 0xcd, 0xef], // First 3 bits indicate 3 bytes follow
            vec![0xab, 0xcd, 0xef],
        )
        .unwrap();
    }
    #[test]
    fn test_leading_length_insufficient_data() {
        assert!(
            test_leading_length(
                8,
                0,
                0,
                vec![0x03, 0xab], // Indicates 3 bytes but only 1 byte available
                vec![],
            )
            .is_err()
        );
    }

    #[test]
    fn test_leading_length_zero() {
        assert!(test_leading_length(8, 0, 0, vec![0x00, 0xff], vec![]).is_err());
    }

    #[test]
    fn test_leading_length_max_value() {
        // Test with maximum possible value for 8-bit length
        let max_length = 0xFF;
        let mut payload = vec![max_length];
        let expected: Vec<u8> = (0..max_length).collect();
        payload.extend(&expected);

        test_leading_length(8, 0, 0, payload, expected).unwrap();
    }

    #[test]
    fn test_unicode2string_length_violation() {
        assert!(DataType::Unicode2String.validate_bit_len(0).is_err());
        assert!(DataType::Unicode2String.validate_bit_len(15).is_err());
        assert!(DataType::Unicode2String.validate_bit_len(17).is_err());
        assert!(DataType::Unicode2String.validate_bit_len(16).is_ok());
        assert!(DataType::Unicode2String.validate_bit_len(32).is_ok());
    }

    #[test]
    fn test_ascii_string_length_violation() {
        assert!(DataType::AsciiString.validate_bit_len(0).is_err());
        assert!(DataType::AsciiString.validate_bit_len(8).is_ok());
    }

    #[test]
    fn test_utf8_string_length_violation() {
        assert!(DataType::Utf8String.validate_bit_len(0).is_err());
        assert!(DataType::Utf8String.validate_bit_len(8).is_ok());
    }

    #[test]
    fn test_byte_field_length_violation() {
        assert!(DataType::ByteField.validate_bit_len(0).is_err());
        assert!(DataType::ByteField.validate_bit_len(8).is_ok());
    }
}
