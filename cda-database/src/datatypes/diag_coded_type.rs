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

use std::vec;

use crate::{
    datatypes::{DiagCodedTypeMap, ref_optional_none},
    proto::dataformat::{self, diag_coded_type},
};
use cda_interfaces::DiagServiceError;
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

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

        if matches!(self, DataType::Int32 | DataType::UInt32) && bit_len > 64 {
            return Err(DiagServiceError::BadPayload(format!(
                "Length must be at most 64 bit for {:?}, got {bit_len} bit",
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
    pub fn new_high_low_byte_order(
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
                if !matches!(
                    &base_datatype,
                    DataType::ByteField
                        | DataType::AsciiString
                        | DataType::Unicode2String
                        | DataType::Utf8String
                ) {
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
        self.validate_bit_pos(bit_pos)?;

        let byte_order = self.byte_order();

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
                    byte_order,
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
            DiagCodedTypeVariant::MinMaxLength(ref mmlt) => {
                mmlt.validate(&self.base_datatype)?;
                let max_end = usize::min(byte_pos + mmlt.max_length as usize, uds_payload.len());
                let mut end_pos = byte_pos;

                let res = match mmlt.termination {
                    Termination::EndOfPdu => {
                        // Read until end of pdu or max size, whatever comes first.
                        uds_payload[byte_pos..max_end].to_vec()
                    }
                    Termination::Zero => {
                        match self.base_datatype {
                            DataType::Unicode2String => {
                                while end_pos < max_end {
                                    if end_pos - byte_pos >= mmlt.min_length as usize
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
                                    if end_pos - byte_pos >= mmlt.min_length as usize
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
                                        && (end_pos - byte_pos) >= mmlt.min_length as usize
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
                                    if (end_pos - byte_pos) >= mmlt.min_length as usize
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

                if res.len() < mmlt.min_length as usize {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Reached termination or end of PDU before reading {} min bytes",
                        mmlt.min_length
                    )));
                }
                res
            }

            DiagCodedTypeVariant::StandardLength(ref slt) => {
                self.base_datatype.validate_bit_len(slt.bit_length)?;
                let mask = slt.bitmask.as_ref().map(|m| Mask {
                    data: m,
                    condensed: slt.condensed,
                });

                extract_bits(
                    slt.bit_length as usize,
                    bit_pos,
                    byte_pos,
                    mask.as_ref(),
                    uds_payload,
                    byte_order,
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

    pub fn encode(
        &self,
        mut input_data: Vec<u8>,
        uds_payload: &mut Vec<u8>,
        byte_pos: usize,
        bit_pos: u32,
    ) -> Result<(), DiagServiceError> {
        self.validate_bit_pos(bit_pos)?;
        let (mut packed_bytes, bit_len, mask) = match &self.type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(bit_len) => {
                // Subtract the next multiple of 8 from the length in usize as bits.
                // Shift the length up this amount of bits to put the relevant data into
                // the MSBs of the length usize.
                // Convert the length usize to a big endian bytes, then extract the relevant
                // bits via extract_bits, which will discard the least significant bits,
                // we shifted out.
                let len_bytes = (input_data.len()
                    << ((std::mem::size_of::<usize>() * 8) - ((bit_len.div_ceil(8)) * 8) as usize))
                    .to_be_bytes();

                // using extract bits to get the relevant bits from the leading length info
                let mut result_data =
                    extract_bits(*bit_len as usize, 0, 0, None, &len_bytes, ByteOrder::Keep)?;
                if result_data.is_empty() {
                    return Err(DiagServiceError::BadPayload(
                        "Failed to create length info for leading length".to_owned(),
                    ));
                }

                result_data.append(&mut input_data);
                let packed = pack_data(result_data.len() * 8, None, &result_data)?;
                let len = packed.len() * 8;
                (packed, len, None) // using packed length as bit length, because leading length is byte aligned
            }
            DiagCodedTypeVariant::MinMaxLength(mmlt) => {
                mmlt.validate(&self.base_datatype)?;
                let packed = match mmlt.termination {
                    Termination::EndOfPdu => {
                        // No special termination, just pack the data as is
                        pack_data(input_data.len() * 8, None, &input_data)
                    }
                    Termination::Zero => {
                        if self.base_datatype == DataType::Unicode2String {
                            input_data.append(&mut vec![0_u8, 0_u8]);
                        } else {
                            input_data.push(0_u8);
                        }
                        pack_data(input_data.len() * 8, None, &input_data)
                    }
                    Termination::HexFF => {
                        if self.base_datatype == DataType::Unicode2String {
                            input_data.append(&mut vec![0xff_u8, 0xff_u8]);
                        } else {
                            input_data.push(0xff_u8);
                        }
                        pack_data(input_data.len() * 8, None, &input_data)
                    }
                }?;

                let len = packed.len() * 8;
                (packed, len, None)
            }
            DiagCodedTypeVariant::StandardLength(slt) => {
                self.base_datatype.validate_bit_len(slt.bit_length)?;
                let mask = slt.bitmask.as_ref().map(|m| Mask {
                    data: m,
                    condensed: slt.condensed,
                });

                let packed = pack_data(slt.bit_length as usize, mask, &input_data)?;

                (packed, slt.bit_length as usize, slt.bitmask.clone())
            }
        };

        let byte_count = (bit_pos + bit_len as u32).div_ceil(8) as usize;

        // Step 1: Ensure PDU cut-out exists and is zero-initialized
        if uds_payload.len() < byte_pos + byte_count {
            uds_payload.resize(byte_pos + byte_count, 0);
        }

        // Step 2: Extract PDU cut-out
        let pdu_cut_out = &mut uds_payload[byte_pos..byte_pos + byte_count];

        // Step 3: Normalize input bytes if needed
        let mut normalized_input = normalize_byte_order(&mut packed_bytes, self.byte_order());

        // Step 4: Apply BIT-MASK (set bits in input to 0 where mask bit is 1)
        if let Some(mask) = mask {
            // Apply mask per bit to account for bit offsets
            for i in 0..bit_len {
                let mask_byte = mask[i / 8];
                let mask_bit = (mask_byte >> (i % 8)) & 1;
                if mask_bit == 1 {
                    let input_byte = i / 8;
                    let input_bit = i % 8;
                    normalized_input[input_byte] &= !(1 << input_bit);
                }
            }
        }

        // Step 5: Merge bit-stream into cut-out using logical OR, bit-by-bit
        for i in 0..bit_len {
            let input_byte = i / 8;
            let input_bit = i % 8;
            let input_bit_val = (normalized_input[input_byte] >> input_bit) & 1;

            let cut_out_bit_index = bit_pos as usize + i;
            let cut_out_bit = cut_out_bit_index % 8;
            let cut_out_byte = cut_out_bit_index / 8;

            pdu_cut_out[cut_out_byte] |= input_bit_val << cut_out_bit;
        }

         normalize_byte_order(pdu_cut_out, self.byte_order());
        Ok(())
    }

    fn byte_order(&self) -> ByteOrder {
        if self.is_high_low_byte_order {
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
        }
    }

    fn validate_bit_pos(&self, bit_pos: u32) -> Result<(), DiagServiceError> {
        // Bit offset for these datatypes are not allowed.
        if matches!(
            &self.base_datatype,
            DataType::Unicode2String
                | DataType::ByteField
                | DataType::AsciiString
                | DataType::Utf8String
        ) && bit_pos != 0
        {
            return Err(DiagServiceError::BadPayload(format!(
                "Bit position must be 0 for {:?}, got {bit_pos}",
                self.base_datatype
            )));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCodedTypeVariant {
    LeadingLengthInfo(BitLength),
    MinMaxLength(MinMaxLengthType),
    StandardLength(StandardLengthType),
}

impl MinMaxLengthType {
    pub fn validate(&self, data_type: &DataType) -> Result<(), DiagServiceError> {
        // todo alexmohr do this at construction time
        if self.max_length == 0 {
            return Err(DiagServiceError::BadPayload(
                "MinMaxLengthType max_length cannot be 0".to_owned(),
            ));
        }
        if self.max_length < self.min_length {
            return Err(DiagServiceError::BadPayload(format!(
                "MinMaxLengthType max_length {} cannot be less than min_length {}",
                self.max_length, self.min_length
            )));
        }
        if *data_type == DataType::Unicode2String
            && (!self.min_length.is_multiple_of(2) || !self.max_length.is_multiple_of(2))
        {
            return Err(DiagServiceError::BadPayload(format!(
                "DataType {data_type:?} needs an even amount of min/max bytes",
            )));
        }

        Ok(())
    }
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
    pub bit_length: BitLength,
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

    // Step 1: Calculate ByteCount using ceiling function
    // Not using div_ceil here because implementing it again is measurably faster
    // The following numbers are from a benchmark, and are an average of 3 run with 5*10^6 iterations
    // each
    //          mask  	    condensed	normal
    // ceil	    4.447730293	5.913945188	4.033881121
    // manual   4.262537672	5.68874875	3.937747568
    // improved 4.16%	    3.81%	    2.38%
    #[allow(clippy::manual_div_ceil)]
    let byte_count = ((bit_pos + bits as u32 + 7) / 8) as usize;
    if byte_pos + byte_count > uds_payload.len() {
        return Err(DiagServiceError::BadPayload(format!(
            "Input too short: need {byte_count} bytes starting at byte {byte_pos}, but payload \
             has {} bytes total",
            uds_payload.len()
        )));
    }

    // Step 2: Extract ByteCount bytes starting at byte_pos
    let mut extracted_bytes: Vec<u8> = uds_payload[byte_pos..byte_pos + byte_count].to_vec();
    let normalized_bytes = normalize_byte_order(&mut extracted_bytes, byte_order);

    // Step 4: Extract bits using bitwise operations instead of bit arrays
    let total_bits_needed = bits;
    #[allow(clippy::manual_div_ceil)]
    let result_byte_count = (total_bits_needed + 7) / 8;
    let mut result_bytes = vec![0u8; result_byte_count];

    // Extract bits
    for i in 0..total_bits_needed {
        let src_bit_index = bit_pos as usize + i;
        let src_byte_index = src_bit_index / 8;
        let src_bit_offset = src_bit_index % 8;

        if src_byte_index < normalized_bytes.len() {
            let bit_value = (normalized_bytes[src_byte_index] >> src_bit_offset) & 1;

            let dst_byte_index = i / 8;
            let dst_bit_offset = i % 8;

            if bit_value != 0 {
                result_bytes[dst_byte_index] |= 1 << dst_bit_offset;
            }
        }
    }

    // Step 5: Apply the mask if provided
    if let Some(mask) = mask {
        let mask_bit_count = std::cmp::min(mask.data.len() * 8, total_bits_needed);

        if mask.condensed {
            // Count set bits first to pre-allocate
            let mut set_bits_count = 0;
            for i in 0..mask_bit_count {
                let mask_byte_index = i / 8;
                let mask_bit_offset = i % 8;
                if mask_byte_index < mask.data.len() {
                    let mask_bit = (mask.data[mask_byte_index] >> mask_bit_offset) & 1;
                    if mask_bit != 0 {
                        set_bits_count += 1;
                    }
                }
            }

            // Create condensed result
            #[allow(clippy::manual_div_ceil)]
            let condensed_byte_count = (set_bits_count + 7) / 8;
            let mut condensed_bytes = vec![0u8; condensed_byte_count];
            let mut condensed_bit_index = 0;

            for i in 0..mask_bit_count {
                let mask_byte_index = i / 8;
                let mask_bit_offset = i % 8;

                if mask_byte_index < mask.data.len() {
                    let mask_bit = (mask.data[mask_byte_index] >> mask_bit_offset) & 1;

                    if mask_bit != 0 {
                        // Get the bit from result_bytes
                        let result_byte_index = i / 8;
                        let result_bit_offset = i % 8;

                        if result_byte_index < result_bytes.len() {
                            let result_bit =
                                (result_bytes[result_byte_index] >> result_bit_offset) & 1;

                            if result_bit != 0 {
                                let condensed_byte_index = condensed_bit_index / 8;
                                let condensed_bit_offset = condensed_bit_index % 8;
                                condensed_bytes[condensed_byte_index] |= 1 << condensed_bit_offset;
                            }
                        }
                        condensed_bit_index += 1;
                    }
                }
            }
            result_bytes = condensed_bytes;
        } else {
            // Apply mask normally without condensing
            for i in 0..mask_bit_count {
                let mask_byte_index = i / 8;
                let mask_bit_offset = i % 8;

                if mask_byte_index < mask.data.len() {
                    let mask_bit = (mask.data[mask_byte_index] >> mask_bit_offset) & 1;

                    if mask_bit == 0 {
                        let result_byte_index = i / 8;
                        let result_bit_offset = i % 8;

                        if result_byte_index < result_bytes.len() {
                            result_bytes[result_byte_index] &= !(1 << result_bit_offset);
                        }
                    }
                }
            }
        }
    }

    Ok(result_bytes)
}

fn pack_data(
    bit_length: usize,
    mask: Option<Mask>,
    source_value: &[u8],
) -> Result<Vec<u8>, DiagServiceError> {
    fn clear_bits_above_bit_len(bit_length: usize, result: &mut [u8]) {
        if bit_length % 8 != 0 {
            let last_byte_idx = bit_length / 8;
            if last_byte_idx < result.len() {
                let bits_to_keep = bit_length % 8;
                let mask_byte = (1u8 << bits_to_keep) - 1;
                result[last_byte_idx] &= mask_byte;
            }
        }
    }

    if bit_length == 0 {
        return Err(DiagServiceError::BadPayload(
            "Cannot insert 0 bits".to_owned(),
        ));
    }

    let condensed = mask.as_ref().is_some_and(|m| m.condensed);

    if let Some(mask) = mask {
        let mask_data = &mask.data;

        if condensed {
            // Count how many mask bits are set to 1
            let value_length = mask_data
                .iter()
                .map(|&byte| byte.count_ones() as usize)
                .sum::<usize>();

            // Calculate result size in bytes
            let result_byte_len = (mask_data.len() * 8 + 7) / 8;
            let mut result = vec![0u8; result_byte_len];

            let mut input_bit_index = 0;

            // Iterate through each bit in the mask (LSB first)
            for mask_bit_index in 0..(mask_data.len() * 8) {
                let mask_byte_idx = mask_bit_index / 8;
                let mask_bit_pos = mask_bit_index % 8;
                if mask_byte_idx < mask_data.len() {
                    let mask_bit = (mask_data[mask_byte_idx] >> mask_bit_pos) & 1;
                    if mask_bit == 1 {
                        // Copy input bit to result at mask position (LSB first)
                        if input_bit_index < bit_length && input_bit_index / 8 < source_value.len()
                        {
                            let input_byte_idx = input_bit_index / 8;
                            let input_bit_pos = input_bit_index % 8;
                            let input_bit = (source_value[input_byte_idx] >> input_bit_pos) & 1;
                            if input_bit == 1 {
                                let result_byte_idx = mask_bit_index / 8;
                                let result_bit_pos = mask_bit_pos;
                                if result_byte_idx < result.len() {
                                    result[result_byte_idx] |= 1 << result_bit_pos;
                                }
                            }
                            input_bit_index += 1;
                        } else if input_bit_index >= value_length * 8 {
                            return Err(DiagServiceError::BadPayload(format!(
                                "Mask provides more data than input, mask {} bits, input {} bits",
                                mask_data.len() * 8,
                                source_value.len() * 8
                            )));
                        }
                    }
                }
            }

            Ok(result)
        } else {
            // Non-condensed: apply mask directly
            let result_byte_len = (bit_length + 7) / 8;
            let mut result = vec![0u8; result_byte_len];

            // Copy input data up to bit_length
            let copy_bytes = std::cmp::min(source_value.len(), (bit_length + 7) / 8);
            let source_len = source_value.len();
            let result_len = result.len();
            let copy_bytes = std::cmp::min(source_len, result_len);

            result[(result_len - copy_bytes)..]
                .copy_from_slice(&source_value[(source_len - copy_bytes)..]);

            clear_bits_above_bit_len(bit_length, &mut result);

            // Apply mask - clear bits where mask is 0
            let mask_bytes = std::cmp::min(mask_data.len(), result.len());
            for i in 0..mask_bytes {
                result[i] &= mask_data[i];
            }

            Ok(result)
        }
    } else {
        // No mask: just copy data and clear bits beyond bit_length (LSB first)
        let result_byte_len = (bit_length + 7) / 8;
        let mut result = vec![0u8; result_byte_len];

        let source_len = source_value.len();
        let result_len = result.len();
        let copy_bytes = std::cmp::min(source_len, result_len);

        result[(result_len - copy_bytes)..]
            .copy_from_slice(&source_value[(source_len - copy_bytes)..]);

        clear_bits_above_bit_len(bit_length, &mut result);

        Ok(result)
    }
}

fn normalize_byte_order(data: &mut [u8], byte_order: ByteOrder) -> Vec<u8> {
    // Step 3: Normalization of data
    match byte_order {
        ByteOrder::Keep => {}
        ByteOrder::ReorderPairs => {
            // Reverse the byte order in pairs for Unicode2String
            for i in (0..data.len()).step_by(2) {
                if i + 1 < data.len() {
                    data.swap(i, i + 1);
                }
            }
        }
        ByteOrder::Reverse => {
            // Reverse the byte order
            data.reverse();
        }
    }
    data.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_type_variant_mapping() {
        // let mut input_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1];
        // let coded_type = DiagCodedType::new_high_low_byte_order(
        //     DataType::ByteField,
        //     DiagCodedTypeVariant::LeadingLengthInfo(8),
        // )
        // .unwrap();
        // let mut  uds_payload = Vec::new();
        // coded_type.encode(input_data, uds_payload.as_mut()).unwrap();
        // input_data.insert(0, 0x08); // insert length byte
        // assert_eq!(uds_payload, input_data);
        //
        // // make sure extra byte is cut off
        // let mut input_data = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0xab];
        // let coded_type = DiagCodedType::new_high_low_byte_order(
        //     DataType::ByteField,
        //     DiagCodedTypeVariant::LeadingLengthInfo(2), // 2 bit -> 3 max elements
        // )
        // .unwrap();
        //
        // let mut  uds_payload = Vec::new();
        // coded_type.encode(&input_data, uds_payload.as_mut()).unwrap();
        // input_data.insert(0, 0x03); // insert length byte
        // // the length info is only 2 bits,
        // // this means the remaining data is not written on exact byte borders
        // // the last byte 0x7a is ignored because it does not fit into our length
        // // data bits: 000100100011010001010110
        // // length:    11
        // // combined:  11000100100011010001010110
        // // + 6 bits padding to get full bytes
        // // 11000100100011010001010110000000
        // // converted to base is the value below
        // // inclusive range, to account for the length byte
        // assert_eq!(uds_payload, [0xc4, 0x8d, 0x15, 0x80]);
        //
        // let mut input_data = Vec::new();
        // for i in 0..=u32::from(u16::MAX) {
        //     // deliberately provide too much data that fully fills the length byte
        //     input_data.push(i as u8);
        // }
        // let coded_type = DiagCodedType::new_high_low_byte_order(
        //     DataType::ByteField,
        //     DiagCodedTypeVariant::LeadingLengthInfo(16),
        // )
        // .unwrap();
        //
        // let mut  uds_payload = Vec::new();
        // coded_type.encode(&input_data, &mut uds_payload).unwrap();
        // // insert both length bytes.
        // input_data.splice(..0, [0xFF, 0xFF]);
        // assert_eq!(uds_payload, input_data[0..=u16::MAX as usize + 1]);
        //
        // let input_data = vec![0x12, 0x34, 0x56, 0x7A];
        // let coded_type = DiagCodedType::new_high_low_byte_order(
        //     DataType::ByteField,
        //     DiagCodedTypeVariant::StandardLength(StandardLengthType {
        //         bit_length: 16,
        //         bitmask: Some(vec![0xFF, 0x0F]),
        //         condensed: false,
        //     }),
        // )
        // .unwrap();
        // let mut  uds_payload = Vec::new();
        // let result = coded_type.encode(&input_data, &mut uds_payload).unwrap();
        // // 0x12 & 0xFF = 0x12
        // // 0x34 & 0x0F = 0x04
        // assert_eq!(uds_payload, vec![0x12, 0x04]);
    }

    #[test]
    fn test_extract_bits_masked() {
        let mask = Mask {
            data: &vec![0b_1111_0000],
            condensed: false,
        };
        let payload: Vec<u8> = vec![0b_1010_1010];
        // 10101010 -- payload
        // 11110000 -- mask
        // ----------
        // 10100000
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_1010_0000]);
    }

    #[test]
    fn test_extract_bits_condensed() {
        let mask = Mask {
            data: &vec![0b_1111_0000],
            condensed: true,
        };
        let payload: Vec<u8> = vec![0b_1010_1010];
        // 10101010 -- payload
        // 11110000 -- mask
        // ----------> apply mask
        // 10100000 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1010     --> pad msb
        // 00001010 --> result byte
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_0000_1010]);
    }

    #[test]
    fn test_extract_bits_condensed_complex() {
        let mask = Mask {
            data: &vec![0b_1010_1010, 0b_0101_0101],
            condensed: true,
        };

        // 11111111 -- payload
        // 10101010 -- mask
        // ----------> apply mask
        // 10101010 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1-1-1-1-
        let payload: Vec<u8> = vec![0b_1111_1111, 0b_1111_1111];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_1111]);
    }

    #[test]
    fn test_extract_bits_condensed_all_zeros() {
        let mask = Mask {
            data: &vec![0b_0000_0000, 0b_0000_0000],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b_1111_1111, 0b_1111_1111];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        // If condensed is set to true, bits are only added to the result if the mask bit is 1.
        // As the mask is all zeros and the length of the result is equal to the count of
        // '1's in the mask, the result should be empty.
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_bits_condensed_sparse() {
        let mask = Mask {
            data: &vec![0b_1000_0001],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b_1000_0001];
        let result = extract_bits(8, 0, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_0000_0011]);
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
        assert_eq!(result, vec![0b_0110_1101, 0b_0001_0110]);

        // Extracting 3 bits starting from bit position 5 in byte 0
        // Byte 0: 0xab = 10101011
        //
        // Byte 0: -----101  --> take bits 5-7 from first byte  (total bits 3)
        let result = extract_bits(3, 5, 0, None, &[0xab], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_101]);

        // Extracting 4 bits starting from bit position 6 in byte 0
        // Byte 0: 0xf0 = 11110000
        // Byte 1: 0x0f = 00001111
        //
        // Byte 0: ------11  --> take bits 6-7 from first byte  (total bits 2)
        //         ----11--  --> take bits 0-1 from second byte (total bits 4)
        //         00001111  --> Result Byte 0
        let result = extract_bits(4, 6, 0, None, &[0xf0, 0x0f], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_1111]);

        // Extracting 7 bits starting from bit position 3 in byte 1
        // Byte 0: 0x01 = 00000001
        // Byte 1: 0xff = 11111111
        // Byte 2: 0x03 = 00000011
        // Extracting bits sequentially starting from byte 1, bit 3:
        // Byte 0: 00011111 --> take bits 3-7 from first byte (total bits 5)
        //         011      --> take 3 bits from second byte  (total bits 8)
        //         01111111 --> Result Byte 0
        let result = extract_bits(7, 3, 1, None, &[0x01, 0xff, 0x03], ByteOrder::Keep).unwrap();
        assert_eq!(result, vec![0b_1111_111]);
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

    #[test]
    fn test_data_packing() {
        // simple case, no mask, no truncation
        let source_value = vec![0, 0, 0, 4];
        // bit_length = 8, so no truncation, mask applied
        let result = pack_data(4, None, &source_value).unwrap();
        assert_eq!(result, vec![4]);

        // CONDENSED = false, truncate above BitLength, apply bitwise AND with mask
        let mask = Mask {
            data: &vec![0b_0101_0101],
            condensed: false,
        };
        let source_value = vec![0b_0101_0000];
        // bit_length = 8, so no truncation, mask applied
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_0101_0000]);

        // test extending of bits via condensed
        let mask = Mask {
            data: &vec![0b_0101_0101],
            condensed: true,
        };
        let source_value = vec![0b_0000_1100];
        // bit_length = 8, so no truncation, mask applied
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_0101_0000]);

        // CONDENSED = false, truncate above BitLength
        let mask = Mask {
            data: &vec![0b_1111_1111],
            condensed: false,
        };
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        // Only first 8 bits should remain, second byte truncated
        assert_eq!(result, vec![0b_1111_1111]);

        // CONDENSED = true, truncate above ValueLength, merge mask and input
        let mask = Mask {
            data: &vec![0b_1010_1010],
            condensed: true,
        };
        let source_value = vec![0b_1111_0000];
        // ValueLength = 4 (number of 1s in mask)
        // Only first 4 bits of input used: 0000
        // Mask: 10101010, replace each '1' with bits from input (LSB first)
        // OUT: 1-1-1-1- (positions 1,3,5,7 get bits 0,1,2,3 of input)
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        // Only bits at mask positions 0,2,4,6 replaced, rest remain 0
        // So result is 0b_00000000 (since input bits are 0)
        assert_eq!(result, vec![0b_00000000]);

        // CONDENSED = true, mask with all 1s, input fills all bits
        let mask = Mask {
            data: &vec![0b_1111_1111],
            condensed: true,
        };
        let source_value = vec![0b_1010_1010];
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        // All mask bits are 1, so output is input
        assert_eq!(result, vec![0b_1010_1010]);

        // CONDENSED = true, mask with sparse 1s, input fills only those bits
        let mask = Mask {
            data: &vec![0b_1000_0001],
            condensed: true,
        };
        let source_value = vec![0b_11];
        let result = pack_data(8, Some(mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_1000_0001]); // bits are extended over the mask positions

        // No mask, truncate above bit_length
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let result = pack_data(8, None, &source_value).unwrap();
        assert_eq!(result, vec![0b_1111_1111]);

        // Truncate to 5 bits, no mask
        let source_value = vec![0b11111111];
        let result = pack_data(5, None, &source_value).unwrap();
        // Only first 5 bits remain: 11111 (0b11111 = 31)
        assert_eq!(result, vec![0b00011111]);

        // Truncate to 12 bits, no mask
        let source_value = vec![0b11111111, 0b11111111];
        let result = pack_data(12, None, &source_value).unwrap();
        // Only first 12 bits remain: 0b11111111_1111 (0xFFF)
        assert_eq!(result, vec![0b11111111, 0b00001111]);

        // Mask with bit_length = 5, condensed = false
        let mask = Mask {
            data: &vec![0b00011111],
            condensed: false,
        };
        let source_value = vec![0b11111111];
        let result = pack_data(5, Some(mask), &source_value).unwrap();
        // Only first 5 bits, mask applied: 11111 & 11111 = 11111
        assert_eq!(result, vec![0b00011111]);

        // Mask with bit_length = 10, condensed = false
        let mask = Mask {
            data: &vec![0b11111111, 0b00000011],
            condensed: false,
        };
        let source_value = vec![0b11111111, 0b11111111];
        let result = pack_data(10, Some(mask), &source_value).unwrap();
        // Only first 10 bits, mask applied: 11111111_11 & 11111111_11 = 11111111_11
        assert_eq!(result, vec![0b11111111, 0b00000011]);

        // Mask with bit_length = 5, condensed = true
        let mask = Mask {
            data: &vec![0b00011111],
            condensed: true,
        };
        let source_value = vec![0b11111111];
        let result = pack_data(5, Some(mask), &source_value).unwrap();
        // Only bits at mask positions 0-4 replaced, rest remain 0
        assert_eq!(result, vec![0b00011111]);

        // Mask with bit_length = 10, condensed = true
        let mask = Mask {
            data: &vec![0b11111111, 0b00000011],
            condensed: true,
        };
        let source_value = vec![0b11111111, 0b11];
        let result = pack_data(10, Some(mask), &source_value).unwrap();
        // All mask bits are 1, so output is input
        assert_eq!(result, vec![0b11111111, 0b00000011]);
    }

    fn test_min_max_length(
        min_length: u32,
        max_length: u32,
        payload: Vec<u8>,
        expected: Vec<u8>,
        base_datatype: DataType,
        termination: Termination,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
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
                2,
                10,
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
                vec![0x61, 0x62], // min length not reached, expect error
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
        let diag_type = DiagCodedType::new_high_low_byte_order(
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
            vec![0b_1010_0011, 0x01, 0x02, 0x03, 0x04], // First 4 bits (1010) indicate 3 bytes
            vec![0x01, 0x02, 0x03],                     // Expected: 3 bytes after length
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

    fn test_encode_leading_length(
        bit_length: u32,
        input_data: Vec<u8>,
        expected: Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(bit_length),
        )?;
        let mut uds_payload = Vec::new();
        diag_type.encode(input_data.clone(), &mut uds_payload, 0, 0)?;
        assert_eq!(uds_payload, expected);
        Ok(())
    }

    #[test]
    fn test_encode_leading_length_8bit() {
        let input = vec![0xab, 0xcd, 0xef];
        let mut expected = vec![0x03];
        expected.extend(input.clone());
        test_encode_leading_length(8, input, expected).unwrap();
    }

    #[test]
    fn test_encode_leading_length_16bit() {
        let input = vec![0xcd, 0xef];
        let mut expected = vec![0x00, 0x02];
        expected.extend(input.clone());
        test_encode_leading_length(16, input, expected).unwrap();
    }

    #[test]
    fn test_encode_leading_length_32bit() {
        let input = vec![0xcd, 0xef];
        let mut expected = vec![0x00, 0x00, 0x00, 0x02];
        expected.extend(input.clone());
        test_encode_leading_length(32, input, expected).unwrap();
    }

    #[test]
    fn test_encode_leading_length_4bit() {
        let input = vec![0x01, 0x02, 0x03];
        test_encode_leading_length(4, input, vec![3, 1, 2, 3]).unwrap();
    }

    fn test_encode_min_max_length(
        min_length: u32,
        max_length: u32,
        input_data: Vec<u8>,
        expected: Vec<u8>,
        base_datatype: DataType,
        termination: Termination,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
            base_datatype,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length,
                max_length,
                termination,
            }),
        )?;
        let mut uds_payload = Vec::new();
        diag_type.encode(input_data.clone(), &mut uds_payload, 0, 0)?;
        assert_eq!(uds_payload, expected);
        Ok(())
    }

    #[test]
    fn test_encode_min_max_length_ascii_zero_termination() {
        let input = vec![b'a', b'b'];
        let mut expected = input.clone();
        expected.push(0x00);
        test_encode_min_max_length(
            2,
            10,
            input,
            expected,
            DataType::AsciiString,
            Termination::Zero,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_min_max_length_utf8_ff_termination() {
        let input = vec![0x68, 0x69];
        let mut expected = input.clone();
        expected.push(0xFF);
        test_encode_min_max_length(
            2,
            10,
            input,
            expected,
            DataType::Utf8String,
            Termination::HexFF,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_min_max_length_unicode2_zero_termination() {
        let input = vec![0x00, 0x61, 0x00, 0x62];
        let mut expected = input.clone();
        expected.extend(vec![0x00, 0x00]);
        test_encode_min_max_length(
            4,
            8,
            input,
            expected,
            DataType::Unicode2String,
            Termination::Zero,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_min_max_length_unicode2_ff_termination() {
        let input = vec![0x00, 0x61, 0x00, 0x62];
        let mut expected = input.clone();
        expected.extend(vec![0xFF, 0xFF]);
        test_encode_min_max_length(
            4,
            8,
            input,
            expected,
            DataType::Unicode2String,
            Termination::HexFF,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_min_max_length_bytefield_end_of_pdu() {
        let input = vec![0x01, 0x02, 0x03];
        let expected = input.clone();
        test_encode_min_max_length(
            2,
            4,
            input,
            expected,
            DataType::ByteField,
            Termination::EndOfPdu,
        )
        .unwrap();
    }

    fn test_encode_standard_length(
        bit_length: u32,
        bitmask: Option<Vec<u8>>,
        condensed: bool,
        input_data: Vec<u8>,
        expected: Vec<u8>,
        base_datatype: DataType,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
            base_datatype,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length,
                bitmask: bitmask.clone(),
                condensed,
            }),
        )?;
        let mut uds_payload = vec![0; ((bit_length + 7) / 8) as usize];
        diag_type.encode(input_data.clone(), &mut uds_payload, 0, 0)?;
        assert_eq!(uds_payload, expected);
        Ok(())
    }

    #[test]
    fn test_encode_standard_length_no_mask() {
        let input = vec![0x12, 0x34];
        let expected = input.clone();
        test_encode_standard_length(16, None, false, input, expected, DataType::ByteField).unwrap();
    }

    #[test]
    fn test_encode_standard_length_with_mask() {
        let input = vec![0x12, 0x34];
        let expected = vec![0x12, 0x04];
        test_encode_standard_length(
            16,
            Some(vec![0xFF, 0x0F]),
            false,
            input,
            expected,
            DataType::ByteField,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_standard_length_condensed() {
        let input = vec![0x12, 0x34];
        test_encode_standard_length(
            16,
            Some(vec![0xFF, 0x0F]),
            true,
            input,
            vec![0x12, 0x04],
            DataType::ByteField,
        )
        .unwrap();
    }

    #[test]
    fn test_encode_standard_length_ascii_string() {
        let input = vec![b'A', b'B'];
        let expected = input.clone();
        test_encode_standard_length(16, None, false, input, expected, DataType::AsciiString)
            .unwrap();
    }

    #[test]
    fn test_encode_standard_length_utf8_string() {
        let input = vec![0x68, 0x69];
        let expected = input.clone();
        test_encode_standard_length(16, None, false, input, expected, DataType::Utf8String)
            .unwrap();
    }

    #[test]
    fn test_encode_standard_length_unicode2_string() {
        let input = vec![0x00, 0x61, 0x00, 0x62];
        let expected = input.clone();
        test_encode_standard_length(32, None, false, input, expected, DataType::Unicode2String)
            .unwrap();
    }

    #[test]
    fn test_encode_standard_length_float32() {
        let input = vec![0x12, 0x34, 0x56, 0x78];
        let expected = input.clone();
        test_encode_standard_length(32, None, false, input, expected, DataType::Float32).unwrap();
    }

    #[test]
    fn test_encode_standard_length_float64() {
        let input = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1];
        let expected = input.clone();
        test_encode_standard_length(64, None, false, input, expected, DataType::Float64).unwrap();
    }

    #[test]
    fn test_encode_standard_length_uint32() {
        let input = vec![0x12, 0x34, 0x56, 0x78];
        let expected = input.clone();
        test_encode_standard_length(32, None, false, input, expected, DataType::UInt32).unwrap();
    }

    #[test]
    fn test_encode_standard_length_int32() {
        let input = vec![0x12, 0x34, 0x56, 0x78];
        let expected = input.clone();
        test_encode_standard_length(32, None, false, input, expected, DataType::Int32).unwrap();
    }

    #[test]
    fn test_encode_standard_length_masked_protection() {
        // Initial payload with some bits set
        let mut uds_payload = vec![0b_1111_0000, 0b_1010_1010];
        // Input data to encode
        let input = vec![0b_0000_1111, 0b_0101_0101];
        // Mask: protect upper 4 bits of first byte, lower 4 bits of second byte
        let bitmask = vec![0b_1111_0000, 0b_0000_1111];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(bitmask.clone()),
                condensed: false,
            }),
        )
        .unwrap();

        // Encode into payload, modifying only unmasked bits
        diag_type
            .encode(input.clone(), &mut uds_payload, 0, 0)
            .unwrap();

        // For this test we can ignore the cut-out rules, because the payload and input
        // are both 16 bits long
        // 1. Mask the input with
        //   0000 1111 0101 0101
        // & 1111 0000 0000 1111
        //   -------------------
        //   00000 0000 0000 0101
        // 2. Clear all bits in the cut-out where bit mask is 1
        //    Do this by negating the mask and AND'ing with uds_payload
        //   1111 0000 1010 1010
        // & 0000 1111 1111 0000
        //   -------------------
        //   0000 0000 1010 0000
        // 3. OR the results of step 1 and step 2
        //   0000 0000 0000 0101
        // | 0000 0000 1010 0000
        //   -------------------
        //   0000 0000 1010 0101

        assert_eq!(uds_payload, vec![0b0000_0000, 0b1010_0101]);
    }

    #[test]
    fn test_encode_standard_length_masked_partial_protection() {
        // Initial payload with alternating bits
        let mut uds_payload = vec![0b_1010_1010, 0b_0101_0101];
        // Input data to encode
        let input = vec![0b_11001100, 0b_00110011];
        // Mask: protect only bits 0 and 7 in both bytes
        let bitmask = vec![0b_10000001, 0b_10000001];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(bitmask.clone()),
                condensed: false,
            }),
        )
        .unwrap();

        diag_type
            .encode(input.clone(), &mut uds_payload, 0, 0)
            .unwrap();

        // Bits 0 and 7 remain unchanged, others are OR'ed with input
        // For byte 0:
        // bits 0 and 7: original
        // bits 1-6: (original & !mask) | (input & !mask)
        let expected0 = (0b_1010_1010 & 0b_10000001)
            | ((0b_10101010 & !0b_10000001) | (0b_11001100 & !0b_10000001));
        let expected1 = (0b_0101_0101 & 0b_10000001)
            | ((0b_01010101 & !0b_10000001) | (0b_00110011 & !0b_10000001));
        assert_eq!(uds_payload, vec![expected0, expected1]);
    }

    #[test]
    fn test_encode_standard_length_masked_no_change_on_protected_bits() {
        // Initial payload with all bits set
        let mut uds_payload = vec![0xFF, 0xFF];
        // Input data to encode (all zeros)
        let input = vec![0x00, 0x00];
        // Mask: protect all bits
        let bitmask = vec![0xFF, 0xFF];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(bitmask.clone()),
                condensed: false,
            }),
        )
        .unwrap();

        diag_type
            .encode(input.clone(), &mut uds_payload, 0, 0)
            .unwrap();

        // All bits are protected, so payload should remain unchanged
        assert_eq!(uds_payload, vec![0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_standard_length_masked_change_unprotected_bits_only() {
        // Initial payload with all bits set
        let mut uds_payload = vec![0x00, 0x00];
        // Input data to encode (all zeros)
        let input = vec![0xff, 0xff];
        // Mask: protect only upper nibble
        let bitmask = vec![0xF0, 0xF0];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(bitmask.clone()),
                condensed: false,
            }),
        )
        .unwrap();

        diag_type
            .encode(input.clone(), &mut uds_payload, 0, 0)
            .unwrap();

        // Bits 0-3 and 8-11 remain unchanged, others are set to 0
        assert_eq!(uds_payload, vec![0b11110000, 0b11110000]);
    }

    #[test]
    fn test_encode_standard_length_masked_cut_out_middle_of_payload_condensed_false() {
        // Initial payload: 8 bytes, all set to 0b_1010_1010
        let mut uds_payload = vec![0b_1010_1010; 8];
        // Input data: 3 bytes
        let input = vec![0b_1010_1010, 0b_1100_1100, 0b_1111_0000];
        // Mask: protect upper nibble of each byte
        let bitmask = vec![0xF0, 0xF0, 0xF0];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 24,
                bitmask: Some(bitmask.clone()),
                condensed: false,
            }),
        )
        .unwrap();

        // Encode into payload at byte offset 3, bit offset 5
        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 5)
            .unwrap();

        // Only lower nibbles of bytes 3,4,5 should be changed
        let affected = &uds_payload[3..6];
        let expected: Vec<u8> = affected
            .iter()
            .zip(input.iter())
            .zip(bitmask.iter())
            .map(|((orig, inp), mask)| (orig & mask) | (inp & !mask))
            .collect();
        assert_eq!(affected, &expected[..]);
    }

    #[test]
    fn test_encode_standard_length_masked_cut_out_middle_of_payload_condensed_true() {
        // Initial payload: 8 bytes, all set to 0b_1010_1010
        let mut uds_payload = vec![0b_1010_1010; 8];
        // Input data: 0b_11001100 (8 bits)
        let input = vec![0b_11001100];
        // Mask: only bits 1,3,5,7 in each byte
        let bitmask = vec![0b_10101010, 0b_10101010, 0b_10101010];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 24,
                bitmask: Some(bitmask.clone()),
                condensed: true,
            }),
        )
        .unwrap();

        // Encode into payload at byte offset 3, bit offset 5
        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 5)
            .unwrap();

        // Only bits in mask positions should be set according to input bits
        // For simplicity, just check that masked positions in affected region are set
        let affected = &uds_payload[3..6];
        let expected = vec![0b_10101010, 0b_10101010, 0b_10101010]; // unchanged except masked bits
        assert_eq!(affected, &expected[..]);
    }
    #[test]
    fn test_encode_standard_length_normalization_reverse_byte_order() {
        // Initial payload: 4 bytes, all zeros
        let mut uds_payload = vec![0x00; 4];
        // Input data: 0x12, 0x34, 0x56, 0x78 (big endian)
        let input = vec![0x12, 0x34, 0x56, 0x78];
        let diag_type = DiagCodedType::new(
            DataType::UInt32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 32,
                bitmask: None,
                condensed: false,
            }),
            false, // is_high_low_byte_order = false (little endian)
        )
        .unwrap();

        diag_type
            .encode(input.clone(), &mut uds_payload, 0, 0)
            .unwrap();

        // Expect bytes reversed in payload
        assert_eq!(uds_payload, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_encode_iso_example() {
        let mut uds_payload = vec![42, 37, 18, 0b_1100_0011, 0b_1010_1000, 192];
        let input = vec![5];
        // No mask, not condensed
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Int32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 4,
                bitmask: Some(vec![0b_0000_0111_u8]),
                condensed: false,
            }),
        )
        .unwrap();

        // Encode into payload at byte offset 3, bit offset 5
        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 5)
            .unwrap();

        assert_eq!(
            uds_payload,
            vec![42, 37, 18, 0b_1100_0011, 0b_1010_1000, 192]
        );
    }

    #[test]
    fn test_encode_standard_length_cut_out_middle_of_payload_byte_border() {
        // Initial payload: 8 bytes, all set to 0b_1010_1010
        let mut uds_payload = vec![0b_1010_1010; 8];
        // Input data: 3 bytes
        let input = vec![0b_1010_1010, 0b_1100_1100, 0b_1111_0000];
        // No mask, not condensed
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Int32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 24,
                bitmask: None,
                condensed: false,
            }),
        )
            .unwrap();

        // Encode into payload at byte offset 3, bit offset 5
        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 0)
            .unwrap();

        assert_eq!(
            uds_payload,
            vec![
                0b_1010_1010, // 0
                0b_1010_1010, // 1
                0b_1010_1010, // 2
                0b_1010_1010, // 3
                0b_1100_1100|0b_1010_1010, // 4
                0b_1111_0000|0b_1010_1010, // 5
                0b_1010_1010, // 6
                0b_1010_1010, // 7
            ]
        );
    }

    #[test]
    fn test_encode_standard_length_cut_out_middle_of_payload_offset() {
        // Initial payload: 8 bytes, all set to 0b_1010_1010
        let mut uds_payload = vec![0b_1010_1010; 8];
        // Input data: 3 bytes
        let input = vec![0b_1010_1010, 0b_1100_1100, 0b_1111_0000];
        // No mask, not condensed
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Int32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 24,
                bitmask: None,
                condensed: false,
            }),
        )
        .unwrap();

        // Encode into payload at byte offset 3, bit offset 5
        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 5)
            .unwrap();

        assert_eq!(
            uds_payload,
            vec![
                0b_1010_1010, // 0
                0b_1010_1010, // 1
                0b_1010_1010, // 2
                0b_1010_1010, // 3
                0b_1100_1100, // 4
                0b_1111_0000, // 5
                0b_1010_1010, // 6
                0b_1010_1010, // 7
            ]
        );
    }
}
