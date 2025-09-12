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

use cda_interfaces::DiagServiceError;
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{DiagCodedTypeMap, ref_optional_none},
    proto::dataformat::{self, diag_coded_type},
};

pub type BitLength = u32;

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

        if &DataType::Unicode2String == self && !bit_len.is_multiple_of(16) {
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

#[derive(Copy, Clone)]
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
    /// Creates a new `DiagCodedType` with high-low byte order.
    pub fn new_high_low_byte_order(
        base_datatype: DataType,
        type_: DiagCodedTypeVariant,
    ) -> Result<Self, DiagServiceError> {
        Self::new(base_datatype, type_, true)
    }

    /// Creates a new `DiagCodedType` with the given byte order.
    /// Set `is_high_low_byte_order` to `true` for high-low byte order (Big Endian),
    pub fn new(
        base_datatype: DataType,
        type_: DiagCodedTypeVariant,
        is_high_low_byte_order: bool,
    ) -> Result<Self, DiagServiceError> {
        match type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(_) | DiagCodedTypeVariant::MinMaxLength(_) => {
                if !matches!(
                    base_datatype,
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

                if let DiagCodedTypeVariant::MinMaxLength(mmlt) = &type_
                    && base_datatype == DataType::Unicode2String
                    && (!mmlt.min_length.is_multiple_of(2)
                        || !mmlt.max_length.is_some_and(|l| l.is_multiple_of(2)))
                {
                    return Err(DiagServiceError::BadPayload(format!(
                        "DataType {base_datatype:?} needs an even amount of min/max bytes",
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

    pub fn base_datatype(&self) -> DataType {
        self.base_datatype
    }

    pub fn type_(&self) -> &DiagCodedTypeVariant {
        &self.type_
    }

    /// Decodes data from a UDS payload according to the coded type.
    ///
    /// # Arguments
    /// * `uds_payload` - The payload bytes.
    /// * `byte_pos` - The starting byte position, starting with 0 at most significant byte.
    /// * `bit_pos` - The starting bit position, starting with 0 at least significant bit.
    ///
    /// # Returns
    /// `Ok((Vec<u8>, usize))` with decoded data and bit length, or `Err(DiagServiceError)`
    ///
    /// The bit length will be necessary to convert the data into a physical value
    /// This function is implementing the data decoding logic as described in
    /// chapter 7.3.6.2. of ISO 22901-1:2008.
    pub fn decode(
        &self,
        uds_payload: &[u8],
        byte_pos: usize,
        bit_pos: usize,
    ) -> Result<(Vec<u8>, usize), DiagServiceError> {
        self.validate_bit_pos(bit_pos)?;
        let byte_order = self.byte_order();
        let (bit_len, start_pos, mask) = match self.type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(bits) => {
                self.base_datatype.validate_bit_len(bits)?;

                // The leading length parameter must be extracted separately
                let (length_info_bytes, _len) = unpack_data(
                    bits as usize,
                    bit_pos,
                    None,
                    &uds_payload[byte_pos..bits.div_ceil(8) as usize],
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
                let start_pos = byte_pos + length_info_bytes.len();
                let end_pos = start_pos + len;
                if end_pos > uds_payload.len() {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Not enough data in payload: need {} bytes, but only {} bytes available",
                        end_pos,
                        uds_payload.len()
                    )));
                }
                ((end_pos - start_pos) * 8, start_pos, None)
            }
            DiagCodedTypeVariant::MinMaxLength(ref mmlt) => {
                let max_end = if let Some(max_length) = mmlt.max_length {
                    usize::min(byte_pos + max_length as usize, uds_payload.len())
                } else {
                    uds_payload.len()
                };

                let end_pos = match mmlt.termination {
                    Termination::EndOfPdu => {
                        // Read until end of pdu or max size, whatever comes first.
                        max_end
                    }
                    Termination::Zero => {
                        let mut end_pos = byte_pos;
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

                        end_pos
                    }
                    Termination::HexFF => {
                        let mut end_pos = byte_pos;
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

                        end_pos
                    }
                };

                let len = end_pos - byte_pos;
                if len < mmlt.min_length as usize {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Not enough data in payload, needed at least {} bytes, got {} bytes",
                        mmlt.min_length, len
                    )));
                }

                ((end_pos - byte_pos) * 8, byte_pos, None)
            }

            DiagCodedTypeVariant::StandardLength(ref slt) => {
                self.base_datatype.validate_bit_len(slt.bit_length)?;
                let mask = slt.bitmask.as_ref().map(|m| Mask {
                    data: m.clone(),
                    condensed: slt.condensed,
                });

                (slt.bit_length as usize, byte_pos, mask)
            }
        };

        // no data extraction necessary here, skip it
        // for example this can happen  with end of pdu min max sizes, where min size = 0
        // and no data actually is at the end of the payload.
        if bit_len == 0 {
            return Ok((Vec::new(), 0));
        }

        let end_pos = start_pos + (bit_len.div_ceil(8));
        if uds_payload.len() < end_pos {
            return Err(DiagServiceError::NotEnoughData {
                expected: end_pos,
                actual: uds_payload.len(),
            });
        }

        unpack_data(
            bit_len,
            bit_pos,
            mask.as_ref(),
            &uds_payload[start_pos..end_pos],
            byte_order,
        )
    }

    /// Encodes input data into a UDS payload according to the coded type.
    /// No conversion from physical values is done here.
    ///
    /// # Arguments
    /// * `input_data` - The data to encode, this is the computed value for the parameter.
    /// * `uds_payload` - The payload bytes.
    ///   New data is directly injected into the `uds_payload`.
    /// * `byte_pos` - The starting byte position, counting starts with 0 at most significant byte.
    /// * `bit_pos` - The starting bit position, starting with 0 at least significant bit.
    ///   Valid range is 0..=7.
    ///
    /// This function is implementing the data encoding logic as described in
    /// chapter 7.3.6.4 of ISO 22901-1:2008.
    pub fn encode(
        &self,
        mut input_data: Vec<u8>,
        uds_payload: &mut Vec<u8>,
        byte_pos: usize,
        bit_pos: usize,
    ) -> Result<(), DiagServiceError> {
        self.validate_bit_pos(bit_pos)?;
        let (packed_bytes, bit_len, mask) = match &self.type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(bit_len) => {
                // Subtract the next multiple of 8 from the length in usize as bits.
                // Shift the length up this amount of bits to put the relevant data into
                // the MSBs of the length usize.
                let len_byte_count = bit_len.div_ceil(8);
                let len_bit_len = len_byte_count * 8;
                let mut data = (input_data.len() << (usize::BITS - len_bit_len)).to_be_bytes()
                    [0..len_byte_count as usize]
                    .to_vec();

                if data.is_empty() {
                    return Err(DiagServiceError::BadPayload(
                        "Failed to create length info for leading length".to_owned(),
                    ));
                }

                data.append(&mut input_data);
                let (packed, len) = pack_data(data.len() * 8, 0, None, &data)?;
                (packed, len, None)
            }
            DiagCodedTypeVariant::MinMaxLength(mmlt) => {
                // Note: Unicode2String is always 2 bytes per character,
                // therefore all Termination expect EndOfPdu will add 2 termination bytes.
                let (packed, len) = match mmlt.termination {
                    Termination::EndOfPdu => {
                        // No special termination, just pack the data as is
                        pack_data(input_data.len() * 8, 0, None, &input_data)
                    }
                    Termination::Zero => {
                        if self.base_datatype == DataType::Unicode2String {
                            input_data.append(&mut vec![0_u8, 0_u8]);
                        } else {
                            input_data.push(0_u8);
                        }
                        pack_data(input_data.len() * 8, 0, None, &input_data)
                    }
                    Termination::HexFF => {
                        if self.base_datatype == DataType::Unicode2String {
                            input_data.append(&mut vec![0xff_u8, 0xff_u8]);
                        } else {
                            input_data.push(0xff_u8);
                        }
                        pack_data(input_data.len() * 8, 0, None, &input_data)
                    }
                }?;

                (packed, len, None)
            }
            DiagCodedTypeVariant::StandardLength(slt) => {
                self.base_datatype.validate_bit_len(slt.bit_length)?;
                let mask = slt.bitmask.as_ref().map(|m| Mask {
                    data: m.clone(),
                    condensed: slt.condensed,
                });

                let (packed, len) =
                    pack_data(slt.bit_length as usize, 0, mask.as_ref(), &input_data)?;
                (packed, len, mask)
            }
        };

        let byte_count = (bit_pos + bit_len).div_ceil(8);
        // Ensure PDU cut-out exists and is zero-initialized
        if uds_payload.len() < byte_pos + byte_count {
            uds_payload.resize(byte_pos + byte_count, 0);
        }
        let mut pdu_cut_out = uds_payload[byte_pos..byte_pos + byte_count].to_vec();
        normalize_byte_order(&mut pdu_cut_out, self.byte_order());

        if let Some(mask) = mask {
            // apply inverted mask, this is protecting bits already set in the pdu.
            apply_bit_mask(
                &mut pdu_cut_out,
                mask.data.iter().map(|b| !b).collect::<Vec<u8>>().as_ref(),
                bit_len,
                bit_pos,
            );
        }

        inject_bits(bit_len, bit_pos, &mut pdu_cut_out, &packed_bytes)?;
        normalize_byte_order(&mut pdu_cut_out, self.byte_order());
        uds_payload[byte_pos..byte_pos + byte_count].copy_from_slice(&pdu_cut_out);

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

    /// Validate the bit position for the current data type.
    /// The types `Unicode2String`, `ByteField`, `AsciiString`, `Utf8String`
    /// as well as complex objects have to cover whole bytes, meaning
    /// the bit position must be 0 and the length must be a multiple of 8
    /// (16 in case of A_UNICODE2STRING).
    /// This remains true even if the bit-length of the data object is dynamically defined,
    /// through min max length or leading length info.
    fn validate_bit_pos(&self, bit_pos: usize) -> Result<(), DiagServiceError> {
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

/// Injects bits from source_data into dst_data at the given bit position and length.
/// Used to inject bits into a PDU payload.
/// # Arguments
/// * `bit_len` - Number of bits to inject.
/// * `bit_pos` - Bit position to start, counting starts at least significant bit.
///   Valid range is 0..=7.
/// * `dst_data` - Destination data slice, where data will be copied into.
/// * `source_data` - Source data slice, to get data from.
///
fn inject_bits(
    bit_len: usize,
    mut bit_pos: usize,
    dst_data: &mut [u8],
    source_data: &[u8],
) -> Result<(), DiagServiceError> {
    // Validate inputs
    if bit_pos > 7 {
        return Err(DiagServiceError::BadPayload(format!(
            "BitPosition range is 0..=7, got {bit_pos}",
        )));
    }

    if bit_len == 0 {
        return Err(DiagServiceError::BadPayload(
            "Cannot inject 0 bits".to_owned(),
        ));
    }

    let byte_count = (bit_pos + bit_len).div_ceil(8);
    for i in 0..bit_len.min(source_data.len() * 8) {
        let src_byte_index = source_data.len() - (i / 8) - 1;
        let src_bit_offset = i % 8;
        let bit_value = (source_data[src_byte_index] >> src_bit_offset) & 1;

        let dst_byte_index = byte_count - 1 - (bit_pos / 8);
        let dst_bit_offset = bit_pos % 8;
        if dst_byte_index >= dst_data.len() {
            break;
        }

        dst_data[dst_byte_index] |= bit_value << dst_bit_offset;
        bit_pos += 1;
    }
    Ok(())
}

/// Read a given number of bits from the data slice starting at the given bit position.
/// Used to extract bits from a PDU payload.
/// # Arguments
/// * `bit_len` - Number of bits to extract.
/// * `bit_pos` - Bit position to start, counting starts at least significant bit.
///   Valid range is 0..=7.
/// * `data` - Source data slice.
pub fn extract_bits(
    bit_len: usize,
    bit_pos: usize,
    data: &[u8],
) -> Result<Vec<u8>, DiagServiceError> {
    if bit_pos > 7 {
        return Err(DiagServiceError::BadPayload(format!(
            "BitPosition range is 0..=7, got {bit_pos}",
        )));
    }

    if bit_len == 0 {
        return Err(DiagServiceError::BadPayload(
            "Cannot extract 0 bits".to_owned(),
        ));
    }

    if bit_pos + bit_len > data.len() * 8 {
        return Err(DiagServiceError::BadPayload(format!(
            "Bit position {bit_pos} with length {bit_len} exceeds data length {} bits",
            data.len() * 8
        )));
    }

    let result_byte_count = bit_len.div_ceil(8);
    let mut result_bytes = vec![0u8; result_byte_count];

    for i in 0..bit_len {
        let src_bit_index = bit_pos + i;
        let src_byte_index = data.len() - (src_bit_index / 8) - 1;
        let src_bit_offset = src_bit_index % 8;

        let bit_value = (data[src_byte_index] >> src_bit_offset) & 1;

        let dst_byte_index = result_byte_count - (i / 8) - 1;
        let dst_bit_offset = i % 8;

        result_bytes[dst_byte_index] |= bit_value << dst_bit_offset;
    }

    Ok(result_bytes)
}

/// Applies a bit mask to the data slice.
///
/// # Arguments
/// * `data` - Data to mask.
/// * `mask` - Mask to apply.
/// * `bit_len` - Maximum number of bits.
///   Processing stops when this number of bits is reached or data ends.
/// * `bit_pos` - Bit position to start from.
///   Bits are started counting from the least significant bit.
///   Valid range is 0..=7.
fn apply_bit_mask(data: &mut [u8], mask: &[u8], bit_len: usize, bit_pos: usize) {
    for i in 0..bit_len {
        if bit_pos + i >= data.len() * 8 {
            // If the bit position exceeds the data length, we stop processing
            break;
        }

        let mask_byte_idx = mask.len() - (i / 8) - 1;
        let mask_bit_pos = i % 8;
        let mask_bit = (mask[mask_byte_idx] >> mask_bit_pos) & 1;

        let data_byte_idx = data.len() - ((bit_pos + i) / 8) - 1;
        let data_bit_pos = (bit_pos + i) % 8;
        let data_bit = (data[data_byte_idx] >> data_bit_pos) & 1;

        let data_byte = &mut data[data_byte_idx];

        *data_byte &= !(1 << data_bit_pos); // clear bit before setting it
        *data_byte |= (data_bit & mask_bit) << data_bit_pos;
    }
}

/// The function iterates over the mask and collects up to bit_len bits with the following logic.
/// * Iterate over each bit in the mask.
/// * If the bit is 0, skip it.
/// * If the bit is 1, extract the corresponding bit from the data at the given bit position.
///   and write this into a new result vector.
/// * Stop when we have collected enough bits (up to bit_len).
/// * The returned result vector contains the condensed data, the new bit length is the number
///   of bits collected, which is either equal to bit_len or the sum of '1's in the mask,
///   whichever is smaller.
///
/// For more details see chapter 7.3.6.3. e) in ISO 22901-1:2008.
fn apply_condensed_mask_unpacking(
    bit_mask: &[u8],
    bit_field: &[u8],
    bit_len: usize,
) -> (Vec<u8>, usize) {
    let max_bits = bit_mask
        .iter()
        .map(|&byte| byte.count_ones() as usize)
        .sum::<usize>()
        .min(bit_len);

    if max_bits == 0 {
        return (Vec::new(), 0);
    }

    let result_byte_count = max_bits.div_ceil(8);
    let mut result_bytes = vec![0u8; result_byte_count];

    let mut extracted_bits_count = 0;
    for i in 0..bit_len {
        let src_byte_index = bit_field.len() - (i / 8) - 1;
        let src_bit_offset = i % 8;

        if src_byte_index < bit_mask.len() {
            let mask_bit = (bit_mask[src_byte_index] >> src_bit_offset) & 1;
            if mask_bit == 1 {
                let bit_value = (bit_field[src_byte_index] >> src_bit_offset) & 1;

                let target_byte_index = result_byte_count - (extracted_bits_count / 8) - 1;
                let target_bit_offset = extracted_bits_count % 8;

                result_bytes[target_byte_index] |= bit_value << target_bit_offset;
                extracted_bits_count += 1;
            }
        }
    }

    if extracted_bits_count.div_ceil(8) < result_bytes.len() {
        // If we have less bits than bytes, we need to truncate the result.
        result_bytes.drain(..extracted_bits_count.div_ceil(8));
    }

    (result_bytes, max_bits)
}

/// Applies a condensed mask for packing bits.
/// Copies the mask into a new result vector.
/// For each '1' bit in the mask, it copies over the next bit from the data slice.
///
/// input: 0000 1100
/// mask:  0101 0101
/// output: 0101 0000
/// 0000: Copied the input bits at 0 and 1 into the 1s of the lower nibble
/// 0101: Copied the input bits at 2 and 3 into the 1s of the upper nibble
/// For more details see chapter 7.3.6.4 a) 5) in ISO 22901-1:2008.
fn apply_condensed_mask_packing(data: &[u8], mask: &[u8], bit_pos: usize) -> (Vec<u8>, usize) {
    let mut result = mask.to_vec();
    let mut data_bit_idx = 0;
    let mut mask_bit_idx = 0;

    loop {
        if mask_bit_idx >= mask.len() * 8 {
            break;
        }

        let mask_byte_idx = mask.len() - (mask_bit_idx / 8) - 1;
        let mask_bit_pos = mask_bit_idx % 8;
        let mask_bit = (mask[mask_byte_idx] >> mask_bit_pos) & 1;
        mask_bit_idx += 1;

        if mask_bit == 1 && data_bit_idx < data.len() * 8 {
            let data_byte_idx = data.len() - ((bit_pos + data_bit_idx) / 8) - 1;
            let data_bit_pos = (bit_pos + data_bit_idx) % 8;
            let data_bit = (data[data_byte_idx] >> data_bit_pos) & 1;

            result[mask_byte_idx] &= !(1 << mask_bit_pos); // clear bit before setting it
            result[mask_byte_idx] |= data_bit << mask_bit_pos;
            data_bit_idx += 1;
        }
    }

    (result, mask_bit_idx)
}

#[derive(Clone)]
struct Mask {
    data: Vec<u8>,
    condensed: bool,
}

/// Unpacks data from a byte slice, applying mask if needed.
///
/// # Arguments
/// * `bit_len` - Number of bits to pack.
/// * `bit_pos` - Bit position to start.
///   Valid range is 0..=7, counting starts at least significant bit.
/// * `mask` - Optional mask.
/// * `data` - Source data slice.
/// * `byte_order` - Byte order to apply to the data slice, to apply normalization.
///
/// Implements 7.3.6.4 a) of ISO 22901-1:2008.
fn unpack_data(
    bit_len: usize,
    bit_pos: usize,
    mask: Option<&Mask>,
    data: &[u8],
    byte_order: ByteOrder,
) -> Result<(Vec<u8>, usize), DiagServiceError> {
    let data = &mut data.to_vec();
    normalize_byte_order(data, byte_order);
    let mut bit_data = extract_bits(bit_len, bit_pos, data)?;
    if let Some(mask) = mask {
        if mask.condensed {
            return Ok(apply_condensed_mask_unpacking(
                mask.data.as_slice(),
                &bit_data,
                bit_len,
            ));
        } else {
            apply_bit_mask(&mut bit_data, mask.data.as_slice(), bit_len, bit_pos);
        }
    }
    Ok((bit_data, bit_len))
}

/// Packs data into a byte slice, applying mask if needed.
/// Data is packed, condensed and truncated if necessary.
///
/// # Arguments
/// * `bit_len` - Number of bits to pack.
/// * `bit_pos` - Bit position to start.
///   Valid range is 0..=7, counting starts at least significant bit.
/// * `mask` - Optional mask.
/// * `data` - Source data slice.
///
/// In contrast to `unpack_data` normalization is not applied here in accordance with the
/// standard. This will be done when the data is put into the UDS payload.
/// Implements 7.3.6.4 a) of ISO 22901-1:2008.
fn pack_data(
    bit_len: usize,
    bit_pos: usize,
    mask: Option<&Mask>,
    data: &[u8],
) -> Result<(Vec<u8>, usize), DiagServiceError> {
    #[inline]
    fn clear_bits_above_bit_len(bit_length: usize, result: &mut [u8]) {
        let remainder = bit_length % 8;
        if remainder != 0 {
            let last_byte_idx = bit_length / 8;
            if last_byte_idx < result.len() {
                let mask_byte = (1u8 << remainder) - 1;
                result[last_byte_idx] &= mask_byte;
            }
        }
    }

    if bit_len == 0 {
        return Err(DiagServiceError::BadPayload("Cannot insert 0 bits".into()));
    }

    if let Some(mask) = &mask {
        if mask.condensed {
            Ok(apply_condensed_mask_packing(data, &mask.data, bit_pos))
        } else {
            let result_byte_len = bit_len.div_ceil(8);
            let mut result = vec![0u8; result_byte_len];

            let copy_bytes = data.len().min(result_byte_len);
            let start_idx = result_byte_len - copy_bytes;

            result[start_idx..].copy_from_slice(&data[data.len() - copy_bytes..]);
            clear_bits_above_bit_len(bit_len, &mut result);
            apply_bit_mask(&mut result, &mask.data, bit_len, bit_pos);

            Ok((result, bit_len))
        }
    } else {
        // No mask: just copy data and clear bits beyond bit_length
        let result_byte_len = bit_len.div_ceil(8);
        let mut result = vec![0u8; result_byte_len];

        let copy_bytes = data.len().min(result_byte_len);
        let start_idx = result_byte_len - copy_bytes;

        result[start_idx..].copy_from_slice(&data[data.len() - copy_bytes..]);
        clear_bits_above_bit_len(bit_len, &mut result);

        Ok((result, bit_len))
    }
}

/// Normalizes the byte order of a data slice according to the specified order.
fn normalize_byte_order(data: &mut [u8], byte_order: ByteOrder) {
    match byte_order {
        ByteOrder::Keep => {}
        ByteOrder::ReorderPairs => {
            // Reverse the byte order in pairs for Unicode2String
            for chunk in data.chunks_mut(2) {
                if chunk.len() == 2 {
                    chunk.swap(0, 1);
                }
            }
        }
        ByteOrder::Reverse => {
            // Reverse the byte order
            data.reverse();
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCodedTypeVariant {
    LeadingLengthInfo(BitLength),
    MinMaxLength(MinMaxLengthType),
    StandardLength(StandardLengthType),
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MinMaxLengthType {
    pub min_length: u32,
    pub max_length: Option<u32>,
    pub termination: Termination,
}

impl MinMaxLengthType {
    pub fn new(
        min_length: u32,
        max_length: Option<u32>,
        termination: Termination,
    ) -> Result<Self, DiagServiceError> {
        if let Some(max_length) = max_length {
            if max_length == 0 {
                return Err(DiagServiceError::BadPayload(
                    "MinMaxLengthType max_length cannot be 0".to_owned(),
                ));
            }

            if max_length < min_length {
                return Err(DiagServiceError::BadPayload(format!(
                    "MinMaxLengthType max_length {max_length} cannot be less than min_length \
                     {min_length}",
                )));
            }
        }

        let instance = Self {
            min_length,
            max_length,
            termination,
        };

        Ok(instance)
    }

    pub fn min_length(&self) -> u32 {
        self.min_length
    }

    pub fn max_length(&self) -> Option<u32> {
        self.max_length
    }

    pub fn termination(&self) -> &Termination {
        &self.termination
    }
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
                    match MinMaxLengthType::new(
                        m.min_length,
                        m.max_length,
                        match m.termination.try_into().ok() {
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
                    ) {
                        Ok(mmlt) => DiagCodedTypeVariant::MinMaxLength(mmlt),
                        Err(e) => {
                            return Err(e);
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpack_data_masked() {
        let mask = Mask {
            data: vec![0b_1111_0000],
            condensed: false,
        };
        let payload: Vec<u8> = vec![0b_1010_1010];
        // 10101010 -- payload
        // 11110000 -- mask
        // ----------
        // 10100000
        let (data, bit_len) = unpack_data(8, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(data, vec![0b_1010_0000]);
        assert_eq!(bit_len, 8);
    }
    #[test]
    fn test_unpack_data_condensed() {
        let mask = Mask {
            data: vec![0b_1111_0000],
            condensed: true,
        };
        let payload: Vec<u8> = vec![0b_1010_1111];
        // 10101010 -- payload
        // 11110000 -- mask
        // 10100000 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1010     --> pad msb
        // 00001010 --> result byte
        let (data, bit_len) = unpack_data(8, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(data, vec![0b_0000_1010]);
        assert_eq!(bit_len, 4);
    }

    #[test]
    fn test_unpack_data_condensed_complex() {
        let mask = Mask {
            data: vec![0b_1010_1010, 0b_0101_0101],
            condensed: true,
        };

        // 11111111 -- payload
        // 10101010 -- mask
        // ----------> apply mask
        // 10101010 -- to condense extract the bits from the payload where the mask has "1"s.
        // 1-1-1-1-
        let payload: Vec<u8> = vec![0b_1111_1111, 0b_1111_1111];
        let (data, bit_len) = unpack_data(8, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(data, vec![0b_0000_1111]);
        assert_eq!(bit_len, 8);
    }

    #[test]
    fn test_unpack_data_condensed_all_zeros() {
        let mask = Mask {
            data: vec![0b_0000_0000, 0b_0000_0000],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b_1111_1111, 0b_1111_1111];
        let (data, bit_len) = unpack_data(8, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        // If condensed is set to true, bits are only added to the result if the mask bit is 1.
        // As the mask is all zeros and the length of the result is equal to the count of
        // '1's in the mask, the result should be empty.
        assert!(data.is_empty());
        assert_eq!(bit_len, 0);
    }

    #[test]
    fn test_unpack_data_condensed_sparse() {
        let mask = Mask {
            data: vec![0b_1000_0001],
            condensed: true,
        };

        let payload: Vec<u8> = vec![0b_1000_0001];
        let (data, bit_len) = unpack_data(8, 0, Some(&mask), &payload, ByteOrder::Keep).unwrap();
        assert_eq!(data, vec![0b_0000_0011]);
        assert_eq!(bit_len, 2);
    }

    #[test]
    fn test_extract_bits_standard_length_cases() {
        let result = extract_bits(4, 5, &[0b_1100_0011, 0b_1010_1000]).unwrap();
        assert_eq!(result, vec![0b_1101]);

        let result = extract_bits(8, 0, &[0b_1010_1000]).unwrap();
        assert_eq!(result, vec![0b_1010_1000]);

        let result = extract_bits(8, 0, &[0xff, 0x00]).unwrap();
        assert_eq!(result, vec![0]);

        // Test standard length with byte alignment
        // 16 bits from 2 bytes, no offset
        // Should extract bytes as is since we're starting at bit 0
        let result = extract_bits(16, 0, &[0xab, 0xcd]).unwrap();
        assert_eq!(result, vec![0xab, 0xcd]);

        // bits are read LSB first, therefore 18 bits 1, which means 6 most significant bits = 0
        let result = extract_bits(18, 0, &[0xff, 0xff, 0xff]).unwrap();
        assert_eq!(result, vec![0b_11, 0xff, 0xff]);

        // Extracting 13 bits starting from bit position 5
        // 101010111100110101000010 -- input
        //      1010101111001101010 -- from bit pos 5
        //            1111001101010 -- 13 bits
        //        00011110 01101010 -- 2 result bytes
        let result = extract_bits(13, 5, &[0b_1010_1011, 0b_1100_1101, 0b_0100_0010]).unwrap();
        assert_eq!(result, vec![0b_0001_1110, 0b_0110_1010]);

        // Extracting 3 bits starting from bit position 5
        // Byte 0: 0xab = 10101011
        //
        // Byte 0: -----101  --> take bits 5-7 from first byte  (total bits 3)
        let result = extract_bits(3, 5, &[0xab]).unwrap();
        assert_eq!(result, vec![0b_101]);

        // Extracting 4 bits starting from bit position 6
        // 1111000000001111 -- input
        //       1111000000 -- from bit pos 6
        //          1000000 -- 5 bits
        let result = extract_bits(7, 6, &[0b_1111_0000, 0b_0000_1111]).unwrap();
        assert_eq!(result, vec![0b_0100_0000]);
    }

    #[test]
    fn test_extract_bits_error_cases() {
        // Test insufficient data
        assert!(extract_bits(16, 0, &[0xab]).is_err());

        // Test invalid bit position
        assert!(extract_bits(8, 8, &[0xff]).is_err());

        // Test zero bits
        assert!(extract_bits(0, 0, &[0xff]).is_err());
    }

    #[test]
    fn test_unpack_data_byte_order_cases() {
        let (data, bit_len) = unpack_data(16, 0, None, &[0x12, 0x34], ByteOrder::Reverse).unwrap();
        assert_eq!(data, vec![0x34, 0x12]);
        assert_eq!(bit_len, 16);

        let (data, bit_len) =
            unpack_data(32, 0, None, &[0x12, 0x34, 0x56, 0x78], ByteOrder::Reverse).unwrap();
        assert_eq!(data, vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(bit_len, 32);

        // Test Unicode2String byte pair reversal
        let (data, bit_len) = unpack_data(
            32,
            0,
            None,
            &[0x12, 0x34, 0x56, 0x78],
            ByteOrder::ReorderPairs,
        )
        .unwrap();
        assert_eq!(data, vec![0x34, 0x12, 0x78, 0x56]);
        assert_eq!(bit_len, 32);

        // Test Unicode2String byte pair reversal with odd number of bytes
        let (data, bit_len) =
            unpack_data(24, 0, None, &[0x12, 0x34, 0x56], ByteOrder::ReorderPairs).unwrap();
        assert_eq!(data, vec![0x34, 0x12, 0x56]);
        assert_eq!(bit_len, 24);

        // Test byte reversal with masking
        let mask = Mask {
            data: vec![0xFF, 0x0F],
            condensed: false,
        };
        let (data, bit_len) =
            unpack_data(16, 0, Some(&mask), &[0x12, 0x34], ByteOrder::Reverse).unwrap();
        // First reverse bytes: [0x34, 0x12]
        // Then apply mask:     [0xFF, 0x0F]
        // Result:             [0x34, 0x02]
        assert_eq!(data, vec![0x34, 0x02]);
        assert_eq!(bit_len, 16);

        // Test byte reversal with condensed masking
        let mask = Mask {
            data: vec![0b_1111_0000, 0b_1111_0000],
            condensed: true,
        };
        let (data, bit_len) = unpack_data(
            16,
            0,
            Some(&mask),
            &[0b_1100_1100, 0b_0011_0011],
            ByteOrder::Reverse,
        )
        .unwrap();
        // First reverse bytes, then apply condensed mask:
        // 0011_0011 1100_1100
        // 1111_0000 1111_0000
        // ---------------
        // 0011_---- 1100_---
        assert_eq!(data, vec![0b_0011_1100]);
        assert_eq!(bit_len, 8);
    }

    #[test]
    fn test_data_packing() {
        // simple case, no mask, no truncation
        let source_value = vec![0, 0, 0, 4];
        let (result, len) = pack_data(4, 0, None, &source_value).unwrap();
        assert_eq!(result, vec![4]);
        assert_eq!(len, 4);

        // CONDENSED = false, truncate above BitLength, apply bitwise AND with mask
        let mask = Mask {
            data: vec![0b_0101_0101],
            condensed: false,
        };
        let source_value = vec![0b_0101_0000];
        // bit_length = 8, so no truncation, mask applied
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_0101_0000]);
        assert_eq!(len, 8);

        // test extending of bits via condensed
        let mask = Mask {
            data: vec![0b_0101_0101],
            condensed: true,
        };
        let source_value = vec![0b_0000_1100];
        // 0101_0101 -- mask
        // 0000_1100 -- source value
        // 0101_0000 -- init output with mask, then copy bits from source value
        // where mask is 1
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_0101_0000]);
        assert_eq!(len, 8);

        // CONDENSED = false, truncate above BitLength
        let mask = Mask {
            data: vec![0b_1111_1111],
            condensed: false,
        };
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        // Only first 8 bits should remain, second byte truncated
        assert_eq!(result, vec![0b_1111_1111]);
        assert_eq!(len, 8);

        let mask = Mask {
            data: vec![0b_1010_1010],
            condensed: true,
        };
        let source_value = vec![0b_1111_0000];
        // 1010_1010 -- mask
        // 1111_0000 -- value
        // Mask bits from LSB | output | bit of value
        // 0 | 0 | -
        // 1 | 0 | 0
        // 0 | 0 | -
        // 1 | 0 | 1
        // 0 | 0 | -
        // 1 | 0 | 2
        // 0 | 0 | -
        // 1 | 0 | 3
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0]);
        assert_eq!(len, 8);

        // CONDENSED = true, mask with all 1s
        let mask = Mask {
            data: vec![0b_1111_1111],
            condensed: true,
        };
        let source_value = vec![0b_1010_1010];
        // 1010_1010 -- value
        // 1111_1111 -- mask
        // 1010_1010 -- bits of source where mask = 1
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_1010_1010]);
        assert_eq!(len, 8);

        // CONDENSED = true, mask with sparse 1s
        let mask = Mask {
            data: vec![0b_1000_0001],
            condensed: true,
        };
        let source_value = vec![0b_11];

        // 1000_0001 -- mask
        // 0000_0011 -- value
        let (result, len) = pack_data(8, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_1000_0001]);
        assert_eq!(len, 8);

        // No mask, truncate above bit_length
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let (result, len) = pack_data(8, 0, None, &source_value).unwrap();
        assert_eq!(result, vec![0b_1111_1111]);
        assert_eq!(len, 8);

        // Truncate to 5 bits, no mask
        let source_value = vec![0b_1111_1111];
        let (result, len) = pack_data(5, 0, None, &source_value).unwrap();
        // Only first 5 bits remain: 11111 (0b_0001_1111 = 31)
        assert_eq!(result, vec![0b_0001_1111]);
        assert_eq!(len, 5);

        // Truncate to 12 bits, no mask
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let (result, len) = pack_data(12, 0, None, &source_value).unwrap();
        // Only first 12 bits remain: 0b_1111_1111_1111 (0xFFF)
        assert_eq!(result, vec![0b_1111_1111, 0b_0000_1111]);
        assert_eq!(len, 12);

        // Mask with bit_length = 5, condensed = false
        let mask = Mask {
            data: vec![0b_0001_1111],
            condensed: false,
        };
        let source_value = vec![0b_1111_1111];
        let (result, len) = pack_data(5, 0, Some(&mask), &source_value).unwrap();
        // Only first 5 bits, mask applied: 11111 & 11111 = 11111
        assert_eq!(result, vec![0b_0001_1111]);
        assert_eq!(len, 5);

        // Mask with bit_length = 10, condensed = false
        let mask = Mask {
            data: vec![0b_1111_1111, 0b_0000_0011],
            condensed: false,
        };
        let source_value = vec![0b_1111_1111, 0b_1111_1111];
        let (result, len) = pack_data(10, 0, Some(&mask), &source_value).unwrap();
        // Only first 10 bits, mask applied: 11111111_11 & 11111111_11 = 11111111_11
        assert_eq!(result, vec![0b_1111_1111, 0b_0000_0011]);
        assert_eq!(len, 10);

        // Mask with bit_length = 5, condensed = true
        let mask = Mask {
            data: vec![0b_0001_1111],
            condensed: true,
        };
        let source_value = vec![0b_1111_1111];
        let (result, len) = pack_data(5, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_0001_1111]);
        assert_eq!(len, 8);

        // Mask with bit_length = 10, condensed = true
        let mask = Mask {
            data: vec![0b_1111_1111, 0b_0000_0011],
            condensed: true,
        };
        let source_value = vec![0b_1111_1111, 0b11];
        // 1111_1111 0000_0011 -- input
        // 1111_1111 0000_0011 -- mask
        let (result, len) = pack_data(10, 0, Some(&mask), &source_value).unwrap();
        assert_eq!(result, vec![0b_1100_0000, 0b_0000_0011]);
        assert_eq!(len, 16);

        // Test with bit_pos != 0
        let source_value = vec![0b_1010_1010];
        // Pack 5 bits starting at bit_pos 3
        let (result, len) = pack_data(5, 3, None, &source_value).unwrap();
        assert_eq!(result, vec![0b_01010]);
        assert_eq!(len, 5);
    }

    fn test_min_max_length(
        min_length: u32,
        max_length: u32,
        payload: Vec<u8>,
        expected: Vec<u8>,
        base_datatype: DataType,
        termination: Termination,
    ) -> Result<(), DiagServiceError> {
        test_min_max_length_with_byte_pos(
            min_length,
            max_length,
            payload,
            expected,
            0,
            base_datatype,
            termination,
        )
    }

    fn test_min_max_length_with_byte_pos(
        min_length: u32,
        max_length: u32,
        payload: Vec<u8>,
        expected: Vec<u8>,
        byte_pos: usize,
        base_datatype: DataType,
        termination: Termination,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
            base_datatype,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length,
                max_length: Some(max_length),
                termination,
            }),
        )?;

        let (data, bit_len) = diag_type.decode(&payload, byte_pos, 0)?;
        assert_eq!(data, expected);
        assert_eq!(bit_len, expected.len() * 8);
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

    fn test_leading_length(
        bit_length: u32,
        byte_pos: usize,
        bit_pos: usize,
        payload: Vec<u8>,
        expected: Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(bit_length),
        )?;

        let (data, bit_len) = diag_type.decode(&payload, byte_pos, bit_pos)?;
        assert_eq!(data, expected);
        assert_eq!(bit_len, expected.len() * 8);
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
        test_leading_length(8, 0, 0, vec![0x00, 0xff], vec![]).unwrap();
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
                max_length: Some(max_length),
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
        test_encode_standard_length_with_byte_pos(
            0,
            bit_length,
            bitmask,
            condensed,
            input_data,
            expected,
            base_datatype,
        )
    }

    fn test_encode_standard_length_with_byte_pos(
        byte_pos: usize,
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
        let mut uds_payload = vec![0; bit_length.div_ceil(8) as usize];
        diag_type.encode(input_data.clone(), &mut uds_payload, byte_pos, 0)?;
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
        // 1111_1111 0000_1111 -- mask
        // 0001_0010 0011_0100 -- input
        // 0010_0011 0000_0100 -- condensed input
        // 1111_1111  -- mask
        // 0001_0010 0011 -- input
        // 0010 0011
        // 0010_0011
        // 0010_0000
        let input = vec![0x12, 0x34];
        test_encode_standard_length(
            16,
            Some(vec![0xFF, 0x0F]),
            true,
            input,
            vec![0b_0010_0011, 0b_0000_0100],
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
        let input = vec![0xff, 0xff, 0xff, 0xaa];
        // expect 4 bytes payload, with 0xaa for the last byte
        // since we have to allocate 4 bytes to be able to allocate
        // data at index (byte pos) 3
        let expected = vec![0x00, 0x00, 0x00, 0xaa];
        test_encode_standard_length_with_byte_pos(
            3,
            8,
            None,
            false,
            input,
            expected,
            DataType::UInt32,
        )
        .unwrap();

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
        let input = vec![0b_1100_1100, 0b_0011_0011];
        // Mask: protect only bits 0 and 7 in both bytes
        let bitmask = vec![0b_1000_0001, 0b_1000_0001];
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

        // 1100_1100 0011_0011 -- input
        // 1000_0001 1000_0001 -- mask
        // 1000_0000 0000_0001 -- mask & input
        //
        // 1010_1010 0101_0101 -- payload
        // 0111_1110 0111_1110 -- !mask
        // 0010_1010 0101_0100 -- payload & !mask
        // 1000_0000 0000_0001 -- mask & payload
        // 1010_1010 0101_0101 -- (mask & payload) | (input & !mask)
        assert_eq!(uds_payload, vec![0b_1010_1010, 0b_0101_0101]);
    }

    #[test]
    fn test_encode_standard_length_masked_no_change_on_protected_bits() {
        // Initial payload with all bits set
        let mut uds_payload = vec![0xFF, 0xFF];
        // Input data to encode (all zeros)
        let input = vec![0xFF, 0xFF];
        // Mask: protect all bits
        let bitmask = vec![0x00, 0xFF];
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
        let mut uds_payload = vec![0x00, 0x00];
        let input = vec![0xff, 0xff];
        // Mask: protect only upper nibble
        // will protect 0x0f for both payload bytes.
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

        assert_eq!(uds_payload, vec![0b1111_0000, 0b_1111_0000]);
    }

    #[test]
    fn test_encode_standard_length_masked_cut_out_middle_of_payload_condensed() {
        let mut uds_payload = vec![0b_1010_1010; 8];
        let input = vec![0b_1100_1100];
        let bitmask = vec![0b_1110_1001, 0b_1101_1111, 0b_1101_1111];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Int32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 24,
                bitmask: Some(bitmask.clone()),
                condensed: true,
            }),
        )
        .unwrap();

        diag_type
            .encode(input.clone(), &mut uds_payload, 3, 6)
            .unwrap();

        // 0000_0000 0000_0000 1100_1100 -- input
        // 1110_1001 1101_0001 1101_1111 -- mask
        // 1. combine mask and input with condensing rules.
        // 111010011101000111001100
        // 2. prepare cut out
        // 10101010101010101010101010101010
        // 3. Mask the cut-out with the negated mask starting at byte offset 3, bit pos 6
        // 4. OR new data into the cut-out
        let expected = [
            0b_1010_1010,
            0b_1010_1010,
            0b_1010_1010,
            0b_1011_1010,
            0b_1111_1111,
            0b_1110_1011,
            0b_0010_1010,
            0b_1010_1010,
        ];
        assert_eq!(uds_payload, expected);
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
        // 11000000
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
                0b_1010_1010,                // 0
                0b_1010_1010,                // 1
                0b_1010_1010,                // 2
                0b_1010_1010,                // 3
                0b_1100_1100 | 0b_1010_1010, // 4
                0b_1111_0000 | 0b_1010_1010, // 5
                0b_1010_1010,                // 6
                0b_1010_1010,                // 7
            ]
        );
    }

    #[test]
    fn test_encode_standard_length_cut_out_middle_of_payload_offset() {
        // Initial payload: 8 bytes, all set to 0b_1010_1010
        let mut uds_payload = vec![0b_1010_1010; 8];
        // Input data: 3 bytes
        let input = vec![0b_1010_1010, 0b_1100_1100, 0b_1110_0001];
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

        // data is written least significant bit first, there reading the data injection below
        // bottom up is the order the data will be applied to the uds_payload
        assert_eq!(
            uds_payload,
            vec![
                0b_1010_1010,
                0b_1010_1010,
                0b_1010_1010,
                // 5 bits from byte 0
                0b_1010_1010 | 0b_10101,
                // 5 bits from byte 1, 3 bits from byte 0
                0b_1010_1010 | 0b_0100_0000 | 0b_0001_1001,
                // 5 bits from byte 2, 3 bits from byte 1
                0b_1010_1010 | 0b_1000_0000 | 0b_0001_1100,
                // 3 bits from byte 2 inserted at bit pos 5
                0b_1010_1010 | 0b_0010_0000,
                0b_1010_1010
            ]
        );
    }

    #[test]
    fn test_decode_leading_length_8bit() {
        let payload = vec![0x03, 0xab, 0xcd, 0xef];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(8),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0xab, 0xcd, 0xef]);
        assert_eq!(bit_len, 24);
    }

    #[test]
    fn test_decode_leading_length_16bit() {
        let payload = vec![0x00, 0x02, 0xcd, 0xef];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(16),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0xcd, 0xef]);
        assert_eq!(bit_len, 16);
    }

    #[test]
    fn test_decode_leading_length_32bit() {
        let payload = vec![0x00, 0x00, 0x00, 0x02, 0xcd, 0xef];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(32),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0xcd, 0xef]);
        assert_eq!(bit_len, 16);
    }

    #[test]
    fn test_decode_leading_length_4bit() {
        let payload = vec![0b_1010_0011, 0x01, 0x02, 0x03, 0x04];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(4),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03]);
        assert_eq!(bit_len, 24);
    }

    #[test]
    fn test_decode_min_max_length_ascii_zero_termination() {
        let payload = vec![b'a', b'b', 0x00, b'c'];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::AsciiString,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length: 2,
                max_length: Some(10),
                termination: Termination::Zero,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![b'a', b'b']);
        assert_eq!(bit_len, 16);
    }

    #[test]
    fn test_decode_min_max_length_utf8_ff_termination() {
        let payload = vec![0x68, 0x69, 0xFF, 0x00];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Utf8String,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length: 2,
                max_length: Some(10),
                termination: Termination::HexFF,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0x68, 0x69]);
        assert_eq!(bit_len, 16);
    }

    #[test]
    fn test_decode_min_max_length_unicode2_zero_termination() {
        let payload = vec![0x00, 0x61, 0x00, 0x62, 0x00, 0x00];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Unicode2String,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length: 4,
                max_length: Some(8),
                termination: Termination::Zero,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0x00, 0x61, 0x00, 0x62]);
        assert_eq!(bit_len, 32);
    }

    #[test]
    fn test_decode_min_max_length_end_of_pdu_termination() {
        // special case, we have no data at the end of the PDU
        let payload = vec![0xaa, 0xbb];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length: 0,
                max_length: Some(0x9001),
                termination: Termination::EndOfPdu,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 2, 0).unwrap();
        assert!(data.is_empty());
        assert_eq!(bit_len, 0);

        // special case, we have no data at the end of the PDU
        let payload = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length: 1,
                max_length: Some(0x9001),
                termination: Termination::EndOfPdu,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 1, 0).unwrap();
        assert_eq!(data, vec![0xbb, 0xcc, 0xdd]);
        assert_eq!(bit_len, 24);
    }

    #[test]
    fn test_decode_standard_length_no_mask() {
        let payload = vec![0x12, 0x34];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: None,
                condensed: false,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0x12, 0x34]);
        assert_eq!(bit_len, 16);

        let payload = vec![0x72, 0x01, 0x02, 0x03, 0x04, 0x42];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::UInt32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 1,
                bitmask: None,
                condensed: false,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 5, 1).unwrap();
        assert_eq!(data, vec![0x01]);
        assert_eq!(bit_len, 1);
    }

    #[test]
    fn test_decode_standard_length_with_mask() {
        let payload = vec![0x12, 0x34];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(vec![0xFF, 0x0F]),
                condensed: false,
            }),
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        // 0000 0100
        // 0000 1111
        // 0000 0100
        assert_eq!(data, vec![0x12, 0x04]);
        assert_eq!(bit_len, 16);
    }

    #[test]
    fn test_decode_standard_length_condensed() {
        let payload = vec![0b_0001_0010, 0b_0011_0100];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bitmask: Some(vec![0b_1111_1111, 0b_0000_1111]),
                condensed: true,
            }),
        )
        .unwrap();

        // 0001 0010 0011_0100 -- payload
        // 1111_1111 0000_1111 -- mask
        // 0001 0010 ---- 0100
        // 0000 0001 0010_0100 -- condensed result
        // 0000_0000 0000_0000
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0b_0000_0001, 0b_0010_0100]);
        assert_eq!(bit_len, 12);
    }

    #[test]
    fn test_decode_standard_length_reverse_byte_order() {
        let payload = vec![0x12, 0x34, 0x56, 0x78];
        let diag_type = DiagCodedType::new(
            DataType::UInt32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 32,
                bitmask: None,
                condensed: false,
            }),
            false,
        )
        .unwrap();
        let (data, bit_len) = diag_type.decode(&payload, 0, 0).unwrap();
        assert_eq!(data, vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(bit_len, 32);
    }

    #[test]
    fn test_decode_error_cases() {
        // Insufficient data for leading length
        let payload = vec![0x03, 0xab];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::ByteField,
            DiagCodedTypeVariant::LeadingLengthInfo(8),
        )
        .unwrap();
        assert!(diag_type.decode(&payload, 0, 0).is_err());

        // Invalid bit position for Unicode2String
        let payload = vec![0x00, 0x61, 0x00, 0x62];
        let diag_type = DiagCodedType::new_high_low_byte_order(
            DataType::Unicode2String,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 32,
                bitmask: None,
                condensed: false,
            }),
        )
        .unwrap();
        assert!(diag_type.decode(&payload, 0, 1).is_err());
    }

    #[test]
    fn test_inject_bits_basic() {
        let mut dst = [0u8; 2];
        let src = [0b_1010_1010];
        inject_bits(8, 0, &mut dst, &src).unwrap();
        assert_eq!(dst, [0b_1010_1010, 0]);
    }

    #[test]
    fn test_extract_bits_basic() {
        let src = [0b_1010_1010];
        let result = extract_bits(8, 0, &src).unwrap();
        assert_eq!(result, vec![0b_1010_1010]);
    }

    #[test]
    fn test_apply_bit_mask_basic() {
        let mut data = [0b_1010_1010];
        let mask = [0b_1111_0000];
        apply_bit_mask(&mut data, &mask, 8, 0);
        assert_eq!(data, [0b_1010_0000]);
    }

    #[test]
    fn test_normalize_byte_order_reverse() {
        let mut data = [0x12, 0x34, 0x56, 0x78];
        normalize_byte_order(&mut data, ByteOrder::Reverse);
        assert_eq!(data, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_normalize_byte_order_reorder_pairs() {
        let mut data = [0x12, 0x34, 0x56, 0x78];
        normalize_byte_order(&mut data, ByteOrder::ReorderPairs);
        assert_eq!(data, [0x34, 0x12, 0x78, 0x56]);
    }

    #[test]
    fn test_apply_condensed_mask_unpacking_basic() {
        let mask = [0b_1010_1010];
        let field = [0b_1111_0000];
        let (result, bit_len) = apply_condensed_mask_unpacking(&mask, &field, 8);
        // 1111_0000
        // 1010_1010
        // 1-1-_0-0-
        // 0000_1100
        assert_eq!(result, vec![0b_0000_1100]);
        assert_eq!(bit_len, 4);
    }

    #[test]
    fn test_apply_condensed_mask_packing_basic() {
        let input = [0b_0000_1100];
        let mask = [0b_0101_0101];
        let (result, bit_len) = apply_condensed_mask_packing(&input, &mask, 0);
        assert_eq!(result, vec![0b_0101_0000]);
        assert_eq!(bit_len, 8);
    }

    #[test]
    fn test_min_max_length_type_error_on_max_less_than_min() {
        let min_length = 10;
        let max_length = Some(5);
        let termination = Termination::EndOfPdu;
        let result = MinMaxLengthType::new(min_length, max_length, termination);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            DiagServiceError::BadPayload(
                "MinMaxLengthType max_length 5 cannot be less than min_length 10".to_owned()
            )
        );
    }
}
