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
use crate::DiagServiceError;

pub mod tracing {
    #[must_use]
    pub fn print_hex(data: &[u8], max_size: usize) -> String {
        if data.len() > max_size {
            &data[..max_size]
        } else {
            data
        }
        .iter()
        .map(|b| format!("{b:#04X}"))
        .collect::<Vec<_>>()
        .join(",")
    }
}

pub mod tokio_ext {
    #[macro_export]
    #[cfg(feature = "tokio-tracing")]
    macro_rules! spawn_named {
        ($name:expr, $future:expr) => {
            // see: https://docs.rs/tokio/latest/src/tokio/task/builder.rs.html#87-98
            // the function always returns Ok(...)
            tokio::task::Builder::new()
                .name($name)
                .spawn($future)
                .expect("unable to spawn task")
        };
    }
    #[macro_export]
    #[cfg(not(feature = "tokio-tracing"))]
    macro_rules! spawn_named {
        ($name:expr, $future:expr) => {{
            let _ = &$name; // ignore the name in non-tracing builds
            tokio::task::spawn($future)
        }};
    }
}

pub fn u32_padded_bytes(data: &[u8]) -> Result<[u8; 4], DiagServiceError> {
    if data.len() > 4 {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Invalid data length for I32: {}",
            data.len()
        )));
    }
    let padd = 4 - data.len();
    let bytes: [u8; 4] = if padd > 0 {
        let mut padded: Vec<u8> = vec![0u8; padd];
        padded.extend(data.to_vec());
        padded
            .try_into()
            .expect("The padded 8 byte value can never exceed the 8 bytes")
    } else {
        data.try_into()
            .expect("Converting an < 8 byte vector into an 8 byte array.")
    };
    Ok(bytes)
}
pub fn f64_padded_bytes(data: &[u8]) -> Result<[u8; 8], DiagServiceError> {
    if data.len() > 8 {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Invalid data length for F64: {}",
            data.len()
        )));
    }
    let padd = 8 - data.len();
    let bytes: [u8; 8] = if padd > 0 {
        let mut padded: Vec<u8> = vec![0u8; padd];
        padded.extend(data.to_vec());
        padded
            .try_into()
            .expect("The padded 8 byte value can never exceed the 8 bytes")
    } else {
        data.try_into()
            .expect("Converting an < 8 byte vector into an 8 byte array.")
    };
    Ok(bytes)
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(DiagServiceError::ParameterConversionError(
            "Non-hex character found".to_owned(),
        ));
    }
    let value = if value.len().is_multiple_of(2) {
        value
    } else {
        &format!(
            "{}0{}",
            &value[..value.len() - 1],
            &value[value.len() - 1..]
        )
    };

    hex::decode(value).map_err(|e| {
        DiagServiceError::ParameterConversionError(format!("Invalid hex value, error={e}"))
    })
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_extract_bits_basic() {
        let src = [0b_1010_1010];
        let result = extract_bits(8, 0, &src).unwrap();
        assert_eq!(result, vec![0b_1010_1010]);
    }
}
