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
