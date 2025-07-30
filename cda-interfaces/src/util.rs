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
