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

pub mod single_ecu {

    pub struct LongName {
        pub value: Option<String>,
        pub ti: Option<String>,
    }

    pub struct Param {
        pub short_name: String,
        pub physical_default_value: Option<String>,

        // todo dop is out of for POC
        // pub dop: u32,
        pub semantic: Option<String>,
        pub long_name: Option<LongName>,
    }

    pub struct ProgCode {
        pub code_file: String,
        pub encryption: Option<String>,
        pub syntax: Option<String>,
        pub revision: String,
        pub entrypoint: String,
    }

    pub struct Job {
        pub input_params: Vec<Param>,
        pub output_params: Vec<Param>,
        pub neg_output_params: Vec<Param>,
        pub prog_codes: Vec<ProgCode>,
    }
}
