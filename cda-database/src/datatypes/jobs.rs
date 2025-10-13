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

use crate::flatbuf::diagnostic_description::dataformat;

impl From<dataformat::LongName<'_>> for cda_interfaces::datatypes::single_ecu::LongName {
    fn from(val: dataformat::LongName<'_>) -> Self {
        cda_interfaces::datatypes::single_ecu::LongName {
            value: val.value().map(ToOwned::to_owned),
            ti: val.ti().map(ToOwned::to_owned),
        }
    }
}

impl From<dataformat::JobParam<'_>> for cda_interfaces::datatypes::single_ecu::Param {
    fn from(val: dataformat::JobParam<'_>) -> Self {
        cda_interfaces::datatypes::single_ecu::Param {
            short_name: val.short_name().map(ToOwned::to_owned).unwrap_or_default(),
            physical_default_value: val.physical_default_value().map(ToOwned::to_owned),
            semantic: val.semantic().map(ToOwned::to_owned),
            long_name: val.long_name().map(|ln| ln.into()),
        }
    }
}

impl From<dataformat::ProgCode<'_>> for cda_interfaces::datatypes::single_ecu::ProgCode {
    fn from(val: dataformat::ProgCode<'_>) -> Self {
        cda_interfaces::datatypes::single_ecu::ProgCode {
            code_file: val.code_file().map(ToOwned::to_owned).unwrap_or_default(),
            encryption: val.encryption().map(ToOwned::to_owned),
            syntax: val.syntax().map(ToOwned::to_owned),
            revision: val.revision().map(ToOwned::to_owned).unwrap_or_default(),
            entrypoint: val.entrypoint().map(ToOwned::to_owned).unwrap_or_default(),
        }
    }
}

impl From<dataformat::SingleEcuJob<'_>> for cda_interfaces::datatypes::single_ecu::Job {
    fn from(val: dataformat::SingleEcuJob<'_>) -> Self {
        cda_interfaces::datatypes::single_ecu::Job {
            input_params: val
                .input_params()
                .map(|p| p.iter().map(|jp| jp.into()).collect())
                .unwrap_or_default(),
            output_params: val
                .output_params()
                .map(|p| p.iter().map(|jp| jp.into()).collect())
                .unwrap_or_default(),
            neg_output_params: val
                .neg_output_params()
                .map(|p| p.iter().map(|jp| jp.into()).collect())
                .unwrap_or_default(),
            prog_codes: val
                .prog_codes()
                .map(|p| p.iter().map(Into::into).collect())
                .unwrap_or_default(),
        }
    }
}
