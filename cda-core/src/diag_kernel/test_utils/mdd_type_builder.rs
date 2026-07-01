/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

//! Macros for building individual MDD flatbuffer types (`DiagComm`, `DiagService`,
//! requests, responses and parameters) in tests.

/// Build a [`DiagComm`] flatbuffer node with test-default fields.
macro_rules! new_diag_comm {
    ($builder:expr, $name:expr, $protocol:expr) => {
        $builder.create_diag_comm(cda_database::datatypes::database_builder::DiagCommParams {
            short_name: $name,
            diag_class_type: cda_database::datatypes::database_builder::DiagClassType::START_COMM,
            protocols: Some(vec![$protocol]),
            ..Default::default()
        })
    };
}
pub(crate) use new_diag_comm;

/// Build a [`DiagService`] flatbuffer node with test-default fields.
macro_rules! new_diag_service {
    ($builder:expr, $diag_comm:expr, $request:expr, $pos:expr, $neg:expr) => {
        $builder.create_diag_service(
            cda_database::datatypes::database_builder::DiagServiceParams {
                diag_comm: Some($diag_comm),
                request: Some($request),
                pos_responses: $pos,
                neg_responses: $neg,
                addressing:
                    *cda_database::datatypes::database_builder::Addressing::FUNCTIONAL_OR_PHYSICAL,
                transmission_mode:
                    *cda_database::datatypes::database_builder::TransmissionMode::SEND_AND_RECEIVE,
                ..Default::default()
            },
        )
    };
}
pub(crate) use new_diag_service;

/// Create a CODED-CONST SID parameter at byte position 0.
macro_rules! create_sid_param {
    ($builder:expr, $name:expr, $sid:expr) => {
        $builder.create_coded_const_param(
            $name,
            &$sid.to_string(),
            0,
            0,
            8,
            cda_database::datatypes::DataType::UInt32,
        )
    };
    ($builder:expr, $sid:expr) => {
        $crate::diag_kernel::test_utils::mdd_type_builder::create_sid_param!(
            $builder,
            $crate::diag_kernel::test_utils::ecu_manager_builder::SID_PARM_NAME,
            $sid
        )
    };
}
pub(crate) use create_sid_param;

/// Create a request containing only a SID parameter.
macro_rules! create_sid_only_request {
    ($builder:expr, $name:expr, $sid:expr) => {{
        let sid_param = $crate::diag_kernel::test_utils::mdd_type_builder::create_sid_param!(
            $builder, $name, $sid
        );
        $builder.create_request(Some(vec![sid_param]), None)
    }};
    ($builder:expr, $sid:expr) => {
        $crate::diag_kernel::test_utils::mdd_type_builder::create_sid_only_request!(
            $builder,
            $crate::diag_kernel::test_utils::ecu_manager_builder::SID_PARM_NAME,
            $sid
        )
    };
}
pub(crate) use create_sid_only_request;

/// Create a positive response with a SID param and one value param.
macro_rules! create_pos_response_with_param {
    ($builder:expr, $sid:expr, $param_name:expr, $dop:expr, $byte_pos:expr) => {{
        let sid_param = $crate::diag_kernel::test_utils::mdd_type_builder::create_sid_param!(
            $builder,
            "test_service_pos_sid",
            $sid
        );
        let value_param = $builder.create_value_param($param_name, $dop, $byte_pos, 0);
        $builder.create_response(
            cda_database::datatypes::ResponseType::Positive,
            Some(vec![sid_param, value_param]),
            None,
        )
    }};
}
pub(crate) use create_pos_response_with_param;
