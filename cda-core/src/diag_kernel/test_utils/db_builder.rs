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

//! Macros for assembling a complete [`DiagnosticDatabase`] from an
//! [`EcuDataBuilder`] in tests.

/// Finish an [`EcuDataBuilder`] into a [`DiagnosticDatabase`] containing a
/// single variant with the given diag services, using test defaults for layer
/// name, ECU name, revision and version.
///
/// Delegates to [`EcuDataBuilder::finish_with_single_variant`].
macro_rules! finish_db {
    ($builder:expr, $protocol:expr, $diag_services:expr) => {
        $builder.finish_with_single_variant(
            $protocol,
            $diag_services,
            $crate::diag_kernel::test_utils::ecu_manager_builder::TEST_DIAG_LAYER,
            "TestEcu",
            "1",
            "1.0.0",
        )
    };
}
pub(crate) use finish_db;

/// Build a database with a single variant and functional groups.
macro_rules! finish_db_with_functional_groups {
    ($builder:expr, $protocol:expr, $variant_services:expr, $functional_groups:expr) => {{
        use cda_database::datatypes::database_builder::{DiagLayerParams, EcuDataParams};
        let cp_ref = $builder.create_com_param_ref(None, None, None, Some($protocol), None);
        let diag_layer = $builder.create_diag_layer(DiagLayerParams {
            short_name: $crate::diag_kernel::test_utils::ecu_manager_builder::TEST_DIAG_LAYER,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: {
                let services: Vec<_> = $variant_services;
                if services.is_empty() {
                    None
                } else {
                    Some(services)
                }
            },
            ..Default::default()
        });
        let variant = $builder.create_variant(diag_layer, true, None, None);
        $builder.finish(EcuDataParams {
            ecu_name: "TestEcu",
            revision: "1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            functional_groups: Some($functional_groups),
            ..Default::default()
        })
    }};
}
pub(crate) use finish_db_with_functional_groups;
