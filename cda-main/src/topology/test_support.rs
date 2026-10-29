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

//! Builds ECU managers with chosen addresses and variants for topology tests.

use cda_core::{EcuManager, EcuManagerConfig};
use cda_database::datatypes::database_builder::{DiagLayerParams, EcuDataBuilder, EcuDataParams};
use cda_interfaces::{
    EcuManagerType, FunctionalDescriptionConfig, Protocol,
    datatypes::{
        ComParamPrecedence, ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition,
        Semantics,
    },
};
use cda_plugin_security::mock::TestSecurityPlugin;
use tokio::sync::RwLock;

use crate::vehicle::DatabaseMap;

/// A physical ECU with the given addresses and the given specific variants, next to a
/// base variant `BaseVariant`. Every variant has the default session and security
/// state charts, which restoring a variant needs.
pub(crate) fn ecu_manager(
    logical_address: u16,
    gateway_address: u16,
    variants: &[&str],
) -> EcuManager<TestSecurityPlugin> {
    let mut builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = builder.create_protocol(&protocol_name, None, None, None);
    let com_param_ref = builder.create_com_param_ref(None, None, None, Some(protocol), None);
    let semantics = Semantics::default();
    let session = builder.create_state("DefaultSession", None);
    let session_chart = builder.create_state_chart(
        "Session",
        Some(&semantics.session),
        None,
        Some("DefaultSession"),
        Some(vec![session]),
    );
    let locked = builder.create_state("Locked", None);
    let security_chart = builder.create_state_chart(
        "SecurityAccess",
        Some(&semantics.security),
        None,
        Some("Locked"),
        Some(vec![locked]),
    );
    let variants = std::iter::once(("BaseVariant", true))
        .chain(variants.iter().map(|name| (*name, false)))
        .map(|(name, is_base_variant)| {
            let diag_layer = builder.create_diag_layer(DiagLayerParams {
                short_name: name,
                com_param_refs: Some(vec![com_param_ref]),
                state_charts: Some(vec![session_chart, security_chart]),
                ..Default::default()
            });
            builder.create_variant(diag_layer, is_base_variant, None, None)
        })
        .collect();
    let database = builder.finish(EcuDataParams {
        ecu_name: "TestEcu",
        revision: "1",
        version: "1.0.0",
        variants: Some(variants),
        ..Default::default()
    });

    // Forced from the "configuration", so the addresses need not be in the database.
    let mut com_params = ComParams::default();
    com_params.doip.logical_ecu_address.value = logical_address;
    com_params.doip.logical_ecu_address.precedence = ComParamPrecedence::Config;
    com_params.doip.logical_gateway_address.value = gateway_address;
    com_params.doip.logical_gateway_address.precedence = ComParamPrecedence::Config;

    EcuManager::new(
        database,
        Protocol::default(),
        &com_params,
        DatabaseNamingConvention::default(),
        EcuManagerConfig {
            type_: EcuManagerType::Ecu,
            fallback_to_base_variant: true,
            strict_parameter_validation: false,
        },
        &FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: DiagnosticServiceAffixPosition::Suffix,
        },
    )
    .expect("ECU manager")
}

/// Databases keyed by ECU name.
pub(crate) fn databases(
    ecus: impl IntoIterator<Item = (&'static str, EcuManager<TestSecurityPlugin>)>,
) -> DatabaseMap<TestSecurityPlugin> {
    ecus.into_iter()
        .map(|(name, ecu)| (name.to_owned(), RwLock::new(ecu)))
        .collect()
}
