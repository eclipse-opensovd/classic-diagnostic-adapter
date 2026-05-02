/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! Standalone helpers for extracting parameter type metadata from MDD
//! diagnostic descriptions.
//!
//! These functions operate on individual [`datatypes::Parameter`] values
//! without requiring access to `EcuManager` state, which keeps the main
//! `ecumanager` module shorter and avoids duplication between the request-
//! and response-side metadata extraction paths.

use cda_database::datatypes;
use cda_interfaces::{
    CompuScaleInfo, DiagServiceError, ParameterTypeMetadata, ResponseParameterInfo,
};

/// Parse a limit value string as a `u64`.
///
/// Tries integer parsing first; falls back to `f64` parsing with
/// truncation for values like `"3.0"` that ODX databases occasionally use.
// f64->u64 cast is intentional: ODX limit values are expected to fit
// within u64; fractional parts are truncated by design.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_limit_as_u64(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .or_else(|| value.parse::<f64>().ok().map(|f| f as u64))
}

/// Resolve a PHYS-CONST text value to its coded integer via the
/// parameter's DOP -> `NormalDOP` -> `CompuMethod` chain.
///
/// Supported compu-method categories:
/// - `TextTable`: scans `internal_to_phys` scales for a `CompuValues`
///   entry whose `vt` or `vt_ti` matches `phys_value`, then returns the
///   scale's `lower_limit` value.  Only `CLOSED` lower and upper bounds are
///   accepted; `OPEN` or `INFINITE` bounds indicate a genuine range rather
///   than an exact point value, and are skipped.
/// - `Identical`: the physical text IS the coded value; the string is
///   parsed directly as a `u64`.
///
/// Returns `None` for unsupported categories (`Linear`, `ScaleLinear`, …) or
/// when no matching scale entry is found.
pub(crate) fn resolve_phys_const_coded_value(
    param: &datatypes::Parameter<'_>,
    phys_value: &str,
) -> Option<u64> {
    let pc = param.specific_data_as_phys_const()?;
    let dop = pc.dop()?;
    let normal_dop = dop.specific_data_as_normal_dop()?;
    let cm = normal_dop.compu_method()?;
    let category: datatypes::CompuCategory = cm.category().into();

    match category {
        datatypes::CompuCategory::TextTable => {
            let scales = cm.internal_to_phys()?.compu_scales()?;
            for scale in scales {
                let text_match = scale.consts().is_some_and(|cv| {
                    cv.vt().is_some_and(|vt| vt == phys_value)
                        || cv.vt_ti().is_some_and(|ti| ti == phys_value)
                });
                if !text_match {
                    continue;
                }
                let limit = scale.lower_limit()?;
                // Only accept scales where both bounds are CLOSED and equal,
                // meaning a single point value. An OPEN or INFINITE upper
                // bound means the scale covers a range, not an exact match.
                let lower_interval: datatypes::IntervalType = limit.interval_type().into();
                if !matches!(lower_interval, datatypes::IntervalType::Closed) {
                    continue;
                }
                let upper_interval: datatypes::IntervalType = scale
                    .upper_limit()
                    .map_or(datatypes::IntervalType::Infinite, |ul| {
                        ul.interval_type().into()
                    });
                if !matches!(upper_interval, datatypes::IntervalType::Closed) {
                    continue;
                }
                return limit.value().and_then(parse_limit_as_u64);
            }
            None
        }
        datatypes::CompuCategory::Identical => {
            // For IDENTICAL the physical string is also the coded value.
            parse_limit_as_u64(phys_value)
        }
        _ => None,
    }
}

/// Extract `CompuScaleInfo` entries from a Value param's DOP `CompuMethod`.
///
/// Returns `(physical_default_value, coded_default_value, compu_scales)`.
/// Used by both request-side and response-side metadata extraction.
pub(crate) fn extract_value_dop_info(
    param: &datatypes::Parameter<'_>,
) -> (Option<String>, Option<u64>, Vec<CompuScaleInfo>) {
    let Some(value_data) = param.specific_data_as_value() else {
        return (None, None, Vec::new());
    };

    let physical_default = value_data.physical_default_value().map(ToOwned::to_owned);

    let Some(dop) = value_data.dop() else {
        return (physical_default, None, Vec::new());
    };
    let Some(normal_dop) = dop.specific_data_as_normal_dop() else {
        return (physical_default, None, Vec::new());
    };
    let Some(cm) = normal_dop.compu_method() else {
        return (physical_default, None, Vec::new());
    };

    let category: datatypes::CompuCategory = cm.category().into();
    let mut scales = Vec::new();

    if matches!(category, datatypes::CompuCategory::TextTable)
        && let Some(itp) = cm.internal_to_phys()
        && let Some(compu_scales) = itp.compu_scales()
    {
        for scale in compu_scales {
            let short_label = scale
                .short_label()
                .and_then(|t| t.value())
                .map(ToOwned::to_owned);
            let compu_const_vt = scale
                .consts()
                .and_then(|cv| cv.vt().or_else(|| cv.vt_ti()).map(ToOwned::to_owned));
            let lower = scale
                .lower_limit()
                .and_then(|l| l.value().and_then(parse_limit_as_u64));
            let upper = scale
                .upper_limit()
                .and_then(|l| l.value().and_then(parse_limit_as_u64));
            scales.push(CompuScaleInfo {
                short_label,
                lower_limit: lower,
                upper_limit: upper.or(lower),
                compu_const_vt,
            });
        }
    }

    // Resolve coded default from physical default via the CompuMethod
    let coded_default = physical_default.as_deref().and_then(|pd| match category {
        datatypes::CompuCategory::TextTable => scales.iter().find_map(|s| {
            if s.compu_const_vt.as_deref() == Some(pd) {
                s.lower_limit
            } else {
                None
            }
        }),
        datatypes::CompuCategory::Identical => parse_limit_as_u64(pd),
        _ => None,
    });

    (physical_default, coded_default, scales)
}

/// Extract `CodedConst` metadata from a parameter, falling back to the
/// default `Value` variant when no coded value is present.
fn extract_coded_const_metadata(param: &datatypes::Parameter<'_>) -> ParameterTypeMetadata {
    param
        .specific_data_as_coded_const()
        .and_then(|cc| cc.coded_value())
        .map_or(ParameterTypeMetadata::default(), |v| {
            ParameterTypeMetadata::CodedConst {
                coded_value: v.to_owned(),
            }
        })
}

/// Extract [`ParameterTypeMetadata`] for a request-side parameter.
///
/// Resolves `CodedConst`, `PhysConst` (with coded-value resolution through
/// the DOP chain), and `Value` (with DOP-derived scales and defaults).
pub(crate) fn extract_request_param_type(
    param: &datatypes::Parameter<'_>,
    service_name: &str,
    name: &str,
) -> Result<ParameterTypeMetadata, DiagServiceError> {
    let param_type = match param.param_type()? {
        datatypes::ParamType::CodedConst => extract_coded_const_metadata(param),
        datatypes::ParamType::PhysConst => {
            let phys_value = param
                .specific_data_as_phys_const()
                .and_then(|pc| pc.phys_constant_value());

            if let Some(pv) = phys_value {
                let coded = resolve_phys_const_coded_value(param, pv);
                if coded.is_none() {
                    tracing::debug!(
                        "Service '{}' param '{}' PHYS-CONST '{}' coded value unresolved \
                         (unsupported DOP category or no matching scale)",
                        service_name,
                        name,
                        pv,
                    );
                }
                ParameterTypeMetadata::PhysConst {
                    phys_constant_value: pv.to_owned(),
                    coded_value: coded,
                }
            } else {
                tracing::warn!(
                    "Service '{}' param '{}' PHYS-CONST has no value",
                    service_name,
                    name
                );
                ParameterTypeMetadata::default()
            }
        }
        _ => {
            let (phys_default, coded_default, compu_scales) = extract_value_dop_info(param);
            ParameterTypeMetadata::Value {
                physical_default_value: phys_default,
                coded_default_value: coded_default,
                compu_scales,
            }
        }
    };

    Ok(param_type)
}

/// Extract [`ParameterTypeMetadata`] for a response-side parameter.
///
/// Unlike the request-side variant, this also handles `MatchingRequestParam`
/// and does not resolve `PhysConst` coded values (they are not needed for
/// response decoding).
pub(crate) fn extract_response_param_type(
    param: &datatypes::Parameter<'_>,
) -> ParameterTypeMetadata {
    let Ok(pt) = param.param_type() else {
        return ParameterTypeMetadata::default();
    };

    match pt {
        datatypes::ParamType::CodedConst => extract_coded_const_metadata(param),
        datatypes::ParamType::MatchingRequestParam => {
            let byte_length = param
                .specific_data_as_matching_request_param()
                .map_or(0, |m| m.byte_length());
            ParameterTypeMetadata::MatchingRequestParam { byte_length }
        }
        datatypes::ParamType::PhysConst => {
            let phys_value = param
                .specific_data_as_phys_const()
                .and_then(|p| p.phys_constant_value().map(ToOwned::to_owned));
            match phys_value {
                Some(v) => ParameterTypeMetadata::PhysConst {
                    phys_constant_value: v,
                    coded_value: None,
                },
                None => ParameterTypeMetadata::default(),
            }
        }
        _ => {
            let (phys_default, coded_default, compu_scales) = extract_value_dop_info(param);
            ParameterTypeMetadata::Value {
                physical_default_value: phys_default,
                coded_default_value: coded_default,
                compu_scales,
            }
        }
    }
}

pub(crate) fn byte_size_from_diag_coded_type(
    dct: Result<datatypes::DiagCodedType, DiagServiceError>,
) -> Option<u32> {
    dct.ok()
        .and_then(|dt| dt.bit_len())
        .map(|bits| bits.div_ceil(8))
}

pub(crate) fn byte_size_from_value_param(param: &datatypes::Parameter<'_>) -> (Option<u32>, bool) {
    let Some(dop) = param.specific_data_as_value().and_then(|v| v.dop()) else {
        return (None, false);
    };
    let data_op = datatypes::DataOperation(dop);
    match data_op.variant() {
        Ok(datatypes::DataOperationVariant::Normal(n)) => {
            (byte_size_from_diag_coded_type(n.diag_coded_type()), false)
        }
        Ok(datatypes::DataOperationVariant::Mux(_)) => (None, true),
        _ => (None, false),
    }
}

pub(crate) fn byte_size_from_coded_const(param: &datatypes::Parameter<'_>) -> Option<u32> {
    let cc = param.specific_data_as_coded_const()?;
    let dct = cc.diag_coded_type()?;
    let dct: Result<datatypes::DiagCodedType, _> = dct.try_into();
    byte_size_from_diag_coded_type(dct)
}

/// Expand MUX DOP cases into a flat list of [`ResponseParameterInfo`].
///
/// Each MUX case's inner structure parameters are returned with their names
/// prefixed by the case short name (e.g. `"CaseName/ParamName"`).
pub(crate) fn expand_mux_cases(
    param: &datatypes::Parameter<'_>,
    mux_byte_position: u32,
) -> Vec<ResponseParameterInfo> {
    let Some(value_data) = param.specific_data_as_value() else {
        return Vec::new();
    };
    let Some(dop) = value_data.dop() else {
        return Vec::new();
    };
    let data_op = datatypes::DataOperation(dop);
    let Ok(datatypes::DataOperationVariant::Mux(mux_dop)) = data_op.variant() else {
        return Vec::new();
    };

    let switch_key_size = mux_dop
        .switch_key()
        .and_then(|sk| sk.dop())
        .and_then(|dop| {
            let data_op = datatypes::DataOperation(dop);
            if let Ok(datatypes::DataOperationVariant::Normal(n)) = data_op.variant() {
                byte_size_from_diag_coded_type(n.diag_coded_type())
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            tracing::warn!("MUX DOP switch-key size could not be determined; assuming 0");
            0
        });

    let Some(cases) = mux_dop.cases() else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for case in cases {
        let case_name = case.short_name().unwrap_or_default();
        let lower_limit = case
            .lower_limit()
            .and_then(|ll| ll.value())
            .map(ToOwned::to_owned);

        let Some(case_dop) = case.structure() else {
            continue;
        };
        let Some(structure) = case_dop.specific_data_as_structure() else {
            continue;
        };
        let Some(inner_params) = structure.params() else {
            continue;
        };

        for inner_param in inner_params {
            let inner = datatypes::Parameter(inner_param);
            let Some(inner_name) = inner.short_name() else {
                continue;
            };
            let inner_type = extract_response_param_type(&inner);
            let (inner_byte_size, _) = match &inner_type {
                ParameterTypeMetadata::CodedConst { .. } => {
                    (byte_size_from_coded_const(&inner), false)
                }
                ParameterTypeMetadata::Value { .. } => byte_size_from_value_param(&inner),
                _ => (None, false),
            };

            let byte_position = mux_byte_position
                .checked_add(switch_key_size)
                .and_then(|v| v.checked_add(inner.byte_position()))
                .unwrap_or(mux_byte_position);

            result.push(ResponseParameterInfo {
                name: format!("{case_name}/{inner_name}"),
                semantic: inner.semantic().map(ToOwned::to_owned),
                param_type: inner_type,
                byte_position,
                bit_position: inner.bit_position(),
                byte_size: inner_byte_size,
            });
        }

        let marker_position = mux_byte_position
            .checked_add(switch_key_size)
            .unwrap_or(mux_byte_position);

        result.push(ResponseParameterInfo {
            name: format!("__mux_case__/{case_name}"),
            semantic: Some("MUX-CASE".to_owned()),
            param_type: ParameterTypeMetadata::CodedConst {
                coded_value: lower_limit.unwrap_or_default(),
            },
            byte_position: marker_position,
            bit_position: 0,
            byte_size: structure.byte_size(),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        self, CompuCategory, DataType, IntervalType, Limit, ResponseType,
        database_builder::{DiagCommParams, DiagServiceParams, EcuDataBuilder},
    };
    use cda_interfaces::{ParameterTypeMetadata, Protocol};

    use super::{
        byte_size_from_coded_const, byte_size_from_value_param, expand_mux_cases,
        extract_request_param_type, extract_response_param_type, extract_value_dop_info,
        resolve_phys_const_coded_value,
    };

    /// Wraps a finished database and provides access to individual parameters
    /// from the first service's request or response.
    struct TestDb {
        db: datatypes::DiagnosticDatabase,
    }

    impl TestDb {
        fn param(&self, idx: usize) -> datatypes::Parameter<'_> {
            let variant = self.db.base_variant().expect("no base variant");
            let services = variant.diag_layer().unwrap().diag_services().unwrap();
            let service = datatypes::DiagService(services.get(0));
            let params = service.request().unwrap().params().unwrap();
            datatypes::Parameter(params.get(idx))
        }

        fn response_param(&self, idx: usize) -> datatypes::Parameter<'_> {
            let variant = self.db.base_variant().expect("no base variant");
            let services = variant.diag_layer().unwrap().diag_services().unwrap();
            let service = datatypes::DiagService(services.get(0));
            let responses = service.pos_responses().unwrap();
            let params = responses.iter().next().unwrap().params().unwrap();
            datatypes::Parameter(params.get(idx))
        }
    }

    /// Wrap builder, protocol, request, and optional responses into a
    /// single-service `TestDb`. Mirrors the `finish_db!` / `new_diag_comm!` /
    /// `new_diag_service!` macros from the ecumanager.rs test module.
    macro_rules! finish_test_db {
        ($db:expr, $protocol:expr, $request:expr) => {
            finish_test_db!($db, $protocol, $request, vec![])
        };
        ($db:expr, $protocol:expr, $request:expr, $pos_responses:expr) => {{
            let dc = $db.create_diag_comm(DiagCommParams {
                short_name: "TestSvc",
                protocols: Some(vec![$protocol]),
                ..Default::default()
            });
            let svc = $db.create_diag_service(DiagServiceParams {
                diag_comm: Some(dc),
                request: Some($request),
                pos_responses: $pos_responses,
                ..Default::default()
            });
            TestDb {
                db: $db.finish_with_single_variant($protocol, vec![svc], "L", "E", "1", "1.0"),
            }
        }};
    }

    /// Build a database with a single request-parameter for PHYS-CONST tests.
    fn build_phys_const_db(
        scales: &[(&str, u64, IntervalType, IntervalType)],
        phys_value: &str,
        bit_len: u32,
        identical: bool,
    ) -> TestDb {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let diag_type = db.create_diag_coded_type_standard_length(bit_len, DataType::UInt32);
        let compu_method = if identical {
            db.create_compu_method(CompuCategory::Identical, None, None)
        } else {
            db.create_text_table_compu_method(scales)
        };
        let dop = db.create_regular_normal_dop("test_dop", diag_type, compu_method);
        let param = db.create_phys_const_param("test_param", Some(phys_value), dop, 0, 0);
        let request = db.create_request(Some(vec![param]), None);
        finish_test_db!(db, protocol, request)
    }

    /// Build a database with a VALUE parameter backed by a DOP.
    fn build_value_db(
        bit_len: u32,
        text_table_scales: &[(&str, u64, IntervalType, IntervalType)],
        identical: bool,
        physical_default_value: Option<&str>,
    ) -> TestDb {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let diag_type = db.create_diag_coded_type_standard_length(bit_len, DataType::UInt32);
        let compu_method = if identical {
            db.create_compu_method(CompuCategory::Identical, None, None)
        } else {
            db.create_text_table_compu_method(text_table_scales)
        };
        let dop = db.create_regular_normal_dop("test_dop", diag_type, compu_method);
        let param =
            db.create_value_param_with_default("test_param", dop, 0, 0, physical_default_value);
        let request = db.create_request(Some(vec![param]), None);
        finish_test_db!(db, protocol, request)
    }

    /// Build a database with a CODED-CONST parameter.
    fn build_coded_const_db(coded_value: &str, bit_len: u32) -> TestDb {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let param =
            db.create_coded_const_param("test_param", coded_value, 0, 0, bit_len, DataType::UInt32);
        let request = db.create_request(Some(vec![param]), None);
        finish_test_db!(db, protocol, request)
    }

    /// Build a database with a response containing multiple parameter types.
    fn build_response_db() -> TestDb {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let diag_type = db.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let dop = db.create_regular_normal_dop("resp_dop", diag_type, compu);

        let coded_param = db.create_coded_const_param("sid_resp", "34", 0, 0, 8, DataType::UInt32);
        let value_param = db.create_value_param("resp_value", dop, 1, 0);
        let phys_param = db.create_phys_const_param("resp_phys", Some("ON"), dop, 3, 0);

        let request = db.create_request(None, None);
        let pos_response = db.create_response(
            ResponseType::Positive,
            Some(vec![coded_param, value_param, phys_param]),
            None,
        );
        finish_test_db!(db, protocol, request, vec![pos_response])
    }

    /// Build a database with a MUX parameter in the response.
    fn build_mux_response_db() -> TestDb {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let u8_diag = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag = db.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);

        let case_param_dop = db.create_regular_normal_dop("case_dop", u8_diag, compu);
        let case_param = db.create_value_param("inner_param", case_param_dop, 0, 0);
        let structure = db.create_structure(Some(vec![case_param]), Some(1), true);
        let case = db.create_case(
            "case_1",
            Some(Limit {
                value: "1".to_owned(),
                interval_type: IntervalType::Closed,
            }),
            Some(Limit {
                value: "1".to_owned(),
                interval_type: IntervalType::Closed,
            }),
            Some(structure),
        );

        let switch_key_dop = db.create_regular_normal_dop("sk_dop", u16_diag, compu);
        let switch_key = db.create_switch_key(0, Some(0), Some(switch_key_dop));
        let mux_dop = db.create_mux_dop(
            "test_mux",
            1,
            Some(switch_key),
            None,
            Some(vec![case]),
            true,
        );
        let mux_param = db.create_value_param("mux_param", mux_dop, 1, 0);

        let request = db.create_request(None, None);
        let pos_response = db.create_response(ResponseType::Positive, Some(vec![mux_param]), None);
        finish_test_db!(db, protocol, request, vec![pos_response])
    }

    #[test]
    fn text_table_resolves_exact_closed_closed_scale() {
        let tdb = build_phys_const_db(
            &[("ACTIVE", 1, IntervalType::Closed, IntervalType::Closed)],
            "ACTIVE",
            8,
            false,
        );
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "ACTIVE"),
            Some(1)
        );
    }

    #[test]
    fn text_table_picks_correct_entry_among_multiple_scales() {
        let tdb = build_phys_const_db(
            &[
                ("OFF", 0, IntervalType::Closed, IntervalType::Closed),
                ("ON", 1, IntervalType::Closed, IntervalType::Closed),
                ("STANDBY", 2, IntervalType::Closed, IntervalType::Closed),
            ],
            "ON",
            8,
            false,
        );
        assert_eq!(resolve_phys_const_coded_value(&tdb.param(0), "ON"), Some(1));
    }

    #[test]
    fn text_table_skips_open_lower_bound() {
        let tdb = build_phys_const_db(
            &[("RANGE_VALUE", 5, IntervalType::Open, IntervalType::Closed)],
            "RANGE_VALUE",
            8,
            false,
        );
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "RANGE_VALUE"),
            None
        );
    }

    #[test]
    fn text_table_skips_open_upper_bound() {
        let tdb = build_phys_const_db(
            &[("RANGE_VALUE", 5, IntervalType::Closed, IntervalType::Open)],
            "RANGE_VALUE",
            8,
            false,
        );
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "RANGE_VALUE"),
            None
        );
    }

    #[test]
    fn text_table_no_matching_entry_returns_none() {
        let tdb = build_phys_const_db(
            &[("ACTIVE", 1, IntervalType::Closed, IntervalType::Closed)],
            "ACTIVE",
            8,
            false,
        );
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "UNKNOWN"),
            None
        );
    }

    #[test]
    fn text_table_empty_scales_returns_none() {
        let tdb = build_phys_const_db(&[], "ACTIVE", 8, false);
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "ACTIVE"),
            None
        );
    }

    #[test]
    fn identical_parses_integer_string() {
        let tdb = build_phys_const_db(&[], "61840", 16, true);
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "61840"),
            Some(61840)
        );
    }

    #[test]
    fn identical_parses_float_string_truncates() {
        let tdb = build_phys_const_db(&[], "3.0", 8, true);
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "3.0"),
            Some(3)
        );
    }

    #[test]
    fn identical_non_numeric_returns_none() {
        let tdb = build_phys_const_db(&[], "not_a_number", 8, true);
        assert_eq!(
            resolve_phys_const_coded_value(&tdb.param(0), "not_a_number"),
            None
        );
    }

    #[test]
    fn value_dop_info_identical_no_scales() {
        let tdb = build_value_db(16, &[], true, None);
        let (phys_default, coded_default, scales) = extract_value_dop_info(&tdb.param(0));
        assert_eq!(phys_default, None);
        assert_eq!(coded_default, None);
        assert!(scales.is_empty());
    }

    #[test]
    fn value_dop_info_text_table_returns_scales() {
        let tdb = build_value_db(
            8,
            &[
                ("OFF", 0, IntervalType::Closed, IntervalType::Closed),
                ("ON", 1, IntervalType::Closed, IntervalType::Closed),
            ],
            false,
            None,
        );
        let (_, _, scales) = extract_value_dop_info(&tdb.param(0));
        assert_eq!(scales.len(), 2);
        let s0 = scales.first().unwrap();
        let s1 = scales.get(1).unwrap();
        assert_eq!(s0.compu_const_vt.as_deref(), Some("OFF"));
        assert_eq!(s0.lower_limit, Some(0));
        assert_eq!(s1.compu_const_vt.as_deref(), Some("ON"));
        assert_eq!(s1.lower_limit, Some(1));
    }

    #[test]
    fn value_dop_info_with_physical_default_resolves_coded() {
        let tdb = build_value_db(
            8,
            &[("ON", 1, IntervalType::Closed, IntervalType::Closed)],
            false,
            Some("ON"),
        );
        let (phys_default, coded_default, _) = extract_value_dop_info(&tdb.param(0));
        assert_eq!(phys_default.as_deref(), Some("ON"));
        assert_eq!(coded_default, Some(1));
    }

    #[test]
    fn value_dop_info_with_identical_default_resolves_coded() {
        let tdb = build_value_db(16, &[], true, Some("42"));
        let (phys_default, coded_default, scales) = extract_value_dop_info(&tdb.param(0));
        assert_eq!(phys_default.as_deref(), Some("42"));
        assert_eq!(coded_default, Some(42));
        assert!(scales.is_empty());
    }

    #[test]
    fn value_dop_info_non_value_param_returns_defaults() {
        let tdb = build_coded_const_db("34", 8);
        let (phys_default, coded_default, scales) = extract_value_dop_info(&tdb.param(0));
        assert_eq!(phys_default, None);
        assert_eq!(coded_default, None);
        assert!(scales.is_empty());
    }

    #[test]
    fn request_param_coded_const() {
        let tdb = build_coded_const_db("34", 8);
        let result = extract_request_param_type(&tdb.param(0), "Svc", "p").unwrap();
        assert!(matches!(
            result,
            ParameterTypeMetadata::CodedConst { coded_value } if coded_value == "34"
        ));
    }

    #[test]
    fn request_param_phys_const_with_text_table() {
        let tdb = build_phys_const_db(
            &[("ACTIVE", 1, IntervalType::Closed, IntervalType::Closed)],
            "ACTIVE",
            8,
            false,
        );
        let result = extract_request_param_type(&tdb.param(0), "Svc", "p").unwrap();
        match result {
            ParameterTypeMetadata::PhysConst {
                phys_constant_value,
                coded_value,
            } => {
                assert_eq!(phys_constant_value, "ACTIVE");
                assert_eq!(coded_value, Some(1));
            }
            other => panic!("expected PhysConst, got {other:?}"),
        }
    }

    #[test]
    fn request_param_phys_const_unresolvable() {
        let tdb = build_phys_const_db(
            &[("ACTIVE", 1, IntervalType::Open, IntervalType::Open)],
            "ACTIVE",
            8,
            false,
        );
        let result = extract_request_param_type(&tdb.param(0), "Svc", "p").unwrap();
        match result {
            ParameterTypeMetadata::PhysConst { coded_value, .. } => {
                assert_eq!(coded_value, None);
            }
            other => panic!("expected PhysConst, got {other:?}"),
        }
    }

    #[test]
    fn request_param_value_with_scales() {
        let tdb = build_value_db(
            8,
            &[("A", 0, IntervalType::Closed, IntervalType::Closed)],
            false,
            None,
        );
        let result = extract_request_param_type(&tdb.param(0), "Svc", "p").unwrap();
        match result {
            ParameterTypeMetadata::Value { compu_scales, .. } => {
                assert_eq!(compu_scales.len(), 1);
                let s0 = compu_scales.first().unwrap();
                assert_eq!(s0.compu_const_vt.as_deref(), Some("A"));
            }
            other => panic!("expected Value, got {other:?}"),
        }
    }

    #[test]
    fn response_param_coded_const() {
        let tdb = build_response_db();
        let result = extract_response_param_type(&tdb.response_param(0));
        assert!(matches!(
            result,
            ParameterTypeMetadata::CodedConst { coded_value } if coded_value == "34"
        ));
    }

    #[test]
    fn response_param_value() {
        let tdb = build_response_db();
        let result = extract_response_param_type(&tdb.response_param(1));
        assert!(matches!(result, ParameterTypeMetadata::Value { .. }));
    }

    #[test]
    fn response_param_phys_const_no_coded_resolution() {
        let tdb = build_response_db();
        let result = extract_response_param_type(&tdb.response_param(2));
        match result {
            ParameterTypeMetadata::PhysConst {
                phys_constant_value,
                coded_value,
            } => {
                assert_eq!(phys_constant_value, "ON");
                assert_eq!(coded_value, None);
            }
            other => panic!("expected PhysConst, got {other:?}"),
        }
    }

    #[test]
    fn byte_size_coded_const_8_bit() {
        let tdb = build_coded_const_db("34", 8);
        assert_eq!(byte_size_from_coded_const(&tdb.param(0)), Some(1));
    }

    #[test]
    fn byte_size_coded_const_16_bit() {
        let tdb = build_coded_const_db("256", 16);
        assert_eq!(byte_size_from_coded_const(&tdb.param(0)), Some(2));
    }

    #[test]
    fn byte_size_coded_const_non_aligned() {
        let tdb = build_coded_const_db("1", 12);
        assert_eq!(byte_size_from_coded_const(&tdb.param(0)), Some(2));
    }

    #[test]
    fn byte_size_value_param_returns_size() {
        let tdb = build_value_db(32, &[], true, None);
        let (size, is_mux) = byte_size_from_value_param(&tdb.param(0));
        assert_eq!(size, Some(4));
        assert!(!is_mux);
    }

    #[test]
    fn byte_size_value_param_mux_returns_none_and_flag() {
        let tdb = build_mux_response_db();
        let (size, is_mux) = byte_size_from_value_param(&tdb.response_param(0));
        assert_eq!(size, None);
        assert!(is_mux);
    }

    #[test]
    fn byte_size_from_coded_const_on_value_param_returns_none() {
        let tdb = build_value_db(16, &[], true, None);
        assert_eq!(byte_size_from_coded_const(&tdb.param(0)), None);
    }

    #[test]
    fn mux_cases_expand_inner_params() {
        let tdb = build_mux_response_db();
        let result = expand_mux_cases(&tdb.response_param(0), 1);

        assert_eq!(result.len(), 2);
        let r0 = result.first().unwrap();
        let r1 = result.get(1).unwrap();
        assert_eq!(r0.name, "case_1/inner_param");
        // mux_byte_pos(1) + switch_key_size(2) + inner_byte_pos(0)
        assert_eq!(r0.byte_position, 3);
        assert_eq!(r1.name, "__mux_case__/case_1");
        assert_eq!(r1.semantic.as_deref(), Some("MUX-CASE"));
    }

    #[test]
    fn mux_cases_non_mux_param_returns_empty() {
        let tdb = build_value_db(16, &[], true, None);
        let result = expand_mux_cases(&tdb.param(0), 0);
        assert!(result.is_empty());
    }
}
