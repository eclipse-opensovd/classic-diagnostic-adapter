/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use cda_interfaces::{
    DiagServiceError, HashMap,
    datatypes::{ComParamSimpleValue, ComParamValue, Unit},
};

use crate::flatbuf::diagnostic_description::dataformat;

pub(super) fn lookup(
    ecu_data: &crate::datatypes::DiagnosticDatabase,
    protocol: &dataformat::Protocol,
    param_name: &str,
) -> Result<ComParamValue, DiagServiceError> {
    let protocol_name = protocol.diag_layer().and_then(|dl| dl.short_name()).ok_or(
        DiagServiceError::InvalidDatabase("Protocol has no short name".to_owned()),
    )?;

    let ignore_protocol = ecu_data.config().ignore_protocol;

    let com_param_refs = ecu_data
        .base_variant()?
        .diag_layer()
        .and_then(|dl| dl.com_param_refs());

    // When ignore_protocol is true, the protocol filter is bypassed and parameters
    // are matched by name alone. This is safe because ignore_protocol validity
    // (single protocol in DB) is enforced at database construction time.
    let cp_ref = com_param_refs
        .as_ref()
        .and_then(|refs| {
            refs.iter().find(|cp_ref| {
                let name_matches = cp_ref
                    .com_param()
                    .and_then(|cp| cp.short_name())
                    .is_some_and(|n| n == param_name);

                name_matches
                    && (ignore_protocol
                        || cp_ref
                            .protocol()
                            .and_then(|p| p.diag_layer().and_then(|dl| dl.short_name()))
                            .is_some_and(|sn| sn.eq_ignore_ascii_case(protocol_name)))
            })
        })
        .ok_or_else(|| {
            DiagServiceError::NotFound(format!("No ComParamRef found for {param_name}"))
        })?;

    let cp = cp_ref.com_param().ok_or(DiagServiceError::InvalidDatabase(
        "ComParamRef has no ComParam".to_owned(),
    ))?;
    let (_, cp) = resolve_with_value(&cp_ref, &cp)?;
    Ok(cp)
}

fn resolve_with_value(
    cpref: &dataformat::ComParamRef,
    com_param: &dataformat::ComParam,
) -> Result<(String, ComParamValue), DiagServiceError> {
    if cpref
        .simple_value()
        .as_ref()
        .and(cpref.complex_value().as_ref())
        .is_some()
    {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {:?} has both simple and complex value",
            com_param.short_name()
        )));
    }
    let short_name = com_param.short_name().ok_or_else(|| {
        DiagServiceError::InvalidDatabase("ComParamRef has no short name".to_owned())
    })?;

    if let Some(value) = &cpref.simple_value() {
        let value = value.value().map(ToOwned::to_owned).ok_or_else(|| {
            DiagServiceError::InvalidDatabase(format!(
                "ComParamRef for {short_name} has no simple value",
            ))
        })?;

        match com_param.com_param_type() {
            dataformat::ComParamType::REGULAR => {
                let regular = com_param
                    .specific_data_as_regular_com_param()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not regular, but has regular type",
                        ))
                    })?;

                let dop = regular.dop().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "ComParamRef for {short_name} has no data operation",
                    ))
                })?;
                let unit = extract_dop_unit(&dop);

                Ok((
                    short_name.to_owned(),
                    ComParamValue::Simple(ComParamSimpleValue { value, unit }),
                ))
            }
            _ => {
                unreachable!("Will only be called if comparam is simple")
            }
        }
    } else if let Some(complex_value) = &cpref.complex_value() {
        resolve_complex_value(com_param, complex_value)
    } else {
        Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {short_name} has no value",
        )))
    }
}

/// Resolve a `ComParamRef` into its name and value.
/// # Errors
/// If the `ComParamRef` is invalid or has no value.
pub fn resolve_comparam(
    cpref: &dataformat::ComParamRef,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let com_param = cpref.com_param().ok_or(DiagServiceError::InvalidDatabase(
        "ComParamRef has no ComParam".to_owned(),
    ))?;
    resolve_with_value(cpref, &com_param)
}

fn resolve_complex_value(
    com_param: &dataformat::ComParam,
    complex_value: &dataformat::ComplexValue,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let com_param_shortname = com_param
        .short_name()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            DiagServiceError::InvalidDatabase("ComParamRef has no short name".to_owned())
        })?;

    let variant = match com_param.com_param_type() {
        dataformat::ComParamType::COMPLEX => com_param
            .specific_data_as_complex_com_param()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "ComParam {com_param_shortname} is not complex, but has complex type",
                ))
            })?,
        _ => {
            unreachable!("Will only be called if comparam is complex")
        }
    };

    let com_params = variant.com_params().ok_or_else(|| {
        DiagServiceError::InvalidDatabase(format!(
            "Complex ComParam {com_param_shortname} has no comParams",
        ))
    })?;

    let entries = com_params
        .iter()
        .enumerate()
        .map(|(i, cp)| {
            let short_name = cp.short_name().map(ToOwned::to_owned).ok_or_else(|| {
                DiagServiceError::InvalidDatabase("ComParam has no short name".to_string())
            })?;

            match cp.com_param_type() {
                dataformat::ComParamType::REGULAR => {
                    let regular = cp.specific_data_as_regular_com_param().ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not regular, but has regular type",
                        ))
                    })?;

                    let c = if let Some(simple) = complex_value.entries_item_as_simple_value(i) {
                        let value = simple.value().map(ToOwned::to_owned).ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(format!(
                                "ComParam {short_name} has no simple value",
                            ))
                        })?;

                        let unit = regular.dop().as_ref().and_then(extract_dop_unit);
                        ComParamValue::Simple(ComParamSimpleValue { value, unit })
                    } else if let Some(_complex) = complex_value.entries_item_as_complex_value(i) {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not a complex ComParam",
                        )));
                    } else {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComplexValue entry for ComParam {short_name} at index {i} has no \
                             value",
                        )));
                    };

                    Ok((short_name, c))
                }
                dataformat::ComParamType::COMPLEX => {
                    let v = if let Some(_simple) = complex_value.entries_item_as_simple_value(i) {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not a simple ComParam",
                        )));
                    } else if let Some(_complex) = complex_value.entries_item_as_complex_value(i) {
                        resolve_complex_value(&cp, complex_value)?
                    } else {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComplexValue entry for ComParam {short_name} at index {i} has no \
                             value",
                        )));
                    };
                    Ok(v)
                }
                _ => Err(DiagServiceError::InvalidDatabase(format!(
                    "ComParam {short_name} has unknown type",
                ))),
            }
        })
        .collect::<Result<HashMap<String, ComParamValue>, DiagServiceError>>()?;

    Ok((com_param_shortname, ComParamValue::Complex(entries)))
}

fn extract_dop_unit(dop: &dataformat::DOP) -> Option<Unit> {
    dop.specific_data_as_normal_dop().map(|normal_dop| Unit {
        factor_to_si_unit: normal_dop.unit_ref().and_then(|u| u.factorsitounit()),
        offset_to_si_unit: normal_dop.unit_ref().and_then(|u| u.offsetitounit()),
    })
}

/// Map a DOIP NACK number of retries parameter from (String, u32) to (u8, u32).
/// # Errors
/// If the string cannot be parsed as a u8 (decimal or hex).
pub fn map_nack_number_of_retries<K: AsRef<str>>(
    (name, value): (K, &u32),
) -> Result<(u8, u32), DiagServiceError> {
    let name = name.as_ref();
    let key_result = if let Some(hex_str) = name.strip_prefix("0x") {
        u8::from_str_radix(hex_str, 16)
    } else {
        name.parse::<u8>()
    }
    .map_err(|_| {
        DiagServiceError::ParameterConversionError(format!(
            "Invalid string for doip.nack_number_of_retries: {name}"
        ))
    });

    key_result.map(|key| (key, *value))
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{HashSet, HashSetExtensions};

    use super::*;
    use crate::datatypes::{
        DatabaseConfig,
        database_builder::{DiagLayerParams, EcuDataBuilder, EcuDataParams},
    };

    struct ComParamRefSpec<'a> {
        protocol: &'a str,
        name: &'a str,
        value: &'a str,
    }

    fn do_lookup(
        param_refs: &[ComParamRefSpec<'_>],
        param_name: &str,
        ignore_protocol: bool,
    ) -> Result<ComParamValue, DiagServiceError> {
        let db = build_db(param_refs, ignore_protocol)?;
        let mut builder = EcuDataBuilder::new();
        let protocol = builder.create_protocol("MY_PROTO", None, None, None);
        let proto_bytes = builder.finish_protocol(protocol);
        lookup(
            &db,
            &flatbuffers::root::<dataformat::Protocol<'_>>(&proto_bytes)
                .expect("valid Protocol flatbuffer"),
            param_name,
        )
    }

    /// Build a `DiagnosticDatabase` that contains one base variant.
    ///
    /// Each element of `param_refs` describes one `ComParamRef` to attach:
    ///   `(protocol_short_name, param_short_name, simple_value_str)`
    ///
    /// When `protocol` is `""` the ref is created without a protocol.
    fn build_db(
        param_refs: &[ComParamRefSpec<'_>],
        ignore_protocol: bool,
    ) -> Result<crate::datatypes::DiagnosticDatabase, DiagServiceError> {
        let mut builder = EcuDataBuilder::new();

        // Collect unique protocol names to create parent_refs for the variant.
        let mut seen_protocols: HashSet<&str> = HashSet::new();
        let cp_refs: Vec<_> = param_refs
            .iter()
            .map(|r| {
                let com_param = builder.create_com_param(r.name);
                let simple_value = builder.create_simple_value(r.value);

                let protocol = if r.protocol.is_empty() {
                    None
                } else {
                    seen_protocols.insert(r.protocol);
                    Some(builder.create_protocol(r.protocol, None, None, None))
                };

                builder.create_com_param_ref(
                    Some(simple_value),
                    None,
                    Some(com_param),
                    protocol,
                    None,
                )
            })
            .collect();

        // Create parent_refs pointing to the distinct protocols.
        let parent_refs: Vec<_> = seen_protocols
            .iter()
            .map(|name| {
                let proto = builder.create_protocol(name, None, None, None);
                builder.create_parent_ref(
                    dataformat::ParentRefType::Protocol,
                    Some(dataformat::ParentRefType::tag_as_protocol(proto)),
                )
            })
            .collect();

        let diag_layer = builder.create_diag_layer(DiagLayerParams {
            short_name: "TestLayer",
            com_param_refs: Some(cp_refs),
            ..Default::default()
        });
        let variant = builder.create_variant(
            diag_layer,
            true,
            None,
            if parent_refs.is_empty() {
                None
            } else {
                Some(parent_refs)
            },
        );

        builder.finish_with_config(
            EcuDataParams {
                ecu_name: "TestEcu",
                revision: "1",
                version: "1.0",
                variants: Some(vec![variant]),
                ..Default::default()
            },
            DatabaseConfig {
                ignore_protocol,
                ..Default::default()
            },
        )
    }

    #[test]
    fn test_lookup_protocol_not_found_no_fallback() {
        // DB has a ComParamRef for protocol "OTHER", but we look up "MY_PROTO".
        let result = do_lookup(
            &[ComParamRefSpec {
                protocol: "OTHER",
                name: "CP_MyParam",
                value: "42",
            }],
            "CP_MyParam",
            false,
        );

        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "expected NotFound, got an unexpected variant"
        );
    }

    #[test]
    fn test_lookup_fallback_single_protocol_match_found() {
        // DB has one ComParamRef for protocol "DB_PROTO".
        // We look up with a different protocol ("MY_PROTO"), but ignore_protocol=true.
        let result = do_lookup(
            &[ComParamRefSpec {
                protocol: "DB_PROTO",
                name: "CP_MyParam",
                value: "99",
            }],
            "CP_MyParam",
            true,
        );

        match result {
            Ok(ComParamValue::Simple(s)) => assert_eq!(s.value, "99"),
            Ok(ComParamValue::Complex(_)) => panic!("expected Simple, got Complex"),
            Err(e) => panic!("expected Ok(Simple(\"99\")), got Err({e:?})"),
        }
    }

    #[test]
    fn test_lookup_fallback_single_protocol_no_match() {
        let result = do_lookup(
            &[ComParamRefSpec {
                protocol: "DB_PROTO",
                name: "CP_OtherParam",
                value: "5",
            }],
            "CP_Missing",
            true,
        );

        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "expected NotFound, got an unexpected variant"
        );
    }

    #[test]
    fn test_lookup_fallback_multiple_protocols_error() {
        // DB has ComParamRefs for two distinct protocols.
        let result = do_lookup(
            &[
                ComParamRefSpec {
                    protocol: "PROTO_A",
                    name: "CP_MyParam",
                    value: "1",
                },
                ComParamRefSpec {
                    protocol: "PROTO_B",
                    name: "CP_MyParam",
                    value: "2",
                },
            ],
            "CP_MyParam",
            true,
        );

        assert!(
            matches!(result, Err(DiagServiceError::InvalidDatabase(_))),
            "expected InvalidDatabase, got an unexpected variant"
        );
    }
}
