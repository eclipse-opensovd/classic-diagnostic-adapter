/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
use cda_database::datatypes::{self, DiagService, DiagnosticDatabase};
use cda_interfaces::{DiagServiceError, EcuAddresses, EcuSchemas, SchemaDescription, dlt_ctx};
use cda_plugin_security::SecurityPlugin;

use crate::EcuManager;

impl<S: SecurityPlugin> EcuSchemas for EcuManager<S> {
    async fn schema_for_request(
        &self,
        service: &cda_interfaces::DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service, None, None).await?;
        let ctx = service_context(service, &mapped_service);

        let request = mapped_service.request().map(datatypes::Request).ok_or(
            DiagServiceError::InvalidDatabase(format!(
                "Missing request for service {} in ecu {}.",
                service.name,
                self.ecu_name()
            )),
        )?;
        let schema = request.json_schema(&ctx, &self.diag_database);

        Ok(schema)
    }

    async fn schema_for_responses(
        &self,
        service: &cda_interfaces::DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service, None, None).await?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::InvalidDatabase(format!(
                "Missing request for service {} in ecu {}.",
                service.name,
                self.ecu_name()
            )))?;

        let ctx = service_context(service, &mapped_service);
        let responses: Vec<SchemaDescription> = mapped_service
            .pos_responses()
            .map(|rs| {
                rs.iter()
                    .map(datatypes::Response)
                    .map(|resp| resp.json_schema(&ctx, &self.diag_database, request.into()))
                    .collect()
            })
            .unwrap_or_default();

        let main_schema = match responses.len() {
            0 => None,
            1 => responses
                .into_iter()
                .next()
                .and_then(SchemaDescription::into_schema),
            _ => Some(schemars::json_schema!({
                "anyOf": responses.into_iter()
                    .filter_map(SchemaDescription::into_schema)
                    .collect::<Vec<_>>()
            })),
        };
        Ok(SchemaDescription::new(
            format!("Responses_{ctx}"),
            format!("Responses for {ctx}"),
            main_schema,
        ))
    }

    async fn schema_for_fg_request(
        &self,
        service: &cda_interfaces::DiagComm,
        functional_group_name: &str,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self
            .lookup_diag_service(service, Some(functional_group_name), None)
            .await?;
        let ctx = service_context(service, &mapped_service);

        let request = mapped_service.request().map(datatypes::Request).ok_or(
            DiagServiceError::InvalidDatabase(format!(
                "Missing request for service {} in functional group {}.",
                service.name, functional_group_name
            )),
        )?;
        let schema = request.json_schema(&ctx, &self.diag_database);

        Ok(schema)
    }
}

fn service_context(service: &cda_interfaces::DiagComm, mapped_service: &DiagService) -> String {
    mapped_service
        .diag_comm()
        .and_then(|dc| dc.short_name().map(ToOwned::to_owned))
        .unwrap_or_else(|| {
            let action = mapped_service
                .request_id()
                .and_then(|id| id.try_into().ok())
                .map(
                    |type_: cda_interfaces::DiagCommType| -> cda_interfaces::DiagCommAction {
                        type_.into()
                    },
                );

            format!(
                "{}_{}",
                service.name,
                action.map_or_else(|| "<unknown action>".to_string(), |a| a.to_string())
            )
        })
}

pub(crate) trait ResponseJsonSchema {
    fn json_schema(
        &self,
        ctx: &str,
        ecu_db: &DiagnosticDatabase,
        request: datatypes::Request,
    ) -> SchemaDescription;
}

pub(crate) trait RequestJsonSchema {
    fn json_schema(&self, ctx: &str, ecu_db: &DiagnosticDatabase) -> SchemaDescription;
}

impl RequestJsonSchema for datatypes::Request<'_> {
    fn json_schema(&self, ctx: &str, ecu_db: &DiagnosticDatabase) -> SchemaDescription {
        let schema = if let Some(params) = &self
            .params()
            .map(|params| params.iter().map(datatypes::Parameter).collect::<Vec<_>>())
        {
            params_to_schema(params, ctx, ecu_db, Some(self))
        } else {
            None
        };

        SchemaDescription::new(
            format!("Request_{ctx}"),
            format!("Request for {ctx}"),
            schema,
        )
    }
}

impl ResponseJsonSchema for datatypes::Response<'_> {
    fn json_schema(
        &self,
        ctx: &str,
        ecu_db: &DiagnosticDatabase,
        request: datatypes::Request,
    ) -> SchemaDescription {
        let schema = if let Some(params) = &self
            .params()
            .map(|params| params.iter().map(datatypes::Parameter).collect::<Vec<_>>())
        {
            params_to_schema(params, ctx, ecu_db, Some(&request))
        } else {
            None
        };

        SchemaDescription::new(
            format!("Response_{ctx}"),
            format!("Response for {ctx}"),
            schema,
        )
    }
}

#[tracing::instrument(skip_all,
    fields(
        dlt_context = dlt_ctx!("CORE"),
    )
)]
fn params_to_schema(
    params: &[datatypes::Parameter],
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
) -> Option<schemars::Schema> {
    let mut schema: Option<schemars::Schema> = None;

    for param in params {
        let Some(name) = param.short_name().map(ToOwned::to_owned) else {
            tracing::trace!("Mapping {ctx}: Parameter short name is None. skipping");
            continue;
        };
        let val = if let Some(matching) = &param.specific_data_as_matching_request_param() {
            let Some(request) = request else {
                tracing::trace!(
                    "Mapping {ctx}: Parameter is a MatchingRequestParam within a request context."
                );
                continue;
            };

            let Some(val) = request.params().and_then(|p| {
                p.iter()
                    .find(|params| {
                        params.byte_position().is_some_and(|bp| {
                            let request_bp = matching.request_byte_pos();
                            #[allow(
                                clippy::cast_sign_loss,
                                reason = "Safe because sign is checked with >= 0 above"
                            )]
                            let matching_request_byte_pos = matching.request_byte_pos() as u32;
                            request_bp >= 0 && bp == matching_request_byte_pos
                        })
                    })
                    .and_then(|matching_param| matching_param.specific_data_as_value())
            }) else {
                tracing::trace!(
                    "Mapping {ctx}: Matching request parameter not found in request. skipping"
                );
                continue;
            };
            val
        } else if let Some(v) = param.specific_data_as_value() {
            v
        } else {
            tracing::trace!(
                "Mapping {ctx}: Parameter is not a value or matching request param. skipping"
            );
            continue;
        };

        let Some(dop) = val.dop().map(datatypes::DataOperation) else {
            tracing::trace!("Mapping {ctx}: Parameter DOP not found in ECU database. skipping");
            continue;
        };

        let default_value = val.physical_default_value().unwrap_or_default();
        let schema = if let Some(ref mut s) = schema {
            s
        } else {
            schema = Some(schemars::json_schema!(true));
            if let Some(ref mut s) = schema {
                s
            } else {
                unreachable!("schema was just set to Some")
            }
        };

        let variant = match dop.variant() {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!("Mapping {ctx}: Failed to get DOP variant: {}. skipping", e);
                continue;
            }
        };

        if let Err(e) =
            dop_variant_to_schema(ctx, ecu_db, request, name, default_value, schema, variant)
        {
            tracing::trace!(
                "Mapping {ctx}: Failed to map DOP variant to schema: {}. skipping",
                e
            );
        }
    }
    schema.map(|schema| {
        schemars::json_schema!({
            "type": "object",
            "properties": schema
        })
    })
}

/// Collect accepted text values from a `TextTable` compu method's scales.
///
/// Each scale entry maps a coded/internal value to a human-readable text value.
/// Returns the text values (`vt`, with `vt_ti` as fallback) that the user can
/// supply when executing this service.
fn text_table_enum_values<'a>(normal_dop: &'a datatypes::NormalDop<'a>) -> Vec<&'a str> {
    normal_dop
        .compu_method()
        .and_then(|cm| cm.internal_to_phys())
        .and_then(|itp| itp.compu_scales())
        .map(|scales| {
            scales
                .iter()
                .filter_map(|scale| scale.consts().and_then(|c| c.vt().or(c.vt_ti())))
                .collect()
        })
        .unwrap_or_default()
}

/// If the `NormalDop` carries a physical constraint (`phys_constr`) with
/// parseable numeric limits, add the corresponding JSON Schema range keywords
/// (`minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum`) to `schema`.
///
/// Limits with `IntervalType::Infinite` or non-numeric values are silently
/// skipped so that this helper never fails.
fn add_phys_constr_range(normal_dop: &datatypes::NormalDop, schema: &mut schemars::Schema) {
    let Some(constr) = normal_dop.phys_constr() else {
        return;
    };
    let Some(props) = schema.as_object_mut() else {
        return;
    };

    if let Some(lower) = constr.lower_limit() {
        let interval: datatypes::IntervalType = lower.interval_type().into();
        if interval != datatypes::IntervalType::Infinite
            && let Some(value) = lower.value().and_then(|v| v.parse::<f64>().ok())
        {
            let key = if interval == datatypes::IntervalType::Open {
                "exclusiveMinimum"
            } else {
                "minimum"
            };
            props.insert(key.to_owned(), serde_json::json!(value));
        }
    }

    if let Some(upper) = constr.upper_limit() {
        let interval: datatypes::IntervalType = upper.interval_type().into();
        if interval != datatypes::IntervalType::Infinite
            && let Some(value) = upper.value().and_then(|v| v.parse::<f64>().ok())
        {
            let key = if interval == datatypes::IntervalType::Open {
                "exclusiveMaximum"
            } else {
                "maximum"
            };
            props.insert(key.to_owned(), serde_json::json!(value));
        }
    }
}

fn normal_dop_to_schema(
    ctx: &str,
    normal_dop: &datatypes::NormalDop,
    name: String,
    default_value: &str,
    schema: &mut schemars::Schema,
) -> Result<(), DiagServiceError> {
    let Some(category) = normal_dop
        .compu_method()
        .map(|cm| cm.category())
        .map(Into::into)
    else {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Mapping {ctx}: Compu Method or Category not found in ECU database"
        )));
    };

    match category {
        datatypes::CompuCategory::TextTable => {
            let enum_values = text_table_enum_values(normal_dop);
            let mut param_schema = schemars::json_schema!({ "type": "string" });
            if !enum_values.is_empty() {
                param_schema.insert("enum".to_owned(), enum_values.into());
            }
            if !default_value.is_empty() {
                param_schema.insert("default".to_owned(), default_value.into());
            }
            schema.insert(name, param_schema.into());
        }
        datatypes::CompuCategory::Identical
        | datatypes::CompuCategory::Linear
        | datatypes::CompuCategory::ScaleLinear
        | datatypes::CompuCategory::TabIntp
        | datatypes::CompuCategory::RatFunc
        | datatypes::CompuCategory::ScaleRatFunc
        | datatypes::CompuCategory::CompuCode => {
            let Some(datatype) = normal_dop.diag_coded_type().ok() else {
                return Err(DiagServiceError::ParameterConversionError(format!(
                    "Mapping {ctx}: Diag Coded Type not found in ECU database"
                )));
            };
            let type_ = ecu_datatype_to_jsontype(value_datatype(
                category,
                datatype.base_datatype(),
                normal_dop,
            ));

            let mut param_schema = schemars::json_schema!({ "type": type_ });
            if let Some(default) = default_to_json(default_value, &type_) {
                param_schema.insert("default".to_owned(), default);
            }
            if datatype.base_datatype() == datatypes::DataType::ByteField && type_ == "string" {
                // Base64 is the default, `SchemaDescription::with_binary_encoding`
                // switches it to the encoding selected for the request.
                param_schema.insert(
                    "format".to_owned(),
                    cda_interfaces::BinaryEncoding::Base64
                        .json_schema_format()
                        .into(),
                );
                // Database defaults are hex coded, convert them so the default
                // matches the declared format.
                match cda_interfaces::BinaryEncoding::Hex.decode(default_value) {
                    Ok(bytes) if !bytes.is_empty() => {
                        param_schema.insert(
                            "default".to_owned(),
                            cda_interfaces::BinaryEncoding::Base64.encode(&bytes).into(),
                        );
                    }
                    Ok(_) => {
                        param_schema.remove("default");
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = ?e,
                            "Mapping {ctx}: Byte field default is not valid hex, omitting it"
                        );
                        param_schema.remove("default");
                    }
                }
            }
            add_phys_constr_range(normal_dop, &mut param_schema);
            schema.insert(name, param_schema.into());
        }
    }
    Ok(())
}

fn dop_variant_to_schema(
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
    name: String,
    default_value: &str,
    schema: &mut schemars::Schema,
    variant: datatypes::DataOperationVariant,
) -> Result<(), DiagServiceError> {
    match variant {
        datatypes::DataOperationVariant::Normal(normal_dop) => {
            normal_dop_to_schema(ctx, &normal_dop, name, default_value, schema)?;
        }
        datatypes::DataOperationVariant::EndOfPdu(end_of_pdu_dop) => {
            if let Some(end_of_pdu_schema) = map_dop_field_to_schema(
                end_of_pdu_dop.field().map(datatypes::DopField).as_ref(),
                ctx,
                ecu_db,
                request,
            ) {
                schema.insert(
                    name,
                    schemars::json_schema!({
                        "type": "array",
                        "items": end_of_pdu_schema
                    })
                    .into(),
                );
            }
        }
        datatypes::DataOperationVariant::Structure(structure_dop) => {
            if let Some(struct_schema) = map_struct_to_schema(&structure_dop, ctx, ecu_db, request)
            {
                schema.insert(name, struct_schema.into());
            }
        }
        datatypes::DataOperationVariant::StaticField(static_field_dop) => {
            if let Some(static_field_schema) = map_dop_field_to_schema(
                static_field_dop.field().map(datatypes::DopField).as_ref(),
                ctx,
                ecu_db,
                request,
            ) {
                schema.insert(name, static_field_schema.into());
            }
        }
        datatypes::DataOperationVariant::EnvDataDesc(env_data_desc_dop) => {
            let variants = env_data_desc_to_variants(&env_data_desc_dop, ctx, ecu_db, request);
            if !variants.is_empty() {
                schema.insert(name, schemars::json_schema!({ "anyOf": variants }).into());
            }
        }
        datatypes::DataOperationVariant::EnvData(_env_data_dop) => {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Mapping {ctx}: EnvData DOPs are not yet supported in JSON Schema."
            )));
        }
        datatypes::DataOperationVariant::Dtc(_dtc_dop) => {
            // todo implement dtc dop
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Mapping {ctx}: DTC DOPs are not yet supported in JSON Schema."
            )));
        }
        datatypes::DataOperationVariant::Mux(mux_dop) => {
            schema.insert(
                name,
                map_mux_to_schema(&mux_dop, ctx, ecu_db, request).into(),
            );
        }
        datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field) => {
            if let Some(v) =
                map_dynamic_length_field_to_schema(&dynamic_length_field, ctx, ecu_db, request)?
            {
                schema.insert(name, v);
            }
        }
    }
    Ok(())
}

fn map_struct_to_schema(
    struct_: &datatypes::StructureDop,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
) -> Option<schemars::Schema> {
    let params = struct_
        .params()
        .map(|params| params.iter().map(datatypes::Parameter).collect::<Vec<_>>())
        .unwrap_or_default();
    params_to_schema(&params, ctx, ecu_db, request)
}

fn env_data_desc_to_variants(
    env_data_desc: &datatypes::EnvDataDescDop<'_>,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request<'_>>,
) -> Vec<serde_json::Value> {
    env_data_desc
        .env_datas()
        .into_iter()
        .flat_map(|v| v.iter())
        .filter_map(|dop| {
            let env_data = dop.specific_data_as_env_data()?;
            let params: Vec<datatypes::Parameter> = env_data
                .params()
                .into_iter()
                .flat_map(|p| p.iter())
                .map(datatypes::Parameter)
                .collect();
            params_to_schema(&params, ctx, ecu_db, request).map(Into::into)
        })
        .collect()
}

fn map_dynamic_length_field_to_schema(
    dynamic_length_field: &datatypes::DynamicLengthDop<'_>,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request<'_>>,
) -> Result<Option<serde_json::Value>, DiagServiceError> {
    if let Some(structure_dop) = dynamic_length_field
        .field()
        .and_then(|f| f.basic_structure())
        .and_then(|s| s.specific_data_as_structure())
        .map(datatypes::StructureDop)
    {
        Ok(map_struct_to_schema(&structure_dop, ctx, ecu_db, request)
            .map(|s| schemars::json_schema!({ "type": "array", "items": s }).into()))
    } else if let Some(env_data_desc) = dynamic_length_field
        .field()
        .and_then(|f| f.env_data_desc())
        .and_then(|dop| dop.specific_data_as_env_data_desc())
        .map(datatypes::EnvDataDescDop)
    {
        let variants = env_data_desc_to_variants(&env_data_desc, ctx, ecu_db, request);
        if variants.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                schemars::json_schema!({ "type": "array", "items": { "anyOf": variants } }).into(),
            ))
        }
    } else {
        Err(DiagServiceError::ParameterConversionError(format!(
            "Mapping {ctx}: DynamicLengthField DopField value is neither BasicStruct nor \
             EnvDataDesc."
        )))
    }
}

#[tracing::instrument(skip_all,
    fields(
        dlt_context = dlt_ctx!("CORE"),
    )
)]
fn map_dop_field_to_schema(
    dop_field: Option<&datatypes::DopField>,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
) -> Option<schemars::Schema> {
    let Some(dop_field) = dop_field else {
        tracing::trace!("Mapping {ctx}: DopField is None. skipping");
        return None;
    };

    if let Some(basic_struct) = dop_field
        .basic_structure()
        .and_then(|s| s.specific_data_as_structure().map(datatypes::StructureDop))
    {
        map_struct_to_schema(&basic_struct, ctx, ecu_db, request)
    } else if let Some(env_data_desc) = dop_field
        .env_data_desc()
        .and_then(|dop| dop.specific_data_as_env_data_desc())
        .map(datatypes::EnvDataDescDop)
    {
        let variants = env_data_desc_to_variants(&env_data_desc, ctx, ecu_db, request);
        if variants.is_empty() {
            None
        } else {
            Some(schemars::json_schema!({ "anyOf": variants }))
        }
    } else {
        tracing::trace!(
            "Mapping {ctx}: DopField value is neither BasicStruct nor EnvDataDesc. skipping"
        );
        None
    }
}

#[tracing::instrument(skip_all,
    fields(
        dlt_context = dlt_ctx!("CORE"),
    )
)]
fn map_mux_to_schema(
    mux: &datatypes::MuxDop,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
) -> schemars::Schema {
    let mut schemas: Vec<serde_json::Value> = Vec::new();
    if let Some(cases) = mux.cases() {
        for case in cases {
            let Some(case_struct) = case
                .structure()
                .and_then(|s| s.specific_data_as_structure())
                .map(datatypes::StructureDop)
            else {
                tracing::trace!(
                    "Mapping {ctx}: Mux case structure not found or not a StructureDop. skipping"
                );
                continue;
            };

            if let Some(case_schema) = map_struct_to_schema(&case_struct, ctx, ecu_db, request) {
                schemas.push(case_schema.into());
            }
        }
    }
    schemars::json_schema!({
        "anyOf": schemas
    })
}

/// Data type of the value the CDA returns and accepts for a parameter.
///
/// Matches `operations::uds_data_to_physical`: values of an `IDENTICAL` compu
/// method keep the coded type, all other compu methods compute a value of the
/// DOP's physical type (e.g. `A_FLOAT64` for a LINEAR scaling of an `A_UINT32`).
fn value_datatype(
    category: datatypes::CompuCategory,
    coded: datatypes::DataType,
    normal_dop: &datatypes::NormalDop,
) -> datatypes::DataType {
    if matches!(category, datatypes::CompuCategory::Identical) {
        return coded;
    }
    normal_dop
        .physical_type()
        .map_or(coded, |p| datatypes::PhysicalType::from(p).base_type)
}

/// Convert a database default value to the JSON type of the schema.
///
/// Returns `None` for an empty default (none defined in the database) or a
/// default that is not valid for the type, so the schema omits it instead of
/// declaring a value of the wrong type.
fn default_to_json(default_value: &str, json_type: &str) -> Option<serde_json::Value> {
    if default_value.is_empty() {
        return None;
    }
    match json_type {
        "integer" => default_value
            .parse::<i64>()
            .map(Into::into)
            .or_else(|_| default_value.parse::<u64>().map(Into::into))
            .ok(),
        "number" => default_value
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Into::into),
        _ => Some(default_value.into()),
    }
}

fn ecu_datatype_to_jsontype(type_: datatypes::DataType) -> String {
    match type_ {
        datatypes::DataType::Int32 | datatypes::DataType::UInt32 => "integer".to_owned(),
        datatypes::DataType::Float32 | datatypes::DataType::Float64 => "number".to_owned(),
        // Byte fields are represented as base64 or hex coded string.
        datatypes::DataType::AsciiString
        | datatypes::DataType::Utf8String
        | datatypes::DataType::Unicode2String
        | datatypes::DataType::ByteField => "string".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::EcuSchemas;
    use serde_json::json;

    use super::default_to_json;
    use crate::diag_kernel::test_utils::ecu_manager_builder::create_ecu_manager_with_physical_type_service;

    #[tokio::test]
    async fn value_types_follow_the_physical_type_and_defaults_are_typed() {
        let (ecu_manager, dc) = create_ecu_manager_with_physical_type_service();
        let schema = ecu_manager
            .schema_for_responses(&dc)
            .await
            .expect("Schema must be created")
            .into_schema()
            .expect("Response has parameters");
        let properties = schema
            .as_value()
            .pointer("/properties")
            .expect("Object schema");

        // LINEAR compu method: the CDA returns the physical (float) value.
        assert_eq!(properties.get("scaled"), Some(&json!({ "type": "number" })));
        // IDENTICAL keeps the coded type, the default has the JSON type.
        assert_eq!(
            properties.get("identical"),
            Some(&json!({ "type": "integer", "default": 5 }))
        );
        assert_eq!(
            properties.get("identical_float_phys"),
            Some(&json!({ "type": "integer" }))
        );
        // No default in the database: no empty string default.
        assert_eq!(
            properties.get("state"),
            Some(&json!({ "type": "string", "enum": ["ON"] }))
        );
    }

    #[test]
    fn defaults_are_converted_to_the_json_type() {
        assert_eq!(default_to_json("", "integer"), None);
        assert_eq!(default_to_json("", "string"), None);
        assert_eq!(default_to_json("-3", "integer"), Some(json!(-3)));
        assert_eq!(
            default_to_json("4294967295", "integer"),
            Some(json!(4_294_967_295u32))
        );
        assert_eq!(default_to_json("1.5", "integer"), None);
        assert_eq!(default_to_json("1.5", "number"), Some(json!(1.5)));
        assert_eq!(default_to_json("2", "number"), Some(json!(2.0)));
        assert_eq!(default_to_json("x", "number"), None);
        assert_eq!(default_to_json("ACTIVE", "string"), Some(json!("ACTIVE")));
    }
}
