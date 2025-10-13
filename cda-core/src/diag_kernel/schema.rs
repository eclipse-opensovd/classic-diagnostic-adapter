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
use cda_database::datatypes::{self, DiagService, DiagnosticDatabase};
use cda_interfaces::{DiagServiceError, EcuAddressProvider, EcuSchemaProvider, SchemaDescription};
use cda_plugin_security::SecurityPlugin;

use crate::EcuManager;

impl<S: SecurityPlugin> EcuSchemaProvider for EcuManager<S> {
    async fn schema_for_request(
        &self,
        service: &cda_interfaces::DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service).await?;
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
        let mapped_service = self.lookup_diag_service(service).await?;
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
            1 => responses.into_iter().next().and_then(|it| it.into_schema()),
            _ => Some(schemars::json_schema!({
                "any-of": responses.into_iter()
                    .filter_map(|s| s.into_schema())
                    .collect::<Vec<_>>(),
                "type": "array"
            })),
        };
        Ok(SchemaDescription::new(
            format!("Responses_{ctx}"),
            format!("Responses for {ctx}"),
            main_schema,
        ))
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
                action
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "<unknown action>".to_string())
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
                            request_bp >= 0 && bp == matching.request_byte_pos() as u32
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
        } else {
            match param.specific_data_as_value() {
                Some(v) => v,
                None => {
                    tracing::trace!(
                        "Mapping {ctx}: Parameter is not a value or matching request param. \
                         skipping"
                    );
                    continue;
                }
            }
        };

        let Some(dop) = val.dop().map(datatypes::DataOperation) else {
            tracing::trace!("Mapping {ctx}: Parameter DOP not found in ECU database. skipping");
            continue;
        };

        let default_value = val.physical_default_value().unwrap_or_default();
        let schema = match schema {
            Some(ref mut s) => s,
            None => {
                schema = Some(schemars::json_schema!(true));
                schema.as_mut().unwrap()
            }
        };

        let variant = match dop.variant() {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!("Mapping {ctx}: Failed to get DOP variant: {}. skipping", e);
                continue;
            }
        };

        match variant {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                // todo: schould we add a description or something
                // regarding how the DOPs work? (scales, ...)
                let Some(category) = normal_dop
                    .compu_method()
                    .map(|cm| cm.category())
                    .map(|category| category.into())
                else {
                    tracing::trace!(
                        "Mapping {ctx}: Compu Method or Category not found in ECU database. \
                         skipping"
                    );
                    continue;
                };

                let type_ = match category {
                    datatypes::CompuCategory::TextTable => "string".to_owned(),
                    datatypes::CompuCategory::Identical
                    | datatypes::CompuCategory::Linear
                    | datatypes::CompuCategory::ScaleLinear
                    | datatypes::CompuCategory::TabIntp
                    | datatypes::CompuCategory::RatFunc
                    | datatypes::CompuCategory::ScaleRatFunc
                    | datatypes::CompuCategory::CompuCode => {
                        let Some(datatype) = normal_dop.diag_coded_type().ok() else {
                            tracing::trace!(
                                "Mapping {ctx}: Coded Type not found in ECU database. skipping"
                            );
                            continue;
                        };
                        ecu_datatype_to_jsontype(datatype.base_datatype())
                    }
                };

                schema.insert(
                    name,
                    schemars::json_schema!({
                        "default": default_value,
                        "type": type_
                    })
                    .into(),
                );
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
                if let Some(struct_schema) =
                    map_struct_to_schema(&structure_dop, ctx, ecu_db, request)
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
            datatypes::DataOperationVariant::EnvDataDesc(_env_data_desc_dop) => {
                // todo: implement env data description
                tracing::trace!(
                    "Mapping {ctx}: EnvDataDesc DOPs are not yet supported in JSON Schema. \
                     skipping"
                );
            }
            datatypes::DataOperationVariant::EnvData(_env_data_dop) => {
                // todo: implement env data dop
                tracing::trace!(
                    "Mapping {ctx}: EnvData DOPs are not yet supported in JSON Schema. skipping"
                );
            }
            datatypes::DataOperationVariant::Dtc(_dtc_dop) => {
                // todo implement dtc dop
                tracing::trace!(
                    "Mapping {ctx}: DTC DOPs are not yet supported in JSON Schema. skipping"
                );
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                schema.insert(
                    name,
                    map_mux_to_schema(&mux_dop, ctx, ecu_db, request).into(),
                );
            }
            datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field) => {
                if let Some(structure_dop) = dynamic_length_field
                    .field()
                    .and_then(|f| f.basic_structure())
                    .and_then(|s| s.specific_data_as_structure())
                {
                    if let Some(struct_schema) =
                        map_struct_to_schema(&(structure_dop.into()), ctx, ecu_db, request)
                    {
                        schema.insert(name, serde_json::Value::Array(vec![struct_schema.into()]));
                    }
                } else if let Some(_env_data_desc) =
                    dynamic_length_field.field().and_then(|f| f.env_data_desc())
                {
                    tracing::trace!(
                        "Mapping {ctx}: DynamicLengthField DopField is an EnvDataDesc which is \
                         not yet supported in JSON Schema. skipping"
                    );
                    continue;
                } else {
                    tracing::trace!(
                        "Mapping {ctx}: DynamicLengthField DopField value is neither BasicStruct \
                         nor EnvDataDesc. skipping"
                    );
                    continue;
                };
            }
        }
    }
    schema.map(|schema| {
        schemars::json_schema!({
            "type": "object",
            "properties": schema
        })
    })
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
    } else if let Some(_env_data_desc) = dop_field.env_data_desc() {
        tracing::trace!(
            "Mapping {ctx}: EnvDataDesc DopFields are not yet supported in JSON Schema. skipping"
        );
        None
    } else {
        tracing::trace!(
            "Mapping {ctx}: DopField value is neither BasicStruct nor EnvDataDesc. skipping"
        );
        None
    }
}

fn map_mux_to_schema(
    mux: &datatypes::MuxDop,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request: Option<&datatypes::Request>,
) -> schemars::Schema {
    let mut schemas: Vec<serde_json::Value> = Vec::new();
    if let Some(cases) = mux.cases() {
        // probably an any-of here instead of a list?
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
        "any-of": schemas
    })
}

fn ecu_datatype_to_jsontype(type_: datatypes::DataType) -> String {
    match type_ {
        datatypes::DataType::Int32 | datatypes::DataType::UInt32 => "integer".to_owned(),
        datatypes::DataType::Float32 | datatypes::DataType::Float64 => "number".to_owned(),
        datatypes::DataType::AsciiString
        | datatypes::DataType::Utf8String
        | datatypes::DataType::Unicode2String => "string".to_owned(),
        datatypes::DataType::ByteField => "array".to_owned(),
    }
}
