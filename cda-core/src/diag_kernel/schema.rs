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

use cda_database::datatypes::{self, DataOperationVariant, DiagnosticDatabase, DopFieldValue};
use cda_interfaces::{
    DiagComm, DiagServiceError, EcuAddressProvider, EcuSchemaProvider, Id, STRINGS,
    SchemaDescription,
};
use cda_plugin_security::SecurityPlugin;

use crate::EcuManager;

impl<S: SecurityPlugin> EcuSchemaProvider for EcuManager<S> {
    fn schema_for_request(
        &self,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self.lookup_diag_comm(service)?;
        let Some(request) = self.ecu_data.requests.get(&mapped_service.request_id) else {
            return Err(DiagServiceError::InvalidDatabase(format!(
                "The request referenced by {} could not be found in the ECU Database of {}.",
                service.name,
                self.ecu_name()
            )));
        };
        let ctx = STRINGS
            .get(mapped_service.short_name)
            .unwrap_or_else(|| format!("{}_{}", service.name, service.action));
        let schema = request.json_schema(&ctx, &self.ecu_data);

        Ok(schema)
    }

    fn schema_for_responses(
        &self,
        service: &DiagComm,
    ) -> Result<SchemaDescription, DiagServiceError> {
        let mapped_service = self.lookup_diag_comm(service)?;
        let ctx = STRINGS
            .get(mapped_service.short_name)
            .unwrap_or_else(|| format!("{}_{}", service.name, service.action));

        let request_id = mapped_service.request_id;

        let mut responses = Vec::new();
        for id in &mapped_service.pos_responses {
            let Some(response) = self.ecu_data.responses.get(id) else {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "A response referenced by {} could not be found in the ECU Database of {}.",
                    service.name,
                    self.ecu_name()
                )));
            };
            let schema = response.json_schema(&ctx, &self.ecu_data, request_id);
            responses.push(schema);
        }
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

pub(crate) trait ResponseJsonSchema {
    fn json_schema(
        &self,
        ctx: &str,
        ecu_db: &DiagnosticDatabase,
        request_id: Id,
    ) -> SchemaDescription;
}

pub(crate) trait RequestJsonSchema {
    fn json_schema(&self, ctx: &str, ecu_db: &DiagnosticDatabase) -> SchemaDescription;
}

impl RequestJsonSchema for datatypes::Request {
    fn json_schema(&self, ctx: &str, ecu_db: &DiagnosticDatabase) -> SchemaDescription {
        let schema = params_to_schema(&self.params, ctx, ecu_db, None);

        SchemaDescription::new(
            format!("Request_{ctx}"),
            format!("Request for {ctx}"),
            schema,
        )
    }
}

impl ResponseJsonSchema for datatypes::Response {
    fn json_schema(
        &self,
        ctx: &str,
        ecu_db: &DiagnosticDatabase,
        request_id: Id,
    ) -> SchemaDescription {
        let schema = params_to_schema(&self.params, ctx, ecu_db, Some(request_id));

        SchemaDescription::new(
            format!("Response_{ctx}"),
            format!("Response for {ctx}"),
            schema,
        )
    }
}

fn params_to_schema(
    params: &[cda_interfaces::Id],
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request_id: Option<Id>,
) -> Option<schemars::Schema> {
    let mut schema: Option<schemars::Schema> = None;

    for param in params {
        let Some(param) = ecu_db.params.get(param) else {
            tracing::trace!("Mapping {ctx}: Parameter not found in ECU database. skipping");
            continue;
        };
        let Some(name) = STRINGS.get(param.short_name) else {
            tracing::trace!("Mapping {ctx}: Parameter short name not found in strings. skipping");
            continue;
        };
        let val = if let datatypes::ParameterValue::MatchingRequestParam(matching) = &param.value {
            let Some(request_id) = request_id else {
                tracing::trace!(
                    "Mapping {ctx}: Parameter is a MatchingRequestParam within a request context."
                );
                continue;
            };
            let Some(val) = ecu_db
                .requests
                .get(&request_id)
                .and_then(|req| {
                    req.params.iter().find_map(|p| {
                        ecu_db.params.get(p).and_then(|p| {
                            // note: check explicitly if its safe to convert it to a u32
                            // if it is < 0 we can safely assume that no param will match
                            if matching.request_byte_pos > 0
                                && (p.byte_pos == matching.request_byte_pos as u32)
                            {
                                Some(p)
                            } else {
                                None
                            }
                        })
                    })
                })
                .and_then(|matching_param| {
                    let datatypes::ParameterValue::Value(val) = &matching_param.value else {
                        return None;
                    };
                    Some(val)
                })
            else {
                tracing::trace!(
                    "Mapping {ctx}: Matching request parameter not found in request. skipping"
                );
                continue;
            };
            val
        } else {
            let datatypes::ParameterValue::Value(val) = &param.value else {
                tracing::trace!("Mapping {ctx}: Parameter is not a value. skipping");
                continue;
            };
            val
        };
        let Some(dop) = ecu_db.data_operations.get(&val.dop) else {
            tracing::trace!("Mapping {ctx}: DOP not found in ECU database. skipping");
            continue;
        };
        let default_value = match val.default_value {
            Some(ref_) => STRINGS.get(ref_),
            None => None,
        }
        .unwrap_or_default();

        let schema = match schema {
            Some(ref mut s) => s,
            None => {
                schema = Some(schemars::json_schema!(true));
                schema.as_mut().unwrap()
            }
        };

        match &dop.variant {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                // todo: schould we add a description or something
                // regarding how the DOPs work? (scales, ...)
                let type_ = match normal_dop.compu_method.category {
                    datatypes::CompuCategory::TextTable => "string".to_owned(),
                    datatypes::CompuCategory::Identical
                    | datatypes::CompuCategory::Linear
                    | datatypes::CompuCategory::ScaleLinear
                    | datatypes::CompuCategory::TabIntp
                    | datatypes::CompuCategory::RatFunc
                    | datatypes::CompuCategory::ScaleRatFunc
                    | datatypes::CompuCategory::CompuCode => {
                        let Some(datatype) = ecu_db.diag_coded_types.get(&normal_dop.diag_type)
                        else {
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
                if let Some(end_of_pdu_schema) =
                    map_dop_field_to_schema(&end_of_pdu_dop.field, ctx, ecu_db, request_id)
                {
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
                    map_struct_to_schema(structure_dop, ctx, ecu_db, request_id)
                {
                    schema.insert(name, struct_schema.into());
                }
            }
            datatypes::DataOperationVariant::StaticField(static_field_dop) => {
                if let Some(static_field_schema) =
                    map_dop_field_to_schema(&static_field_dop.field, ctx, ecu_db, request_id)
                {
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
                    map_mux_to_schema(mux_dop, ctx, ecu_db, request_id).into(),
                );
            }
            datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field) => {
                let repeated_dop = if let Some(dop) = ecu_db
                    .data_operations
                    .get(&dynamic_length_field.repeated_dop_id)
                {
                    dop
                } else {
                    tracing::trace!(
                        "Mapping {ctx}: Repeated DOP not found in ECU database. skipping"
                    );
                    continue;
                };

                match &repeated_dop.variant {
                    DataOperationVariant::Structure(structure_dop) => {
                        if let Some(struct_schema) =
                            map_struct_to_schema(structure_dop, ctx, ecu_db, request_id)
                        {
                            schema
                                .insert(name, serde_json::Value::Array(vec![struct_schema.into()]));
                        }
                    }
                    DataOperationVariant::EnvDataDesc(_) => {
                        tracing::trace!(
                            "Mapping {ctx}: Repeated DOP is an EnvDataDesc which is not yet \
                             supported in JSON Schema. skipping"
                        );
                    }
                    _ => {
                        tracing::trace!(
                            "Mapping {ctx}: Repeated DOP is not a Structure or EnvDataDesc. \
                             skipping"
                        );
                        continue;
                    }
                }
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
    request_id: Option<Id>,
) -> Option<schemars::Schema> {
    params_to_schema(&struct_.params, ctx, ecu_db, request_id)
}

fn map_dop_field_to_schema(
    dop_field: &datatypes::DopField,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request_id: Option<Id>,
) -> Option<schemars::Schema> {
    match &dop_field.value {
        DopFieldValue::BasicStruct(basic_struct) => ecu_db
            .data_operations
            .get(&basic_struct.struct_id)
            .and_then(|dop| {
                let datatypes::DataOperationVariant::Structure(struct_) = &dop.variant else {
                    return None;
                };
                map_struct_to_schema(struct_, ctx, ecu_db, request_id)
            }),
        DopFieldValue::EnvDataDesc(_) => {
            tracing::trace!(
                "Mapping {ctx}: EnvDataDesc DopFields are not yet supported in JSON Schema. \
                 skipping"
            );
            None
        }
    }
}

fn map_mux_to_schema(
    mux: &datatypes::MuxDop,
    ctx: &str,
    ecu_db: &DiagnosticDatabase,
    request_id: Option<Id>,
) -> schemars::Schema {
    let mut schemas: Vec<serde_json::Value> = Vec::new();

    // probably an any-of here instead of a list?
    for case in &mux.cases {
        let Some(datatypes::DataOperationVariant::Structure(case_struct)) = &case
            .structure
            .and_then(|id| ecu_db.data_operations.get(&id))
            .map(|dop| &dop.variant)
        else {
            continue;
        };

        if let Some(case_schema) = map_struct_to_schema(case_struct, ctx, ecu_db, request_id) {
            schemas.push(case_schema.into());
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
