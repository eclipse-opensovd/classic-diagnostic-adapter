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

//! ECU specific schema of the fault environment data in `GET /faults/{id}`.

use aide::openapi::{OpenApi, PathItem, ReferenceOr};
use cda_interfaces::{EcuSchemas, datatypes::DtcReadInformationFunction as Func};
use cda_sovd::docs::faults::{any_of, extended_data_record_schema, snapshot_schema};
use serde_json::{Value, json};

use crate::GeneratorError;

/// How detailed the fault environment data (snapshots and extended data records) of
/// `GET /faults/{id}` is described.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum FaultSchemaDetail {
    /// The data types defined in the MDD for the snapshot and extended data services.
    #[default]
    Full,
    /// The generic schema of the CDA, the record content is not described.
    Generic,
}

/// Snapshot and extended data record schemas of the selected variant.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct EnvironmentDataSchemas {
    pub snapshot: Option<Value>,
    pub extended_data_record: Option<Value>,
}

/// Derives the schemas from the response schemas of the `ReadDTCInformation`
/// services of the selected variant. Services without a usable schema are skipped.
pub(crate) async fn environment_data_schemas<E>(ecu: &E) -> EnvironmentDataSchemas
where
    E: cda_interfaces::Dtc + EcuSchemas + Sync,
{
    let snapshot = response_schemas(
        ecu,
        &[
            Func::FaultMemorySnapshotRecordByDtcNumber,
            Func::UserMemoryDtcSnapshotRecordByDtcNumber,
        ],
    )
    .await;
    let extended = response_schemas(
        ecu,
        &[
            Func::FaultMemoryExtDataRecordByDtcNumber,
            Func::UserMemoryDtcExtDataRecordByDtcNumber,
        ],
    )
    .await;
    EnvironmentDataSchemas {
        snapshot: any_of(snapshot.iter().filter_map(snapshot_schema).collect()),
        extended_data_record: any_of(
            extended
                .iter()
                .filter_map(extended_data_record_schema)
                .collect(),
        ),
    }
}

async fn response_schemas<E>(ecu: &E, functions: &[Func]) -> Vec<Value>
where
    E: cda_interfaces::Dtc + EcuSchemas + Sync,
{
    let Ok(lookups) = ecu.lookup_dtc_services(functions) else {
        return Vec::new();
    };
    let mut services: Vec<_> = lookups.into_values().map(|l| l.service).collect();
    // Deterministic order, the lookup is a hash map.
    services.sort_by(|a, b| a.name.cmp(&b.name));
    let mut schemas = Vec::with_capacity(services.len());
    for service in &services {
        if let Some(schema) = ecu
            .schema_for_responses(service)
            .await
            .ok()
            .and_then(cda_interfaces::SchemaDescription::into_schema)
        {
            schemas.push(schema.to_value());
        }
    }
    schemas
}

/// [[ dimpl~openapi-gen-fault-environment-data, Fault environment data schema ]]
///
/// Replaces the response schema of `GET {base_path}/faults/{id}` by one whose
/// snapshot and extended data record values use `schemas`. The generic parts
/// (fault item, errors, schema) keep referencing the shared components.
pub(crate) fn apply(
    api: &mut OpenApi,
    base_path: &str,
    schemas: &EnvironmentDataSchemas,
) -> Result<(), GeneratorError> {
    if schemas.snapshot.is_none() && schemas.extended_data_record.is_none() {
        return Ok(());
    }
    let err =
        |e: serde_json::Error| GeneratorError::Output(format!("Cannot set fault schema: {e}"));
    let components = serde_json::to_value(&api.components).map_err(err)?;
    let component = |name: &str| components.pointer(&format!("/schemas/{name}")).cloned();
    let (Some(mut fault), Some(mut environment), Some(mut snapshots), Some(mut records)) = (
        component("ExtendedFault"),
        component("EnvironmentData"),
        component("ExtendedSnapshots"),
        component("ExtendedDataRecords"),
    ) else {
        return Ok(());
    };
    let Some(ReferenceOr::Item(item)) = api
        .paths
        .as_mut()
        .and_then(|p| p.paths.get_mut(&format!("{base_path}/faults/{{id}}")))
    else {
        return Ok(());
    };

    if let Some(schema) = &schemas.snapshot {
        set_data(&mut snapshots, schema);
    }
    if let Some(schema) = &schemas.extended_data_record {
        set_data(&mut records, schema);
    }
    replace_ref(&mut environment, "ExtendedSnapshots", &snapshots);
    replace_ref(&mut environment, "ExtendedDataRecords", &records);
    replace_ref(&mut fault, "EnvironmentData", &environment);

    let mut value = serde_json::to_value(&*item).map_err(err)?;
    let Some(slot) = value.pointer_mut("/get/responses/200/content/application~1json/schema")
    else {
        return Ok(());
    };
    *slot = fault;
    *item = serde_json::from_value::<PathItem>(value).map_err(err)?;
    Ok(())
}

/// Sets the value schema of the `data` map of `ExtendedSnapshots` / `ExtendedDataRecords`.
fn set_data(container: &mut Value, schema: &Value) {
    if let Some(data) = container.pointer_mut("/properties/data") {
        *data = json!({
            "type": ["object", "null"],
            "description": "Records by record number.",
            "additionalProperties": schema
        });
    }
}

/// Replaces every reference to the component `name` within `value` by `schema`.
fn replace_ref(value: &mut Value, name: &str, schema: &Value) {
    let target = format!("#/components/schemas/{name}");
    match value {
        Value::Object(map) => {
            if map.get("$ref").and_then(Value::as_str) == Some(target.as_str()) {
                *value = schema.clone();
                return;
            }
            map.values_mut().for_each(|v| replace_ref(v, name, schema));
        }
        Value::Array(list) => list.iter_mut().for_each(|v| replace_ref(v, name, schema)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_replaced_recursively() {
        let mut value = json!({"anyOf": [{"$ref": "#/components/schemas/A"}, {"type": "null"}]});
        replace_ref(&mut value, "A", &json!({"type": "object"}));
        assert_eq!(
            value,
            json!({"anyOf": [{"type": "object"}, {"type": "null"}]})
        );
    }

    #[test]
    fn data_values_use_the_record_schema() {
        let mut snapshots = json!({"properties": {"data": {"type": ["object", "null"]}}});
        set_data(&mut snapshots, &json!({"type": "integer"}));
        assert_eq!(
            snapshots.pointer("/properties/data/additionalProperties"),
            Some(&json!({"type": "integer"}))
        );
    }
}
