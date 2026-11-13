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

//! Schemas of the fault environment data (snapshots and extended data records),
//! derived from the response schemas of the `ReadDTCInformation` services in the
//! database.
//!
//! The CDA maps the responses of the snapshot (0x19 04 / 0x19 18) and extended
//! data (0x19 06 / 0x19 19) services into `environment_data` of
//! `GET /faults/{id}`. The functions here apply the same mapping to the response
//! schemas, so the documentation shows the data types defined in the database.

use serde_json::{Map, Value, json};

/// Schema of a single snapshot, i.e. of the values of
/// `environment_data.snapshots.data`.
///
/// `response` is the response schema of a snapshot service. Returns `None` if
/// it does not contain a list of snapshot records with record entries.
#[must_use]
pub fn snapshot_schema(response: &Value) -> Option<Value> {
    let entries = alternatives(response)
        .into_iter()
        .filter_map(record_properties)
        .flat_map(|props| {
            props
                .values()
                .filter(|v| is_type(v, "array"))
                .filter_map(|v| v.get("items"))
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect();
    let entry = any_of(entries)?;
    Some(json!({
        "type": "object",
        "properties": {
            "DTCSnapshotRecordNumberOfIdentifiers": {
                "type": "integer",
                "format": "uint64",
                "minimum": 0
            },
            "DTCSnapshotRecord": {"type": "array", "items": entry}
        },
        "required": ["DTCSnapshotRecordNumberOfIdentifiers", "DTCSnapshotRecord"]
    }))
}

/// Schema of a single extended data record, i.e. of the values of
/// `environment_data.extended_data_records.data`.
///
/// `response` is the response schema of an extended data service. Returns
/// `None` if it does not contain a list of extended data records.
#[must_use]
pub fn extended_data_record_schema(response: &Value) -> Option<Value> {
    let records = alternatives(response)
        .into_iter()
        .filter_map(record_properties)
        .filter_map(|props| {
            // The record data is the only structured value next to the record number.
            props
                .values()
                .find(|v| v.get("anyOf").is_some() || is_type(v, "object"))
                .cloned()
        })
        .collect();
    any_of(records)
}

/// Combines the schemas of several services (e.g. fault and user memory) into one.
#[must_use]
pub fn any_of(schemas: Vec<Value>) -> Option<Value> {
    let mut unique: Vec<Value> = Vec::with_capacity(schemas.len());
    for schema in schemas {
        if !unique.contains(&schema) {
            unique.push(schema);
        }
    }
    match unique.len() {
        0 => None,
        1 => unique.pop(),
        _ => Some(json!({ "anyOf": unique })),
    }
}

/// The response schemas, a service with several positive responses has one per response.
fn alternatives(response: &Value) -> Vec<&Value> {
    match response.get("anyOf").and_then(Value::as_array) {
        Some(list) => list.iter().collect(),
        None => vec![response],
    }
}

/// Properties of the items of the record list in a response.
fn record_properties(response: &Value) -> Option<&Map<String, Value>> {
    response
        .get("properties")?
        .as_object()?
        .values()
        .filter(|v| is_type(v, "array"))
        .find_map(|v| v.get("items")?.get("properties")?.as_object())
}

fn is_type(value: &Value, ty: &str) -> bool {
    value.get("type").and_then(Value::as_str) == Some(ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_number() -> Value {
        json!({"type": "string", "enum": ["01", "02"]})
    }

    fn status() -> Value {
        json!({"type": "object", "properties": {"testFailed": {"type": "string"}}})
    }

    #[test]
    fn snapshot_schema_contains_the_record_entries() {
        let entry = json!({
            "type": "object",
            "properties": {"Content_of_DID": {"anyOf": [
                {"type": "object", "properties": {"Odometer": {"type": "integer"}}},
                {"type": "object", "properties": {"Time": {"type": "integer"}}}
            ]}}
        });
        let response = json!({
            "type": "object",
            "properties": {
                "DTCAndStatusRecord": status(),
                "DTCSnapshotRecords": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "DTCSnapshotRecordNumber": record_number(),
                        "DTCSnapshotRecordNumberOfIdentifiers": {"type": "integer"},
                        "DTCSnapshotRecord": {"type": "array", "items": entry}
                    }
                }}
            }
        });
        let schema = snapshot_schema(&response).expect("Snapshot schema");
        assert_eq!(
            schema.pointer("/properties/DTCSnapshotRecord/items"),
            Some(&entry)
        );
    }

    #[test]
    fn extended_data_record_schema_is_the_record_data() {
        let data = json!({"anyOf": [
            {"type": "object", "properties": {"Frequency_Counter": {"type": "integer"}}}
        ]});
        let response = json!({
            "type": "object",
            "properties": {
                "ConfirmedDTC": {"type": "string"},
                "ListOfExtendedDataRecords": {"type": "array", "items": {
                    "type": "object",
                    "properties": {"Record_Numbers": record_number(), "DTCExtendedDataRecord": data}
                }}
            }
        });
        assert_eq!(extended_data_record_schema(&response), Some(data));
    }

    #[test]
    fn identical_schemas_are_combined_once() {
        let a = json!({"type": "integer"});
        let b = json!({"type": "string"});
        assert_eq!(any_of(vec![a.clone(), a.clone()]), Some(a.clone()));
        assert_eq!(
            any_of(vec![a.clone(), b.clone()]),
            Some(json!({"anyOf": [a, b]}))
        );
        assert_eq!(any_of(Vec::new()), None);
    }

    #[test]
    fn responses_without_records_have_no_schema() {
        let response = json!({"type": "object", "properties": {"DTCAndStatusRecord": status()}});
        assert_eq!(snapshot_schema(&response), None);
        assert_eq!(extended_data_record_schema(&response), None);
    }
}
