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

//! [[ dimpl~openapi-gen-shared-schemas, Inline schemas are moved to the components ]]
//!
//! Moves the schemas defined inline in the paths into `components/schemas` and
//! replaces them by references. Identical schemas are stored once, which reduces
//! the size of documents where many services share parameter structures (e.g. a
//! data and a configuration service with the same parameters).

use aide::openapi::OpenApi;
use cda_interfaces::{HashMap, HashSet};
use serde_json::{Map, Value};

use crate::GeneratorError;

/// Schemas whose JSON is shorter are left inline, as a reference is not much
/// shorter and they are easier to read inline.
const MIN_SHARED_SCHEMA_LEN: usize = 100;

const COMPONENT_PREFIX: &str = "#/components/schemas/";

/// Keywords whose value is a single subschema.
const SUBSCHEMA_KEYWORDS: [&str; 11] = [
    "items",
    "additionalProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "propertyNames",
    "unevaluatedItems",
    "unevaluatedProperties",
    "contentSchema",
];

/// Keywords whose value is a list of subschemas.
const SUBSCHEMA_LIST_KEYWORDS: [&str; 4] = ["allOf", "anyOf", "oneOf", "prefixItems"];

/// Keywords whose value is a map of subschemas.
const SUBSCHEMA_MAP_KEYWORDS: [&str; 3] = ["properties", "patternProperties", "dependentSchemas"];

/// Moves the inline schemas of all paths into `components/schemas`.
///
/// Local `$defs` of inline schemas are moved as well, their references
/// (`#/$defs/...`) would otherwise resolve against the document root.
///
/// # Errors
/// Returns [`GeneratorError::Output`] if the document cannot be converted.
pub(crate) fn share_schemas(api: &mut OpenApi) -> Result<(), GeneratorError> {
    let to_err =
        |e: serde_json::Error| GeneratorError::Output(format!("Cannot share schemas: {e}"));
    let Some(paths) = api.paths.as_mut() else {
        return Ok(());
    };
    let components = api.components.get_or_insert_default();
    let existing = match serde_json::to_value(&components.schemas).map_err(to_err)? {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    let mut store = SchemaStore::new(existing);

    // Converted one by one, a value map would not keep the order of the paths.
    for (path, item) in &mut paths.paths {
        let mut value = serde_json::to_value(&*item).map_err(to_err)?;
        visit_path_item(&mut value, &path_hint(path), &mut store);
        *item = serde_json::from_value(value).map_err(to_err)?;
    }

    components.schemas = serde_json::from_value(Value::Object(store.schemas)).map_err(to_err)?;
    Ok(())
}

struct SchemaStore {
    schemas: Map<String, Value>,
    /// Serialized schema to its name in `schemas`.
    by_content: HashMap<String, String>,
    names: HashSet<String>,
}

impl SchemaStore {
    fn new(existing: Map<String, Value>) -> Self {
        let by_content = existing
            .iter()
            .map(|(name, schema)| (schema.to_string(), name.clone()))
            .collect();
        let names = existing.keys().cloned().collect();
        Self {
            schemas: existing,
            by_content,
            names,
        }
    }

    /// Stores the schema (or finds an identical one) and returns its name.
    fn store(&mut self, hint: &str, schema: Value) -> String {
        // serde_json maps are ordered by key, so equal schemas serialize equally.
        let content = schema.to_string();
        if let Some(name) = self.by_content.get(&content) {
            return name.clone();
        }
        let name = self.unique_name(hint);
        self.names.insert(name.clone());
        self.by_content.insert(content, name.clone());
        self.schemas.insert(name.clone(), schema);
        name
    }

    fn unique_name(&self, hint: &str) -> String {
        let base = sanitize(hint);
        if !self.names.contains(&base) {
            return base;
        }
        (2..=u32::MAX)
            .map(|i| format!("{base}_{i}"))
            .find(|n| !self.names.contains(n))
            .unwrap_or(base)
    }
}

fn reference(name: &str) -> Value {
    let mut map = Map::new();
    map.insert(
        "$ref".to_owned(),
        Value::String(format!("{COMPONENT_PREFIX}{name}")),
    );
    Value::Object(map)
}

/// Component names must match `^[a-zA-Z0-9.\-_]+$`.
fn sanitize(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "Schema".to_owned()
    } else {
        sanitized
    }
}

/// Name hint of a path, e.g. `data.MyService` for `.../components/ecu/data/MyService`.
fn path_hint(path: &str) -> String {
    let rest = path
        .split_once("/components/")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map_or(path, |(_, rest)| rest);
    let segments: Vec<_> = rest
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches(|c| c == '{' || c == '}'))
        .collect();
    if segments.is_empty() {
        "component".to_owned()
    } else {
        segments.join(".")
    }
}

fn visit_path_item(item: &mut Value, hint: &str, store: &mut SchemaStore) {
    let Some(item) = item.as_object_mut() else {
        return;
    };
    visit_parameters(item.get_mut("parameters"), hint, store);
    for (method, operation) in item.iter_mut() {
        if method == "parameters" {
            continue;
        }
        let Some(operation) = operation.as_object_mut() else {
            continue;
        };
        let hint = format!("{hint}.{method}");
        visit_parameters(operation.get_mut("parameters"), &hint, store);
        if let Some(body) = operation.get_mut("requestBody") {
            visit_content(body, &format!("{hint}.request"), store);
        }
        if let Some(responses) = operation
            .get_mut("responses")
            .and_then(Value::as_object_mut)
        {
            for (status, response) in responses.iter_mut() {
                let hint = format!("{hint}.{status}");
                visit_content(response, &hint, store);
                if let Some(headers) = response.get_mut("headers").and_then(Value::as_object_mut) {
                    for (name, header) in headers.iter_mut() {
                        visit_schema_holder(header, &format!("{hint}.{name}"), store);
                    }
                }
            }
        }
    }
}

fn visit_parameters(params: Option<&mut Value>, hint: &str, store: &mut SchemaStore) {
    for param in params.and_then(Value::as_array_mut).into_iter().flatten() {
        let name = param
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("param")
            .to_owned();
        visit_schema_holder(param, &format!("{hint}.{name}"), store);
    }
}

/// Request body or response with a `content` map.
fn visit_content(holder: &mut Value, hint: &str, store: &mut SchemaStore) {
    let Some(content) = holder.get_mut("content").and_then(Value::as_object_mut) else {
        return;
    };
    let single = content.len() == 1;
    for (media_type, media) in content.iter_mut() {
        let hint = if single {
            hint.to_owned()
        } else {
            format!("{hint}.{media_type}")
        };
        visit_schema_holder(media, &hint, store);
    }
}

/// Object with a `schema` property (media type, parameter, header).
fn visit_schema_holder(holder: &mut Value, hint: &str, store: &mut SchemaStore) {
    if let Some(schema) = holder.get_mut("schema") {
        lift_defs(schema, hint, store);
        share(schema, hint, store);
    }
}

/// Moves the `$defs` of a schema (and its subschemas) into the store and
/// rewrites the references to them.
fn lift_defs(schema: &mut Value, hint: &str, store: &mut SchemaStore) {
    let Some(defs) = schema
        .as_object_mut()
        .and_then(|s| s.remove("$defs"))
        .and_then(|d| match d {
            Value::Object(map) => Some(map),
            _ => None,
        })
    else {
        for_each_subschema(schema, hint, &mut |sub, sub_hint| {
            lift_defs(sub, &sub_hint, store);
        });
        return;
    };

    // Definitions may reference each other, so all names are known before storing.
    let mut renamed = HashMap::default();
    let mut pending = Vec::with_capacity(defs.len());
    for (name, def) in defs {
        let target = store.unique_name(&name);
        store.names.insert(target.clone());
        renamed.insert(format!("#/$defs/{name}"), target.clone());
        pending.push((target, def));
    }
    rewrite_refs(schema, &renamed);
    for (target, mut def) in pending {
        rewrite_refs(&mut def, &renamed);
        lift_defs(&mut def, &target, store);
        store.names.remove(&target);
        let stored = store.store(&target, def);
        if stored != target {
            // An identical schema already exists; point to it instead.
            let mut alias = HashMap::default();
            alias.insert(format!("{COMPONENT_PREFIX}{target}"), stored);
            rewrite_refs(schema, &alias);
            for value in store.schemas.values_mut() {
                rewrite_refs(value, &alias);
            }
        }
    }
    for_each_subschema(schema, hint, &mut |sub, sub_hint| {
        lift_defs(sub, &sub_hint, store);
    });
}

fn rewrite_refs(value: &mut Value, renamed: &HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                match v {
                    Value::String(target) if key == "$ref" => {
                        if let Some(name) = renamed.get(target.as_str()) {
                            *target = format!("{COMPONENT_PREFIX}{name}");
                        }
                    }
                    _ => rewrite_refs(v, renamed),
                }
            }
        }
        Value::Array(list) => list.iter_mut().for_each(|v| rewrite_refs(v, renamed)),
        _ => {}
    }
}

/// Shares the subschemas first, so equal parents become equal after their
/// children were replaced, then the schema itself.
fn share(schema: &mut Value, hint: &str, store: &mut SchemaStore) {
    for_each_subschema(schema, hint, &mut |sub, sub_hint| {
        share(sub, &sub_hint, store);
    });
    let shareable = schema
        .as_object()
        .is_some_and(|s| !s.contains_key("$ref") && !s.contains_key("$defs"))
        && schema.to_string().len() >= MIN_SHARED_SCHEMA_LEN;
    if shareable {
        let name = store.store(hint, std::mem::take(schema));
        *schema = reference(&name);
    }
}

fn for_each_subschema(schema: &mut Value, hint: &str, f: &mut dyn FnMut(&mut Value, String)) {
    let Some(schema) = schema.as_object_mut() else {
        return;
    };
    for (keyword, value) in schema.iter_mut() {
        let keyword = keyword.as_str();
        if SUBSCHEMA_KEYWORDS.contains(&keyword) {
            f(value, format!("{hint}.{keyword}"));
        } else if SUBSCHEMA_LIST_KEYWORDS.contains(&keyword) {
            for (i, sub) in value.as_array_mut().into_iter().flatten().enumerate() {
                f(sub, format!("{hint}.{keyword}{i}"));
            }
        } else if SUBSCHEMA_MAP_KEYWORDS.contains(&keyword) {
            for (name, sub) in value.as_object_mut().into_iter().flatten() {
                f(sub, format!("{hint}.{name}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn data_schema(enum_values: &[&str]) -> Value {
        json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "Mode": {"type": "string", "enum": enum_values}
                    }
                },
                "id": {"type": "string", "description": "Identifier of the data service."}
            }
        })
    }

    fn doc(paths: Vec<(&str, Value)>) -> OpenApi {
        let paths = aide::openapi::Paths {
            paths: paths
                .into_iter()
                .map(|(path, item)| {
                    let item = serde_json::from_value(item).expect("Valid path item");
                    (path.to_owned(), item)
                })
                .collect(),
            ..Default::default()
        };
        OpenApi {
            paths: Some(paths),
            components: Some(
                serde_json::from_value(json!({"schemas": {"Existing": {
                    "type": "object",
                    "properties": {"error_code": {"type": "string"}}
                }}}))
                .expect("Valid components"),
            ),
            ..OpenApi::default()
        }
    }

    fn get_200(schema: &Value) -> Value {
        json!({"get": {"responses": {"200": {"description": "",
            "content": {"application/json": {"schema": schema}}}}}})
    }

    fn at<'a>(value: &'a Value, pointer: &str) -> &'a Value {
        value.pointer(pointer).unwrap_or(&Value::Null)
    }

    fn response_schema<'a>(value: &'a Value, path: &str) -> &'a Value {
        at(
            value,
            &format!(
                "/paths/{}/get/responses/200/content/application~1json/schema",
                path.replace('/', "~1")
            ),
        )
    }

    #[test]
    fn identical_schemas_are_stored_once() {
        let mut api = doc(vec![
            (
                "/vehicle/v15/components/ecu/data/A",
                get_200(&data_schema(&["Running in Application", "Running in Boot"])),
            ),
            (
                "/vehicle/v15/components/ecu/configurations/A",
                get_200(&data_schema(&["Running in Application", "Running in Boot"])),
            ),
            (
                "/vehicle/v15/components/ecu/data/B",
                get_200(&data_schema(&["Default Session", "Extended Session"])),
            ),
        ]);
        share_schemas(&mut api).expect("Sharing must succeed");
        let value = serde_json::to_value(&api).expect("Serializable");

        let schema_of = |path: &str| response_schema(&value, path).clone();
        let a = schema_of("/vehicle/v15/components/ecu/data/A");
        assert_eq!(a, json!({"$ref": "#/components/schemas/data.A.get.200"}));
        assert_eq!(schema_of("/vehicle/v15/components/ecu/configurations/A"), a);
        assert_eq!(
            schema_of("/vehicle/v15/components/ecu/data/B"),
            json!({"$ref": "#/components/schemas/data.B.get.200"})
        );

        assert!(value.pointer("/components/schemas/Existing").is_some());
        // Nested schemas are shared as well and referenced by their parent.
        assert_eq!(
            at(&value, "/components/schemas/data.A.get.200/properties/data"),
            &json!({"$ref": "#/components/schemas/data.A.get.200.data"})
        );
        // Small schemas stay inline.
        assert_eq!(
            at(
                &value,
                "/components/schemas/data.A.get.200/properties/id/type"
            ),
            "string"
        );
    }

    #[test]
    fn local_defs_are_moved_to_the_components() {
        let schema = json!({
            "type": "object",
            "properties": {"error": {"$ref": "#/$defs/Err"}},
            "$defs": {"Err": {"type": "object", "properties": {"code": {"type": "string"}}}}
        });
        let mut api = doc(vec![(
            "/vehicle/v15/components/ecu/operations/X/executions",
            get_200(&schema),
        )]);
        share_schemas(&mut api).expect("Sharing must succeed");
        let value = serde_json::to_value(&api).expect("Serializable");

        let text = value.to_string();
        assert!(!text.contains("$defs"), "{text}");
        assert_eq!(
            at(&value, "/components/schemas/Err/properties/code/type"),
            "string"
        );
        let op_schema = response_schema(
            &value,
            "/vehicle/v15/components/ecu/operations/X/executions",
        );
        assert_eq!(
            at(op_schema, "/properties/error"),
            &json!({"$ref": "#/components/schemas/Err"})
        );
    }

    #[test]
    fn names_are_sanitized_and_unique() {
        let store = SchemaStore::new(Map::from_iter([("a_b".to_owned(), json!({}))]));
        assert_eq!(store.unique_name("a b"), "a_b_2");
        assert_eq!(path_hint("/vehicle/v15/components/ecu/x/{id}"), "x.id");
    }
}
