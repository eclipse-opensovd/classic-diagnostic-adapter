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

//! Assembles `openapi.json` from the serialized documentation of the route groups.
//!
//! Paths and schemas are copied as raw JSON, only path keys and schema names are parsed.
//! Building the document in memory instead needs many times its serialized size, well over
//! 100 MB with the routes of a few dozen ECUs.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use aide::openapi::OpenApi;
use indexmap::IndexMap;
use serde_json::value::RawValue;

use super::ApiRoutes;

/// Start of a reference to a component schema, as `serde_json` serializes it.
const SCHEMA_REF_PREFIX: &str = "\"$ref\":\"#/components/schemas/";

/// Schema names of one route group that had to be changed in the merged document.
type Renames = HashMap<String, String>;

/// Builds the document from `header` (info, servers, ...) and the route `groups`, latest
/// first: the first group serving a path wins.
pub(super) fn build<'a>(
    header: &OpenApi,
    groups: impl Iterator<Item = &'a ApiRoutes>,
) -> Result<Vec<u8>, serde_json::Error> {
    let groups: Vec<&ApiRoutes> = groups.collect();

    let mut header = match serde_json::to_value(header)? {
        serde_json::Value::Object(header) => header,
        _ => serde_json::Map::new(),
    };
    header.remove("paths");
    let mut header_components = match header.remove("components") {
        Some(serde_json::Value::Object(components)) => components,
        _ => serde_json::Map::new(),
    };

    let mut schemas: IndexMap<String, String> = IndexMap::new();
    if let Some(serde_json::Value::Object(header_schemas)) = header_components.remove("schemas") {
        for (name, schema) in header_schemas {
            schemas.insert(name, serde_json::to_string(&schema)?);
        }
    }
    let renames: Vec<Renames> = groups
        .iter()
        .map(|group| merge_schemas(group, &mut schemas))
        .collect();

    let mut out = Vec::new();
    out.push(b'{');
    for (key, value) in &header {
        serde_json::to_writer(&mut out, key)?;
        out.push(b':');
        serde_json::to_writer(&mut out, value)?;
        out.push(b',');
    }

    out.extend_from_slice(b"\"paths\":{");
    let mut claimed: HashSet<String> = HashSet::new();
    for (group, renames) in groups.iter().zip(&renames) {
        for json in &group.paths_json {
            let Ok(paths) = serde_json::from_slice::<IndexMap<String, &RawValue>>(json)
                .inspect_err(|e| tracing::error!(error = %e, "Failed to read OpenAPI paths"))
            else {
                continue;
            };
            // Keys not starting with '/' are extensions of the paths object, which the
            // merged document never contained.
            for (path, item) in paths {
                if !path.starts_with('/') || claimed.contains(&path) {
                    continue;
                }
                if !claimed.is_empty() {
                    out.push(b',');
                }
                serde_json::to_writer(&mut out, &path)?;
                out.push(b':');
                out.extend_from_slice(rewrite_refs(item.get(), renames).as_bytes());
                claimed.insert(path);
            }
        }
    }
    out.push(b'}');

    if !schemas.is_empty() || !header_components.is_empty() {
        out.extend_from_slice(b",\"components\":{");
        for (key, value) in &header_components {
            serde_json::to_writer(&mut out, key)?;
            out.push(b':');
            serde_json::to_writer(&mut out, value)?;
            out.push(b',');
        }
        out.extend_from_slice(b"\"schemas\":{");
        for (index, (name, schema)) in schemas.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            serde_json::to_writer(&mut out, name)?;
            out.push(b':');
            out.extend_from_slice(schema.as_bytes());
        }
        out.extend_from_slice(b"}}");
    }
    out.push(b'}');
    Ok(out)
}

/// Adds the schemas of `group` to `schemas` and returns the names that had to be changed.
///
/// Route groups are documented independently, so the same name can stand for different
/// types in two groups. Such a schema gets a new, unused name in this group, also when it
/// only differs by referencing a renamed schema.
fn merge_schemas(group: &ApiRoutes, schemas: &mut IndexMap<String, String>) -> Renames {
    let mut renames = Renames::new();
    let Some(json) = &group.schemas_json else {
        return renames;
    };
    let Ok(own) = serde_json::from_slice::<IndexMap<String, &RawValue>>(json)
        .inspect_err(|e| tracing::error!(error = %e, "Failed to read OpenAPI schemas"))
    else {
        return renames;
    };

    loop {
        let mut changed = false;
        for (name, schema) in &own {
            if renames.contains_key(name) {
                continue;
            }
            let schema = rewrite_refs(schema.get(), &renames);
            if schemas
                .get(name)
                .is_some_and(|existing| *existing != *schema)
            {
                let new_name = unused_name(name, schemas, &own, &renames);
                renames.insert(name.clone(), new_name);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for (name, schema) in &own {
        let name = renames.get(name).unwrap_or(name);
        if !schemas.contains_key(name) {
            schemas.insert(
                name.clone(),
                rewrite_refs(schema.get(), &renames).into_owned(),
            );
        }
    }
    renames
}

/// Returns `name` with the lowest number suffix (from 2) that no schema uses yet.
fn unused_name(
    name: &str,
    schemas: &IndexMap<String, String>,
    own: &IndexMap<String, &RawValue>,
    renames: &Renames,
) -> String {
    (2u32..=u32::MAX)
        .map(|n| format!("{name}{n}"))
        .find(|candidate| {
            !schemas.contains_key(candidate)
                && !own.contains_key(candidate)
                && !renames.values().any(|renamed| renamed == candidate)
        })
        .unwrap_or_else(|| format!("{name}_"))
}

/// Replaces the names of renamed schemas in the references of the serialized JSON `text`.
///
/// Works on the text instead of parsing it and relies on how the documentation is
/// serialized: compact `serde_json` output (no whitespace around `:`), so a reference reads
/// exactly [`SCHEMA_REF_PREFIX`] followed by the name, and the name in the reference spelled
/// exactly like the key in `#/components/schemas`, without JSON pointer (`~0`, `~1`) or
/// percent escaping. A reference in another form is left unchanged.
fn rewrite_refs<'t>(text: &'t str, renames: &Renames) -> Cow<'t, str> {
    if renames.is_empty() || !text.contains(SCHEMA_REF_PREFIX) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once(SCHEMA_REF_PREFIX) {
        out.push_str(before);
        out.push_str(SCHEMA_REF_PREFIX);
        let (name, tail) = after.split_once('"').unwrap_or((after, ""));
        out.push_str(renames.get(name).map_or(name, String::as_str));
        if after.contains('"') {
            out.push('"');
        }
        rest = tail;
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    /// A route group as `ApiRoutes::finish` stores it: serialized path parts (its own paths,
    /// then those of nested routers) and serialized schemas.
    fn group(path_parts: &[Value], schemas: Option<Value>) -> ApiRoutes {
        ApiRoutes {
            router: axum::Router::new(),
            paths_json: path_parts
                .iter()
                .map(|part| serde_json::to_vec(part).unwrap().into_boxed_slice())
                .collect(),
            schemas_json: schemas.map(|s| serde_json::to_vec(&s).unwrap().into_boxed_slice()),
        }
    }

    /// Document information as the `openapi.json` handler sets it.
    fn header() -> OpenApi {
        OpenApi {
            info: aide::openapi::Info {
                title: "CDA".to_owned(),
                version: "1.0".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn header_with_components(components: Value) -> OpenApi {
        OpenApi {
            components: Some(serde_json::from_value(components).unwrap()),
            ..header()
        }
    }

    /// Builds the document and parses it, which also checks that it is valid JSON.
    fn build_doc(header: &OpenApi, groups: &[ApiRoutes]) -> Value {
        serde_json::from_slice(&build(header, groups.iter()).unwrap()).unwrap()
    }

    /// Path keys of the document in their serialized order.
    fn path_order(header: &OpenApi, groups: &[ApiRoutes]) -> Vec<String> {
        #[derive(serde::Deserialize)]
        struct Doc {
            paths: IndexMap<String, serde::de::IgnoredAny>,
        }
        let doc: Doc = serde_json::from_slice(&build(header, groups.iter()).unwrap()).unwrap();
        doc.paths.into_keys().collect()
    }

    fn path<'d>(doc: &'d Value, path: &str) -> Option<&'d Value> {
        doc.get("paths")?.get(path)
    }

    fn schema<'d>(doc: &'d Value, name: &str) -> Option<&'d Value> {
        doc.get("components")?.get("schemas")?.get(name)
    }

    fn schema_ref(name: &str) -> Value {
        json!({"$ref": format!("#/components/schemas/{name}")})
    }

    /// A GET operation whose 200 response has the schema `schema`.
    fn get_returning(schema: &Value) -> Value {
        json!({"get": {"responses": {"200": {"description": "ok", "content": {
            "application/json": {"schema": schema}
        }}}}})
    }

    fn response_schema<'d>(doc: &'d Value, route: &str) -> Option<&'d Value> {
        path(doc, route)?.pointer("/get/responses/200/content/application~1json/schema")
    }

    #[test]
    fn build_without_groups_has_header_and_empty_paths() {
        let doc = build_doc(&header(), &[]);

        assert_eq!(
            doc.pointer("/info/title").and_then(Value::as_str),
            Some("CDA")
        );
        assert_eq!(doc.get("paths"), Some(&json!({})));
        assert!(doc.get("components").is_none());
    }

    #[test]
    fn build_ignores_paths_of_the_header() {
        let header = OpenApi {
            paths: Some(serde_json::from_value(json!({"/header": {"get": {}}})).unwrap()),
            ..header()
        };
        let doc = build_doc(&header, &[group(&[json!({"/group": {"get": {}}})], None)]);

        assert!(path(&doc, "/header").is_none());
        assert!(path(&doc, "/group").is_some());
    }

    #[test]
    fn build_copies_path_items_unchanged() {
        let item = json!({"get": {"description": "items", "parameters": [
            {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ]}});
        let doc = build_doc(&header(), &[group(&[json!({"/items/{id}": item})], None)]);

        assert_eq!(path(&doc, "/items/{id}"), Some(&item));
    }

    #[test]
    fn build_keeps_path_order_of_groups_and_parts() {
        // Raw text, `json!` would sort the keys.
        let mut first = group(&[], None);
        first.paths_json = [r#"{"/b":{},"/a":{}}"#, r#"{"/d":{}}"#]
            .map(|part| part.as_bytes().into())
            .into();
        let groups = [first, group(&[json!({"/c": {}})], None)];

        assert_eq!(path_order(&header(), &groups), ["/b", "/a", "/d", "/c"]);
    }

    /// Groups are passed latest first. A later added group overrides the paths of earlier
    /// ones, like its handlers do in the router.
    #[test]
    fn build_takes_a_path_served_by_several_groups_from_the_first() {
        let groups = [
            group(
                &[json!({"/shared": {"get": {"description": "latest"}}})],
                None,
            ),
            group(
                &[json!({
                    "/shared": {"get": {"description": "earlier"}},
                    "/only-earlier": {"get": {}}
                })],
                None,
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert_eq!(
            path(&doc, "/shared")
                .and_then(|item| item.pointer("/get/description"))
                .and_then(Value::as_str),
            Some("latest")
        );
        assert!(path(&doc, "/only-earlier").is_some());
        assert_eq!(path_order(&header(), &groups), ["/shared", "/only-earlier"]);
    }

    #[test]
    fn build_skips_extensions_of_the_paths_object() {
        let doc = build_doc(
            &header(),
            &[group(&[json!({"x-internal": true, "/a": {}})], None)],
        );

        assert_eq!(doc.get("paths"), Some(&json!({"/a": {}})));
    }

    #[test]
    fn build_skips_unreadable_parts_and_keeps_the_rest() {
        let mut broken = group(&[json!({"/a": {}}), json!({"/b": {}})], None);
        if let Some(part) = broken.paths_json.first_mut() {
            *part = b"{not json".to_vec().into_boxed_slice();
        }
        let doc = build_doc(&header(), &[broken]);

        assert_eq!(doc.get("paths"), Some(&json!({"/b": {}})));
    }

    #[test]
    fn build_keeps_header_components_next_to_the_schemas() {
        let header = header_with_components(json!({
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {"Error": {"type": "object"}}
        }));
        let doc = build_doc(
            &header,
            &[group(
                &[json!({"/a": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": {"type": "string"}})),
            )],
        );

        assert!(doc.pointer("/components/securitySchemes/bearer").is_some());
        assert_eq!(schema(&doc, "Error"), Some(&json!({"type": "object"})));
        assert_eq!(schema(&doc, "Item"), Some(&json!({"type": "string"})));
    }

    /// Most schemas (errors, common response types) are the same in every group and are
    /// only added once.
    #[test]
    fn build_shares_schemas_that_are_equal_in_several_groups() {
        let item = json!({"type": "object", "properties": {"a": {"type": "integer"}}});
        let groups = [
            group(
                &[json!({"/a": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": item})),
            ),
            group(
                &[json!({"/b": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": item})),
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert_eq!(
            doc.pointer("/components/schemas"),
            Some(&json!({"Item": item}))
        );
        assert_eq!(response_schema(&doc, "/b"), Some(&schema_ref("Item")));
    }

    /// Each group is documented with its own schema generator, so two groups can use the
    /// same name for different types. The schema of the later group in the iteration gets
    /// a numbered name, and only the references of that group are rewritten.
    #[test]
    fn build_renames_a_conflicting_schema_and_the_references_of_its_group() {
        let groups = [
            group(
                &[json!({"/a": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": {"type": "string"}})),
            ),
            group(
                &[json!({"/b": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": {"type": "integer"}})),
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert_eq!(schema(&doc, "Item"), Some(&json!({"type": "string"})));
        assert_eq!(schema(&doc, "Item2"), Some(&json!({"type": "integer"})));
        assert_eq!(response_schema(&doc, "/a"), Some(&schema_ref("Item")));
        assert_eq!(response_schema(&doc, "/b"), Some(&schema_ref("Item2")));
    }

    /// A schema that is equal in text but references a renamed schema means a different
    /// type, so it is renamed as well.
    #[test]
    fn build_renames_schemas_that_reference_a_renamed_schema() {
        let list = json!({"type": "array", "items": schema_ref("Item")});
        let groups = [
            group(
                &[json!({"/a": get_returning(&schema_ref("List"))})],
                Some(json!({"Item": {"type": "string"}, "List": list})),
            ),
            group(
                &[json!({"/b": get_returning(&schema_ref("List"))})],
                Some(json!({"Item": {"type": "integer"}, "List": list})),
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert_eq!(schema(&doc, "List"), Some(&list));
        assert_eq!(
            schema(&doc, "List2"),
            Some(&json!({"type": "array", "items": schema_ref("Item2")}))
        );
        assert_eq!(response_schema(&doc, "/b"), Some(&schema_ref("List2")));
    }

    #[test]
    fn build_renames_to_a_name_no_schema_uses_yet() {
        let groups = [
            group(
                &[json!({"/a": {}})],
                Some(json!({"Item": {"type": "string"}, "Item2": {"type": "boolean"}})),
            ),
            // `Item3` is used by this group itself.
            group(
                &[json!({"/b": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": {"type": "integer"}, "Item3": {"type": "null"}})),
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert_eq!(schema(&doc, "Item2"), Some(&json!({"type": "boolean"})));
        assert_eq!(schema(&doc, "Item3"), Some(&json!({"type": "null"})));
        assert_eq!(schema(&doc, "Item4"), Some(&json!({"type": "integer"})));
        assert_eq!(response_schema(&doc, "/b"), Some(&schema_ref("Item4")));
    }

    #[test]
    fn build_renames_group_schemas_that_conflict_with_the_header() {
        let header = header_with_components(json!({"schemas": {"Item": {"type": "string"}}}));
        let doc = build_doc(
            &header,
            &[group(
                &[json!({"/a": get_returning(&schema_ref("Item"))})],
                Some(json!({"Item": {"type": "integer"}})),
            )],
        );

        assert_eq!(schema(&doc, "Item"), Some(&json!({"type": "string"})));
        assert_eq!(response_schema(&doc, "/a"), Some(&schema_ref("Item2")));
    }

    /// The schemas of all groups are kept, also those of groups whose paths are all
    /// served by later groups.
    #[test]
    fn build_keeps_schemas_of_overridden_groups() {
        let groups = [
            group(&[json!({"/a": {}})], None),
            group(
                &[json!({"/a": get_returning(&schema_ref("Old"))})],
                Some(json!({"Old": {"type": "string"}})),
            ),
        ];
        let doc = build_doc(&header(), &groups);

        assert!(schema(&doc, "Old").is_some());
    }

    #[test]
    fn merge_schemas_without_or_with_unreadable_schemas_adds_nothing() {
        let mut schemas = IndexMap::new();
        let mut unreadable = group(&[], None);
        unreadable.schemas_json = Some(b"[1, 2".to_vec().into_boxed_slice());

        assert!(merge_schemas(&group(&[], None), &mut schemas).is_empty());
        assert!(merge_schemas(&unreadable, &mut schemas).is_empty());
        assert!(schemas.is_empty());
    }

    #[test]
    fn rewrite_refs_without_renames_borrows_the_text() {
        let text = r##"{"$ref":"#/components/schemas/Item"}"##;

        assert!(matches!(
            rewrite_refs(text, &Renames::new()),
            Cow::Borrowed(_)
        ));
    }

    /// Only the compact form `serde_json` writes is rewritten, see `rewrite_refs`.
    #[test]
    fn rewrite_refs_leaves_other_spellings_unchanged() {
        let renames = Renames::from([("Item".to_owned(), "Item2".to_owned())]);
        let text = r##"{"a":{"$ref": "#/components/schemas/Item"},"b":{"$ref":"#/components/schemas/Item"}}"##;

        assert_eq!(
            rewrite_refs(text, &renames),
            r##"{"a":{"$ref": "#/components/schemas/Item"},"b":{"$ref":"#/components/schemas/Item2"}}"##
        );
    }

    #[test]
    fn rewrite_refs_replaces_only_renamed_schemas() {
        let renames = Renames::from([("Item".to_owned(), "Item2".to_owned())]);
        let text = r##"{"a":{"$ref":"#/components/schemas/Item"},"b":{"$ref":"#/components/schemas/ItemList"},"c":"#/components/schemas/Item"}"##;
        assert_eq!(
            rewrite_refs(text, &renames),
            r##"{"a":{"$ref":"#/components/schemas/Item2"},"b":{"$ref":"#/components/schemas/ItemList"},"c":"#/components/schemas/Item"}"##
        );
    }
}
