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
    use super::*;

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
