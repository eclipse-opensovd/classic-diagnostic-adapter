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
//! Paths are copied as raw JSON, only path keys are parsed. Building the document in memory
//! instead needs many times its serialized size, well over 100 MB with the routes of a few
//! dozen ECUs.

use std::collections::HashSet;

use aide::openapi::OpenApi;
use indexmap::IndexMap;
use serde_json::value::RawValue;

use super::RouteGroup;

/// Builds the document from `header` (info, servers, ...) and the route `groups`, latest
/// first: the first group serving a path wins.
pub(super) fn build<'a>(
    header: &OpenApi,
    groups: impl Iterator<Item = &'a RouteGroup>,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut header = match serde_json::to_value(header)? {
        serde_json::Value::Object(header) => header,
        _ => serde_json::Map::new(),
    };
    header.remove("paths");

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
    for group in groups {
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
                out.extend_from_slice(item.get().as_bytes());
                claimed.insert(path);
            }
        }
    }
    out.extend_from_slice(b"}}");
    Ok(out)
}
