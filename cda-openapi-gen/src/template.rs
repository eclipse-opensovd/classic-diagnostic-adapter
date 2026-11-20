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

//! [[ dimpl~openapi-gen-template-instantiation, Instantiation of per-resource route templates ]]

use aide::openapi::{Operation, Parameter, PathItem, ReferenceOr};
use indexmap::IndexMap;

/// Instantiates all `templates` below `prefix` (e.g. `/data/{service}`) for the
/// resource `id`, except the ones starting with one of the `skip` prefixes.
///
/// The placeholder is replaced, its path parameter removed and operation ids are
/// made unique by appending the id. Returns the paths relative to the ECU base path.
pub(crate) fn instantiate(
    templates: &IndexMap<String, PathItem>,
    prefix: &str,
    placeholder: &str,
    id: &str,
    skip: &[&str],
) -> IndexMap<String, PathItem> {
    let pattern = format!("{{{placeholder}}}");
    templates
        .iter()
        .filter(|(path, _)| path.starts_with(prefix) && !skip.iter().any(|s| path.starts_with(s)))
        .map(|(path, item)| {
            let mut item = item.clone();
            remove_path_param(&mut item.parameters, placeholder);
            for op in operations_mut(&mut item) {
                remove_path_param(&mut op.parameters, placeholder);
                if let Some(op_id) = op.operation_id.as_mut() {
                    op_id.push('_');
                    op_id.push_str(id);
                }
            }
            (path.replacen(&pattern, id, 1), item)
        })
        .collect()
}

/// All operations of a path item.
pub(crate) fn operations_mut(item: &mut PathItem) -> impl Iterator<Item = &mut Operation> {
    [
        item.get.as_mut(),
        item.put.as_mut(),
        item.post.as_mut(),
        item.delete.as_mut(),
        item.options.as_mut(),
        item.head.as_mut(),
        item.patch.as_mut(),
        item.trace.as_mut(),
    ]
    .into_iter()
    .flatten()
}

fn remove_path_param(params: &mut Vec<ReferenceOr<Parameter>>, name: &str) {
    params.retain(|p| {
        !matches!(p, ReferenceOr::Item(param @ Parameter::Path { .. })
            if param.parameter_data_ref().name == name)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str) -> ReferenceOr<Parameter> {
        ReferenceOr::Item(
            serde_json::from_value(serde_json::json!({
                "in": "path",
                "name": name,
                "required": true,
                "schema": {"type": "string"}
            }))
            .expect("Valid parameter"),
        )
    }

    fn template() -> IndexMap<String, PathItem> {
        let op = Operation {
            operation_id: Some("job_get".to_owned()),
            parameters: vec![param("job_name"), param("other")],
            ..Default::default()
        };
        let mut templates = IndexMap::new();
        templates.insert(
            "/x-single-ecu-jobs/{job_name}".to_owned(),
            PathItem {
                get: Some(op),
                ..Default::default()
            },
        );
        templates.insert(
            "/x-single-ecu-jobs/{job_name}/skipped".to_owned(),
            PathItem::default(),
        );
        templates.insert("/data/{service}".to_owned(), PathItem::default());
        templates
    }

    /// [[ test~openapi-gen-template-instantiation, Templates are instantiated per resource, test ]]
    #[test]
    fn instantiates_matching_templates() {
        let paths = instantiate(
            &template(),
            "/x-single-ecu-jobs/{job_name}",
            "job_name",
            "myjob",
            &["/x-single-ecu-jobs/{job_name}/skipped"],
        );
        assert_eq!(
            paths.keys().collect::<Vec<_>>(),
            vec!["/x-single-ecu-jobs/myjob"]
        );
        let op = paths
            .get("/x-single-ecu-jobs/myjob")
            .and_then(|i| i.get.as_ref())
            .expect("get operation");
        assert_eq!(op.operation_id.as_deref(), Some("job_get_myjob"));
        let names: Vec<_> = op
            .parameters
            .iter()
            .filter_map(|p| match p {
                ReferenceOr::Item(p) => Some(p.parameter_data_ref().name.as_str()),
                ReferenceOr::Reference { .. } => None,
            })
            .collect();
        assert_eq!(names, vec!["other"]);
    }
}
