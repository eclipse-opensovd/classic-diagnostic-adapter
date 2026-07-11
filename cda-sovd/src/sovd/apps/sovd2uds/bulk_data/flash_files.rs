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

use std::{path::PathBuf, sync::LazyLock};

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::UdsEcu;
use http::StatusCode;
use regex::Regex;

use crate::sovd::{
    WebserverState, create_schema,
    error::{ApiError, ErrorWrapper},
};

fn file_name_to_id(file_name: &str) -> String {
    #[allow(
        clippy::unwrap_used,
        reason = "Regex literal is valid; checked by clippy::invalid_regex"
    )]
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9_]").unwrap());
    RE.replace_all(file_name, "_").to_string()
}

async fn process_directory(
    dir: PathBuf,
) -> Result<Vec<sovd_interfaces::sovd2uds::BulkDataDescriptor>, ApiError> {
    fn process(
        dir: &PathBuf,
        relative_sub_dir: Option<&PathBuf>,
    ) -> Vec<sovd_interfaces::sovd2uds::BulkDataDescriptor> {
        std::fs::read_dir(dir)
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                if file_type.is_file() {
                    let metadata = entry.metadata().ok()?;
                    let file_name = relative_sub_dir.as_ref().map_or_else(
                        || entry.file_name().to_string_lossy().to_string(),
                        |rel| rel.join(entry.file_name()).to_string_lossy().to_string(),
                    );
                    Some(vec![sovd_interfaces::sovd2uds::BulkDataDescriptor {
                        hash: None,
                        hash_algorithm: None,
                        id: file_name_to_id(&file_name),
                        mimetype: mime::APPLICATION_OCTET_STREAM.essence_str().to_string(),
                        size: Some(metadata.len()),
                        origin_path: Some(file_name),
                        revision: None,
                    }])
                } else if file_type.is_dir() {
                    let path = entry.path();
                    if std::fs::read_dir(&path).is_ok() {
                        let mut new_relative_sub_dir =
                            relative_sub_dir.cloned().unwrap_or_default();
                        new_relative_sub_dir.push(entry.file_name());
                        Some(process(&path, Some(&new_relative_sub_dir)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .flatten()
            .collect()
    }

    tokio::task::spawn_blocking(move || process(&dir, None))
        .await
        .map_err(|e| {
            ApiError::InternalServerError(Some(format!("Failed to process directory: {e}")))
        })
}

pub(crate) async fn get<T: UdsEcu + Clone>(
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    State(state): State<WebserverState<T>>,
) -> Response {
    let include_schema = query.include_schema;
    let flash_files = &mut state.flash_data.as_ref().write().await;
    let files = if let Some(flash_files_path) = &flash_files.path {
        process_directory(flash_files_path.clone()).await
    } else {
        Err(ApiError::InternalServerError(Some(
            "Flash files path is not set.".to_string(),
        )))
    };

    let schema = if include_schema {
        Some(create_schema!(
            sovd_interfaces::apps::sovd2uds::bulk_data::flash_files::get::Response
        ))
    } else {
        None
    };

    match files {
        Ok(files) => {
            flash_files.files.clone_from(&files);
            let file_list =
                sovd_interfaces::apps::sovd2uds::bulk_data::flash_files::get::Response {
                    files,
                    path: flash_files.path.clone(),
                    schema,
                };
            (StatusCode::OK, Json(file_list)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: e,
            include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    use sovd_interfaces::apps::sovd2uds::bulk_data::flash_files::get::Response;
    op.description("Get the list of flash files available")
        .response_with::<200, Json<Response>, _>(|res| {
            res.description("Successful response").example(Response {
                path: Some("example/path/to/flash/files".into()),
                files: vec![sovd_interfaces::sovd2uds::BulkDataDescriptor {
                    id: "example_file".to_string(),
                    mimetype: "application/octet-stream".to_string(),
                    size: Some(1234),
                    hash: None,
                    hash_algorithm: None,
                    origin_path: Some("example/path/to/file.bin".to_string()),
                    revision: None,
                }],
                schema: None,
            })
        })
}
