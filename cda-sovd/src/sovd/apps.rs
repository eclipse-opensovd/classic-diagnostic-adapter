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

use axum::{extract::OriginalUri, response::Response};
use axum_extra::extract::Host;

use crate::sovd::resource_response;

pub(in crate::sovd) async fn get(Host(host): Host, OriginalUri(uri): OriginalUri) -> Response {
    resource_response(&host, &uri, vec![("sovd2uds", None)])
}

pub(in crate::sovd) mod sovd2uds {
    use axum::{extract::OriginalUri, response::Response};
    use axum_extra::extract::Host;

    use crate::sovd::resource_response;

    pub(in crate::sovd) async fn get(Host(host): Host, OriginalUri(uri): OriginalUri) -> Response {
        resource_response(&host, &uri, vec![("bulk-data", None)])
    }

    pub(in crate::sovd) mod bulk_data {
        use axum::{extract::OriginalUri, response::Response};
        use axum_extra::extract::Host;

        use crate::sovd::resource_response;

        pub(in crate::sovd) async fn get(
            Host(host): Host,
            OriginalUri(uri): OriginalUri,
        ) -> Response {
            resource_response(&host, &uri, vec![("flashfiles", None)])
        }

        pub(in crate::sovd) mod flash_files {
            use std::{path::PathBuf, sync::LazyLock};

            use axum::{
                Json,
                extract::State,
                response::{IntoResponse, Response},
            };
            use http::StatusCode;
            use regex::Regex;

            use crate::sovd::{
                HashAlgorithm, SovdFile, SovdFileList, WebserverState, error::ApiError,
            };

            fn file_name_to_id(file_name: &str) -> String {
                // Keeping the regex as a static Lazy variable to avoid recompilation
                // the expression is checked by clippy:
                // https://rust-lang.github.io/rust-clippy/master/#invalid_regex
                static RE: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9_]").unwrap());
                // replace all non-alphanumeric characters, except underscore, with underscores
                RE.replace_all(file_name, "_").to_string()
            }

            async fn process_directory(dir: PathBuf) -> Result<Vec<SovdFile>, ApiError> {
                fn process(dir: &PathBuf, relative_sub_dir: Option<&PathBuf>) -> Vec<SovdFile> {
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
                                Some(vec![SovdFile {
                                    hash: None,
                                    hash_algorithm: Some(HashAlgorithm::None),
                                    id: file_name_to_id(&file_name),
                                    mimetype: mime::APPLICATION_OCTET_STREAM
                                        .essence_str()
                                        .to_string(),
                                    size: metadata.len(),
                                    origin_path: file_name,
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
                        ApiError::InternalServerError(Some(format!(
                            "Failed to process directory: {e}"
                        )))
                    })
            }

            pub(in crate::sovd) async fn get(State(state): State<WebserverState>) -> Response {
                let flash_files = &mut state.flash_data.as_ref().write().await;
                let files = if let Some(flash_files_path) = &flash_files.path {
                    process_directory(flash_files_path.clone()).await
                } else {
                    Err(ApiError::InternalServerError(Some(
                        "Flash files path is not set.".to_string(),
                    )))
                };

                match files {
                    Ok(files) => {
                        flash_files.files.clone_from(&files);
                        let file_list = SovdFileList {
                            files,
                            path: flash_files.path.clone(),
                        };
                        (StatusCode::OK, Json(file_list)).into_response()
                    }
                    Err(e) => e.into_response(),
                }
            }
        }
    }
}
