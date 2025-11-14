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

use aide::UseApi;
use axum::{
    extract::{OriginalUri, Query},
    response::Response,
};
use axum_extra::extract::{Host, WithRejection};

use crate::sovd::{IntoSovd, error::ApiError, resource_response};

pub(crate) async fn get(
    UseApi(Host(host), _): UseApi<Host, String>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    OriginalUri(uri): OriginalUri,
) -> Response {
    resource_response(&host, &uri, vec![("sovd2uds", None)], query.include_schema)
}

pub(crate) mod sovd2uds {
    use super::{
        ApiError, Host, OriginalUri, Query, Response, UseApi, WithRejection, resource_response,
    };

    pub(crate) async fn get(
        UseApi(Host(host), _): UseApi<Host, String>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        OriginalUri(uri): OriginalUri,
    ) -> Response {
        resource_response(&host, &uri, vec![("bulk-data", None)], query.include_schema)
    }

    pub(crate) mod bulk_data {
        use super::{
            ApiError, Host, OriginalUri, Query, Response, UseApi, WithRejection, resource_response,
        };

        pub(crate) async fn get(
            UseApi(Host(host), _): UseApi<Host, String>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
            OriginalUri(uri): OriginalUri,
        ) -> Response {
            resource_response(
                &host,
                &uri,
                vec![("flashfiles", None)],
                query.include_schema,
            )
        }

        pub(crate) mod flash_files {
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
                // Keeping the regex as a static Lazy variable to avoid recompilation
                // the expression is checked by clippy:
                // https://rust-lang.github.io/rust-clippy/master/#invalid_regex
                #[allow(clippy::unwrap_used)]
                static RE: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9_]").unwrap());
                // replace all non-alphanumeric characters, except underscore, with underscores
                RE.replace_all(file_name, "_").to_string()
            }

            async fn process_directory(
                dir: PathBuf,
            ) -> Result<Vec<sovd_interfaces::sovd2uds::File>, ApiError> {
                fn process(
                    dir: &PathBuf,
                    relative_sub_dir: Option<&PathBuf>,
                ) -> Vec<sovd_interfaces::sovd2uds::File> {
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
                                Some(vec![sovd_interfaces::sovd2uds::File {
                                    hash: None,
                                    hash_algorithm: Some(
                                        sovd_interfaces::sovd2uds::HashAlgorithm::None,
                                    ),
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
                            files: vec![sovd_interfaces::sovd2uds::File {
                                id: "example_file".to_string(),
                                mimetype: "application/octet-stream".to_string(),
                                size: 1234,
                                hash: None,
                                hash_algorithm: Some(
                                    sovd_interfaces::sovd2uds::HashAlgorithm::None,
                                ),
                                origin_path: "example/path/to/file.bin".to_string(),
                            }],
                            schema: None,
                        })
                    })
            }
        }
    }

    pub(crate) mod data {
        pub(crate) mod networkstructure {
            use std::vec;

            use aide::transform::TransformOperation;
            use axum::{
                Json,
                extract::{Query, State},
                response::{IntoResponse as _, Response},
            };
            use axum_extra::extract::WithRejection;
            use cda_interfaces::UdsEcu;
            use http::StatusCode;

            use crate::sovd::{IntoSovd, create_schema, error::ApiError};

            pub(crate) async fn get<T: UdsEcu>(
                WithRejection(Query(query), _): WithRejection<
                    Query<sovd_interfaces::IncludeSchemaQuery>,
                    ApiError,
                >,
                State(gateway): State<T>,
            ) -> Response {
                let networkstructure_data = gateway.get_network_structure().await.into_sovd();

                let schema = if query.include_schema {
                    Some(create_schema!(
                        sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response
                    ))
                } else {
                    None
                };

                (
                    StatusCode::OK,
                    Json(
                        sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response {
                            id: "networkstructure".to_owned(),
                            data: vec![networkstructure_data],
                            schema,
                        },
                    ),
                )
                    .into_response()
            }

            pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
                use sovd_interfaces::apps::sovd2uds::data::network_structure::{
                    Gateway, NetworkStructure, get::Response,
                };

                op.description("Get the network structure of the Vehicle")
                    .response_with::<200, Json<Response>, _>(|res| {
                        res.description("Successful response").example(Response {
                            id: "networkstructure".to_owned(),
                            data: vec![NetworkStructure {
                                functional_groups: vec![],
                                gateways: vec![Gateway {
                                    name: "Gateway1".to_owned(),
                                    network_address: "1.2.3.4".to_owned(),
                                    logical_address: "0x1234".to_owned(),
                                    ecus: vec![],
                                }],
                            }],
                            schema: None,
                        })
                    })
            }
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::NetworkStructure {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::NetworkStructure;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            functional_groups: self
                .functional_groups
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
            gateways: self
                .gateways
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::Gateway {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::Gateway;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            name: self.name,
            network_address: self.network_address,
            logical_address: self.logical_address,
            ecus: self
                .ecus
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::FunctionalGroup {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::FunctionalGroup;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            qualifier: self.qualifier,
            ecus: self
                .ecus
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::Ecu {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::Ecu;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            qualifier: self.qualifier,
            variant: self.variant,
            state: self.state,
            logical_address: self.logical_address,
            logical_link: self.logical_link,
        }
    }
}
