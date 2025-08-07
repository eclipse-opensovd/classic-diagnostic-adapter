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

pub(crate) async fn get(Host(host): Host, OriginalUri(uri): OriginalUri) -> Response {
    resource_response(&host, &uri, vec![("mdd-embedded-files", None)])
}

pub(crate) mod mdd_embedded_files {
    use axum::{
        Json,
        extract::{Path, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        UdsEcu,
        diagservices::DiagServiceResponse,
        file_manager::{ChunkMetaData, FileManager},
    };
    use http::{StatusCode, header};
    use sovd_interfaces::components::ecu::x::sovd2uds;

    use crate::sovd::{WebserverEcuState, error::ApiError};

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState {
            mdd_embedded_files, ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let items = sovd2uds::bulk_data::embedded_files::get::Response {
            items: mdd_embedded_files
                .list()
                .await
                .iter()
                .map(|(id, meta)| sovd_interfaces::sovd2uds::File {
                    hash: None,
                    hash_algorithm: None,
                    id: id.clone(),
                    mimetype: content_type_from_meta(meta),
                    size: meta.uncompressed_size,
                    origin_path: meta.name.clone(),
                })
                .collect(),
        };

        (StatusCode::OK, Json(items)).into_response()
    }

    pub(crate) mod id {
        use super::*;
        pub(crate) async fn get<
            R: DiagServiceResponse + Send + Sync,
            T: UdsEcu + Send + Sync + Clone,
            U: FileManager + Send + Sync + Clone,
        >(
            Path(id): Path<String>,
            State(WebserverEcuState {
                mdd_embedded_files, ..
            }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            match mdd_embedded_files.get(&id).await {
                Ok((meta, payload)) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, content_type_from_meta(&meta))],
                    payload,
                )
                    .into_response(),
                Err(e) => {
                    let api_error: ApiError = e.into();
                    api_error.into_response()
                }
            }
        }
    }

    fn content_type_from_meta(meta: &ChunkMetaData) -> String {
        meta.content_type
            .clone()
            .unwrap_or(mime::APPLICATION_OCTET_STREAM.essence_str().to_string())
    }
}
