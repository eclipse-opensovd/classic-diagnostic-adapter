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
    response::{IntoResponse, Response},
};
use axum_extra::extract::{Host, WithRejection};
use cda_interfaces::{
    UdsEcu,
    diagservices::{
        DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType, UdsPayloadData,
    },
};
use hashbrown::HashMap;

use crate::sovd::{
    error::{ApiError, ErrorWrapper, api_error_from_diag_response},
    resource_response,
};

const FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS: &str = "flash_download_upload";

async fn sovd_to_func_class_service_exec<T: UdsEcu + Clone>(
    uds: &T,
    func_class: &str,
    ecu_name: &str,
    service_id: u8,
    parameters: HashMap<String, serde_json::Value>,
    include_schema: bool,
) -> Result<DiagServiceJsonResponse, Response> {
    let params = UdsPayloadData::ParameterMap(parameters);
    let response = match uds
        .ecu_exec_service_from_function_class(ecu_name, func_class, service_id, params)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return Err(ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response());
        }
    };

    if let DiagServiceResponseType::Negative = response.response_type() {
        return Err(api_error_from_diag_response(response, include_schema).into_response());
    }

    let mapped_data = match response.into_json() {
        Ok(v) => v,
        Err(e) => {
            return Err(ErrorWrapper {
                error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                include_schema,
            }
            .into_response());
        }
    };
    Ok(mapped_data)
}

pub(crate) async fn get(
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    UseApi(Host(host), _): UseApi<Host, String>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    resource_response(
        &host,
        &uri,
        vec![("RequestDownload", Some("requestdownload"))],
        query.include_schema.unwrap_or(false),
    )
}

pub(crate) mod request_download {
    use aide::transform::TransformOperation;
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        SchemaProvider, UdsEcu,
        diagservices::{DiagServiceJsonResponse, DiagServiceResponse},
        file_manager::FileManager,
        service_ids,
    };
    use sovd_interfaces::components::ecu::x::sovd2uds;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            components::field_parse_errors_to_json,
            create_response_schema,
            error::{ApiError, ErrorWrapper, VendorErrorCode},
            x_sovd2uds_download::{
                FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS, sovd_to_func_class_service_exec,
            },
        },
    };

    pub(crate) async fn put<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager,
    >(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Json<sovd2uds::download::request_download::put::Request>,
    ) -> Response {
        let include_schema = query.include_schema.unwrap_or(false);
        let schema = if include_schema {
            'schema: {
                let Ok(service) = uds
                    .ecu_lookup_service_through_func_class(
                        &ecu_name,
                        FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
                        service_ids::REQUEST_DOWNLOAD,
                    )
                    .await
                else {
                    break 'schema None;
                };

                let Ok(subschema) = uds
                    .schema_for_responses(&ecu_name, &service)
                    .await
                    .map(|s| s.into_schema())
                else {
                    break 'schema None;
                };

                Some(create_response_schema!(
                    sovd2uds::download::request_download::put::Response<VendorErrorCode>,
                    "parameters",
                    subschema
                ))
            }
        } else {
            None
        };
        match sovd_to_func_class_service_exec::<T>(
            &uds,
            FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
            &ecu_name,
            service_ids::REQUEST_DOWNLOAD,
            body.parameters.clone(),
            include_schema,
        )
        .await
        {
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(mapped_data),
                errors,
            }) => (
                StatusCode::OK,
                Json(sovd2uds::download::request_download::put::Response {
                    parameters: mapped_data,
                    errors: field_parse_errors_to_json(errors, "parameters"),
                    schema,
                }),
            )
                .into_response(),
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Null,
                errors,
            }) => {
                if errors.is_empty() {
                    return StatusCode::NO_CONTENT.into_response();
                }
                (
                    StatusCode::OK,
                    Json(sovd2uds::download::request_download::put::Response {
                        parameters: serde_json::Map::new(),
                        errors: field_parse_errors_to_json(errors, "parameters"),
                        schema,
                    }),
                )
                    .into_response()
            }
            Ok(val) => ErrorWrapper {
                error: ApiError::InternalServerError(Some(format!(
                    "Expected a map, got: {}",
                    val.data
                ))),
                include_schema,
            }
            .into_response(),
            Err(response) => response,
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Execute the request download service on the component")
            .response_with::<
                200,
                Json<sovd2uds::download::request_download::put::Response<VendorErrorCode>>,
                _>(
                |res| {
                    res.example(sovd2uds::download::request_download::put::Response {
                        parameters: [
                            ("val1".to_owned(), serde_json::json!("example1")),
                            ("val2".to_owned(), serde_json::json!(123456)),
                        ]
                        .into_iter()
                        .collect(),
                        errors: vec![],
                        schema: None,
                    })
                },
            )
            .with(openapi::error_bad_request)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_gateway)
    }
}

pub(crate) mod flash_transfer {
    use std::path::PathBuf;

    use aide::transform::TransformOperation;
    use axum::{
        Json,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};
    use http::StatusCode;
    use sovd_interfaces::components::ecu::x::sovd2uds;
    use uuid::Uuid;

    use crate::{
        openapi,
        sovd::{
            IntoSovd, WebserverEcuState, create_schema,
            error::{ApiError, ErrorWrapper},
            x_sovd2uds_download::FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
        },
    };

    pub(crate) async fn post<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState {
            ecu_name,
            uds,
            flash_data,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        body: Json<sovd2uds::download::flash_transfer::post::Request>,
    ) -> Response {
        let include_schema = query.include_schema.unwrap_or(false);
        match flash_data
            .read()
            .await
            .files
            .iter()
            .find(|file| file.id == body.id)
        {
            Some(file) => {
                let id = Uuid::new_v4().to_string();
                let transfer = cda_interfaces::datatypes::DataTransferMetaData {
                    acknowledged_bytes: 0,
                    blocksize: body.blocksize,
                    next_block_sequence_counter: body.block_sequence_counter,
                    id: id.clone(),
                    file_id: body.id.clone(),
                    status: cda_interfaces::datatypes::DataTransferStatus::Queued,
                    error: None,
                };

                match uds
                    .ecu_flash_transfer_start(
                        &ecu_name,
                        FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
                        &flash_data
                            .read()
                            .await
                            .path
                            .as_ref()
                            .unwrap_or(&PathBuf::new())
                            .join(&file.origin_path)
                            .to_string_lossy(),
                        body.offset,
                        body.length,
                        transfer,
                    )
                    .await
                {
                    Ok(()) => {
                        let schema = if include_schema {
                            Some(create_schema!(
                                sovd2uds::download::flash_transfer::post::Response
                            ))
                        } else {
                            None
                        };
                        (
                            StatusCode::OK,
                            Json(sovd2uds::download::flash_transfer::post::Response { id, schema }),
                        )
                            .into_response()
                    }
                    Err(e) => ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response(),
                }
            }
            None => ErrorWrapper {
                error: ApiError::NotFound(Some(format!("File with id '{}' not found", body.id))),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        op.description("Start a flash transfer for a file")
            .input::<Json<sovd2uds::download::flash_transfer::post::Request>>()
            .response_with::<200, Json<sovd2uds::download::flash_transfer::post::Response>, _>(
                |res| {
                    res.example(sovd2uds::download::flash_transfer::post::Response {
                        id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
                        schema: None,
                    })
                },
            )
            .with(openapi::error_bad_request)
            .with(openapi::error_not_found)
    }

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let include_schema = query.include_schema.unwrap_or(false);
        let schema = if include_schema {
            Some(create_schema!(
                sovd2uds::download::flash_transfer::get::Response
            ))
        } else {
            None
        };
        match uds.ecu_flash_transfer_status(&ecu_name).await {
            Ok(data) => {
                let items = data.into_sovd();
                (
                    StatusCode::OK,
                    Json(sovd2uds::download::flash_transfer::get::Response { items, schema }),
                )
                    .into_response()
            }
            Err(e) => ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        use sovd2uds::download::flash_transfer::get::{DataTransferMetaData, DataTransferStatus};
        op.description("Get all flash transfers for the component")
            .response_with::<200, Json<sovd2uds::download::flash_transfer::get::Response>, _>(
                |res| {
                    res.example(sovd2uds::download::flash_transfer::get::Response {
                        items: vec![DataTransferMetaData {
                            acknowledged_bytes: 0,
                            blocksize: 1024,
                            next_block_sequence_counter: 1,
                            id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
                            file_id: "file-id".to_owned(),
                            status: DataTransferStatus::Queued,
                            error: None,
                            schema: None,
                        }],
                        schema: None,
                    })
                },
            )
    }

    pub(crate) mod id {
        use super::*;
        use crate::sovd::components::IdPathParam;
        pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(id): Path<IdPathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            let include_schema = query.include_schema.unwrap_or(false);
            match uds.ecu_flash_transfer_status_id(&ecu_name, &id).await {
                Ok(data) => {
                    let mut data = data.into_sovd();
                    if include_schema {
                        data.schema = Some(create_schema!(
                            sovd2uds::download::flash_transfer::get::DataTransferMetaData
                        ));
                    }
                    (StatusCode::OK, Json(data)).into_response()
                }
                Err(e) => ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response(),
            }
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            use sovd2uds::download::flash_transfer::get::{
                DataTransferMetaData, DataTransferStatus,
            };

            op.description("Get flash transfer status for a specific transfer")
                .response_with::<200, Json<DataTransferMetaData>, _>(|res| {
                    res.example(DataTransferMetaData {
                        acknowledged_bytes: 0,
                        blocksize: 1024,
                        next_block_sequence_counter: 1,
                        id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
                        file_id: "file-id".to_owned(),
                        status: DataTransferStatus::Queued,
                        error: None,
                        schema: None,
                    })
                })
                .with(openapi::error_not_found)
        }

        pub(crate) async fn delete<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(id): Path<IdPathParam>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            match uds.ecu_flash_transfer_exit(&ecu_name, &id).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(e) => ErrorWrapper {
                    error: e.into(),
                    include_schema: false,
                }
                .into_response(),
            }
        }

        pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
            op.description(
                "Remove an aborted or finished flashtransfer to allow new flashtransfers to be \
                 started.",
            )
            .response_with::<204, (), _>(|res| res)
            .with(openapi::error_not_found)
            .with(openapi::error_bad_request)
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferStatus {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferStatus;

        fn into_sovd(self) -> Self::SovdType {
            match self {
                Self::Running => Self::SovdType::Running,
                Self::Aborted => Self::SovdType::Aborted,
                Self::Finished => Self::SovdType::Finished,
                Self::Queued => Self::SovdType::Queued,
            }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferError {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferError;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType { text: self.text }
        }
    }

    impl IntoSovd for cda_interfaces::datatypes::DataTransferMetaData {
        type SovdType = sovd2uds::download::flash_transfer::get::DataTransferMetaData;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                acknowledged_bytes: self.acknowledged_bytes,
                blocksize: self.blocksize,
                next_block_sequence_counter: self.next_block_sequence_counter,
                id: self.id,
                file_id: self.file_id,
                status: self.status.into_sovd(),
                error: self
                    .error
                    .map(|e| e.into_iter().map(|e| e.into_sovd()).collect()),
                schema: None,
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::DataTransferMetaData> {
        type SovdType = Vec<sovd2uds::download::flash_transfer::get::DataTransferMetaData>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter().map(|md| md.into_sovd()).collect()
        }
    }
}

pub(crate) mod transferexit {
    use aide::transform::TransformOperation;
    use axum::{
        extract::State,
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager, service_ids,
    };
    use hashbrown::HashMap;
    use http::StatusCode;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            x_sovd2uds_download::{
                FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS, sovd_to_func_class_service_exec,
            },
        },
    };

    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match sovd_to_func_class_service_exec::<T>(
            &uds,
            FLASH_DOWNLOAD_UPLOAD_FUNC_CLASS,
            &ecu_name,
            service_ids::REQUEST_TRANSFER_EXIT,
            HashMap::new(),
            false,
        )
        .await
        {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(response) => response,
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Exit a transfer session")
            .response_with::<204, (), _>(|res| res)
            .with(openapi::error_bad_request)
            .with(openapi::error_not_found)
            .with(openapi::error_bad_gateway)
    }
}
