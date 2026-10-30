/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
    extract::{OriginalUri, Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DynamicPlugin, HashMap, UdsEcu,
    diagservices::{
        DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType, UdsPayloadData,
    },
    file_manager::FileManager,
};
use cda_plugin_security::{Secured, SecurityPlugin};
use opensovd_axum_extra::ExtractHost;

use crate::sovd::{
    error::{ApiError, ErrorWrapper, api_error_from_diag_response},
    locks::require_ecu_access,
    resource_response,
};

/// Selects the functional class used to resolve a flash service.
///
/// Uses the class provided by the client, or `default` if none is provided.
/// An empty (or whitespace only) class provided by the client is rejected.
pub(crate) fn resolve_flash_class<'a>(
    requested: Option<&'a str>,
    default: &'a str,
) -> Result<&'a str, ApiError> {
    match requested {
        None => Ok(default),
        Some(class) if class.trim().is_empty() => Err(ApiError::BadRequest(
            "flashClass must not be empty".to_owned(),
        )),
        Some(class) => Ok(class),
    }
}

/// Resolves the functional class of a flash request body via [`resolve_flash_class`]
/// and returns the error response from the calling handler on failure.
macro_rules! flash_class_or_return {
    ($body:expr, $default:expr, $include_schema:expr) => {
        match $crate::sovd::components::ecu::x_sovd2uds_download::resolve_flash_class(
            $body.flash_class.as_deref(),
            &$default,
        ) {
            Ok(class) => class,
            Err(error) => {
                return $crate::sovd::error::ErrorWrapper {
                    error,
                    include_schema: $include_schema,
                }
                .into_response();
            }
        }
    };
}

#[allow(
    clippy::too_many_arguments,
    reason = "Combining parameters into a struct would not improve readability here"
)]
async fn sovd_to_func_class_service_exec<T: UdsEcu + Clone>(
    uds: &T,
    func_class: &str,
    ecu_name: &str,
    service_id: u8,
    parameters: HashMap<String, serde_json::Value>,
    security_plugin: Box<dyn SecurityPlugin>,
    include_schema: bool,
    binary_encoding: cda_interfaces::BinaryEncoding,
) -> Result<DiagServiceJsonResponse, Box<Response>> {
    let params = UdsPayloadData::ParameterMap(parameters, binary_encoding);
    let response = match uds
        .ecu_exec_service_from_function_class(
            ecu_name,
            func_class,
            service_id,
            &(security_plugin as DynamicPlugin),
            params,
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(
                ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response(),
            ));
        }
    };

    if let DiagServiceResponseType::Negative = response.response_type() {
        return Err(Box::new(
            api_error_from_diag_response(&response, include_schema).into_response(),
        ));
    }

    let mapped_data = match response.into_json(binary_encoding) {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(
                ErrorWrapper {
                    error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                    include_schema,
                }
                .into_response(),
            ));
        }
    };
    Ok(mapped_data)
}

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    State(crate::sovd::WebserverEcuState {
        ecu_name, locks, ..
    }): State<crate::sovd::WebserverEcuState<T, U>>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    require_ecu_access!(
        write,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    resource_response(
        &host,
        &uri,
        vec![("RequestDownload", Some("requestdownload"))],
        query.include_schema,
    )
}

pub(crate) mod request_download {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        SchemaProvider, UdsEcu, diagservices::DiagServiceJsonResponse, file_manager::FileManager,
        service_ids,
    };
    use cda_plugin_security::Secured;
    use sovd_interfaces::components::ecu::x::sovd2uds;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            binary_encoding::BinaryEncodingParam,
            create_response_schema,
            error::{ApiError, ErrorWrapper, VendorErrorCode},
            field_parse_errors_to_json,
            locks::require_ecu_access,
            x_sovd2uds_download::sovd_to_func_class_service_exec,
        },
    };

    pub(crate) async fn put<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            flash_functional_class_default,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd2uds::download::request_download::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let include_schema = query.include_schema;
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
        let func_class =
            flash_class_or_return!(body, flash_functional_class_default, include_schema);
        let schema = if include_schema {
            'schema: {
                let Ok(service) = uds
                    .ecu_lookup_service_through_func_class(
                        &ecu_name,
                        func_class,
                        service_ids::REQUEST_DOWNLOAD,
                    )
                    .await
                else {
                    break 'schema None;
                };

                let Ok(subschema) = uds
                    .schema_for_responses(&ecu_name, &service)
                    .await
                    .map(|s| s.with_binary_encoding(binary_encoding).into_schema())
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
            func_class,
            &ecu_name,
            service_ids::REQUEST_DOWNLOAD,
            body.parameters,
            security_plugin,
            include_schema,
            binary_encoding,
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
            Err(response) => *response,
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description(
            "Execute the request download service on the component. The service is resolved \
             through the functional class given in `flashClass`, or the configured default.",
        )
            .response_with::<
                200,
                Json<sovd2uds::download::request_download::put::Response<VendorErrorCode>>,
                _>(
                |res| {
                    res.example(sovd2uds::download::request_download::put::Response {
                        parameters: [
                            ("val1".to_owned(), serde_json::json!("example1")),
                            ("val2".to_owned(), serde_json::json!(123_456)),
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

    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        DynamicPlugin, FlashTransferStartParams, UdsEcu, file_manager::FileManager,
    };
    use cda_plugin_security::Secured;
    use http::StatusCode;
    use sovd_interfaces::components::ecu::x::sovd2uds;
    use uuid::Uuid;

    use crate::{
        openapi,
        sovd::{
            IntoSovd, WebserverEcuState, create_schema,
            error::{ApiError, ErrorWrapper},
            locks::require_ecu_access,
        },
    };

    pub(crate) async fn post<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            flash_data,
            flash_functional_class_default,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd2uds::download::flash_transfer::post::Request>,
            ApiError,
        >,
    ) -> Response {
        let include_schema = query.include_schema;
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
        let func_class =
            flash_class_or_return!(body, flash_functional_class_default, include_schema);
        match flash_data
            .read()
            .await
            .files
            .iter()
            .find(|file| file.id == body.id)
        {
            Some(file) => {
                let Some(origin_path) = file.origin_path.as_deref() else {
                    return ApiError::InternalServerError(Some(
                        "origin_path not set for flash file".to_string(),
                    ))
                    .into_response();
                };

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
                        func_class,
                        &(security_plugin as DynamicPlugin),
                        FlashTransferStartParams {
                            file_path: &flash_data
                                .read()
                                .await
                                .path
                                .as_ref()
                                .unwrap_or(&PathBuf::new())
                                .join(origin_path)
                                .to_string_lossy(),
                            offset: body.offset,
                            length: body.length,
                            transfer_meta_data: transfer,
                        },
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
        op.description(
            "Start a flash transfer for a file. The TransferData service is resolved through the \
             functional class given in `flashClass`, or the configured default.",
        )
        .input::<Json<sovd2uds::download::flash_transfer::post::Request>>()
        .response_with::<200, Json<sovd2uds::download::flash_transfer::post::Response>, _>(|res| {
            res.example(sovd2uds::download::flash_transfer::post::Response {
                id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
                schema: None,
            })
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_not_found)
    }

    pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
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
        use super::{
            ApiError, ErrorWrapper, FileManager, IntoResponse, IntoSovd, Json, Path, Query,
            Response, Secured, State, StatusCode, TransformOperation, UdsEcu, UseApi,
            WebserverEcuState, WithRejection, create_schema, openapi, sovd2uds,
        };
        use crate::sovd::{components::IdPathParam, locks::require_ecu_access};
        pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(id): Path<IdPathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
            State(WebserverEcuState {
                ecu_name,
                uds,
                locks,
                ..
            }): State<WebserverEcuState<T, U>>,
        ) -> Response {
            let include_schema = query.include_schema;
            require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
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

        pub(crate) async fn delete<T: UdsEcu + Clone, U: FileManager>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(id): Path<IdPathParam>,
            State(WebserverEcuState {
                ecu_name,
                uds,
                locks,
                ..
            }): State<WebserverEcuState<T, U>>,
        ) -> Response {
            require_ecu_access!(write, security_plugin, &ecu_name, &locks, false);
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
                error: self.error.map(|e| {
                    e.into_iter()
                        .map(crate::sovd::IntoSovd::into_sovd)
                        .collect()
                }),
                schema: None,
            }
        }
    }

    impl IntoSovd for Vec<cda_interfaces::datatypes::DataTransferMetaData> {
        type SovdType = Vec<sovd2uds::download::flash_transfer::get::DataTransferMetaData>;

        fn into_sovd(self) -> Self::SovdType {
            self.into_iter()
                .map(crate::sovd::IntoSovd::into_sovd)
                .collect()
        }
    }
}

pub(crate) mod transferexit {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        body::Bytes,
        extract::State,
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        HashMap, HashMapExtensions, UdsEcu, file_manager::FileManager, service_ids,
    };
    use cda_plugin_security::Secured;
    use http::StatusCode;
    use sovd_interfaces::components::ecu::x::sovd2uds::download::transfer_exit;

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState, binary_encoding::BinaryEncodingParam, error::ApiError,
            locks::require_ecu_access, x_sovd2uds_download::sovd_to_func_class_service_exec,
        },
    };

    /// Parses the optional request body. An empty (or whitespace only) body is accepted
    /// and results in the default request.
    pub(super) fn parse_body(body: &[u8]) -> Result<transfer_exit::put::Request, ApiError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(transfer_exit::put::Request::default());
        }
        serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))
    }

    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            flash_functional_class_default,
            ..
        }): State<WebserverEcuState<T, U>>,
        body: Bytes,
    ) -> Response {
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, false);
        let request = match parse_body(&body) {
            Ok(request) => request,
            Err(e) => return e.into_response(),
        };
        let func_class = flash_class_or_return!(request, flash_functional_class_default, false);
        match sovd_to_func_class_service_exec::<T>(
            &uds,
            func_class,
            &ecu_name,
            service_ids::REQUEST_TRANSFER_EXIT,
            HashMap::new(),
            security_plugin,
            false,
            binary_encoding,
        )
        .await
        {
            Ok(_) => StatusCode::NO_CONTENT.into_response(),
            Err(response) => *response,
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description(
            "Exit a transfer session. The optional body can select the functional class used to \
             resolve the RequestTransferExit service via `flashClass`; without it the configured \
             default is used.",
        )
        .input::<Json<transfer_exit::put::Request>>()
        .response_with::<204, (), _>(|res| res)
        .with(openapi::error_bad_request)
        .with(openapi::error_not_found)
        .with(openapi::error_bad_gateway)
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_flash_class;
    use crate::sovd::error::ApiError;

    #[test]
    fn resolve_flash_class_uses_default_when_absent() {
        assert!(matches!(
            resolve_flash_class(None, "flash_download_upload"),
            Ok("flash_download_upload")
        ));
    }

    #[test]
    fn resolve_flash_class_prefers_requested_class() {
        assert!(matches!(
            resolve_flash_class(Some("Bootloader"), "flash_download_upload"),
            Ok("Bootloader")
        ));
    }

    #[test]
    fn resolve_flash_class_rejects_empty_class() {
        assert!(matches!(
            resolve_flash_class(Some(""), "flash_download_upload"),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            resolve_flash_class(Some("  "), "flash_download_upload"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn transfer_exit_body_parsing() {
        assert!(super::transferexit::parse_body(b"").is_ok_and(|r| r.flash_class.is_none()));
        assert!(
            super::transferexit::parse_body(br#"{"FlashClass":"x"}"#)
                .is_ok_and(|r| r.flash_class.as_deref() == Some("x"))
        );
        assert!(matches!(
            super::transferexit::parse_body(b"{not json"),
            Err(ApiError::BadRequest(_))
        ));
    }
}
