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

use std::{sync::Arc, time::Duration};

use axum::{
    Json,
    http::{StatusCode, header::LOCATION},
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    DynamicPlugin,
    runtime_update_api::{RuntimeFilesUpdatePlugin, RuntimeUpdateError},
};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::VendorErrorCode;

/// State shared by every runtime-update route.
///
/// Carries no lock provider: authorization is the update plugin's decision, and
/// this layer only transports the request and renders the verdict as HTTP. See
/// [`require_mutation_allowed`].
pub struct RuntimeUpdateRouteState<P> {
    pub plugin: Arc<P>,
    pub retry_after: Duration,
}

impl<P> Clone for RuntimeUpdateRouteState<P> {
    fn clone(&self) -> Self {
        Self {
            plugin: Arc::clone(&self.plugin),
            retry_after: self.retry_after,
        }
    }
}

pub(crate) struct DbUpdateErrorResponse {
    error: RuntimeUpdateError,
    retry_after: Duration,
}

impl DbUpdateErrorResponse {
    pub(crate) fn new(error: RuntimeUpdateError, retry_after: Duration) -> Self {
        Self { error, retry_after }
    }
}
impl IntoResponse for DbUpdateErrorResponse {
    fn into_response(self) -> Response {
        // Helper function to construct the API error response
        let build_api_error_response =
            |status_code: StatusCode,
             error_code: ErrorCode,
             vendor_code: Option<VendorErrorCode>,
             retry_after: Option<Duration>| {
                let resp = (
                    status_code,
                    Json(ApiErrorResponse {
                        message: self.error.to_string(),
                        error_code,
                        vendor_code,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();

                crate::sovd::with_retry_after(resp, retry_after)
            };

        match &self.error {
            RuntimeUpdateError::OperationsInProgress(_) | RuntimeUpdateError::LockConflict(_) => {
                build_api_error_response(
                    StatusCode::CONFLICT,
                    ErrorCode::PreconditionsNotFulfilled,
                    None,
                    None,
                )
            }
            RuntimeUpdateError::ExecutionConflict => build_api_error_response(
                StatusCode::CONFLICT,
                ErrorCode::UpdateProcessInProgress,
                None,
                None,
            ),
            RuntimeUpdateError::TransactionBusy => build_api_error_response(
                StatusCode::CONFLICT,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::StorageTransactionBusy),
                Some(self.retry_after),
            ),
            RuntimeUpdateError::NoPendingUpdate
            | RuntimeUpdateError::NoBackup
            | RuntimeUpdateError::FileNotFound(_) => build_api_error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::NotFound),
                None,
            ),
            RuntimeUpdateError::InvalidMddFile(_)
            | RuntimeUpdateError::InvalidFileType(_)
            | RuntimeUpdateError::ValidationFailed(_) => build_api_error_response(
                StatusCode::BAD_REQUEST,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::InvalidData),
                None,
            ),
            RuntimeUpdateError::StorageError(_)
            | RuntimeUpdateError::ReloadFailed(_)
            | RuntimeUpdateError::CommunicationFailure(_)
            | RuntimeUpdateError::ReplacementFailure(_) => build_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::SovdServerFailure,
                None,
                None,
            ),
            RuntimeUpdateError::NoLock(_) => build_api_error_response(
                StatusCode::FORBIDDEN,
                ErrorCode::InsufficientAccessRights,
                None,
                None,
            ),
            RuntimeUpdateError::SevereError(_) => build_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::SevereError),
                None,
            ),
            RuntimeUpdateError::FatalError(_) => build_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::FatalError),
                None,
            ),
        }
    }
}

fn bulk_data_list_response(
    mut list: sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataList,
    include_schema: bool,
) -> Response {
    if include_schema {
        list.schema = Some(crate::sovd::create_schema!(
            sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataList
        ));
    }
    (StatusCode::OK, Json(list)).into_response()
}

fn bulk_data_created_response(
    host: &str,
    result: sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataCreatedList,
) -> Response {
    let Some(first) = result.items.first() else {
        return DbUpdateErrorResponse::new(
            RuntimeUpdateError::StorageError(cda_interfaces::storage_api::StorageError::Other(
                "upload completed without creating bulk-data".to_owned(),
            )),
            Duration::ZERO,
        )
        .into_response();
    };
    let location = format!(
        "http://{host}/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{}",
        first.id
    );
    (StatusCode::CREATED, [(LOCATION, location)], Json(result)).into_response()
}

/// Asks the update plugin whether this caller may mutate the staging area.
///
/// The security plugin is the authority for that decision; this layer only
/// transports the request and renders the plugin's verdict as HTTP. It
/// deliberately does not inspect claims or lock ownership itself, because a
/// replacement security policy may apply checks that such a shortcut would skip.
///
/// Called before reading a request body so an unauthorized upload is rejected
/// without buffering it. The mutating calls re-check.
pub(crate) async fn require_mutation_allowed(
    plugin: &impl RuntimeFilesUpdatePlugin,
    security: &DynamicPlugin,
    retry_after: Duration,
) -> Result<(), Box<Response>> {
    plugin
        .authorize_mutation(security)
        .await
        .map_err(|error| Box::new(DbUpdateErrorResponse::new(error, retry_after).into_response()))
}

pub(crate) mod current {
    use axum::{
        extract::{Query, State},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin;
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state
            .plugin
            .list_current(query.list_options())
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |files| {
                    super::bulk_data_list_response(
                        sovd_interfaces::runtime_files::bulk_data_list(files),
                        query.include_schema,
                    )
                },
            )
    }
}

pub(crate) mod nextupdate {
    use aide::UseApi;
    use axum::{
        Json, RequestExt,
        extract::{FromRequest, Query, Request, State},
        http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::runtime_update_api::{
        RuntimeFilesUpdatePlugin, RuntimeUpdateError, UploadFile,
    };
    use cda_plugin_security::Secured;
    use opensovd_axum_extra::ExtractHost;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_mutation_allowed};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state
            .plugin
            .list_nextupdate(query.list_options())
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |files| {
                    super::bulk_data_list_response(
                        sovd_interfaces::runtime_files::bulk_data_list(files),
                        query.include_schema,
                    )
                },
            )
    }

    /// Parses the `filename` parameter out of a `Content-Disposition` header value.
    ///
    /// Supports both the quoted form (`filename="foo.mdd"`) and the unquoted form
    /// (`filename=foo.mdd`). Returns `None` if the header is missing, or if no
    /// non-empty `filename` parameter can be found.
    fn parse_content_disposition_filename(headers: &HeaderMap) -> Option<String> {
        headers
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(|value| {
                split_content_disposition_parameters(value).find_map(|part| {
                    let part = part.trim();
                    let (key, val) = part.split_once('=')?;
                    if !key.trim().eq_ignore_ascii_case("filename") {
                        return None;
                    }
                    let val = val.trim();
                    let filename = val
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(val);
                    (!filename.is_empty()).then(|| filename.to_owned())
                })
            })
    }

    /// Splits `Content-Disposition` parameters without treating semicolons in quoted values
    /// as delimiters.
    fn split_content_disposition_parameters(value: &str) -> impl Iterator<Item = &str> {
        let mut in_quotes = false;
        let mut escaped = false;
        value.split(move |character| {
            if escaped {
                escaped = false;
            } else if in_quotes && character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_quotes = !in_quotes;
            }
            character == ';' && !in_quotes
        })
    }

    #[cfg(test)]
    mod tests {
        use axum::http::{HeaderMap, HeaderValue, header::CONTENT_DISPOSITION};

        use super::parse_content_disposition_filename;

        fn headers_with_content_disposition(value: &str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_DISPOSITION, HeaderValue::from_str(value).unwrap());
            headers
        }

        #[test]
        fn missing_header_returns_none() {
            let headers = HeaderMap::new();
            assert_eq!(parse_content_disposition_filename(&headers), None);
        }

        #[test]
        fn quoted_filename_after_disposition_type() {
            // Regression test: the `attachment` segment (with no `=`) precedes
            // `filename=...` and must not cause the whole parse to bail out early.
            let headers = headers_with_content_disposition(r#"attachment; filename="foo.mdd""#);
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("foo.mdd".to_owned())
            );
        }

        #[test]
        fn quoted_filename_may_contain_semicolons() {
            let headers =
                headers_with_content_disposition(r#"attachment; filename="database;backup.mdd""#);
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("database;backup.mdd".to_owned())
            );
        }

        #[test]
        fn unquoted_filename_after_disposition_type() {
            let headers = headers_with_content_disposition("attachment; filename=foo.mdd");
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("foo.mdd".to_owned())
            );
        }

        #[test]
        fn filename_only_no_disposition_type() {
            let headers = headers_with_content_disposition(r#"filename="foo.mdd""#);
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("foo.mdd".to_owned())
            );
        }

        #[test]
        fn filename_parameter_is_case_insensitive() {
            let headers = headers_with_content_disposition(r#"attachment; FileName="foo.mdd""#);
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("foo.mdd".to_owned())
            );
        }

        #[test]
        fn empty_filename_returns_none() {
            let headers = headers_with_content_disposition(r#"attachment; filename="""#);
            assert_eq!(parse_content_disposition_filename(&headers), None);
        }

        #[test]
        fn missing_filename_parameter_returns_none() {
            let headers = headers_with_content_disposition("attachment");
            assert_eq!(parse_content_disposition_filename(&headers), None);
        }

        #[test]
        fn ignores_other_parameters_before_filename() {
            let headers =
                headers_with_content_disposition(r#"attachment; name="field"; filename="foo.mdd""#);
            assert_eq!(
                parse_content_disposition_filename(&headers),
                Some("foo.mdd".to_owned())
            );
        }
    }

    /// Accepts either a `multipart/form-data` upload (potentially multiple files,
    /// filenames taken from each field's `filename` parameter), or a single
    /// `application/octet-stream` upload, where the filename must be provided via
    /// the `Content-Disposition` header (e.g. `attachment; filename="foo.mdd"`).
    pub(crate) async fn post<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        Secured(sec_plugin): Secured,
        request: Request,
    ) -> impl IntoResponse {
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<mime::Mime>().ok());

        match content_type.as_ref().map(|m| (m.type_(), m.subtype())) {
            Some((mime::MULTIPART, mime::FORM_DATA)) => {
                handle_multipart_upload(route_state, sec_plugin, host, request).await
            }
            Some((mime::APPLICATION, mime::OCTET_STREAM)) => {
                handle_octet_stream_upload(route_state, sec_plugin, host, request).await
            }
            _ => DbUpdateErrorResponse::new(
                RuntimeUpdateError::ValidationFailed(
                    "Unsupported Content-Type, expected multipart/form-data or \
                     application/octet-stream"
                        .to_owned(),
                ),
                route_state.retry_after,
            )
            .into_response(),
        }
    }

    async fn handle_multipart_upload<P: RuntimeFilesUpdatePlugin>(
        route_state: RuntimeUpdateRouteState<P>,
        sec_plugin: cda_plugin_security::SecurityPluginData,
        host: String,
        request: Request,
    ) -> Response {
        let mut multipart =
            match axum::extract::Multipart::from_request(request, &route_state).await {
                Ok(multipart) => multipart,
                Err(e) => {
                    return DbUpdateErrorResponse::new(
                        RuntimeUpdateError::ValidationFailed(e.to_string()),
                        route_state.retry_after,
                    )
                    .into_response();
                }
            };

        // The plugin takes care about rejecting new uploads during an active apply
        let security = sec_plugin as cda_interfaces::DynamicPlugin;
        if let Err(resp) =
            require_mutation_allowed(&*route_state.plugin, &security, route_state.retry_after).await
        {
            // The client may still be streaming the (potentially large) multipart
            // body. If we respond and close/reset the connection before the body
            // has been fully read, the client's in-flight write can fail with a
            // transport-level error (e.g. a connection reset) instead of cleanly
            // receiving this response. Drain the remaining body first so the
            // connection can be closed/reused safely.
            while let Ok(Some(_field)) = multipart.next_field().await {}
            return (*resp).into_response();
        }

        let mut files = Vec::new();
        while let Ok(Some(field)) = multipart.next_field().await {
            let Some(filename) = field.file_name().map(str::to_owned) else {
                continue;
            };
            match field.bytes().await {
                Ok(data) => files.push(UploadFile { filename, data }),
                Err(e) => {
                    return DbUpdateErrorResponse::new(
                        RuntimeUpdateError::ValidationFailed(e.to_string()),
                        route_state.retry_after,
                    )
                    .into_response();
                }
            }
        }

        route_state
            .plugin
            .upload(files, &security)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |ids| {
                    super::bulk_data_created_response(
                        &host,
                        sovd_interfaces::runtime_files::bulk_data_created(ids),
                    )
                },
            )
    }

    async fn handle_octet_stream_upload<P: RuntimeFilesUpdatePlugin>(
        route_state: RuntimeUpdateRouteState<P>,
        sec_plugin: cda_plugin_security::SecurityPluginData,
        host: String,
        request: Request,
    ) -> Response {
        let security = sec_plugin as cda_interfaces::DynamicPlugin;
        if let Err(resp) =
            require_mutation_allowed(&*route_state.plugin, &security, route_state.retry_after).await
        {
            // As with the multipart path: drain the (potentially large) body before
            // responding, so an early rejection doesn't race the client's in-flight
            // write and cause a transport-level error instead of a clean response.
            let _ = axum::body::to_bytes(request.into_limited_body(), usize::MAX).await;
            return resp.into_response();
        }

        let Some(filename) = parse_content_disposition_filename(request.headers()) else {
            // Drain the body before rejecting the request for the same reason as the
            // lock-rejection path above.
            let _ = axum::body::to_bytes(request.into_limited_body(), usize::MAX).await;
            return DbUpdateErrorResponse::new(
                RuntimeUpdateError::ValidationFailed(
                    "Missing or invalid Content-Disposition header, expected e.g. 'attachment; \
                     filename=\"foo.mdd\"'"
                        .to_owned(),
                ),
                route_state.retry_after,
            )
            .into_response();
        };

        let data = match axum::body::to_bytes(request.into_limited_body(), usize::MAX).await {
            Ok(data) => data,
            Err(e) => {
                return DbUpdateErrorResponse::new(
                    RuntimeUpdateError::ValidationFailed(e.to_string()),
                    route_state.retry_after,
                )
                .into_response();
            }
        };

        route_state
            .plugin
            .upload(vec![UploadFile { filename, data }], &security)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |ids| {
                    super::bulk_data_created_response(
                        &host,
                        sovd_interfaces::runtime_files::bulk_data_created(ids),
                    )
                },
            )
    }

    pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let security = sec_plugin as cda_interfaces::DynamicPlugin;
        if let Err(resp) =
            require_mutation_allowed(&*route_state.plugin, &security, route_state.retry_after).await
        {
            return (*resp).into_response();
        }
        route_state
            .plugin
            .delete_nextupdate(&security)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |deleted_ids| {
                    (
                        StatusCode::OK,
                        Json(
                            sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataDeleted {
                                deleted_ids,
                                errors: vec![],
                            },
                        ),
                    )
                        .into_response()
                },
            )
    }

    pub(crate) mod id {
        use axum::{
            extract::{Path, State},
            http::StatusCode,
            response::IntoResponse,
        };
        use cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin;
        use cda_plugin_security::Secured;

        use super::super::{
            DbUpdateErrorResponse, RuntimeUpdateRouteState, require_mutation_allowed,
        };

        pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin>(
            State(route_state): State<RuntimeUpdateRouteState<P>>,
            Secured(sec_plugin): Secured,
            Path(id): Path<String>,
        ) -> impl IntoResponse {
            let security = sec_plugin as cda_interfaces::DynamicPlugin;
            if let Err(resp) =
                require_mutation_allowed(&*route_state.plugin, &security, route_state.retry_after)
                    .await
            {
                return (*resp).into_response();
            }
            route_state
                .plugin
                .delete_nextupdate_by_id(&id, &security)
                .await
                .map_or_else(
                    |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                    |()| StatusCode::NO_CONTENT.into_response(),
                )
        }
    }
}

pub(crate) mod backup {
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin;
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_mutation_allowed};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state
            .plugin
            .list_backup(query.list_options())
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |files| {
                    super::bulk_data_list_response(
                        sovd_interfaces::runtime_files::bulk_data_list(files),
                        query.include_schema,
                    )
                },
            )
    }

    pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin>(
        State(route_state): State<RuntimeUpdateRouteState<P>>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let security = sec_plugin as cda_interfaces::DynamicPlugin;
        if let Err(resp) =
            require_mutation_allowed(&*route_state.plugin, &security, route_state.retry_after).await
        {
            return (*resp).into_response();
        }
        route_state
            .plugin
            .delete_backup(&security)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |deleted_ids| {
                    (
                        StatusCode::OK,
                        Json(
                            sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataDeleted {
                                deleted_ids,
                                errors: vec![],
                            },
                        ),
                    )
                        .into_response()
                },
            )
    }
}

const RUNTIMEFILES_CURRENT_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-current";
const RUNTIMEFILES_NEXTUPDATE_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate";
const RUNTIMEFILES_BACKUP_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-backup";

pub fn routes<S: cda_plugin_security::SecurityPluginLoader, P: RuntimeFilesUpdatePlugin>(
    state: RuntimeUpdateRouteState<P>,
    upload_limit: usize,
) -> axum::Router {
    axum::Router::new()
        .route(
            RUNTIMEFILES_CURRENT_ROUTE,
            axum::routing::get(current::get::<P>),
        )
        .route(
            RUNTIMEFILES_NEXTUPDATE_ROUTE,
            axum::routing::get(nextupdate::get::<P>)
                .post(nextupdate::post::<P>)
                .layer(axum::extract::DefaultBodyLimit::max(upload_limit))
                .delete(nextupdate::delete::<P>),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{id}",
            axum::routing::delete(nextupdate::id::delete::<P>),
        )
        .route(
            RUNTIMEFILES_BACKUP_ROUTE,
            axum::routing::get(backup::get::<P>).delete(backup::delete::<P>),
        )
        .layer(axum::middleware::from_fn(
            cda_plugin_security::security_plugin_middleware::<S>,
        ))
        .with_state(state)
}
