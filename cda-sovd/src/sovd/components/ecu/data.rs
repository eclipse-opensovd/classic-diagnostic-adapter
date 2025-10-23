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

use sovd_interfaces::error::ApiErrorResponse;

use super::{
    ApiError, DiagServiceResponse, ErrorWrapper, FileManager, IntoResponse, Json, Query, Response,
    State, StatusCode, TransformOperation, UdsEcu, WebserverEcuState, WithRejection,
};
use crate::sovd::{self, create_schema};

pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::components::ecu::data::get::Query>,
        ApiError,
    >,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::components::ecu::data::get::Response
        ))
    } else {
        None
    };
    match uds.get_components_data_info(&ecu_name).await {
        Ok(mut items) => {
            let sovd_component_data = sovd_interfaces::components::ecu::data::get::Response {
                items: items
                    .drain(0..)
                    .map(crate::sovd::IntoSovd::into_sovd)
                    .collect(),
                schema,
            };
            (StatusCode::OK, Json(sovd_component_data)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all ECU data.")
        .response_with::<200, Json<sovd_interfaces::components::ecu::data::get::Response>, _>(
            |res| {
                res.description("Response with all data.").example(
                    sovd_interfaces::components::ecu::data::get::Response {
                        items: vec![sovd_interfaces::components::ecu::ComponentDataInfo {
                            category: "example_category".to_string(),
                            id: "example_id".to_string(),
                            name: "example_name".to_string(),
                        }],
                        schema: None,
                    },
                )
            },
        )
        .response_with::<400, Json<ApiErrorResponse<sovd::error::VendorErrorCode>>, _>(|res| {
            res.description("Error while fetching data from ECU.")
                .example(sovd_interfaces::error::ApiErrorResponse {
                    message: "Failed to fetch ECU data".to_string(),
                    error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                    vendor_code: Some(sovd::error::VendorErrorCode::BadRequest),
                    parameters: None,
                    error_source: Some("ECU".to_string()),
                    schema: None,
                })
        })
}

pub(crate) mod diag_service {
    use aide::{
        UseApi,
        transform::{TransformOperation, TransformParameter},
    };
    use axum::{
        Json,
        body::Bytes,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        DiagComm, DiagCommType, SchemaProvider, UdsEcu, diagservices::DiagServiceResponse,
        file_manager::FileManager,
    };
    use cda_plugin_security::Secured;
    use hashbrown::HashMap;
    use http::{HeaderMap, StatusCode};

    use crate::{
        openapi,
        sovd::{
            IntoSovd, WebserverEcuState,
            components::ecu::{DiagServicePathParam, data_request},
            create_schema,
            error::{ApiError, ErrorWrapper},
        },
    };

    async fn get_sdgs_handler<T: UdsEcu + Clone>(
        service: String,
        ecu_name: &str,
        gateway: &T,
        include_schema: bool,
    ) -> Response {
        let service_ops = vec![
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Data,
                lookup_name: None,
            },
            DiagComm {
                name: service,
                type_: DiagCommType::Data,
                lookup_name: None,
            },
        ];
        let schema = if include_schema {
            Some(create_schema!(
                sovd_interfaces::components::ecu::ServicesSdgs
            ))
        } else {
            None
        };
        let mut resp = sovd_interfaces::components::ecu::ServicesSdgs {
            items: HashMap::new(),
            schema,
        };
        for service in service_ops {
            match gateway.get_sdgs(ecu_name, Some(&service)).await {
                Ok(sdgs) => {
                    if sdgs.is_empty() {
                        continue;
                    }
                    resp.items.insert(
                        format!("{}_{:?}", service.name, service.action()).to_lowercase(),
                        sovd_interfaces::components::ecu::ServiceSdgs {
                            sdgs: sdgs.into_sovd(),
                        },
                    );
                }
                Err(e) => {
                    return ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response();
                }
            }
        }
        (StatusCode::OK, Json(resp)).into_response()
    }

    pub(crate) async fn get<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Send + Sync + Clone,
        U: FileManager,
    >(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam { diag_service }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::components::ComponentQuery>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        if query.include_sdgs {
            get_sdgs_handler::<T>(diag_service, &ecu_name, &uds, include_schema).await
        } else {
            if diag_service.contains('/') {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Invalid path".to_owned()),
                    include_schema,
                }
                .into_response();
            }
            data_request::<T>(
                DiagComm {
                    name: diag_service,
                    type_: DiagCommType::Data,
                    lookup_name: None,
                },
                &ecu_name,
                &uds,
                headers,
                None,
                security_plugin,
                include_schema,
            )
            .await
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get a specific diagnostic service.")
            .parameter("x-include-sdgs", |op: TransformParameter<bool>| {
                op.description("Set to true to include sdgs.")
            })
            .with(openapi::ecu_service_response)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }

    pub(crate) async fn put<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager,
    >(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam {
            diag_service: service,
        }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::components::ecu::data::service::put::Query>,
            ApiError,
        >,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
        body: Bytes,
    ) -> Response {
        let include_schema = query.include_schema;
        if service.contains('/') {
            return ErrorWrapper {
                error: ApiError::BadRequest("Invalid path".to_owned()),
                include_schema,
            }
            .into_response();
        }
        data_request::<T>(
            DiagComm {
                name: service.clone(),
                type_: DiagCommType::Configurations,
                lookup_name: None,
            },
            &ecu_name,
            &uds,
            headers,
            Some(body),
            security_plugin,
            include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            sovd_interfaces::components::ecu::data::DataRequestPayload
        >(op)
            .description("Update data for a specific data service")
            .with(openapi::ecu_service_response)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }
}
