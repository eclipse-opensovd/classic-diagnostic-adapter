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

use aide::{
    UseApi,
    transform::{TransformOperation, TransformParameter},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DiagComm, DiagCommType, DynamicPlugin, HashMap, HashMapExtensions, SchemaProvider, UdsEcu,
    file_manager::FileManager,
};
use cda_plugin_security::Secured;
use sovd_interfaces::components::{
    ComponentQuery,
    ecu::{ServiceSdgs, ServicesSdgs, operations::OperationCollectionItem},
};

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState, create_schema,
        error::{ApiError, ErrorWrapper},
        locks::require_ecu_access,
    },
};

/// `GET /operations/{service}/docs` - online capability description
pub(crate) mod docs_endpoint;
pub(crate) mod executions;

/// `GET /operations/{service}` - get operation details or SDGs
// [[ dimpl~sovd-api-component-operations-sdgsd, GET /operations/{service} SDG handler ]]
pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    Path(docs_endpoint::OperationNamePathParam { service }): Path<
        docs_endpoint::OperationNamePathParam,
    >,
    WithRejection(Query(query), _): WithRejection<Query<ComponentQuery>, ApiError>,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    let include_schema = query.include_schema;
    require_ecu_access!(read, security_plugin, &ecu_name, &locks, include_schema);
    if query.include_sdgs {
        return get_sdgs_handler::<T>(service, &ecu_name, &uds, include_schema).await;
    }

    // Normal response: return operation info for the named service
    let security_plugin: DynamicPlugin = security_plugin;
    let ops_info = match uds
        .get_components_operations_info(&ecu_name, &security_plugin)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    let Some(op_info) = ops_info
        .iter()
        .find(|o| o.id.eq_ignore_ascii_case(&service))
    else {
        return ApiError::NotFound(Some(format!("Operation '{service}' not found")))
            .into_response();
    };

    let schema = if include_schema {
        Some(create_schema!(OperationCollectionItem))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(sovd_interfaces::Items {
            items: vec![OperationCollectionItem {
                id: op_info.id.clone(),
                name: op_info.name.clone(),
                proximity_proof_required: false,
                asynchronous_execution: op_info.has_stop || op_info.has_request_results,
            }],
            schema,
        }),
    )
        .into_response()
}

async fn get_sdgs_handler<T: UdsEcu + Clone>(
    service: String,
    ecu_name: &str,
    gateway: &T,
    include_schema: bool,
) -> Response {
    let service_ops = vec![
        DiagComm {
            name: service.clone(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: None,
        },
        DiagComm {
            name: service.clone(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: None,
        },
        DiagComm {
            name: service,
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: None,
        },
    ];
    let schema = if include_schema {
        Some(create_schema!(ServicesSdgs))
    } else {
        None
    };
    let mut resp = ServicesSdgs {
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
                    ServiceSdgs {
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

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get a specific operation or its SDG metadata.")
        .parameter("x-sovd2uds-includesdgs", |op: TransformParameter<bool>| {
            op.description("Set to true to include sdgs.")
        })
        .response_with::<200, Json<sovd_interfaces::Items<OperationCollectionItem>>, _>(|res| {
            res.description("Operation details or SDG metadata.")
        })
        .with(openapi::error_not_found)
        .with(openapi::error_internal_server)
}
