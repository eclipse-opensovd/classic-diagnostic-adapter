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

use aide::UseApi;
use axum::extract::{Path, Query, State};
use axum_extra::extract::WithRejection;

use crate::sovd::locks::require_ecu_access;

/// `GET /operations/{service}/docs` - online capability description
pub(crate) mod docs_endpoint;
pub(crate) mod executions;

/// `GET /operations/{service}` - get operation details or SDGs
// [[ dimpl~sovd-api-component-operations-sdgsd, GET /operations/{service} SDG handler ]]
pub(crate) async fn get<
    T: cda_interfaces::UdsEcu + cda_interfaces::SchemaProvider + Clone,
    U: cda_interfaces::file_manager::FileManager,
>(
    UseApi(cda_plugin_security::Secured(security_plugin), _): UseApi<
        cda_plugin_security::Secured,
        (),
    >,
    Path(docs_endpoint::OperationNamePathParam { service }): Path<
        docs_endpoint::OperationNamePathParam,
    >,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::components::ComponentQuery>,
        crate::sovd::error::ApiError,
    >,
    State(crate::sovd::WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<crate::sovd::WebserverEcuState<T, U>>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let include_schema = query.include_schema;
    require_ecu_access!(read, security_plugin, &ecu_name, &locks, include_schema);
    if query.include_sdgs {
        return get_sdgs_handler::<T>(service, &ecu_name, &uds, include_schema).await;
    }

    // Normal response: return operation info for the named service
    let security_plugin: cda_interfaces::DynamicPlugin = security_plugin;
    let ops_info = match uds
        .get_components_operations_info(&ecu_name, &security_plugin)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            return crate::sovd::error::ErrorWrapper {
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
        return crate::sovd::error::ApiError::NotFound(Some(format!(
            "Operation '{service}' not found"
        )))
        .into_response();
    };

    let schema = if include_schema {
        Some(crate::sovd::create_schema!(
            sovd_interfaces::components::ecu::operations::OperationCollectionItem
        ))
    } else {
        None
    };

    (
        http::StatusCode::OK,
        axum::Json(sovd_interfaces::Items {
            items: vec![
                sovd_interfaces::components::ecu::operations::OperationCollectionItem {
                    id: op_info.id.clone(),
                    name: op_info.name.clone(),
                    proximity_proof_required: false,
                    asynchronous_execution: op_info.has_stop || op_info.has_request_results,
                },
            ],
            schema,
        }),
    )
        .into_response()
}

async fn get_sdgs_handler<T: cda_interfaces::UdsEcu + Clone>(
    service: String,
    ecu_name: &str,
    gateway: &T,
    include_schema: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    use cda_interfaces::{DiagComm, DiagCommType, HashMap, HashMapExtensions};

    use crate::sovd::IntoSovd;

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
        Some(crate::sovd::create_schema!(
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
                return crate::sovd::error::ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response();
            }
        }
    }
    (http::StatusCode::OK, axum::Json(resp)).into_response()
}

pub(crate) fn docs_get(
    op: aide::transform::TransformOperation,
) -> aide::transform::TransformOperation {
    use aide::transform::TransformParameter;
    op.description("Get a specific operation or its SDG metadata.")
        .parameter("x-sovd2uds-includesdgs", |op: TransformParameter<bool>| {
            op.description("Set to true to include sdgs.")
        })
        .response_with::<200, axum::Json<
            sovd_interfaces::Items<
                sovd_interfaces::components::ecu::operations::OperationCollectionItem,
            >,
        >, _>(|res| res.description("Operation details or SDG metadata."))
        .with(crate::openapi::error_not_found)
        .with(crate::openapi::error_internal_server)
}
