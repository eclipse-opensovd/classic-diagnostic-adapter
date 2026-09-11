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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{DynamicPlugin, UdsEcu};
use cda_plugin_security::Secured;
use http::StatusCode;

use super::WebserverFgState;
use crate::sovd::{
    IntoSovd, create_schema,
    error::{ApiError, ErrorWrapper},
    locks::validate_fg_read,
};

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::functions::functional_groups::data::get::Query>,
        ApiError,
    >,
    State(WebserverFgState {
        uds,
        locks,
        functional_group_name,
        ..
    }): State<WebserverFgState<T>>,
) -> Response {
    if let Err(response) = validate_fg_read(
        &security_plugin.as_auth_plugin().claims(),
        &functional_group_name,
        &uds,
        &locks,
        query.include_schema,
    )
    .await
    {
        return response.into_response();
    }
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::functions::functional_groups::data::get::Response
        ))
    } else {
        None
    };
    let result = uds
        .get_functional_group_data_info(&(security_plugin as DynamicPlugin), &functional_group_name)
        .await;
    match result {
        Ok(mut items) => {
            let data = sovd_interfaces::functions::functional_groups::data::get::Response {
                items: items.drain(0..).map(IntoSovd::into_sovd).collect(),
                schema,
            };
            (StatusCode::OK, Json(data)).into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all available data services for the functional group.")
        .response_with::<
            200,
            Json<sovd_interfaces::functions::functional_groups::data::get::Response>,
            _,
        >(|res| {
            res.description("Response with all available data services.").example(
                sovd_interfaces::functions::functional_groups::data::get::Response {
                    items: vec![sovd_interfaces::components::ecu::ComponentDataInfo {
                        category: "example_category".to_string(),
                        id: "example_id".to_string(),
                        name: "example_name".to_string(),
                    }],
                    schema: None,
                },
            )
        })
}

pub(crate) mod diag_service {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        body::Bytes,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{DiagComm, DiagCommType, HashMap, UdsEcu};
    use cda_plugin_security::Secured;

    use crate::{
        openapi,
        sovd::{
            components::{ecu::DiagServicePathParam, get_content_type_and_accept},
            error::{ApiError, ErrorWrapper, VendorErrorCode},
            functions::functional_groups::{WebserverFgState, handle_ecu_response, map_to_json},
            get_payload_data,
            locks::{validate_fg_read, validate_fg_write},
        },
    };

    enum FunctionalDataAccess {
        Read,
        Write,
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam {
            service: diag_service,
        }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::functions::functional_groups::data::service::Query>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            locks,
            functional_group_name,
            ..
        }): State<WebserverFgState<T>>,
    ) -> Response {
        let include_schema = query.include_schema;
        if diag_service.contains('/') {
            return ErrorWrapper {
                error: ApiError::BadRequest("Invalid path".to_owned()),
                include_schema,
            }
            .into_response();
        }

        functional_data_request(
            DiagComm {
                name: diag_service,
                type_: DiagCommType::Data,
                lookup_name: None,
                subfunction_id: None,
            },
            &functional_group_name,
            &uds,
            headers,
            None,
            (security_plugin, &locks, FunctionalDataAccess::Read),
            include_schema,
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description(
            "Get data from a functional group service - returns data for all ECUs in the group",
        )
        .response_with::<200, Json<
            sovd_interfaces::functions::functional_groups::data::service::Response<VendorErrorCode>,
        >, _>(|res| {
            res.description(
                "Response with data from all ECUs in the functional group, keyed by ECU name",
            )
            .example(
                sovd_interfaces::functions::functional_groups::data::service::Response {
                    data: {
                        let mut map = HashMap::default();
                        let mut ecu1_data = serde_json::Map::new();
                        ecu1_data.insert("temperature".to_string(), serde_json::json!(25.5));
                        map.insert("ECU1".to_string(), ecu1_data);
                        map
                    },
                    errors: vec![],
                    schema: None,
                },
            )
        })
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_request)
        .with(openapi::error_bad_gateway)
    }

    pub(crate) async fn put<T: UdsEcu + Clone>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam { service }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::functions::functional_groups::data::service::Query>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            locks,
            functional_group_name,
            ..
        }): State<WebserverFgState<T>>,
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

        functional_data_request(
            DiagComm {
                name: service,
                type_: DiagCommType::Configurations,
                lookup_name: None,
                subfunction_id: None,
            },
            &functional_group_name,
            &uds,
            headers,
            Some(body),
            (security_plugin, &locks, FunctionalDataAccess::Write),
            include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
        >(op)
        .description("Update data for a functional group service - sends to all ECUs in the group")
        .response_with::<200, Json<
            sovd_interfaces::functions::functional_groups::data::service::Response<VendorErrorCode>,
        >, _>(|res| {
            res.description("Response with results from all ECUs in the functional group")
        })
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_request)
        .with(openapi::error_bad_gateway)
    }

    async fn functional_data_request<T: UdsEcu + Clone>(
        service: DiagComm,
        functional_group_name: &str,
        gateway: &T,
        headers: HeaderMap,
        body: Option<Bytes>,
        authorization: (
            Box<dyn cda_plugin_security::SecurityPlugin>,
            &crate::sovd::locks::Locks,
            FunctionalDataAccess,
        ),
        include_schema: bool,
    ) -> Response {
        let (security_plugin, locks, access) = authorization;
        let claims = security_plugin.as_auth_plugin().claims();
        let validation = match access {
            FunctionalDataAccess::Read => {
                validate_fg_read(
                    &claims,
                    functional_group_name,
                    gateway,
                    locks,
                    include_schema,
                )
                .await
            }
            FunctionalDataAccess::Write => {
                validate_fg_write(
                    &claims,
                    functional_group_name,
                    gateway,
                    locks,
                    include_schema,
                )
                .await
            }
        };
        if let Err(response) = validation {
            return response.into_response();
        }

        let (content_type, accept) = match get_content_type_and_accept(&headers) {
            Ok(v) => v,
            Err(e) => {
                return ErrorWrapper {
                    error: e,
                    include_schema,
                }
                .into_response();
            }
        };

        let data = if let Some(body) = body {
            match get_payload_data::<
                sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
            >(content_type.as_ref(), &headers, &body)
            {
                Ok(value) => value,
                Err(e) => {
                    return ErrorWrapper {
                        error: e,
                        include_schema,
                    }
                    .into_response();
                }
            }
        } else {
            None
        };

        let map_to_json = match map_to_json(include_schema, &accept) {
            Ok(value) => value,
            Err(e) => return e.into_response(),
        };

        if !map_to_json && include_schema {
            return ErrorWrapper {
                error: ApiError::BadRequest(
                    "Cannot use include-schema with non-JSON response".to_string(),
                ),
                include_schema,
            }
            .into_response();
        }

        // Send functional request to all ECUs in the group
        let results = gateway
            .send_functional_group(
                functional_group_name,
                service,
                &(security_plugin as cda_interfaces::DynamicPlugin),
                data,
                map_to_json,
            )
            .await;

        // Build response with per-ECU data and errors
        let mut response_data: HashMap<String, serde_json::Map<String, serde_json::Value>> =
            HashMap::default();
        let mut errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>> = Vec::new();

        for (ecu_name, result) in results {
            handle_ecu_response(&mut response_data, "data", &mut errors, ecu_name, result);
        }

        let schema = if include_schema {
            Some(crate::sovd::create_schema!(
                sovd_interfaces::functions::functional_groups::data::service::Response<
                    VendorErrorCode,
                >
            ))
        } else {
            None
        };

        (
            StatusCode::OK,
            Json(
                sovd_interfaces::functions::functional_groups::data::service::Response {
                    data: response_data,
                    errors,
                    schema,
                },
            ),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use aide::UseApi;
    use axum::{
        body::Bytes,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode, header},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        diagservices::{
            DiagServiceJsonResponse, DiagServiceResponseType, mock::MockDiagServiceResponse,
        },
        mock::MockUdsEcu,
    };
    use cda_plugin_security::{
        Secured, SecurityPlugin,
        mock::{MockAuthApi, MockClaims, MockSecurityPlugin, TestSecurityPlugin},
    };

    use super::diag_service;
    use crate::sovd::{
        components::ecu::DiagServicePathParam,
        functions::functional_groups::tests::create_test_fg_state, locks::insert_test_fg_lock,
    };

    fn foreign_security_plugin() -> Box<dyn SecurityPlugin> {
        let mut claims = MockClaims::new();
        claims.expect_sub().return_const("foreign_user");
        let claims: &'static dyn cda_plugin_security::Claims = Box::leak(Box::new(claims));
        let mut auth = MockAuthApi::new();
        auth.expect_claims().return_const(Box::new(claims));
        let mut plugin = MockSecurityPlugin::new();
        plugin
            .expect_as_auth_plugin()
            .return_const(Box::new(auth) as Box<dyn cda_plugin_security::AuthApi>);
        Box::new(plugin)
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        headers
    }

    fn query() -> WithRejection<
        Query<sovd_interfaces::functions::functional_groups::data::service::Query>,
        crate::sovd::error::ApiError,
    > {
        WithRejection(
            Query(sovd_interfaces::IncludeSchemaQuery {
                include_schema: false,
            }),
            std::marker::PhantomData,
        )
    }

    fn response() -> MockDiagServiceResponse {
        let mut response = MockDiagServiceResponse::new();
        response
            .expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        response.expect_into_json().return_once(|| {
            Ok(DiagServiceJsonResponse {
                data: serde_json::json!({"value": 1}),
                errors: vec![],
            })
        });
        response
    }

    #[tokio::test]
    async fn data_get_foreign_exclusive_lock_skips_uds() {
        let mut uds = MockUdsEcu::new();
        uds.expect_send_functional_group().times(0);
        let state = create_test_fg_state(uds, "AllECUs".to_owned());
        insert_test_fg_lock(&state.locks, "AllECUs").await;

        let response = diag_service::get::<MockUdsEcu>(
            headers(),
            UseApi(Secured(foreign_security_plugin()), std::marker::PhantomData),
            Path(DiagServicePathParam {
                service: "VehicleSpeed".to_owned(),
            }),
            query(),
            State(state),
        )
        .await;

        assert_eq!(response.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn data_put_without_owned_write_lock_skips_uds() {
        let mut uds = MockUdsEcu::new();
        uds.expect_send_functional_group().times(0);
        let state = create_test_fg_state(uds, "AllECUs".to_owned());

        let response = diag_service::put::<MockUdsEcu>(
            headers(),
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            Path(DiagServicePathParam {
                service: "VehicleSpeed".to_owned(),
            }),
            query(),
            State(state),
            Bytes::from_static(b"{\"data\":{\"value\":1}}"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn data_get_with_owned_lock_calls_uds() {
        let mut uds = MockUdsEcu::new();
        uds.expect_send_functional_group()
            .withf(|group, service, _, data, map_to_json| {
                group == "AllECUs"
                    && service.name == "VehicleSpeed"
                    && service.type_ == cda_interfaces::DiagCommType::Data
                    && data.is_none()
                    && *map_to_json
            })
            .times(1)
            .returning(|_, _, _, _, _| {
                cda_interfaces::HashMap::from_iter([("test-ecu".to_owned(), Ok(response()))])
            });
        let state = create_test_fg_state(uds, "AllECUs".to_owned());
        insert_test_fg_lock(&state.locks, "AllECUs").await;

        let response = diag_service::get::<MockUdsEcu>(
            headers(),
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            Path(DiagServicePathParam {
                service: "VehicleSpeed".to_owned(),
            }),
            query(),
            State(state),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn data_put_with_owned_lock_calls_uds() {
        let mut uds = MockUdsEcu::new();
        uds.expect_send_functional_group()
            .withf(|group, service, _, data, map_to_json| {
                group == "AllECUs"
                    && service.name == "VehicleSpeed"
                    && service.type_ == cda_interfaces::DiagCommType::Configurations
                    && data.is_some()
                    && *map_to_json
            })
            .times(1)
            .returning(|_, _, _, _, _| {
                cda_interfaces::HashMap::from_iter([("test-ecu".to_owned(), Ok(response()))])
            });
        let state = create_test_fg_state(uds, "AllECUs".to_owned());
        insert_test_fg_lock(&state.locks, "AllECUs").await;

        let response = diag_service::put::<MockUdsEcu>(
            headers(),
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            Path(DiagServicePathParam {
                service: "VehicleSpeed".to_owned(),
            }),
            query(),
            State(state),
            Bytes::from_static(b"{\"data\":{\"value\":1}}"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
