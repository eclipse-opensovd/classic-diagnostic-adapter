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

use aide::{axum::IntoApiResponse, transform::TransformOperation};
use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DiagComm, DynamicPlugin, SchemaProvider, UdsEcu,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use cda_plugin_security::SecurityPlugin;
use http::{HeaderMap, StatusCode};

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState,
        components::get_content_type_and_accept,
        create_response_schema, create_schema,
        error::{ApiError, ErrorWrapper, api_error_from_diag_response},
        field_parse_errors_to_json, get_payload_data,
    },
};

pub(crate) mod configurations;
pub(crate) mod data;
pub(crate) mod faults;
pub(crate) mod genericservice;
pub(crate) mod modes;
pub(crate) mod operations;
pub(crate) mod x_single_ecu_jobs;
pub(crate) mod x_sovd2uds_bulk_data;
pub(crate) mod x_sovd2uds_download;

// [[ dimpl~sovd-api-component-sdgsd, GET /components/{ecu} SDG handler ]]
pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::components::ComponentQuery>,
        ApiError,
    >,
) -> impl IntoApiResponse {
    let include_schema = query.include_schema;
    let base_path = format!("http://localhost:20002/vehicle/v15/components/{ecu_name}");
    let status = match uds.get_ecu_state(&ecu_name).await {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };
    let logical_address = match uds.get_logical_address(&ecu_name).await {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    let variant = sovd_interfaces::components::ecu::Variant {
        name: status.name().unwrap_or("Unknown").to_owned(),
        is_base_variant: status.is_base_variant(),
        state: status.into_sovd(),
        logical_address: format!("0x{logical_address:02x}"),
    };

    let sdgs = if query.include_sdgs {
        match uds.get_sdgs(&ecu_name, None).await {
            Ok(v) => Some(
                v.into_iter()
                    .map(super::super::IntoSovd::into_sovd)
                    .collect(),
            ),
            Err(e) => {
                return ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response();
            }
        }
    } else {
        None
    };

    let schema = if include_schema {
        Some(create_schema!(
            sovd_interfaces::components::ecu::get::Response
        ))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(sovd_interfaces::components::ecu::get::Response {
            id: ecu_name.to_lowercase(),
            name: ecu_name.clone(),
            variant,
            locks: format!("{base_path}/locks"),
            operations: format!("{base_path}/operations"),
            configurations: format!("{base_path}/configurations"),
            data: format!("{base_path}/data"),
            sdgs,
            single_ecu_jobs: format!("{base_path}/x-single-ecu-jobs"),
            faults: format!("{base_path}/faults"),
            modes: format!("{base_path}/modes"),
            schema,
        }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get ECU details")
        .response_with::<200, Json<sovd_interfaces::components::ecu::Ecu>, _>(|res| {
            res.example(sovd_interfaces::components::ecu::Ecu {
                id: "my_ecu".to_string(),
                name: "My ECU".to_string(),
                variant: sovd_interfaces::components::ecu::Variant {
                    name: "Variant Name".to_owned(),
                    is_base_variant: false,
                    state: sovd_interfaces::components::ecu::State::Online,
                    logical_address: "0x42".to_owned(),
                },
                locks: "http://localhost:20002/vehicle/v15/components/my_ecu/locks".to_string(),
                operations: "http://localhost:20002/vehicle/v15/components/my_ecu/operations"
                    .to_string(),
                data: "http://localhost:20002/vehicle/v15/components/my_ecu/data".to_string(),
                configurations:
                    "http://localhost:20002/vehicle/v15/components/my_ecu/configurations"
                        .to_string(),
                sdgs: None,
                single_ecu_jobs:
                    "http://localhost:20002/vehicle/v15/components/my_ecu/x-single-ecu-jobs"
                        .to_string(),
                faults: "http://localhost:20002/vehicle/v15/components/my_ecu/faults".to_string(),
                modes: "http://localhost:20002/vehicle/v15/components/my_ecu/modes".to_string(),
                schema: None,
            })
            .description("Response with ECU information (i.e. detected variant) and service URLs")
        })
}

pub(crate) async fn post<T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

// [[ dimpl~sovd-api-ecu-variant-detection, PUT endpoint for ECU variant detection ]]
//
// Handles PUT requests on /components/{ecuName} to trigger variant detection.
// Delegates to the UDS layer which sends diagnostic requests to the ECU and
// evaluates the responses against known variant patterns. Returns 201 on
// success or an error response if detection fails.
pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
) -> Response {
    update(&ecu_name, uds).await
}

pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
    op.description("Trigger ECU variant detection")
        .response_with::<201, (), _>(|res| res.description("ECU variant detection triggered."))
}

async fn update<T: UdsEcu + Clone>(ecu_name: &str, uds: T) -> Response {
    match uds.detect_variant(ecu_name).await {
        Ok(()) => (StatusCode::CREATED, ()).into_response(),
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: false,
        }
        .into_response(),
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComplexComParamValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComplexComParamValue;

    fn into_sovd(self) -> Self::SovdType {
        self.into_iter()
            .map(|(key, value)| (key, value.into_sovd()))
            .collect()
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComParamValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComParamValue;

    fn into_sovd(self) -> Self::SovdType {
        match self {
            Self::Simple(simple) => Self::SovdType::Simple(simple.into_sovd()),
            Self::Complex(complex) => Self::SovdType::Complex(complex.into_sovd()),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::ComParamSimpleValue {
    type SovdType = sovd_interfaces::components::ecu::operations::comparams::ComParamSimpleValue;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            value: self.value.clone(),
            unit: self.unit.map(|u| {
                sovd_interfaces::components::ecu::operations::comparams::Unit {
                    factor_to_si_unit: u.factor_to_si_unit,
                    offset_to_si_unit: u.offset_to_si_unit,
                }
            }),
        }
    }
}

openapi::aide_helper::gen_path_param!(DiagServicePathParam service String);

/// Parsed and validated inputs extracted from request headers and body.
#[derive(Debug)]
struct ParsedRequest {
    data: Option<cda_interfaces::diagservices::UdsPayloadData>,
    map_to_json: bool,
}

/// Parses and validates the HTTP headers and optional request body for a data
/// service request. Returns a [`ParsedRequest`] on success or an [`ApiError`]
/// describing the first validation failure.
fn parse_data_request(
    headers: &HeaderMap,
    body: Option<Bytes>,
    include_schema: bool,
) -> Result<ParsedRequest, ApiError> {
    let (content_type, accept) = get_content_type_and_accept(headers)?;

    let data = if let Some(body) = body {
        get_payload_data::<sovd_interfaces::components::ecu::data::DataRequestPayload>(
            content_type.as_ref(),
            headers,
            &body,
        )?
    } else {
        None
    };

    let map_to_json = match (accept.type_(), accept.subtype()) {
        (mime::APPLICATION, mime::JSON) => true,
        (mime::APPLICATION, mime::OCTET_STREAM) => false,
        unsupported => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported Accept: {unsupported:?}"
            )));
        }
    };

    if !map_to_json && include_schema {
        return Err(ApiError::BadRequest(
            "Cannot use include-schema with non-JSON response".to_string(),
        ));
    }

    Ok(ParsedRequest { data, map_to_json })
}

/// Fetches the optional response schema and sends the UDS diagnostic request.
/// Returns the raw response and optional schema on success, or an [`ApiError`] on failure.
async fn execute_uds_data_request<T: UdsEcu + SchemaProvider + Clone>(
    gateway: &T,
    ecu_name: &str,
    service: &DiagComm,
    security_plugin: Box<dyn SecurityPlugin>,
    data: Option<cda_interfaces::diagservices::UdsPayloadData>,
    map_to_json: bool,
    include_schema: bool,
) -> Result<(T::Response, Option<schemars::Schema>), ApiError> {
    let schema = if include_schema {
        let data_schema = gateway
            .schema_for_responses(ecu_name, service)
            .await
            .map(cda_interfaces::SchemaDescription::into_schema)
            .map_err(Into::into)
            .map_err(|e: ApiError| e)?;
        Some(create_response_schema!(
            sovd_interfaces::ObjectDataItem<VendorErrorCode>,
            "data",
            data_schema
        ))
    } else {
        None
    };

    let response = gateway
        .send(
            ecu_name,
            service.clone(),
            &(security_plugin as DynamicPlugin),
            data,
            map_to_json,
        )
        .await
        .map_err(Into::into)
        .map_err(|e: ApiError| e)?;

    Ok((response, schema))
}

/// Converts a completed [`DiagServiceResponse`] into an HTTP [`Response`],
/// honoring the `map_to_json` flag and the optional inline schema.
fn format_data_response<R: cda_interfaces::diagservices::DiagServiceResponse>(
    response: R,
    service: &DiagComm,
    map_to_json: bool,
    include_schema: bool,
    schema: Option<schemars::Schema>,
) -> Response {
    if let DiagServiceResponseType::Negative = response.response_type() {
        return api_error_from_diag_response(&response, include_schema).into_response();
    }

    if response.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    if map_to_json {
        let (mapped_data, errors) = match response.into_json() {
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(mapped_data),
                errors,
            }) => (mapped_data, errors),
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Null,
                errors,
            }) => {
                if errors.is_empty() {
                    return StatusCode::NO_CONTENT.into_response();
                }
                (serde_json::Map::new(), errors)
            }
            Ok(v) => {
                return ErrorWrapper {
                    error: ApiError::InternalServerError(Some(format!(
                        "Expected JSON object but got: {}",
                        v.data
                    ))),
                    include_schema,
                }
                .into_response();
            }
            Err(e) => {
                return ErrorWrapper {
                    error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                    include_schema,
                }
                .into_response();
            }
        };
        (
            StatusCode::OK,
            Json(sovd_interfaces::ObjectDataItem {
                id: service.name.to_lowercase(),
                data: mapped_data,
                errors: field_parse_errors_to_json(errors, "data"),
                schema,
            }),
        )
            .into_response()
    } else {
        let data = response.get_raw().to_vec();
        (StatusCode::OK, Bytes::from_owner(data)).into_response()
    }
}

/// Orchestrates [`parse_data_request`], [`execute_uds_data_request`], and
/// [`format_data_response`] to handle a complete ECU data service request.
async fn data_request<T: UdsEcu + SchemaProvider + Clone>(
    service: DiagComm,
    ecu_name: &str,
    gateway: &T,
    headers: HeaderMap,
    body: Option<Bytes>,
    security_plugin: Box<dyn SecurityPlugin>,
    include_schema: bool,
) -> Response {
    let parsed = match parse_data_request(&headers, body, include_schema) {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema,
            }
            .into_response();
        }
    };

    let (response, schema) = match execute_uds_data_request(
        gateway,
        ecu_name,
        &service,
        security_plugin,
        parsed.data,
        parsed.map_to_json,
        include_schema,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema,
            }
            .into_response();
        }
    };

    format_data_response(
        response,
        &service,
        parsed.map_to_json,
        include_schema,
        schema,
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use cda_interfaces::{
        DataParseError, DiagComm, DiagCommType,
        diagservices::{
            DiagServiceJsonResponse, DiagServiceResponseType, FieldParseError,
            mock::MockDiagServiceResponse,
        },
    };
    use http::{HeaderMap, HeaderValue, StatusCode, header};

    use super::{format_data_response, parse_data_request};
    use crate::sovd::error::ApiError;

    async fn body_bytes(response: axum::response::Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
    }

    fn make_field_parse_error(path: &str, value: &str, details: &str) -> FieldParseError {
        FieldParseError {
            path: path.to_string(),
            error: DataParseError {
                value: value.to_string(),
                details: details.to_string(),
            },
        }
    }

    #[test]
    fn negative_response_returns_bad_gateway() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Negative);
        mock.expect_as_nrc().returning(|| {
            Ok(cda_interfaces::diagservices::MappedNRC {
                code: Some(0x22),
                description: Some("conditionsNotCorrect".to_string()),
                sid: Some(0x22),
            })
        });

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn empty_positive_response_returns_no_content() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| true);

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(body_bytes(response).await.is_empty());
    }

    #[tokio::test]
    async fn map_to_json_with_object_data_returns_200_with_json_body() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            let mut map = serde_json::Map::new();
            map.insert("rpm".to_string(), serde_json::json!(1200));
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(map),
                errors: vec![],
            })
        });

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("id").and_then(|v| v.as_str()), Some("readrpm"));
        assert_eq!(
            json.get("data")
                .and_then(|v| v.get("rpm"))
                .and_then(serde_json::Value::as_u64),
            Some(1200)
        );
    }

    #[tokio::test]
    async fn map_to_json_null_data_with_no_errors_returns_no_content() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Null,
                errors: vec![],
            })
        });

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn map_to_json_non_object_data_returns_500() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            Ok(DiagServiceJsonResponse {
                data: serde_json::json!([1, 2, 3]),
                errors: vec![],
            })
        });

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn map_to_json_into_json_error_returns_500() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            Err(cda_interfaces::DiagServiceError::InvalidRequest(
                "test".into(),
            ))
        });

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn raw_response_returns_200_with_binary_body() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_get_raw()
            .return_const(vec![0xDEu8, 0xAD, 0xBE, 0xEF]);

        let service = DiagComm::new("ReadRaw", DiagCommType::Data);
        let response = format_data_response(mock, &service, false, false, None);

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(body.as_ref(), &[0xDEu8, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn map_to_json_includes_schema_when_provided() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(serde_json::Map::new()),
                errors: vec![],
            })
        });

        let schema: schemars::Schema =
            serde_json::from_value(serde_json::json!({"type": "object"})).unwrap();

        let service = DiagComm::new("ReadRPM", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, true, Some(schema));

        assert_eq!(response.status(), StatusCode::OK);
        // schema is present in the body because ObjectDataItem serialises it when Some
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("schema").is_some(),
            "expected schema field in body"
        );
    }

    #[tokio::test]
    async fn map_to_json_with_field_parse_errors_includes_errors_in_body() {
        let mut mock = MockDiagServiceResponse::new();
        mock.expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        mock.expect_is_empty().returning(|| false);
        mock.expect_into_json().returning(|| {
            let mut map = serde_json::Map::new();
            map.insert("voltage".to_string(), serde_json::json!(12.0));
            Ok(DiagServiceJsonResponse {
                data: serde_json::Value::Object(map),
                errors: vec![
                    make_field_parse_error("/current", "0xFF", "unknown encoding"),
                    make_field_parse_error("/temperature", "0xAB", "out of range"),
                ],
            })
        });

        let service = DiagComm::new("ReadBattery", DiagCommType::Data);
        let response = format_data_response(mock, &service, true, false, None);

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let errors = json
            .get("errors")
            .and_then(|v| v.as_array())
            .expect("expected errors array");
        assert_eq!(errors.len(), 2);
        // paths should be prefixed with /data
        let paths: Vec<&str> = errors.iter().map(|e| e["path"].as_str().unwrap()).collect();
        assert!(paths.iter().all(|p| p.starts_with("/data")));
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn no_headers_no_body_defaults_to_json() {
        // No Content-Type, no Accept -> should default to application/json
        let headers = HeaderMap::new();
        let result = parse_data_request(&headers, None, false);

        let parsed = result.expect("should succeed");
        assert!(parsed.map_to_json, "expected map_to_json=true");
        assert!(parsed.data.is_none(), "expected no data");
    }

    #[test]
    fn accept_json_no_body_sets_map_to_json_true() {
        let headers = headers_with(&[("accept", "application/json")]);
        let result = parse_data_request(&headers, None, false);

        let parsed = result.expect("should succeed");
        assert!(parsed.map_to_json);
        assert!(parsed.data.is_none());
    }

    #[test]
    fn accept_octet_stream_no_body_sets_map_to_json_false() {
        let headers = headers_with(&[("accept", "application/octet-stream")]);
        let result = parse_data_request(&headers, None, false);

        let parsed = result.expect("should succeed");
        assert!(!parsed.map_to_json);
        assert!(parsed.data.is_none());
    }

    #[test]
    fn accept_wildcard_falls_back_to_json_when_no_content_type() {
        // Accept: */* with no Content-Type -> content_type is None, accept_header
        // collapses to APPLICATION_JSON per get_content_type_and_accept logic.
        let headers = headers_with(&[("accept", "*/*")]);
        let result = parse_data_request(&headers, None, false);

        let parsed = result.expect("should succeed");
        assert!(parsed.map_to_json);
    }

    #[test]
    fn unsupported_accept_returns_bad_request() {
        let headers = headers_with(&[("accept", "text/plain")]);
        let result = parse_data_request(&headers, None, false);

        match result {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("Unsupported Accept"), "unexpected msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn malformed_accept_header_returns_bad_request() {
        let mut headers = HeaderMap::new();
        // Insert raw bytes that are not valid UTF-8
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_bytes(b"\xFF\xFE").unwrap(),
        );
        let result = parse_data_request(&headers, None, false);

        assert!(
            matches!(result, Err(ApiError::BadRequest(_))),
            "expected BadRequest for malformed Accept"
        );
    }

    #[test]
    fn octet_stream_with_include_schema_returns_bad_request() {
        let headers = headers_with(&[("accept", "application/octet-stream")]);
        let result = parse_data_request(&headers, None, true);

        match result {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("include-schema"), "unexpected msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn json_body_is_parsed_into_parameter_map() {
        let headers = headers_with(&[
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ]);
        let body = Bytes::from_static(br#"{"data":{"rpm":1200}}"#);
        let result = parse_data_request(&headers, Some(body), false);

        let parsed = result.expect("should succeed");
        assert!(parsed.map_to_json);

        match parsed.data {
            Some(cda_interfaces::diagservices::UdsPayloadData::ParameterMap(map)) => {
                assert_eq!(
                    map.get("rpm"),
                    Some(&serde_json::json!(1200)),
                    "expected 'rpm' key in parameter map"
                );
            }
            other => panic!("expected ParameterMap, got {other:?}"),
        }
    }

    #[test]
    fn invalid_json_body_returns_bad_request() {
        let headers = headers_with(&[
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ]);
        let body = Bytes::from_static(b"not-json");
        let result = parse_data_request(&headers, Some(body), false);

        match result {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("Invalid JSON"), "unexpected msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn octet_stream_body_is_parsed_into_raw() {
        let payload: &[u8] = &[0x22, 0x01, 0xFF];
        let headers = headers_with(&[
            ("content-type", "application/octet-stream"),
            ("accept", "application/octet-stream"),
            ("content-length", &payload.len().to_string()),
        ]);
        let body = Bytes::copy_from_slice(payload);
        let result = parse_data_request(&headers, Some(body), false);

        let parsed = result.expect("should succeed");
        assert!(!parsed.map_to_json);

        match parsed.data {
            Some(cda_interfaces::diagservices::UdsPayloadData::Raw(bytes)) => {
                assert_eq!(bytes, payload);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }
}
