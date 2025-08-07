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

use cda_interfaces::UdsEcu;
use http::StatusCode;
use sovd_interfaces::components::{ecu as sovd_ecu, ecu::operations::comparams as sovd_comparams};
use utoipa::{
    OpenApi, PartialSchema,
    openapi::{
        ComponentsBuilder, ContentBuilder, HttpMethod, KnownFormat, ObjectBuilder, OpenApiBuilder,
        PathsBuilder, ResponseBuilder, Schema, SchemaFormat,
        path::{OperationBuilder, ParameterBuilder, PathItemBuilder},
        request_body::RequestBodyBuilder,
        schema::SchemaType,
    },
};

use super::sovd::{self, error::ApiError};

#[derive(OpenApi)]
#[openapi(
    info(
        description = "In the SOVD (Service-Oriented Vehicle Diagnostics) context, \
        a Classic Diagnostic Adapter serves as a compatibility bridge between traditional (legacy) \
        diagnostic interfaces and the modern SOVD-based diagnostic \
        architecture used in next-generation vehicles.",
        contact(
            name = "Classic Diagnostic Adapter",
            url = "https://github.com/eclipse-opensovd/classic-diagnostic-adapter/",
            email = "opensovd-dev@eclipse.org"
        ),
        license(name = "Apache-2.0", url = "https://www.apache.org/licenses/LICENSE-2.0")
    ),
    paths(
        sovd::locks::vehicle::post,
        sovd::locks::vehicle::get,
        sovd::locks::vehicle::lock::put,
        sovd::locks::vehicle::lock::get,
        sovd::locks::vehicle::lock::delete,

    ),
    components(
        schemas(
            ApiError,
            sovd_comparams::executions::get::Response,
            sovd_comparams::executions::id::get::Response,
            sovd_comparams::executions::update::Request,
            sovd_comparams::executions::update::Response,
            sovd_interfaces::DataItem,
            sovd_interfaces::ResourceResponse,
            sovd_interfaces::components::ecu::ServicesSdgs,
            sovd_interfaces::components::ecu::data::get::Response,
            sovd_interfaces::components::ecu::get::Response,
            sovd_interfaces::components::get::Response,
            sovd_interfaces::error::ErrorCode,
            sovd_interfaces::locking::get::Response,
            sovd_interfaces::locking::id::get::Response,
            sovd_interfaces::locking::post_put::Response,
        )
    ),
    tags(
        (name = "CDA Rust", description = "Classic Diagnostic Adapter written in Rust")
    )
)]
pub struct ApiDoc {}

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut openapi = ApiDoc::openapi();
    // CDA: we don't need Uuid yet .. but this is proably the place to automagically enhance the
    //      openapi.json with ECU specific endpoints!
    openapi.merge(
        OpenApiBuilder::new()
            .components(Some(
                ComponentsBuilder::new()
                    .schema("Uuid", uuid_schema())
                    .build(),
            ))
            .build(),
    );
    openapi
}

fn uuid_schema() -> Schema {
    Schema::Object(
        ObjectBuilder::new()
            .schema_type(SchemaType::Type(utoipa::openapi::Type::String))
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid)))
            .build(),
    )
}

#[derive(Clone)]
struct OpenApiContent {
    schema: Option<utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>>,
    mime_type: mime::Mime,
}

#[derive(Clone)]
struct OpenApiResponse {
    status_code: StatusCode,
    description: String,
    content: Option<OpenApiContent>,
}

#[derive(Clone)]
struct OpenApiParameter {
    schema: Option<utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>>,
    description: String,
}

#[derive(Clone)]
struct OpenApiOperation {
    description: String,
    methods: Vec<HttpMethod>,
    parameters: Vec<OpenApiParameter>,
    request_body: Option<OpenApiContent>,
    responses: Vec<OpenApiResponse>,
    tag: String,
}

fn operation_builder(operation: OpenApiOperation) -> OperationBuilder {
    let mut builder = OperationBuilder::new()
        .description(Some(operation.description))
        .tag(operation.tag);

    if let Some(request_body) = operation.request_body {
        let body = RequestBodyBuilder::new().content(
            request_body.mime_type.essence_str(),
            ContentBuilder::new().schema(request_body.schema).build(),
        );
        builder = builder.request_body(Some(body.build()));
    }

    for param in operation.parameters {
        builder = builder
            .parameter(ParameterBuilder::new().schema(param.schema))
            .description(Some(param.description));
    }

    for response in operation.responses {
        let mut response_builder = ResponseBuilder::new().description(response.description);
        if let Some(content) = response.content {
            response_builder = response_builder.content(
                content.mime_type.essence_str(),
                ContentBuilder::new().schema(content.schema).build(),
            );
        }

        builder = builder.response(response.status_code.as_str(), response_builder);
    }
    builder
}

fn path_item_builder(operations: Vec<OpenApiOperation>) -> PathItemBuilder {
    let mut pib = PathItemBuilder::new();
    for op in operations {
        for method in op.methods.iter() {
            pib = pib.operation(method.clone(), operation_builder(op.clone()).build());
        }
    }
    pib
}

fn response_lock_not_found() -> OpenApiResponse {
    OpenApiResponse {
        status_code: StatusCode::NOT_FOUND,
        description: "Given lock does not exist.".to_owned(),
        content: Some(OpenApiContent {
            schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                sovd::error::ApiError,
            >::schema()),
            mime_type: mime::APPLICATION_JSON,
        }),
    }
}

fn response_lock_not_owned() -> OpenApiResponse {
    OpenApiResponse {
        status_code: StatusCode::FORBIDDEN,
        description: "Lock is not owned.".to_owned(),
        content: Some(OpenApiContent {
            schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                sovd::error::ApiError,
            >::schema()),
            mime_type: mime::APPLICATION_JSON,
        }),
    }
}

fn response_service_data() -> Vec<OpenApiResponse> {
    vec![
        OpenApiResponse {
            status_code: StatusCode::OK,
            description: "Response with data for the service without sdgs and response type set \
                          to application/json."
                .to_owned(),
            content: Some(OpenApiContent {
                schema: Some(sovd_interfaces::DataItem::schema()),
                mime_type: mime::APPLICATION_JSON,
            }),
        },
        OpenApiResponse {
            status_code: StatusCode::OK,
            description: "Response with data for the service without sdgs and response type set \
                          to application/octet-stream."
                .to_owned(),
            content: Some(OpenApiContent {
                schema: None,
                mime_type: mime::APPLICATION_OCTET_STREAM,
            }),
        },
        OpenApiResponse {
            status_code: StatusCode::OK,
            description: "Response with sdgs".to_owned(),
            content: Some(OpenApiContent {
                schema: Some(sovd_interfaces::components::ecu::ServicesSdgs::schema()),
                mime_type: mime::APPLICATION_JSON,
            }),
        },
        OpenApiResponse {
            status_code: StatusCode::BAD_REQUEST,
            description: "Lookup failed.".to_owned(),
            content: Some(OpenApiContent {
                schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                    sovd::error::ApiError,
                >::schema()),
                mime_type: mime::APPLICATION_JSON,
            }),
        },
    ]
}

fn response_comparam_execution_errors() -> Vec<OpenApiResponse> {
    vec![
        OpenApiResponse {
            status_code: StatusCode::BAD_REQUEST,
            description: "Id does not exist or execution failed".to_owned(),
            content: Some(OpenApiContent {
                schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                    sovd::error::ApiError,
                >::schema()),
                mime_type: mime::APPLICATION_JSON,
            }),
        },
        OpenApiResponse {
            status_code: StatusCode::NOT_FOUND,
            description: "Id does not exist".to_owned(),
            content: Some(OpenApiContent {
                schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                    sovd::error::ApiError,
                >::schema()),
                mime_type: mime::APPLICATION_JSON,
            }),
        },
    ]
}

fn lock_paths(tag: &String, ecu_path: &str, paths: PathsBuilder) -> PathsBuilder {
    paths.path(
        format!("{ecu_path}/locks"),
        path_item_builder(vec![
            OpenApiOperation {
                description: "Get all locks".to_owned(),
                tag: tag.clone(),
                methods: vec![HttpMethod::Get],
                parameters: vec![],
                request_body: None,
                responses: vec![OpenApiResponse {
                    status_code: StatusCode::OK,
                    description: "Response with all locks.".to_owned(),
                    content: Some(OpenApiContent {
                        schema: Some(sovd_interfaces::locking::get::Response::schema()),
                        mime_type: mime::APPLICATION_JSON,
                    }),
                }],
            },
            OpenApiOperation {
                description: "Create a new lock".to_owned(),
                tag: tag.clone(),
                parameters: vec![],
                request_body: None,
                methods: vec![HttpMethod::Post, HttpMethod::Put],
                responses: vec![
                    OpenApiResponse {
                        status_code: StatusCode::CREATED,
                        description: "Lock created successfully.".to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(
                                sovd_interfaces::locking::post_put::Response::schema(),
                            ),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    },
                    OpenApiResponse {
                        status_code: StatusCode::FORBIDDEN,
                        description: "Lock is already owned by someone else."
                            .to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                                sovd::error::ApiError,
                            >::schema(
                            )),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    },
                    OpenApiResponse {
                        status_code: StatusCode::CONFLICT,
                        description: "Functional lock prevents setting lock."
                            .to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                                sovd::error::ApiError,
                            >::schema(
                            )),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    },
                ],
            },
        ])
            .build(),
    )
        .path(
            format!("{ecu_path}/locks/{{lock}}"),
            path_item_builder(vec![
                OpenApiOperation {
                    description: "Delete a specific lock".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Delete],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![
                        OpenApiResponse {
                            status_code: StatusCode::NO_CONTENT,
                            description: "Lock deleted successfully.".to_owned(),
                            content: None,
                        },
                        response_lock_not_found(),
                        response_lock_not_owned(),
                    ],
                },
                OpenApiOperation {
                    description: "Update a specific lock".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Put],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![
                        OpenApiResponse {
                            status_code: StatusCode::NO_CONTENT,
                            description: "Lock updated successfully.".to_owned(),
                            content: None,
                        },
                        response_lock_not_found(),
                        response_lock_not_owned(),
                    ],
                },
                OpenApiOperation {
                    description: "Get a specific lock".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Get],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![
                        OpenApiResponse {
                            status_code: StatusCode::OK,
                            description: "Response with the lock details.".to_owned(),
                            content: Some(OpenApiContent {
                                schema: Some(
                                    sovd_interfaces::locking::id::get::Response::schema(),
                                ),
                                mime_type: mime::APPLICATION_JSON,
                            }),
                        },
                        response_lock_not_found(),
                    ],
                },
            ])
                .build(),
        )
}

fn data_paths(tag: &String, ecu_path: &str, paths: PathsBuilder) -> PathsBuilder {
    paths
        .path(
            format!("{ecu_path}/data"),
            path_item_builder(vec![OpenApiOperation {
                description: "Get all data".to_owned(),
                tag: tag.clone(),
                methods: vec![HttpMethod::Get],
                parameters: vec![],
                request_body: None,
                responses: vec![
                    OpenApiResponse {
                        status_code: StatusCode::OK,
                        description: "Response with all data.".to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(
                                sovd_interfaces::components::ecu::data::get::Response::schema(),
                            ),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    },
                    OpenApiResponse {
                        status_code: StatusCode::BAD_REQUEST,
                        description: "Error while fetching data from ECUs.".to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_interfaces::error::ApiErrorResponse::<
                                sovd::error::ApiError,
                            >::schema()),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    },
                ],
            }])
            .build(),
        )
        .path(
            format!("{ecu_path}/data/{{service}}"),
            path_item_builder(vec![
                OpenApiOperation {
                    description: "Get data for a specific service".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Get],
                    parameters: vec![OpenApiParameter {
                        schema: Some(sovd_ecu::data::service::get::DiagServiceQuery::schema()),
                        description: "Set to true to include sdgs.".to_owned(),
                    }],
                    request_body: Some(OpenApiContent {
                        schema: None,
                        mime_type: mime::APPLICATION_OCTET_STREAM,
                    }),
                    responses: response_service_data()
                        .into_iter()
                        .chain(
                            vec![OpenApiResponse {
                                status_code: StatusCode::OK,
                                description: "Response with sdgs".to_owned(),
                                content: Some(OpenApiContent {
                                    schema: Some(
                                        sovd_interfaces::components::ecu::ServicesSdgs::schema(),
                                    ),
                                    mime_type: mime::APPLICATION_JSON,
                                }),
                            }]
                            .into_iter(),
                        )
                        .collect(),
                },
                OpenApiOperation {
                    description: "Create data for a specific service".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Post],
                    parameters: vec![],
                    request_body: Some(OpenApiContent {
                        schema: None,
                        mime_type: mime::APPLICATION_OCTET_STREAM,
                    }),
                    responses: response_service_data(),
                },
                OpenApiOperation {
                    description: "Update data for a specific service".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Put],
                    parameters: vec![],
                    request_body: Some(OpenApiContent {
                        schema: None,
                        mime_type: mime::APPLICATION_OCTET_STREAM,
                    }),
                    responses: response_service_data(),
                },
            ])
            .build(),
        )
}

fn comparam_execution_paths(tag: &String, ecu_path: &str, paths: PathsBuilder) -> PathsBuilder {
    paths
        .path(
            format!("{ecu_path}/operations/comparam/executions"),
            path_item_builder(vec![
                OpenApiOperation {
                    description: "Get all comparam executions".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Get],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![OpenApiResponse {
                        status_code: StatusCode::OK,
                        description: "Response with all comparam executions.".to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_comparams::executions::get::Response::schema()),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    }],
                },
                OpenApiOperation {
                    description: "Create a new comparam execution".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Post],
                    parameters: vec![],
                    request_body: {
                        Some(OpenApiContent {
                            schema: Some(sovd_comparams::executions::update::Request::schema()),
                            mime_type: mime::APPLICATION_JSON,
                        })
                    },
                    responses: vec![OpenApiResponse {
                        status_code: StatusCode::ACCEPTED,
                        description: "Comparam execution created successfully.".to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_comparams::executions::update::Response::schema()),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    }],
                },
            ])
            .build(),
        )
        .path(
            format!("{ecu_path}/operations/comparam/executions/{{id}}"),
            path_item_builder(vec![
                OpenApiOperation {
                    description: "Get a specific comparam execution".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Get],
                    parameters: vec![],
                    request_body: None,
                    responses: response_comparam_execution_errors()
                        .into_iter()
                        .chain(vec![OpenApiResponse {
                            status_code: StatusCode::OK,
                            description: "Response with the comparam execution details.".to_owned(),
                            content: Some(OpenApiContent {
                                schema: Some(
                                    sovd_comparams::executions::id::get::Response::schema(),
                                ),
                                mime_type: mime::APPLICATION_JSON,
                            }),
                        }])
                        .into_iter()
                        .collect(),
                },
                OpenApiOperation {
                    description: "Delete a specific comparam execution".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Delete],
                    parameters: vec![],
                    request_body: Some(OpenApiContent {
                        schema: None,
                        mime_type: mime::APPLICATION_OCTET_STREAM,
                    }),
                    responses: response_comparam_execution_errors()
                        .into_iter()
                        .chain(vec![OpenApiResponse {
                            status_code: StatusCode::NO_CONTENT,
                            description: "Comparam execution deleted successfully.".to_owned(),
                            content: None,
                        }])
                        .into_iter()
                        .collect(),
                },
                OpenApiOperation {
                    description: "Update a specific comparam execution".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Put],
                    parameters: vec![],
                    request_body: Some(OpenApiContent {
                        schema: None,
                        mime_type: mime::APPLICATION_OCTET_STREAM,
                    }),
                    responses: response_comparam_execution_errors()
                        .into_iter()
                        .chain(vec![OpenApiResponse {
                            status_code: StatusCode::ACCEPTED,
                            description: "Comparam execution started successfully.".to_owned(),
                            content: None,
                        }])
                        .into_iter()
                        .collect(),
                },
            ])
            .build(),
        )
}

/// Generates the OpenAPI paths for all loaded ECUs.
/// This is only a prototype at this point and must be extended to cover all endpoints.
/// At the moment, documenting endpoints is a lot of manual (and error-prone) work, as datatypes
/// have to be extracted and mapped for each method.
/// Automating this is a future task, but for now this is a good, although incomplete,
/// starting point.
pub async fn paths<T: UdsEcu + Send + Sync + Clone + 'static>(uds: &T) -> utoipa::openapi::Paths {
    let mut ecu_names = uds.get_ecus().await;
    let mut paths = PathsBuilder::new();

    let components_path = "/vehicle/v15/components";

    paths = paths.path(
        components_path,
        path_item_builder(vec![OpenApiOperation {
            description: "Get components".to_owned(),
            tag: "sovd/components".to_owned(),
            methods: vec![HttpMethod::Get],
            parameters: vec![],
            request_body: None,
            responses: vec![OpenApiResponse {
                status_code: StatusCode::OK,
                description: "Successful response with components".to_owned(),
                content: Some(OpenApiContent {
                    schema: Some(sovd_interfaces::components::get::Response::schema()),
                    mime_type: mime::APPLICATION_JSON,
                }),
            }],
        }])
        .build(),
    );

    for ecu_name in ecu_names.iter_mut() {
        let tag = format!("sovd/components/{ecu_name}");
        let ecu_path = format!("{components_path}/{ecu_name}");

        paths = lock_paths(&tag, &ecu_path, paths);
        paths = data_paths(&tag, &ecu_path, paths);
        paths = comparam_execution_paths(&tag, &ecu_path, paths);

        paths = paths.path(
            ecu_path.clone(),
            path_item_builder(vec![
                OpenApiOperation {
                    description: "Get ECU details".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Get],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![OpenApiResponse {
                        status_code: StatusCode::OK,
                        description: "Response with ECU information (i.e. detected variant) and \
                                      service URLs"
                            .to_owned(),
                        content: Some(OpenApiContent {
                            schema: Some(sovd_interfaces::components::ecu::get::Response::schema()),
                            mime_type: mime::APPLICATION_JSON,
                        }),
                    }],
                },
                OpenApiOperation {
                    description: "Trigger variant detection".to_owned(),
                    tag: tag.clone(),
                    methods: vec![HttpMethod::Post, HttpMethod::Put],
                    parameters: vec![],
                    request_body: None,
                    responses: vec![OpenApiResponse {
                        status_code: StatusCode::CREATED,
                        description: "Trigger the variant detection for the ECU.".to_owned(),
                        content: None,
                    }],
                },
            ])
            .build(),
        )
    }

    // Todo This list is not complete and the remaining endpoints should be documented.
    // At least the following services are missing:
    // {ecu_path}/operations/{{service}}/executions"
    // {ecu_path}/modes"
    // {ecu_path}/modes/session"
    // {ecu_path}/modes/security"
    // {ecu_path}/x-single-ecu-jobs"
    // {ecu_path}/x-single-ecu-jobs/{{name}}"
    // {ecu_path}/x-sovd2uds-download"
    // {ecu_path}/x-sovd2uds-download/requestdownload"
    // {ecu_path}/x-sovd2uds-download/flashtransfer"
    // {ecu_path}/x-sovd2uds-download/flashtransfer/{{id}}"
    // {ecu_path}/x-sovd2uds-download/transferexit"
    // {ecu_path}/x-sovd2uds-bulk-data"
    // {ecu_path}/x-sovd2uds-bulk-data/mdd-embedded-files"
    // {ecu_path}/x-sovd2uds-bulk-data/mdd-embedded-files/{{id}}"

    paths.build()
}
