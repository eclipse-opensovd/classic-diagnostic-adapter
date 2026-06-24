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

use std::vec;

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::{
        Query,
        State,
    },
    response::{
        IntoResponse as _,
        Response,
    },
};
use axum_extra::extract::WithRejection;
use cda_interfaces::UdsEcu;
use http::StatusCode;

use crate::sovd::{
    IntoSovd,
    create_schema,
    error::ApiError,
};

pub(crate) async fn get<T: UdsEcu>(
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    State(gateway): State<T>,
) -> Response {
    let networkstructure_data = gateway.get_network_structure().await.into_sovd();

    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response
        ))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(
            sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response {
                id: "networkstructure".to_owned(),
                data: vec![networkstructure_data],
                schema,
            },
        ),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    use sovd_interfaces::apps::sovd2uds::data::network_structure::{
        Gateway,
        NetworkStructure,
        get::Response,
    };

    op.description("Get the network structure of the Vehicle")
        .response_with::<200, Json<Response>, _>(|res| {
            res.description("Successful response").example(Response {
                id: "networkstructure".to_owned(),
                data: vec![NetworkStructure {
                    functional_groups: vec![],
                    gateways: vec![Gateway {
                        name: "Gateway1".to_owned(),
                        network_address: "1.2.3.4".to_owned(),
                        logical_address: "0x1234".to_owned(),
                        ecus: vec![],
                    }],
                }],
                schema: None,
            })
        })
}
