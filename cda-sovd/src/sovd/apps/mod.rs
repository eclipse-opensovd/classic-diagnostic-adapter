/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use aide::UseApi;
use axum::{
    extract::{OriginalUri, Query},
    response::Response,
};
use axum_extra::extract::WithRejection;
use opensovd_axum_extra::ExtractHost;

use crate::sovd::{IntoSovd, error::ApiError, resource_response};

pub(crate) mod sovd2uds;

pub(crate) async fn get(
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    OriginalUri(uri): OriginalUri,
) -> Response {
    resource_response(&host, &uri, vec![("sovd2uds", None)], query.include_schema)
}

impl IntoSovd for cda_interfaces::datatypes::NetworkStructure {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::NetworkStructure;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            functional_groups: self
                .functional_groups
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
            gateways: self
                .gateways
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::Gateway {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::Gateway;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            name: self.name,
            network_address: self.network_address,
            logical_address: self.logical_address,
            ecus: self
                .ecus
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::FunctionalGroup {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::FunctionalGroup;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            qualifier: self.qualifier,
            ecus: self
                .ecus
                .into_iter()
                .map(super::IntoSovd::into_sovd)
                .collect(),
        }
    }
}

impl IntoSovd for cda_interfaces::datatypes::Ecu {
    type SovdType = sovd_interfaces::apps::sovd2uds::data::network_structure::Ecu;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            qualifier: self.qualifier,
            variant: if let Some(n) = self.variant.name {
                n.clone()
            } else if self.variant.is_base_variant {
                "BaseVariant".to_owned()
            } else {
                "Unknown".to_owned()
            },
            state: self.variant.state.to_string(),
            logical_address: self.logical_address,
            logical_link: self.logical_link,
        }
    }
}
