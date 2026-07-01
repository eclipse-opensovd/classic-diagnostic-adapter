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

//! API route definitions.

use std::sync::Arc;

use aide::axum::{ApiRouter, routing};

use super::handlers;
use crate::simulator::SimulatorState;

/// Create the API router with all routes.
pub fn create_router(state: Arc<SimulatorState>) -> ApiRouter {
    ApiRouter::new()
        // Simulator info and stats
        .api_route(
            "/",
            routing::get_with(handlers::get_info, handlers::docs_get_info),
        )
        .api_route(
            "/stats",
            routing::get_with(handlers::get_stats, handlers::docs_get_stats)
                .delete_with(handlers::reset_stats, handlers::docs_reset_stats),
        )
        // Variant info
        .api_route(
            "/variant",
            routing::get_with(handlers::get_variant, handlers::docs_get_variant),
        )
        // Services
        .api_route(
            "/services",
            routing::get_with(handlers::list_services, handlers::docs_list_services),
        )
        .api_route(
            "/services/{name}",
            routing::get_with(handlers::get_service, handlers::docs_get_service),
        )
        .api_route(
            "/services/{name}/parameters",
            routing::get_with(handlers::list_parameters, handlers::docs_list_parameters),
        )
        .api_route(
            "/services/{name}/parameters/{param}",
            routing::get_with(handlers::get_parameter, handlers::docs_get_parameter)
                .put_with(handlers::set_parameter, handlers::docs_set_parameter)
                .delete_with(
                    handlers::delete_parameter_override,
                    handlers::docs_delete_parameter_override,
                ),
        )
        // Overrides
        .api_route(
            "/overrides",
            routing::get_with(handlers::list_overrides, handlers::docs_list_overrides)
                .delete_with(handlers::clear_overrides, handlers::docs_clear_overrides),
        )
        .with_state(state)
}
