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

// Simulator is a test/development tool; some pedantic lints are relaxed for maintainability.
#![allow(
    clippy::wildcard_imports,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::must_use_candidate,
    clippy::uninlined_format_args,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    clippy::manual_div_ceil,
    clippy::cast_lossless,
    clippy::redundant_else,
    clippy::collapsible_if,
    clippy::manual_let_else,
    clippy::explicit_iter_loop,
    clippy::redundant_closure_for_method_calls,
    clippy::missing_errors_doc,
    clippy::map_entry,
    clippy::items_after_statements,
    clippy::unnecessary_wraps,
    clippy::map_unwrap_or,
    clippy::indexing_slicing,
    clippy::match_same_arms,
    clippy::type_complexity,
    clippy::needless_borrow,
    clippy::derivable_impls,
    clippy::single_match_else,
    clippy::unnecessary_filter_map,
    clippy::unused_self,
    clippy::similar_names
)]

//! MDD-based ECU Simulator for testing CAN/ISO-TP diagnostic operations.
//!
//! This crate provides a simulator that can emulate any ECU defined by an MDD
//! (Mercedes Diagnostic Database) file. It listens for diagnostic requests on
//! CAN bus via ISO-TP and responds with configurable values.

pub mod api;
pub mod config;
pub mod error;
pub mod mdd;
pub mod simulator;

pub use config::SimulatorArgs;
pub use error::SimulatorError;
