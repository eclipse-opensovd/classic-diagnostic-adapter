/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! Simulator core functionality.

mod handler;
pub mod isotp;
mod state;

pub use handler::RequestHandler;
pub use state::{ActiveVariant, SimulatorState, SimulatorStats};
