/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#[allow(dead_code)] // if we are on nightly, stable is never referenced
#[derive(PartialEq, Eq)]
enum Rustc {
    Nightly,
    Stable,
}

#[rustversion::not(stable)]
const RUSTC: Rustc = Rustc::Nightly;

#[rustversion::stable]
const RUSTC: Rustc = Rustc::Stable;

/// Set the `nightly` cfg flag if we are compiling with a nightly compiler.
/// This allows us to conditionally compile code based on the compiler version.
pub fn set_nightly_flag() {
    if RUSTC == Rustc::Nightly {
        println!("cargo:rustc-cfg=nightly");
    }
}
