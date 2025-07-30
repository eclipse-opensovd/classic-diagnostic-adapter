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

/// Build script for generating Rust code from Protocol Buffers definitions.
/// prost_build places the generated files in OUT_DIR.
/// This build script copies the generated files to the `src/proto/` directory
/// so they can be checked into the repository.
#[cfg(feature = "gen-protos")]
fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["proto/diagnostic_description.proto"], &["proto/"])?;
    prost_build::compile_protos(&["proto/file_format.proto"], &["proto/"])?;

    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "OUT_DIR environment variable is not set",
            )
        })?
        .into_string()
        .expect("OUT_DIR is not valid UTF-8");
    std::fs::copy(
        format!("{out_dir}/{}", "/dataformat.rs"),
        "src/proto/dataformat.rs",
    )?;
    std::fs::copy(
        format!("{out_dir}/{}", "/fileformat.rs"),
        "src/proto/fileformat.rs",
    )?;

    Ok(())
}

#[cfg(not(feature = "gen-protos"))]
fn main() {}
