/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

#[cfg(any(feature = "gen-protos", feature = "gen-flatbuffers"))]
const COPYRIGHT_HEADER: &str = r"/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

";
#[cfg(any(feature = "gen-protos", feature = "gen-flatbuffers"))]
fn prepend_copyright(file_path: &str) -> std::io::Result<()> {
    let content = std::fs::read_to_string(file_path)?;
    let new_content = format!("{COPYRIGHT_HEADER}{content}");
    std::fs::write(file_path, new_content)?;
    Ok(())
}

/// Build script for generating Rust code from Protocol Buffers definitions.
/// `prost_build` places the generated files in `OUT_DIR`.
/// This build script copies the generated files to the `src/proto/` directory
/// so they can be checked into the repository.
#[cfg(feature = "gen-protos")]
fn generate_protos() -> std::io::Result<()> {
    prost_build::compile_protos(&["proto/file_format.proto"], &["proto/"])?;

    let out_dir = out_dir()?;

    let file_format_target = "src/proto/fileformat.rs";
    std::fs::copy(
        format!("{out_dir}/{}", "/fileformat.rs"),
        file_format_target,
    )?;

    prepend_copyright(file_format_target)?;

    Ok(())
}

/// Retrieve `FlatBuffers` git repository and revision from workspace Cargo.toml
#[cfg(feature = "gen-flatbuffers")]
fn get_flatbuffers_info() -> std::io::Result<(String, String)> {
    let workspace_manifest = std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            let mut path = std::path::PathBuf::from(dir);
            path.pop();
            path.push("Cargo.toml");
            path
        })
        .ok()
        .and_then(|path| if path.exists() { Some(path) } else { None })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Workspace Cargo.toml not found",
            )
        })?;

    let manifest = cargo_toml::Manifest::from_path(&workspace_manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let flatbuffers = manifest
        .patch
        .get("crates-io")
        .and_then(|patches| patches.get("flatbuffers"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "flatbuffers patch not found in [patch.crates-io]",
            )
        })?;

    match flatbuffers.detail() {
        Some(detail) if detail.git.is_some() && detail.rev.is_some() => Ok((
            detail
                .git
                .clone()
                .expect("Unable to fetch git url from dependency"),
            detail
                .rev
                .clone()
                .expect("Unable to fetch git url from dependency"),
        )),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "flatbuffers git/rev not found in patch.crates-io",
        )),
    }
}

#[cfg(feature = "gen-flatbuffers")]
fn generate_flatbuffers() -> std::io::Result<()> {
    let (flatc_repo, flatc_rev) = get_flatbuffers_info()?;
    let flatc_dir = std::path::PathBuf::from(out_dir()?).join("flatc");

    if !flatc_dir.exists() {
        std::process::Command::new("git")
            .args([
                "clone",
                &flatc_repo,
                flatc_dir.to_str().expect("Invalid flatc path"),
            ])
            .status()?;

        std::process::Command::new("git")
            .args(["checkout", &flatc_rev])
            .current_dir(&flatc_dir)
            .status()?;
    }

    let flatc_build_dir = "build";
    let flatc_target = "flatc";
    let flatc_binary = flatc_dir.join(flatc_build_dir).join(flatc_target);
    // Build flatc
    if !flatc_binary.exists() {
        std::process::Command::new("cmake")
            .args(["-B", flatc_build_dir, "-S", "."])
            .current_dir(&flatc_dir)
            .status()?;

        std::process::Command::new("cmake")
            .args(["--build", flatc_build_dir, "--target", flatc_target])
            .current_dir(&flatc_dir)
            .status()?;
    }

    // Compile FlatBuffers schemas
    let output_dir = "src/flatbuf/";
    let schema_name = "diagnostic_description";
    let schema_path = format!("{output_dir}{schema_name}.fbs");

    let status = std::process::Command::new(&flatc_binary)
        .args(["--rust", "-o", output_dir, &schema_path])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::other("flatc compilation failed"));
    }

    let generated_file = format!("{output_dir}{schema_name}_generated.rs");
    let final_file = format!("{output_dir}{schema_name}.rs");
    std::fs::rename(generated_file, &final_file)?;
    prepend_copyright(&final_file)?;

    Ok(())
}

#[cfg(any(feature = "gen-protos", feature = "gen-flatbuffers"))]
fn out_dir() -> Result<String, std::io::Error> {
    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::other("OUT_DIR environment variable is not set"))?
        .into_string()
        .expect("OUT_DIR is not valid UTF-8");
    Ok(out_dir)
}

#[cfg(any(feature = "gen-protos", feature = "gen-flatbuffers"))]
fn main() -> std::io::Result<()> {
    #[cfg(feature = "gen-protos")]
    generate_protos()?;

    #[cfg(feature = "gen-flatbuffers")]
    generate_flatbuffers()?;

    Ok(())
}

#[cfg(not(any(feature = "gen-protos", feature = "gen-flatbuffers")))]
fn main() {}
