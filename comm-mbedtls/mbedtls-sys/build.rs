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

use std::{
    env,
    path::{Path, PathBuf},
};

const MBEDTLS_VERSION: &str = "4.0.0";
const TARBALL_URL: &str = const_format::formatcp!(
    "https://github.com/Mbed-TLS/mbedtls/releases/download/\
    mbedtls-{MBEDTLS_VERSION}/mbedtls-{MBEDTLS_VERSION}.tar.bz2"
);
const TARBALL_SHA: &str = "2f3a47f7b3a541ddef450e4867eeecb7ce2ef7776093f3a11d6d43ead6bf2827";

const MBEDTLS_SOURCE_OVERRIDE_VAR: &str = "MBEDTLS_DIR";
const MBEDTLS_SKIP_PATCH_VAR: &str = "MBEDTLS_SKIP_PATCH";

/// The build script takes care of compiling mbedtls and creating up to date binaries.
/// It additionally applies the patches for supporting record size limit on TLS 1.2 as well as
/// support for ED25519 signature algorithms. See `patches/Readme.md` for further information.
///
/// If the mbedtls source is not found in $(pwd)/mbedtls-4.0.0 the build script will
/// try to download the release tarball, verify the sha, extract it and patch it.
///
/// The build can be customized with following environment variables
/// - `BINDGEN_SYSROOT`: provide the path to a sysroot for bindgen. Required when cross-compiling
///   using a SDK.
/// - `MBEDTLS_DIR`: provide the path to the mbedtls source code. This avoids fetching the tarball
///   during build.
/// - `MBEDTLS_SKIP_PATCH`: skip the tls1.2 record-size-limit and ed25519-psa-driver patches
fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Download + patch mbedtls if not already present.
    ensure_mbedtls_source(&manifest_dir);

    let mbedtls_src = manifest_dir.join(format!("mbedtls-{MBEDTLS_VERSION}"));
    let out_dir = PathBuf::from(
        env::var("OUT_DIR")
            .expect("OUT_DIR environment variable not set — build script must be run by Cargo"),
    );

    // Only re-run if the mbedtls source or wrapper header change.
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=patches");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=build.rs");

    // build mbedtls
    cmake::Config::new(&mbedtls_src)
        .define("USE_STATIC_MBEDTLS_LIBRARY", "ON")
        .define("USE_SHARED_MBEDTLS_LIBRARY", "OFF")
        .define("ENABLE_TESTING", "OFF")
        .define("ENABLE_PROGRAMS", "OFF")
        .define("MBEDTLS_FATAL_WARNINGS", "OFF")
        // Disable GEN_FILES — the release tarball ships pre-generated files.
        .define("GEN_FILES", "OFF")
        // Enable RFC 8449 record_size_limit extension (TLS 1.3).
        .cflag("-DMBEDTLS_SSL_RECORD_SIZE_LIMIT")
        // Enable NULL cipher (required for ECDHE_ECDSA_WITH_NULL_SHA etc.)
        .cflag("-DMBEDTLS_SSL_NULL_CIPHERSUITES")
        // Enable our Ed25519 PSA accelerator driver.
        .cflag("-DMBEDTLS_ED25519_PSA_DRIVER")
        // add include dir for ed25519_extract
        .cflag(format!("-I{}", manifest_dir.join("csrc").display()))
        .build();

    for lib in ["lib", "build/library"] {
        let build_lib = out_dir.join(lib);
        if build_lib.exists() {
            println!("cargo:rustc-link-search=native={}", build_lib.display());
        }
    }

    // Link order matters: mbedtls -> mbedx509 -> tfpsacrypto (≈ mbedcrypto).
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=tfpsacrypto");

    // Compile ed25519 PSA accelerator driver
    cc::Build::new()
        .file(manifest_dir.join("csrc").join("ed25519_psa_driver.c"))
        .include(manifest_dir.join("csrc"))
        .include(mbedtls_src.join("tf-psa-crypto").join("include"))
        .include(
            mbedtls_src
                .join("tf-psa-crypto")
                .join("drivers")
                .join("builtin")
                .join("include"),
        )
        .include(mbedtls_src.join("include"))
        .warnings(false)
        .compile("ed25519_psa_driver");

    // generate rust bindings for mbedtls
    let include_paths: Vec<PathBuf> = vec![
        mbedtls_src.join("include"),
        mbedtls_src.join("tf-psa-crypto").join("include"),
        mbedtls_src
            .join("tf-psa-crypto")
            .join("drivers")
            .join("builtin")
            .join("include"),
        mbedtls_src.join("library"),
        mbedtls_src.join("tf-psa-crypto").join("core"),
        mbedtls_src
            .join("tf-psa-crypto")
            .join("drivers")
            .join("builtin")
            .join("src"),
    ];

    let mut builder = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_string_lossy())
        .allowlist_function("mbedtls_.*")
        .allowlist_function("psa_.*")
        .allowlist_type("mbedtls_.*")
        .allowlist_type("psa_.*")
        .allowlist_var("MBEDTLS_.*")
        .allowlist_var("PSA_.*")
        .allowlist_var("TF_PSA_CRYPTO_.*")
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .generate_comments(true)
        .prepend_enum_name(true)
        .layout_tests(false);

    for inc in &include_paths {
        builder = builder.clang_arg(format!("-I{}", inc.display()));
    }

    builder = builder
        .clang_arg("-DMBEDTLS_SSL_RECORD_SIZE_LIMIT")
        .clang_arg("-DMBEDTLS_SSL_NULL_CIPHERSUITES")
        .clang_arg("-DMBEDTLS_ED25519_PSA_DRIVER");

    if let Ok(sysroot) = env::var("BINDGEN_SYSROOT") {
        builder = builder.clang_arg(format!("--sysroot={sysroot}"));
    }

    let bindings = builder
        .generate()
        .expect("bindgen failed to generate bindings");

    let bindings_out = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&bindings_out)
        .expect("failed to write bindings.rs");
}

/// Download a URL to `dest` using curl.
fn download(url: &str, dest: &Path) {
    use std::io::Write;
    let mut res = ureq::get(url)
        .call()
        .expect("Failed to execute ureq request");
    assert_eq!(
        res.status(),
        200,
        "Failed to download file: HTTP {}",
        res.status()
    );
    let mut out = std::fs::File::create(dest).expect("Failed to create file for download");
    let data = res
        .body_mut()
        .read_to_vec()
        .expect("Failed to read response body");
    out.write_all(&data)
        .expect("Failed to write downloaded file.");

    let digest =
        sha256::try_digest(dest).expect("failed to compute SHA-256 digest of downloaded file");
    assert_eq!(digest, TARBALL_SHA, "SHA-256 mismatch for downloaded file");
}

/// Extract a `.tar.bz2` archive into `dest_dir`.
fn extract_tar_bz2(archive: &Path, dest_dir: &Path) {
    let file = std::fs::File::open(archive).expect("Failed to open archive for extraction");
    let decomp = bzip2::read::BzDecoder::new(file);
    let mut archive = tar::Archive::new(decomp);

    std::fs::create_dir_all(dest_dir)
        .expect("Failed to create destination directory for archive extraction");

    for file in archive
        .entries()
        .expect("Failed to read entries in tar file")
    {
        let mut file = file.expect("Failed to read entry in tar file");
        let path = file
            .path()
            .expect("Failed to get path of entry in tar file");
        let dest_path = dest_dir.join(path);
        if let Some(parent) = dest_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)
                .expect("Failed to create parent directory for extracted file");
        }
        file.unpack(dest_path)
            .expect("Failed to unpack entry in tar file");
    }
}

/// Apply a unified diff with `patch -p1`.
fn apply_patch(patch_file: &Path, work_dir: &Path) {
    let input = std::fs::read_to_string(patch_file).expect("Failed to read patch file");
    let lines = input.lines();
    // Split multi file diffs into per-file diff sections
    // strip the `diff ...` header
    let mut sections = Vec::new();
    let mut current_section = Vec::new();
    for line in lines {
        if line.starts_with("diff ") {
            if !current_section.is_empty() {
                let section = std::mem::take(&mut current_section);
                sections.push(section);
            }
            continue; // skip diff line
        }
        current_section.push(line);
    }
    if !current_section.is_empty() {
        sections.push(current_section);
    }

    for section in sections {
        let patch_str = section.join("\n") + "\n";
        let patch = diffy::Patch::from_str(&patch_str)
            .unwrap_or_else(|e| panic!("Unable to parse section: {e}\nSection:\n{patch_str}"));
        let file_path = patch
            .original()
            .or(patch.modified())
            .map(|file| file.trim_start_matches("a/").trim_start_matches("b/"))
            .expect("Patch section contains neither old nor new file.");
        let path = work_dir.join(file_path);
        eprintln!("Patching file: {}", path.to_string_lossy());
        let original_str = if patch.original().is_some() {
            std::fs::read_to_string(path.clone()).expect("Failed to read file")
        } else {
            String::new()
        };
        match diffy::apply(&original_str, &patch) {
            Err(e) => panic!("Failed to apply patch: {e}"),
            Ok(new_file) => std::fs::write(path, new_file).expect("failed to write patched file."),
        }
    }
}

/// Ensure `mbedtls-4.0.0/` exists in `workspace_dir`, downloading and
/// patching it if necessary.
fn ensure_mbedtls_source(workspace_dir: &Path) {
    let prefetched_source_var = std::env::var(MBEDTLS_SOURCE_OVERRIDE_VAR).ok();
    let skip_src_patch = std::env::var(MBEDTLS_SKIP_PATCH_VAR)
        .map(|v| v == "1")
        .unwrap_or(false);

    let mbedtls_dir = if let Some(dir) = prefetched_source_var {
        PathBuf::from(dir)
    } else {
        let dir = workspace_dir.join(format!("mbedtls-{MBEDTLS_VERSION}"));
        if !dir.join("CMakeLists.txt").exists() {
            eprintln!("mbedtls source not found — downloading {TARBALL_URL} …");

            let tarball = workspace_dir.join(format!("mbedtls-{MBEDTLS_VERSION}.tar.bz2"));
            download(TARBALL_URL, &tarball);
            extract_tar_bz2(&tarball, workspace_dir);

            // Remove the tarball after extraction.
            let _ = std::fs::remove_file(&tarball);
        }
        dir
    };

    if !mbedtls_dir.join("CMakeLists.txt").exists() {
        panic!("mbedtls source not found at {}", mbedtls_dir.display());
    }

    if skip_src_patch {
        eprintln!("Skipping source patches as requested by {MBEDTLS_SKIP_PATCH_VAR}=1");
        return;
    }

    if mbedtls_dir.join(".patch_marker").exists() {
        eprintln!("Source already patched, skipping patching.");
        return;
    }

    // Apply record-size-limit patch adding the extension for TLS1.2 aswell
    let patch_file = workspace_dir
        .join("patches")
        .join("record-size-limit-tls12.patch");
    if patch_file.exists() {
        eprintln!("Applying record-size-limit patch …");
        apply_patch(&patch_file, workspace_dir);
    } else {
        eprintln!(
            "warning: patch file {} not found — skipping",
            patch_file.display()
        );
    }

    // Apply Ed25519 PSA-driver patch adding ed25519 support for tls1.2
    let patch_file = workspace_dir
        .join("patches")
        .join("ed25519-psa-driver.patch");
    if patch_file.exists() {
        eprintln!("Applying Ed25519 patch …");
        apply_patch(&patch_file, workspace_dir);
    } else {
        eprintln!(
            "warning: patch file {} not found — skipping",
            patch_file.display()
        );
    }

    // Create a marker file to indicate that the source has been patched.
    std::fs::write(mbedtls_dir.join(".patch_marker"), "")
        .expect("Failed to write patch marker file");

    eprintln!("mbedtls {MBEDTLS_VERSION} ready.");
}
