/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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


// This file is @generated - do not edit manually.
#![allow(clippy::all, warnings)]

";
#[cfg(any(feature = "gen-protos", feature = "gen-flatbuffers"))]
fn prepend_copyright(file_path: &str) -> std::io::Result<()> {
    let content = std::fs::read_to_string(file_path)?;
    let new_content = format!("{COPYRIGHT_HEADER}{content}");
    std::fs::write(file_path, new_content)?;
    Ok(())
}

#[cfg(all(feature = "gen-flatbuffers", feature = "trace-flatbuffers"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceMode {
    DebugValue,
    WipOffset,
    Skip,
}

fn trace_mode_for_return_type(ty: &syn::Type) -> TraceMode {
    if is_wip_offset(ty) {
        return TraceMode::WipOffset;
    }

    if is_debug_value_type(ty) {
        return TraceMode::DebugValue;
    }

    TraceMode::Skip
}

fn is_debug_value_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(reference) => {
            is_str_type(&reference.elem)
        }

        syn::Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return false;
            };

            let ident = segment.ident.to_string();

            matches!(
                ident.as_str(),
                "bool"
                    | "u8" | "u16" | "u32" | "u64" | "usize"
                    | "i8" | "i16" | "i32" | "i64" | "isize"
                    | "f32" | "f64"
            ) || is_option_of_debug_value(segment)
        }

        syn::Type::Tuple(tuple) => tuple.elems.is_empty(),

        _ => false,
    }
}

fn is_option_of_debug_value(segment: &syn::PathSegment) -> bool {
    if segment.ident != "Option" {
        return false;
    }

    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return false;
    };

    let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() else {
        return false;
    };

    is_debug_value_type(inner_ty)
}

fn is_str_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "str"),
        _ => false,
    }
}

fn is_wip_offset(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };

    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "WIPOffset")
}

fn instrument_flatbuffer_trace(file_path: &str) -> std::io::Result<()> {
    use quote::quote;
    use syn::{visit_mut::VisitMut, ImplItem, Item};

    struct Instrument {
        current_impl: Option<String>,
    }

    impl Instrument {
        fn wrap_block(
            &self,
            name: &str,
            output: &syn::ReturnType,
            old_block: syn::Block,
        ) -> syn::Block {
            let name_lit = syn::LitStr::new(name, proc_macro2::Span::call_site());

            let mode = match output {
                syn::ReturnType::Default => TraceMode::Skip,
                syn::ReturnType::Type(_, ty) => trace_mode_for_return_type(ty),
            };

            match mode {
                TraceMode::DebugValue => syn::parse_quote!({
                    let __fb_trace_return = { #old_block };
                    crate::__fb_trace::value_debug(#name_lit, &__fb_trace_return);
                    __fb_trace_return
                }),

                TraceMode::WipOffset => syn::parse_quote!({
                    let __fb_trace_return = { #old_block };
                    crate::__fb_trace::wip_offset(#name_lit, &__fb_trace_return);
                    __fb_trace_return
                }),

                TraceMode::Skip => old_block,
            }
        }
    }

    impl VisitMut for Instrument {
        fn visit_item_impl_mut(&mut self, item_impl: &mut syn::ItemImpl) {
            let previous = self.current_impl.clone();

            self.current_impl = Some(
                quote!(#item_impl.self_ty)
                    .to_string()
                    .replace(' ', ""),
            );

            syn::visit_mut::visit_item_impl_mut(self, item_impl);

            self.current_impl = previous;
        }

        fn visit_impl_item_mut(&mut self, item: &mut ImplItem) {
            if let ImplItem::Fn(func) = item {
                let fn_name = func.sig.ident.to_string();

                let full_name = match &self.current_impl {
                    Some(ty) => format!("{ty}::{fn_name}"),
                    None => fn_name,
                };

                let old_block = func.block.clone();

                func.block = self.wrap_block(
                    &full_name,
                    &func.sig.output,
                    old_block,
                );
            }

            syn::visit_mut::visit_impl_item_mut(self, item);
        }

        fn visit_item_mut(&mut self, item: &mut Item) {
            if let Item::Fn(func) = item {
                let fn_name = func.sig.ident.to_string();
                let old_block = (*func.block).clone();

                func.block = Box::new(self.wrap_block(
                    &fn_name,
                    &func.sig.output,
                    old_block,
                ));
            }

            syn::visit_mut::visit_item_mut(self, item);
        }
    }

    let content = std::fs::read_to_string(file_path)?;
    let mut ast = syn::parse_file(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Instrument { current_impl: None }.visit_file_mut(&mut ast);

    std::fs::write(file_path, prettyplease::unparse(&ast))?;
    Ok(())
}

#[cfg(any(
    not(feature = "gen-flatbuffers"),
    not(feature = "trace-flatbuffers")
))]
fn instrument_flatbuffer_trace(_: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(feature = "gen-flatbuffers")]
fn normalize_trailing_newline(file_path: &str) -> std::io::Result<()> {
    let content = std::fs::read_to_string(file_path)?;
    let normalized = format!("{}\n", content.trim_end_matches('\n'));
    std::fs::write(file_path, normalized)?;
    Ok(())
}

/// Build script for generating Rust code from Protocol Buffers definitions.
/// `prost_build` places the generated files in `OUT_DIR`.
/// This build script copies the generated files to the `src/proto/` directory
/// so they can be checked into the repository.
#[cfg(feature = "gen-protos")]
fn generate_protos() -> std::io::Result<()> {
    let mut config = prost_build::Config::new();
    // Emit `bytes::Bytes` instead of `Vec<u8>` for the chunk data field so that
    // protobuf decoding from an mmap-backed `Bytes` buffer produces zero-copy
    // sub-slices rather than heap-allocated copies.
    config.bytes([".fileformat.Chunk.data"]);
    config.compile_protos(&["proto/file_format.proto"], &["proto/"])?;

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
        .filter(|path| path.exists())
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
instrument_flatbuffer_trace(&final_file)?;
    normalize_trailing_newline(&final_file)?;

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

// allow using result as it is used when features are enabled
#[allow(clippy::unnecessary_wraps)]
fn main() -> std::io::Result<()> {
    cda_build::set_nightly_flag();

    #[cfg(feature = "gen-protos")]
    generate_protos()?;

    #[cfg(feature = "gen-flatbuffers")]
    generate_flatbuffers()?;

    Ok(())
}
