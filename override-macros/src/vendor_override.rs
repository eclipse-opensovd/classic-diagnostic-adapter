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

use quote::quote;
use syn::{
    Ident, ItemFn, Path, ReturnType, Token, Type, Visibility,
    parse::{Parse, ParseStream},
    parse_quote, parse2,
    punctuated::Punctuated,
};

use crate::shared::{hook_ident_for, param_ident, registration_ident_for, registry_paths};

/// Parses `path::to::function` and optional `, erase(param, ...)` arguments.
struct Args {
    hook_path: Path,
    erased: Vec<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let hook_path = input.parse()?;
        let mut erased = Vec::new();
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            let key: Ident = input.parse()?;
            if key != "erase" {
                return Err(syn::Error::new(key.span(), "Expected `erase(param, ...)`"));
            }
            let content;
            syn::parenthesized!(content in input);
            erased = Punctuated::<Ident, Token![,]>::parse_terminated(&content)?
                .into_iter()
                .collect();
        }
        Ok(Self { hook_path, erased })
    }
}

/// Pieces needed to adapt a concrete override to a type-erased hook.
///
/// Bindings downcast erased parameters, call arguments invoke the real
/// override, and assertion types verify its concrete signature against the
/// public dispatcher at compile time.
struct ShimParts {
    shim_params: Punctuated<syn::FnArg, Token![,]>,
    shim_bindings: Vec<proc_macro2::TokenStream>,
    shim_call_args: Vec<proc_macro2::TokenStream>,
    assert_param_types: Vec<proc_macro2::TokenStream>,
}

/// Builds a type-erasing shim and validates every name in `erase(...)`.
///
/// Erased parameters must be references because `Any` downcasts borrowed
/// values without transferring ownership.
fn build_shim_parts(func: &ItemFn, erased: &[Ident], fn_name: &str) -> syn::Result<ShimParts> {
    let param_names: Vec<&Ident> = func
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match pat_type.pat.as_ref() {
                syn::Pat::Ident(pattern) => Some(&pattern.ident),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    for name in erased {
        if !param_names.contains(&name) {
            return Err(syn::Error::new(
                name.span(),
                format!("vendor_override: no parameter named `{name}` in `{fn_name}`"),
            ));
        }
    }

    let mut shim_params = Punctuated::new();
    let mut shim_bindings = Vec::new();
    let mut shim_call_args = Vec::new();
    let mut assert_param_types = Vec::new();
    for arg in &func.sig.inputs {
        let syn::FnArg::Typed(pat_type) = arg else {
            return Err(syn::Error::new_spanned(
                arg,
                "vendor_override does not support `self` parameters",
            ));
        };
        let ident = param_ident(pat_type)?;
        let ty = &pat_type.ty;
        assert_param_types.push(quote! { #ty });

        if erased.contains(&ident) {
            let Type::Reference(reference) = ty.as_ref() else {
                return Err(syn::Error::new_spanned(
                    ty,
                    "vendor_override: erased parameters must be references (`&Type` or `&mut \
                     Type`)",
                ));
            };
            let concrete_ty = &reference.elem;
            let (any_ty, downcast) = if reference.mutability.is_some() {
                (
                    quote! { &mut dyn ::core::any::Any },
                    quote! { downcast_mut },
                )
            } else {
                (quote! { &dyn ::core::any::Any }, quote! { downcast_ref })
            };
            shim_params.push(parse_quote!(#ident: #any_ty));
            shim_bindings.push(quote! {
                let Some(#ident) = #ident.#downcast::<#concrete_ty>() else {
                    ::tracing::debug!(
                        "Vendor override `{}`: downcast of `{}` to `{}` failed, falling back to \
                         the default implementation",
                        #fn_name,
                        stringify!(#ident),
                        stringify!(#concrete_ty),
                    );
                    return ::core::option::Option::None;
                };
            });
        } else {
            shim_params.push(arg.clone());
        }
        shim_call_args.push(quote! { #ident });
    }

    Ok(ShimParts {
        shim_params,
        shim_bindings,
        shim_call_args,
        assert_param_types,
    })
}

pub(crate) fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let args = parse2::<Args>(attr)?;
    let func = parse2::<ItemFn>(item)?;
    if let Some(asyncness) = func.sig.asyncness {
        return Err(syn::Error::new_spanned(
            asyncness,
            "vendor_override does not support async functions",
        ));
    }

    let public_fn_path = args.hook_path.clone();
    let hook_path = {
        let mut hook_path = args.hook_path;
        let Some(last_segment) = hook_path.segments.last_mut() else {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "vendor_override: expected a non-empty path",
            ));
        };
        last_segment.ident = hook_ident_for(&last_segment.ident);
        hook_path
    };
    let (registry_path, registration_type_path) = registry_paths(&hook_path)?;
    let fn_ident = &func.sig.ident;
    let registration_ident = registration_ident_for(fn_ident);
    let registration = quote! {
        #[::linkme::distributed_slice(#registry_path)]
        #[doc(hidden)]
        static #registration_ident: #registration_type_path = #registration_type_path {
            hook_name: stringify!(#public_fn_path),
            count: || #hook_path.len(),
        };
    };

    if args.erased.is_empty() {
        return Ok(quote! {
            #[::linkme::distributed_slice(#hook_path)]
            #func

            #registration
        });
    }

    let fn_name = fn_ident.to_string();
    let shim_ident = Ident::new(
        &format!("__{fn_name}_vendor_override_shim"),
        fn_ident.span(),
    );
    let ret_ty = match &func.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    };
    let ShimParts {
        shim_params,
        shim_bindings,
        shim_call_args,
        assert_param_types,
    } = build_shim_parts(&func, &args.erased, &fn_name)?;

    // Keep the original override intact. Register a private ABI adapter that
    // downcasts erased arguments and returns `None` when concrete types differ.
    let mut shim_fn = func.clone();
    shim_fn.attrs = vec![parse_quote!(#[::linkme::distributed_slice(#hook_path)])];
    shim_fn.vis = Visibility::Inherited;
    shim_fn.sig.ident = shim_ident;
    shim_fn.sig.inputs = shim_params;
    shim_fn.sig.output = parse_quote!(-> ::core::option::Option<#ret_ty>);
    shim_fn.block = parse_quote!({
        #(#shim_bindings)*
        ::core::option::Option::Some(#fn_ident(#(#shim_call_args),*))
    });

    Ok(quote! {
        #func

        // Ensure the concrete override is a valid instantiation of the public
        // dispatcher, including parameter types, return type, and trait bounds.
        const _: fn(#(#assert_param_types),*) -> #ret_ty = #public_fn_path;

        #shim_fn

        #registration
    })
}

#[cfg(test)]
mod tests {
    use quote::quote;

    #[test]
    fn rejects_async_override() {
        let result = super::expand(
            quote!(crate_name::lookup),
            quote!(
                async fn lookup_override(value: u32) -> u32 {
                    value
                }
            ),
        );

        let error = result.expect_err("async override must be rejected");
        assert!(error.to_string().contains("does not support async"));
    }
}
