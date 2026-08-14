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
    Ident, ItemFn, ReturnType, Token, Type, Visibility,
    parse::{Parse, ParseStream},
    parse_quote, parse2,
    punctuated::Punctuated,
};

use crate::shared::{hook_ident_for, mentions_generics, param_ident};

/// Parses `name = <ident>` from `vendor_overridable` arguments.
struct Args {
    name: Ident,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let key: Ident = input.parse()?;
        if key != "name" {
            return Err(syn::Error::new(key.span(), "Expected `name = <ident>`"));
        }
        input.parse::<Token![=]>()?;
        Ok(Self {
            name: input.parse()?,
        })
    }
}

/// Hook types and forwarding expressions after generic parameters are erased.
///
/// `hook_call_args` invoke an override, while `fallback_call_args` preserve the
/// original typed arguments for fallback. `any_erased` controls the hook's
/// `Option<Ret>` protocol used to report a failed runtime downcast.
struct HookParams {
    hook_param_types: Vec<proc_macro2::TokenStream>,
    hook_call_args: Vec<proc_macro2::TokenStream>,
    fallback_call_args: Vec<proc_macro2::TokenStream>,
    any_erased: bool,
}

/// Builds hook parameter types and forwarding expressions.
///
/// Parameters mentioning a generic become `&dyn Any` or `&mut dyn Any`.
/// Generic values passed by value cannot be erased while preserving ownership,
/// so they are rejected.
fn build_hook_params(
    inputs: &Punctuated<syn::FnArg, Token![,]>,
    generic_idents: &[Ident],
) -> syn::Result<HookParams> {
    let mut hook_param_types = Vec::new();
    let mut hook_call_args = Vec::new();
    let mut fallback_call_args = Vec::new();
    let mut any_erased = false;

    for arg in inputs {
        let syn::FnArg::Typed(pat_type) = arg else {
            return Err(syn::Error::new_spanned(
                arg,
                "vendor_overridable does not support `self` parameters",
            ));
        };
        let ident = param_ident(pat_type)?;
        let ty = &pat_type.ty;
        fallback_call_args.push(quote! { #ident });

        if mentions_generics(ty, generic_idents) {
            match ty.as_ref() {
                Type::Reference(reference) if reference.mutability.is_none() => {
                    any_erased = true;
                    hook_param_types.push(quote! { &dyn ::core::any::Any });
                    hook_call_args.push(quote! { #ident as &dyn ::core::any::Any });
                }
                Type::Reference(_) => {
                    any_erased = true;
                    hook_param_types.push(quote! { &mut dyn ::core::any::Any });
                    hook_call_args.push(quote! { &mut *#ident as &mut dyn ::core::any::Any });
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        ty,
                        "vendor_overridable: generic parameters must be references (`&Type<S>` or \
                         `&mut Type<S>`) to be type-erasable",
                    ));
                }
            }
        } else {
            hook_param_types.push(quote! { #ty });
            hook_call_args.push(quote! { #ident });
        }
    }

    Ok(HookParams {
        hook_param_types,
        hook_call_args,
        fallback_call_args,
        any_erased,
    })
}

pub(crate) fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let args = parse2::<Args>(attr)?;
    let fallback_fn = parse2::<ItemFn>(item)?;
    if let Some(asyncness) = fallback_fn.sig.asyncness {
        return Err(syn::Error::new_spanned(
            asyncness,
            "vendor_overridable does not support async functions",
        ));
    }
    if let Some(lifetime) = fallback_fn.sig.generics.lifetimes().next() {
        return Err(syn::Error::new_spanned(
            lifetime,
            "vendor_overridable: explicit lifetime parameters are not supported; use elided \
             lifetimes instead",
        ));
    }

    let public_name = args.name;
    let hook_ident = hook_ident_for(&public_name);
    let fallback_ident = fallback_fn.sig.ident.clone();
    let generic_idents: Vec<Ident> = fallback_fn
        .sig
        .generics
        .type_params()
        .map(|param| param.ident.clone())
        .chain(
            fallback_fn
                .sig
                .generics
                .const_params()
                .map(|param| param.ident.clone()),
        )
        .collect();
    let ret_ty = match &fallback_fn.sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => {
            if mentions_generics(ty, &generic_idents) {
                return Err(syn::Error::new_spanned(
                    ty,
                    "vendor_overridable: return type must not mention generic parameters",
                ));
            }
            quote! { #ty }
        }
    };
    let HookParams {
        hook_param_types,
        hook_call_args,
        fallback_call_args,
        any_erased,
    } = build_hook_params(&fallback_fn.sig.inputs, &generic_idents)?;

    let doc_attrs: Vec<syn::Attribute> = fallback_fn
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .cloned()
        .collect();
    let dispatcher_doc = format!(
        "Vendor-overridable dispatcher generated from [`{fallback_ident}`]. Vendor overrides \
         register through [`{hook_ident}`]."
    );
    let hook_doc = format!("Registration hook for vendor overrides of [`{public_name}`].");

    let mut dispatcher_fn = fallback_fn.clone();
    dispatcher_fn.attrs = doc_attrs;
    dispatcher_fn.attrs.push(parse_quote!(#[doc = ""]));
    dispatcher_fn
        .attrs
        .push(parse_quote!(#[doc = #dispatcher_doc]));
    dispatcher_fn.attrs.push(parse_quote!(
        #[deny(unreachable_pub, reason = "vendor_overridable items must be reachable from the \
            crate root so external crates can register overrides")]
    ));
    dispatcher_fn.vis = Visibility::Public(parse_quote!(pub));
    dispatcher_fn.sig.ident = public_name.clone();
    // Erased hooks return `Option<Ret>` so a failed downcast can fall through
    // to the typed fallback. Non-erased hooks can return directly.
    let override_dispatch = if any_erased {
        quote! {
            if let Some(overridden_fn) = #hook_ident.first()
                && let Some(result) = overridden_fn(#(#hook_call_args),*)
            {
                return result;
            }
        }
    } else {
        quote! {
            if let Some(overridden_fn) = #hook_ident.first() {
                return overridden_fn(#(#hook_call_args),*);
            }
        }
    };
    dispatcher_fn.block = parse_quote!({
        debug_assert!(
            #hook_ident.len() <= 1,
            "Multiple vendor overrides registered for `{}`; at most one override is supported \
             per overridable function",
            stringify!(#public_name),
        );
        #override_dispatch
        #fallback_ident(#(#fallback_call_args),*)
    });

    let hook_return = if any_erased {
        quote! { ::core::option::Option<#ret_ty> }
    } else {
        ret_ty
    };
    Ok(quote! {
        #fallback_fn

        #[::linkme::distributed_slice]
        #[deny(unreachable_pub, reason = "vendor_overridable items must be reachable from the \
            crate root so external crates can register overrides")]
        #[doc = #hook_doc]
        pub static #hook_ident: [fn(#(#hook_param_types),*) -> #hook_return];

        #dispatcher_fn
    })
}

#[cfg(test)]
mod tests {
    use quote::quote;

    #[test]
    fn rejects_async_fallback() {
        let result = super::expand(
            quote!(name = lookup),
            quote!(
                async fn lookup_fallback(value: u32) -> u32 {
                    value
                }
            ),
        );

        let error = result.expect_err("async fallback must be rejected");
        assert!(error.to_string().contains("does not support async"));
    }
}
