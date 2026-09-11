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
use syn::{Ident, Lifetime, Path, Type, visit::Visit, visit_mut::VisitMut};

/// Returns `true` if any typed parameter in the signature contains a reference.
pub(crate) fn has_borrowed_input(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>,
) -> bool {
    struct ContainsReference(bool);

    impl<'ast> Visit<'ast> for ContainsReference {
        fn visit_type_reference(&mut self, reference: &'ast syn::TypeReference) {
            self.0 = true;
            syn::visit::visit_type_reference(self, reference);
        }
    }

    inputs.iter().any(|arg| match arg {
        syn::FnArg::Typed(pat_type) => {
            let mut v = ContainsReference(false);
            v.visit_type(&pat_type.ty);
            v.0
        }
        syn::FnArg::Receiver(_) => false,
    })
}

/// Visitor that checks whether a type mentions any given type or const generic.
///
/// A path counts when its first segment matches a generic parameter. This
/// covers plain uses (`S`), associated types (`S::Assoc`), and const parameters
/// (`N`); generics shadow outer items with the same name in the signature.
pub(crate) struct MentionsGenerics<'a> {
    generics: &'a [Ident],
    found: bool,
}

impl<'ast> Visit<'ast> for MentionsGenerics<'_> {
    fn visit_path(&mut self, path: &'ast Path) {
        if path.leading_colon.is_none()
            && let Some(segment) = path.segments.first()
            && self.generics.contains(&segment.ident)
        {
            self.found = true;
        }
        syn::visit::visit_path(self, path);
    }
}

impl MentionsGenerics<'_> {
    /// Returns `true` if the type mentions any of the given generic parameters.
    pub(crate) fn check(ty: &Type, generics: &[Ident]) -> bool {
        let mut visitor = MentionsGenerics {
            generics,
            found: false,
        };
        visitor.visit_type(ty);
        visitor.found
    }
}

/// Assigns one generated lifetime to every elided reference in a type.
///
/// Names elided reference lifetimes so they can appear inside a boxed future.
pub(crate) struct NameElidedLifetimes<'a> {
    lifetime: &'a Lifetime,
}

impl VisitMut for NameElidedLifetimes<'_> {
    fn visit_type_reference_mut(&mut self, reference: &mut syn::TypeReference) {
        if reference.lifetime.is_none() {
            reference.lifetime = Some(self.lifetime.clone());
        }
        syn::visit_mut::visit_type_reference_mut(self, reference);
    }
}

impl NameElidedLifetimes<'_> {
    /// Returns a copy of `ty` with every elided lifetime replaced by `lifetime`.
    pub(crate) fn apply(ty: &Type, lifetime: &Lifetime) -> Type {
        let mut ty = ty.clone();
        NameElidedLifetimes { lifetime }.visit_type_mut(&mut ty);
        ty
    }
}

/// Extracts a plain identifier from a typed function parameter.
///
/// Generated dispatchers and shims forward parameters by name, so `mut`,
/// `ref`, destructuring, and subpatterns cannot be supported.
pub(crate) fn param_ident(pat_type: &syn::PatType) -> syn::Result<Ident> {
    match pat_type.pat.as_ref() {
        syn::Pat::Ident(pattern)
            if pattern.by_ref.is_none()
                && pattern.mutability.is_none()
                && pattern.subpat.is_none() =>
        {
            Ok(pattern.ident.clone())
        }
        pattern => Err(syn::Error::new_spanned(
            pattern,
            "Parameters must be plain identifiers (no `mut`, `ref`, or pattern destructuring)",
        )),
    }
}

/// Derives the stable hook name, e.g. `do_something` -> `DO_SOMETHING_HOOK`.
///
/// Vendor crates link against this generated name, making the naming scheme
/// part of the vendor-override contract.
pub(crate) fn hook_ident_for(name: &Ident) -> Ident {
    Ident::new(
        &format!("{}_HOOK", name.to_string().to_uppercase()),
        name.span(),
    )
}

/// Derives crate-root registry paths from the first segment of a hook path.
///
/// Bare, `self::`, and `super::` paths cannot identify the defining crate's
/// registry unambiguously from every potential override site.
pub(crate) fn registry_paths(
    hook_path: &Path,
) -> syn::Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    if hook_path.segments.len() < 2 {
        return Err(syn::Error::new_spanned(
            hook_path,
            "vendor_override: hook path must include an explicit crate segment, e.g. \
             `crate::name` or `crate_name::name`",
        ));
    }
    let first_segment = hook_path.segments.first().ok_or_else(|| {
        syn::Error::new_spanned(hook_path, "vendor_override: expected a non-empty path")
    })?;
    if first_segment.ident == "self" || first_segment.ident == "super" {
        return Err(syn::Error::new_spanned(
            first_segment,
            "vendor_override: hook path must be written as `crate::...` or `crate_name::...` (not \
             `self::` or `super::`)",
        ));
    }
    let leading_colon = &hook_path.leading_colon;
    let crate_root = &first_segment.ident;
    Ok((
        quote! { #leading_colon #crate_root::__VENDOR_OVERRIDE_REGISTRY },
        quote! { #leading_colon #crate_root::__VendorOverrideRegistration },
    ))
}

/// Derives an override registration static name from the override function.
///
/// For example, `do_something_vendor` becomes
/// `__DO_SOMETHING_VENDOR_OVERRIDE_REG`.
pub(crate) fn registration_ident_for(name: &Ident) -> Ident {
    Ident::new(
        &format!("__{}_OVERRIDE_REG", name.to_string().to_uppercase()),
        name.span(),
    )
}
