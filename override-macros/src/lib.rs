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

use proc_macro::TokenStream;

mod shared;
mod vendor_overridable;
mod vendor_override;
mod vendor_override_registry;

fn render(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    result.unwrap_or_else(syn::Error::into_compile_error).into()
}

/// Generates a `linkme` distributed-slice hook and public dispatcher from a
/// fallback function.
///
/// Generic parameters used by reference in input types are erased through
/// `Any`. Return types may not reference generic parameters. Explicit lifetime
/// parameters, `self` parameters, and non-identifier parameter patterns are
/// unsupported. Async functions use boxed `Send` futures in generated hooks.
///
/// # Example
/// ```rust,ignore
/// #[override_macros::vendor_overridable(name = do_something)]
/// fn do_something_fallback(value: u32) -> u32 {
///     value
/// }
/// ```
///
/// This emits the unchanged fallback, a public `DO_SOMETHING_HOOK` distributed
/// slice, and the public `do_something` dispatcher. Documentation from the
/// fallback is forwarded to the dispatcher.
///
/// # Hook naming contract
///
/// Hook names are derived by upper-casing the dispatcher name and appending
/// `_HOOK` (`do_something` -> `DO_SOMETHING_HOOK`). [`macro@vendor_override`]
/// relies on this derivation, and vendor crates link against the generated
/// static by name. Renaming the dispatcher is therefore a breaking change for
/// its vendor overrides.
///
/// # Override registration
///
/// At most one override may be registered for each dispatcher. The defining
/// crate must invoke [`macro@declare_vendor_override_registry`] once at crate
/// root. Every [`macro@vendor_override`] then self-registers in that crate's
/// registry. Final binary must explicitly call generated
/// `<crate>::validate_vendor_overrides()` during startup; it reports duplicate
/// linked overrides, whose `linkme` ordering would otherwise be unspecified.
/// Dispatcher also contains a `debug_assert!` as a backstop for tests and
/// binaries that omit startup validation.
///
/// # Generic fallback functions
///
/// Parameters whose types mention generic parameters are type-erased to
/// `&dyn core::any::Any` or `&mut dyn core::any::Any` in the hook, while the
/// dispatcher preserves the original generic signature. Such hooks return
/// `Option<Ret>`: a concrete override returns `None` when a downcast fails, and
/// dispatcher then invokes the fallback.
///
/// ```rust,ignore
/// #[override_macros::vendor_overridable(name = do_something)]
/// fn do_something_fallback<S: SomeTrait>(mgr: &Manager<S>, level: &str) -> u32 {
///     42
/// }
/// ```
///
/// This generates a hook equivalent to
/// `fn(&dyn core::any::Any, &str) -> Option<u32>` and retains the generic
/// dispatcher signature.
///
/// Restrictions for generic fallbacks:
/// - erased parameters must be references; generic values passed by value are
///   rejected
/// - return type must not mention generic parameters
/// - erased concrete type must be `'static`, as required by `dyn Any`
/// - async erased shared references must be `Sync`, and mutable references must
///   be `Send`
/// - non-erased values must remain usable if override declines and fallback is
///   called; by-value parameters therefore generally need to be `Copy`
///
/// # General restrictions
///
/// Explicit lifetime parameters, `self` parameters, and parameter patterns
/// other than plain identifiers are unsupported. Elided lifetimes and async
/// functions are supported. Async override futures must be `Send`.
///
/// # Visibility requirement
///
/// Vendor overrides are cross-crate. Generated dispatcher and hook carry
/// `#[deny(unreachable_pub)]`; annotated function's module must be reachable
/// from crate root, directly or through a `pub use` re-export.
#[proc_macro_attribute]
pub fn vendor_overridable(attr: TokenStream, item: TokenStream) -> TokenStream {
    render(vendor_overridable::expand(attr.into(), item.into()))
}

/// Registers a function as vendor override for an overridable dispatcher.
///
/// Generic dispatcher parameters must be listed in `erase(...)` on the
/// concrete override. Hook paths require an explicit `crate::` or crate-name
/// prefix. Async override functions produce boxed `Send` hook futures.
///
/// # Example
/// ```rust,ignore
/// #[override_macros::vendor_override(crate_a::do_something)]
/// fn do_something_vendor(value: u32) -> u32 {
///     value + 1
/// }
/// ```
///
/// This derives the hook static from the final path segment using the stable
/// naming contract documented by [`macro@vendor_overridable`], then registers
/// the function in that `linkme` slice.
///
/// # Overriding generic functions
///
/// Write generic overrides with concrete parameter types and list every
/// type-erased parameter in `erase(...)`:
///
/// ```rust,ignore
/// #[override_macros::vendor_override(crate_a::do_something, erase(mgr))]
/// fn do_something_vendor(mgr: &Manager<MyPlugin>, level: &str) -> u32 {
///     7
/// }
/// ```
///
/// Macro emits original override plus a private shim. Shim downcasts each
/// erased argument to declared concrete type and returns `Some(result)`. A
/// failed downcast logs through `tracing::debug!` and returns `None`, causing
/// dispatcher to use fallback. Overriding crate therefore needs `tracing`.
/// Macro also emits a compile-time assertion that concrete parameter types,
/// return type, and trait bounds form a valid dispatcher instantiation.
///
/// Each attachment self-registers in defining crate's registry for duplicate
/// detection. Hook path's first segment locates that registry, so paths must be
/// `crate::...` or `crate_name::...`, never bare, `self::...`, or `super::...`.
/// Final binary must call defining crate's `validate_vendor_overrides()` during
/// startup. At most one override may target each dispatcher.
#[proc_macro_attribute]
pub fn vendor_override(attr: TokenStream, item: TokenStream) -> TokenStream {
    render(vendor_override::expand(attr.into(), item.into()))
}

/// Declares vendor-override registration state for the invoking crate.
///
/// Invoke exactly once at crate root in each crate defining overridable
/// functions. Generated `validate_vendor_overrides()` must be called explicitly
/// by the final binary during startup.
///
/// # Example
/// ```rust,ignore
/// override_macros::declare_vendor_override_registry!();
/// ```
///
/// This emits a hidden `linkme` distributed slice into which each
/// [`macro@vendor_override`] targeting this crate self-registers, plus:
///
/// ```rust,ignore
/// pub fn validate_vendor_overrides() -> Result<(), Vec<String>>
/// ```
///
/// `linkme` slices are assembled by linker, so duplicate registrations cannot
/// be checked at compile time. Final binary must call validator once during
/// startup, before invoking overridable functions:
///
/// ```rust,ignore
/// if let Err(errors) = cda_core::validate_vendor_overrides() {
///     panic!("Vendor override configuration error(s): {errors:?}");
/// }
/// ```
#[proc_macro]
pub fn declare_vendor_override_registry(input: TokenStream) -> TokenStream {
    render(vendor_override_registry::expand(input.into()))
}
