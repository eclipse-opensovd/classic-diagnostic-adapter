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

override_macros::declare_vendor_override_registry!();

pub trait SomeTrait: Send + Sync + 'static {}

pub struct PluginA;
impl SomeTrait for PluginA {}

pub struct PluginB;
impl SomeTrait for PluginB {}

pub struct Manager<S: SomeTrait> {
    value: u32,
    _plugin: S,
}

pub mod overridable {
    use super::{Manager, SomeTrait};

    #[override_macros::vendor_overridable(name = describe)]
    async fn describe_fallback(prefix: &str, value: u32) -> String {
        std::future::ready(()).await;
        format!("{prefix}: {value}")
    }

    #[override_macros::vendor_overridable(name = triple)]
    async fn triple_fallback(value: u32) -> u32 {
        std::future::ready(()).await;
        value.saturating_mul(3)
    }

    #[override_macros::vendor_overridable(name = compute)]
    async fn compute_fallback<S: SomeTrait>(mgr: &Manager<S>, base: u32) -> u32 {
        std::future::ready(()).await;
        let _ = mgr;
        base
    }

    #[override_macros::vendor_overridable(name = bump)]
    async fn bump_fallback<S: SomeTrait>(mgr: &mut Manager<S>, amount: u32) -> u32 {
        std::future::ready(()).await;
        mgr.value = mgr.value.saturating_add(amount);
        mgr.value
    }
}

#[override_macros::vendor_override(crate::overridable::describe)]
async fn describe_vendor(prefix: &str, value: u32) -> String {
    std::future::ready(()).await;
    format!("vendor {prefix}: {value}")
}

#[override_macros::vendor_override(crate::overridable::compute, erase(mgr))]
async fn compute_vendor(mgr: &Manager<PluginA>, base: u32) -> u32 {
    std::future::ready(()).await;
    mgr.value.saturating_add(base).saturating_add(1000)
}

#[override_macros::vendor_override(crate::overridable::bump, erase(mgr))]
async fn bump_vendor(mgr: &mut Manager<PluginA>, amount: u32) -> u32 {
    std::future::ready(()).await;
    mgr.value = mgr.value.saturating_add(amount.saturating_mul(2));
    mgr.value
}

#[tokio::test]
async fn plain_async_override_preserves_borrows() {
    let prefix = String::from("count");
    assert_eq!(overridable::describe(&prefix, 7).await, "vendor count: 7");
}

#[tokio::test]
async fn async_fallback_is_used_without_override() {
    assert_eq!(overridable::triple(4).await, 12);
}

#[tokio::test]
async fn generic_async_override_matches_concrete_type() {
    let mgr = Manager {
        value: 5,
        _plugin: PluginA,
    };
    assert_eq!(overridable::compute(&mgr, 3).await, 1008);
}

#[tokio::test]
async fn generic_async_override_falls_back_after_mismatch() {
    let mgr = Manager {
        value: 5,
        _plugin: PluginB,
    };
    assert_eq!(overridable::compute(&mgr, 3).await, 3);
}

#[tokio::test]
async fn mutable_generic_async_override_matches_and_falls_back() {
    let mut matching = Manager {
        value: 10,
        _plugin: PluginA,
    };
    assert_eq!(overridable::bump(&mut matching, 4).await, 18);

    let mut mismatching = Manager {
        value: 10,
        _plugin: PluginB,
    };
    assert_eq!(overridable::bump(&mut mismatching, 4).await, 14);
}

#[test]
fn all_overridables_have_at_most_one_registered_override() {
    assert_eq!(validate_vendor_overrides(), Ok(()));
}
