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

//! Vendor-neutral lock priority configuration.

use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};
use strum_macros::EnumString;

/// Default behavior when a lock request omits its exclusivity field.
#[derive(Clone, Copy, Debug, Serialize, EnumString, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[strum(ascii_case_insensitive, serialize_all = "snake_case")]
pub enum LockExclusivityPolicy {
    /// Omitted exclusivity means an exclusive lock.
    ExclusiveByDefault,
    /// Omitted exclusivity means a non-exclusive lock.
    NonExclusiveByDefault,
}

impl<'de> Deserialize<'de> for LockExclusivityPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Lock priority behavior and limits.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct LockConfig {
    /// Default used when `x_sovd2uds_isexclusive` is omitted.
    pub lock_exclusivity_policy: LockExclusivityPolicy,
    /// Maximum duration of one vendor priority-policy evaluation.
    pub priority_policy_timeout_ms: u64,
    /// Number of fresh policy evaluations allowed after a stale state snapshot.
    #[serde(default = "default_priority_policy_stale_retries")]
    pub priority_policy_stale_retries: u32,
    /// Maximum duration of one best-effort lifecycle callback.
    #[serde(default = "default_priority_lifecycle_timeout_ms")]
    pub priority_lifecycle_timeout_ms: u64,
    /// Number of lifecycle events buffered for ordered best-effort delivery.
    #[serde(default = "default_priority_lifecycle_queue_capacity")]
    pub priority_lifecycle_queue_capacity: usize,
}

const fn default_priority_policy_stale_retries() -> u32 {
    1
}

const fn default_priority_lifecycle_timeout_ms() -> u64 {
    5_000
}

const fn default_priority_lifecycle_queue_capacity() -> usize {
    256
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            lock_exclusivity_policy: LockExclusivityPolicy::ExclusiveByDefault,
            priority_policy_timeout_ms: 5_000,
            priority_policy_stale_retries: default_priority_policy_stale_retries(),
            priority_lifecycle_timeout_ms: default_priority_lifecycle_timeout_ms(),
            priority_lifecycle_queue_capacity: default_priority_lifecycle_queue_capacity(),
        }
    }
}

impl LockConfig {
    /// Resolves an omitted request exclusivity value through configured policy.
    #[must_use]
    pub fn resolve_exclusivity(&self, requested: Option<bool>) -> bool {
        requested.unwrap_or(matches!(
            self.lock_exclusivity_policy,
            LockExclusivityPolicy::ExclusiveByDefault
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusivity_policy_value_is_case_insensitive() {
        let config: LockConfig = serde_json::from_value(serde_json::json!({
            "lock_exclusivity_policy": "ExClUsIvE_bY_dEfAuLt",
            "priority_policy_timeout_ms": 1,
            "priority_policy_stale_retries": 1,
            "priority_lifecycle_timeout_ms": 1,
            "priority_lifecycle_queue_capacity": 1
        }))
        .expect("mixed-case policy value should deserialize");

        assert_eq!(
            config.lock_exclusivity_policy,
            LockExclusivityPolicy::ExclusiveByDefault
        );
    }

    #[test]
    fn exclusivity_policy_uses_canonical_serialized_value() {
        let value = serde_json::to_value(LockExclusivityPolicy::NonExclusiveByDefault)
            .expect("policy should serialize");

        assert_eq!(value, "non_exclusive_by_default");
    }

    #[test]
    fn invalid_exclusivity_policy_value_is_rejected() {
        let result = serde_json::from_str::<LockExclusivityPolicy>(r#""invalid""#);

        assert!(result.is_err());
    }

    #[test]
    fn default_exclusivity_is_resolved() {
        assert!(LockConfig::default().resolve_exclusivity(None));

        let config = LockConfig {
            lock_exclusivity_policy: LockExclusivityPolicy::NonExclusiveByDefault,
            ..LockConfig::default()
        };
        assert!(!config.resolve_exclusivity(None));
        assert!(config.resolve_exclusivity(Some(true)));
    }
}
