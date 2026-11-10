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

use serde::{Deserialize, Serialize};

use crate::config::{ConfigSanity, ConfigSanityError};

/// Default behavior when a lock request omits its exclusivity field.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LockExclusivityPolicy {
    /// Omitted exclusivity means an exclusive lock.
    ExclusiveByDefault,
    /// Omitted exclusivity means a non-exclusive lock.
    NonExclusiveByDefault,
}

/// Precondition for acquiring ECU and functional-group locks.
///
/// [[ dimpl~sovd-api-lock-acquisition-policy-config, Configurable lock acquisition policy, dimpl ]]
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum LockAcquisitionPolicy {
    /// ECU and functional-group locks may be acquired without a vehicle lock.
    #[default]
    Unrestricted,
    /// ECU and functional-group locks require an active vehicle lock, held by any client.
    VehicleLockRequired,
}

/// Lock priority behavior and limits.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct LockConfig {
    /// Default used when `x-sovd2uds-isexclusive` is omitted.
    pub lock_exclusivity_policy: LockExclusivityPolicy,
    /// Whether an active vehicle lock must exist before ECU or functional-group locks
    /// can be acquired.
    #[serde(default)]
    pub lock_acquisition_policy: LockAcquisitionPolicy,
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

impl ConfigSanity for LockConfig {
    fn validate_sanity(&self) -> Result<(), ConfigSanityError> {
        for (field, value) in [
            (
                "locks.priority_policy_timeout_ms",
                self.priority_policy_timeout_ms,
            ),
            (
                "locks.priority_lifecycle_timeout_ms",
                self.priority_lifecycle_timeout_ms,
            ),
        ] {
            if value == 0 {
                return Err(ConfigSanityError::InvalidValue {
                    field: field.to_owned(),
                    reason: "Value must be greater than zero".to_owned(),
                });
            }
        }
        if self.priority_lifecycle_queue_capacity == 0 {
            return Err(ConfigSanityError::InvalidValue {
                field: "locks.priority_lifecycle_queue_capacity".to_owned(),
                reason: "Value must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }
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
            lock_acquisition_policy: LockAcquisitionPolicy::default(),
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
    fn exclusivity_policy_value_deserializes() {
        let config: LockConfig = serde_json::from_value(serde_json::json!({
            "lock_exclusivity_policy": "exclusive_by_default",
            "priority_policy_timeout_ms": 1,
            "priority_policy_stale_retries": 1,
            "priority_lifecycle_timeout_ms": 1,
            "priority_lifecycle_queue_capacity": 1
        }))
        .expect("policy value should deserialize");

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

    /// [[ test~sovd-api-lock-acquisition-policy-config, Acquisition policy defaults to unrestricted and parses its values, test ]]
    #[test]
    fn acquisition_policy_defaults_to_unrestricted_when_omitted() {
        let config: LockConfig = serde_json::from_value(serde_json::json!({
            "lock_exclusivity_policy": "exclusive_by_default",
            "priority_policy_timeout_ms": 1
        }))
        .expect("config without acquisition policy should deserialize");

        assert_eq!(
            config.lock_acquisition_policy,
            LockAcquisitionPolicy::Unrestricted
        );
    }

    #[test]
    fn acquisition_policy_value_deserializes() {
        let policy = serde_json::from_str::<LockAcquisitionPolicy>(r#""vehicle_lock_required""#)
            .expect("policy value should deserialize");

        assert_eq!(policy, LockAcquisitionPolicy::VehicleLockRequired);
        assert!(serde_json::from_str::<LockAcquisitionPolicy>(r#""invalid""#).is_err());
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
