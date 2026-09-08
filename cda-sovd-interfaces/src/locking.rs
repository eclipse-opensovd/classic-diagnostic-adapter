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

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value};

use crate::Items;

/// Maximum number of opaque metadata entries accepted in one lock request.
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Maximum serialized JSON byte length of all opaque metadata in one lock request.
pub const MAX_METADATA_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Lock {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_expiration: Option<String>,

    /// If true, the SOVD client which performed the request owns the
    /// lock. The value is always false if the entity is not locked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_sovd2uds_broken_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_sovd2uds_broken_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Subject of the replacement lock holder, when that replacement still exists.
    /// This field is absent after the replacement lock is removed.
    pub x_sovd2uds_current_holder: Option<String>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Clone, Serialize, schemars::JsonSchema)]
#[schemars(rename = "CreateLockRequest")]
pub struct Request {
    pub lock_expiration: u64,
    #[serde(default)]
    pub break_lock: bool,
    #[serde(default)]
    pub x_sovd2uds_isexclusive: Option<bool>,
    #[serde(flatten)]
    pub metadata: Map<String, Value>,
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = Map::<String, Value>::deserialize(deserializer)?;
        let mut lock_expiration = None;
        let mut break_lock = None;
        let mut is_exclusive = None;
        let mut metadata = Map::new();

        for (key, value) in fields {
            if key.eq_ignore_ascii_case("lock_expiration") {
                set_once(&mut lock_expiration, value, "lock_expiration")?;
            } else if key.eq_ignore_ascii_case("break_lock") {
                set_once(&mut break_lock, value, "break_lock")?;
            } else if key.eq_ignore_ascii_case("x_sovd2uds_isexclusive") {
                set_once(&mut is_exclusive, value, "x_sovd2uds_isexclusive")?;
            } else {
                metadata.insert(key, value);
            }
        }
        validate_metadata::<D::Error>(&metadata)?;

        Ok(Self {
            lock_expiration: lock_expiration
                .ok_or_else(|| de::Error::missing_field("lock_expiration"))?,
            break_lock: break_lock.unwrap_or(false),
            x_sovd2uds_isexclusive: is_exclusive,
            metadata,
        })
    }
}

/// Request body for extending an existing lock.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
#[schemars(rename = "UpdateLockRequest", deny_unknown_fields)]
pub struct UpdateRequest {
    pub lock_expiration: u64,
}

impl<'de> Deserialize<'de> for UpdateRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = Map::<String, Value>::deserialize(deserializer)?;
        let mut lock_expiration = None;

        for (key, value) in fields {
            if key.eq_ignore_ascii_case("lock_expiration") {
                set_once(&mut lock_expiration, value, "lock_expiration")?;
            } else {
                return Err(de::Error::unknown_field(&key, &["lock_expiration"]));
            }
        }

        Ok(Self {
            lock_expiration: lock_expiration
                .ok_or_else(|| de::Error::missing_field("lock_expiration"))?,
        })
    }
}

fn set_once<E, T>(target: &mut Option<T>, value: Value, field: &'static str) -> Result<(), E>
where
    E: de::Error,
    T: for<'de> Deserialize<'de>,
{
    if target.is_some() {
        return Err(de::Error::duplicate_field(field));
    }
    *target = Some(serde_json::from_value(value).map_err(de::Error::custom)?);
    Ok(())
}

fn validate_metadata<E: de::Error>(metadata: &Map<String, Value>) -> Result<(), E> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(de::Error::custom(format!(
            "Lock metadata exceeds {MAX_METADATA_ENTRIES} entries"
        )));
    }
    let size = serde_json::to_vec(metadata)
        .map_err(de::Error::custom)?
        .len();
    if size > MAX_METADATA_SIZE {
        return Err(de::Error::custom(format!(
            "Lock metadata exceeds {MAX_METADATA_SIZE} serialized bytes"
        )));
    }
    Ok(())
}

impl From<Request> for chrono::DateTime<chrono::Utc> {
    fn from(value: Request) -> Self {
        chrono::Utc::now()
            .checked_add_signed(chrono::TimeDelta::seconds(
                value.lock_expiration.try_into().unwrap_or(i64::MAX),
            ))
            .unwrap_or(chrono::Utc::now())
    }
}

pub mod get {
    use super::{Items, Lock};

    pub type Response = Items<Lock>;
}

pub mod id {
    use super::{Deserialize, Serialize};
    pub mod get {
        use super::{Deserialize, Serialize};
        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        #[schemars(rename = "LockResponse")]
        pub struct Response {
            pub lock_expiration: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub x_sovd2uds_broken_by: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub x_sovd2uds_broken_at: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            /// Subject of the replacement lock holder, when that replacement still exists.
            /// This field is absent after the replacement lock is removed.
            pub x_sovd2uds_current_holder: Option<String>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_fields_ignore_case_without_changing_metadata() {
        let request: Request = serde_json::from_value(serde_json::json!({
            "LOCK_EXPIRATION": 60,
            "Break_Lock": true,
            "X_SOVD2UDS_IsExclusive": false,
            "VendorKey": {"MixedCase": "VaLuE"}
        }))
        .expect("Request should deserialize");

        assert_eq!(request.lock_expiration, 60);
        assert!(request.break_lock);
        assert_eq!(request.x_sovd2uds_isexclusive, Some(false));
        assert_eq!(
            request.metadata.get("VendorKey"),
            Some(&serde_json::json!({"MixedCase": "VaLuE"}))
        );
    }

    #[test]
    fn request_rejects_duplicate_case_insensitive_fields() {
        let result = serde_json::from_value::<Request>(serde_json::json!({
            "lock_expiration": 60,
            "LOCK_EXPIRATION": 120
        }));

        assert!(result.is_err());
    }

    #[test]
    fn request_rejects_too_many_metadata_entries() {
        let entries = (0..=MAX_METADATA_ENTRIES)
            .map(|index| (format!("key-{index}"), Value::Null))
            .collect::<Map<_, _>>();
        let mut request = entries;
        request.insert("lock_expiration".to_owned(), serde_json::json!(60));
        assert!(serde_json::from_value::<Request>(Value::Object(request)).is_err());
    }

    #[test]
    fn request_rejects_oversized_total_metadata() {
        let oversized = "x".repeat(MAX_METADATA_SIZE);
        let request = serde_json::json!({"lock_expiration": 60, "vendor": oversized});
        assert!(serde_json::from_value::<Request>(request).is_err());
    }

    #[test]
    fn request_accepts_metadata_at_total_size_limit() {
        let value_size = MAX_METADATA_SIZE - r#"{"vendor":""}"#.len();
        let request = serde_json::json!({
            "lock_expiration": 60,
            "vendor": "x".repeat(value_size)
        });

        assert!(serde_json::from_value::<Request>(request).is_ok());
    }

    #[test]
    fn request_accepts_nested_opaque_metadata() {
        let nested = (0..32).fold(Value::Null, |value, _| Value::Array(vec![value]));
        let request = serde_json::json!({"lock_expiration": 60, "vendor": nested});

        assert!(serde_json::from_value::<Request>(request).is_ok());
    }

    #[test]
    fn update_request_accepts_case_insensitive_expiration_and_serializes_canonical_name() {
        let request: UpdateRequest = serde_json::from_value(serde_json::json!({
            "LOCK_EXPIRATION": 60
        }))
        .expect("Update request should deserialize");

        assert_eq!(request.lock_expiration, 60);
        assert_eq!(
            serde_json::to_value(request).expect("Update request should serialize"),
            serde_json::json!({"lock_expiration": 60})
        );
    }

    #[test]
    fn update_request_rejects_create_fields_and_unknown_fields() {
        for field in [
            "break_lock",
            "BREAK_LOCK",
            "x_sovd2uds_isexclusive",
            "X_SOVD2UDS_ISEXCLUSIVE",
            "vendor_metadata",
        ] {
            let mut request = Map::new();
            request.insert("lock_expiration".to_owned(), serde_json::json!(60));
            request.insert(field.to_owned(), Value::Bool(true));
            assert!(serde_json::from_value::<UpdateRequest>(Value::Object(request)).is_err());
        }
    }

    #[test]
    fn update_request_schema_disallows_unknown_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(UpdateRequest))
            .expect("Update request schema should serialize");

        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            schema.get("required"),
            Some(&serde_json::json!(["lock_expiration"]))
        );
    }
}

pub mod post_put {
    use super::Lock;
    pub type Response = Lock;
}
