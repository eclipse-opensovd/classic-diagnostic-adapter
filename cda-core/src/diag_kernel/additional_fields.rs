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

//! Membership of an ECU in the configured `/components` additional fields.
//!
//! The configured filters are fixed for the lifetime of the manager, but the SDGs an ECU
//! exposes depend on the detected variant. The result is therefore cached together with the
//! variant index it was computed for and recomputed only when the variant changes.

use std::sync::Arc;

use cda_interfaces::{
    HashMap,
    datatypes::{SdBoolMappings, SdSdg, check_sd_sdg_recursive},
    util::std_ext,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

/// Cached additional-field membership for one detected variant.
pub(in crate::diag_kernel) struct AdditionalFieldsCache {
    variant_index: Option<usize>,
    fields: Arc<[String]>,
}

/// Shared, immutable additional-field filters keyed by additional-field name.
pub(in crate::diag_kernel) type AdditionalFieldFilters = Arc<HashMap<String, SdBoolMappings>>;

/// Names of all `filters` that at least one of the `sdgs` satisfies, sorted.
fn matching_field_names(filters: &HashMap<String, SdBoolMappings>, sdgs: &[SdSdg]) -> Vec<String> {
    let mut names: Vec<String> = filters
        .iter()
        .filter(|(_, filter)| sdgs.iter().any(|sdg| check_sd_sdg_recursive(filter, sdg)))
        .map(|(name, _)| name.clone())
        .collect();
    names.sort_unstable();
    names
}

impl<S: SecurityPlugin> EcuManager<S> {
    /// Sets the additional-field filters used to derive request target group membership.
    #[must_use]
    pub fn with_additional_field_filters(
        mut self,
        filters: HashMap<String, SdBoolMappings>,
    ) -> Self {
        self.additional_field_filters = Arc::new(filters);
        self
    }

    /// Names of the configured additional fields this ECU currently belongs to, sorted.
    ///
    /// Computed once per detected variant. Returns an empty list if no filters are configured
    /// or the SDGs are not available (the failure is not cached).
    pub(in crate::diag_kernel) async fn matching_additional_fields(&self) -> Arc<[String]> {
        if self.additional_field_filters.is_empty() {
            return Arc::from([]);
        }
        let variant_index = std_ext::lock_read(&self.runtime_state.ecu_state).variant_index;
        if let Some(cached) = self.cached_additional_fields(variant_index) {
            return cached;
        }

        let sdgs = match self.sdgs_for_additional_fields().await {
            Ok(sdgs) => sdgs,
            Err(error) => {
                tracing::debug!(
                    ecu_name = %self.ecu_name,
                    %error,
                    "No SDGs available to resolve additional fields"
                );
                return Arc::from([]);
            }
        };
        let fields: Arc<[String]> =
            matching_field_names(&self.additional_field_filters, &sdgs).into();

        *std_ext::lock_mutex(&self.additional_fields_cache) = Some(AdditionalFieldsCache {
            variant_index,
            fields: Arc::clone(&fields),
        });
        fields
    }

    /// Pre-populates the cache, for tests whose database has no SDGs to derive fields from.
    #[cfg(test)]
    pub(in crate::diag_kernel) fn seed_additional_fields_cache(
        &self,
        variant_index: Option<usize>,
        fields: &[&str],
    ) {
        *std_ext::lock_mutex(&self.additional_fields_cache) = Some(AdditionalFieldsCache {
            variant_index,
            fields: fields.iter().map(ToString::to_string).collect(),
        });
    }

    fn cached_additional_fields(&self, variant_index: Option<usize>) -> Option<Arc<[String]>> {
        std_ext::lock_mutex(&self.additional_fields_cache)
            .as_ref()
            .filter(|cache| cache.variant_index == variant_index)
            .map(|cache| Arc::clone(&cache.fields))
    }

    async fn sdgs_for_additional_fields(
        &self,
    ) -> Result<Vec<SdSdg>, cda_interfaces::DiagServiceError> {
        use cda_interfaces::EcuManager as _;
        self.sdgs(None).await
    }
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::database_builder::EcuDataBuilder;
    use cda_interfaces::{HashSet, Protocol, datatypes::SdMappingsTruthyValue};
    use cda_plugin_security::DefaultSecurityPluginData;

    use super::*;
    use crate::diag_kernel::test_utils::{
        db_builder::finish_db, ecu_manager_builder::new_ecu_manager,
    };

    fn filter(si: &str, values: &[&str], ignore_case: bool) -> SdBoolMappings {
        HashMap::from_iter([(
            si.to_owned(),
            SdMappingsTruthyValue::new(
                values
                    .iter()
                    .map(ToString::to_string)
                    .collect::<HashSet<_>>(),
                ignore_case,
            ),
        )])
    }

    fn filters() -> HashMap<String, SdBoolMappings> {
        HashMap::from_iter([
            (
                "x-lin".to_owned(),
                filter("LIN", &["LIN Class 3", "yes"], true),
            ),
            ("x-obd".to_owned(), filter("OBD", &["OBD"], false)),
        ])
    }

    fn sd_group(si: &str, value: &str) -> SdSdg {
        SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![SdSdg::Sd {
                value: Some(value.to_owned()),
                si: Some(si.to_owned()),
                ti: None,
            }],
        }
    }

    fn manager() -> EcuManager<DefaultSecurityPluginData> {
        let mut builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = builder.create_protocol(&protocol_name, None, None, None);
        new_ecu_manager(finish_db!(builder, protocol, vec![]))
    }

    fn cache(variant_index: Option<usize>, fields: &[&str]) -> AdditionalFieldsCache {
        AdditionalFieldsCache {
            variant_index,
            fields: fields.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn matches_whole_field_names_and_sorts_them() {
        let sdgs = [sd_group("OBD", "OBD"), sd_group("LIN", "lin class 3")];
        assert_eq!(matching_field_names(&filters(), &sdgs), ["x-lin", "x-obd"]);
    }

    #[test]
    fn only_fields_with_a_matching_sd_are_reported() {
        let sdgs = [sd_group("LIN", "yes")];
        assert_eq!(matching_field_names(&filters(), &sdgs), ["x-lin"]);
        assert!(matching_field_names(&filters(), &[]).is_empty());
        // `x-obd` is case sensitive, so a differently cased value does not match.
        assert!(matching_field_names(&filters(), &[sd_group("OBD", "obd")]).is_empty());
    }

    #[tokio::test]
    async fn no_filters_means_no_fields() {
        assert!(manager().matching_additional_fields().await.is_empty());
    }

    #[tokio::test]
    async fn cached_result_is_reused_for_the_same_variant() {
        let manager = manager().with_additional_field_filters(filters());
        // The test database has no SDGs, so a recomputation could never yield `x-lin`.
        *std_ext::lock_mutex(&manager.additional_fields_cache) = Some(cache(Some(0), &["x-lin"]));

        assert_eq!(&*manager.matching_additional_fields().await, ["x-lin"]);
    }

    #[tokio::test]
    async fn variant_change_discards_the_cached_result() {
        let manager = manager().with_additional_field_filters(filters());
        *std_ext::lock_mutex(&manager.additional_fields_cache) = Some(cache(Some(1), &["x-lin"]));

        // The manager reports variant 0, so the entry for variant 1 is stale and the
        // (unavailable) SDGs are consulted instead.
        assert!(manager.matching_additional_fields().await.is_empty());
    }

    #[tokio::test]
    async fn unavailable_sdgs_are_not_cached() {
        let manager = manager().with_additional_field_filters(filters());

        assert!(manager.matching_additional_fields().await.is_empty());
        assert!(std_ext::lock_mutex(&manager.additional_fields_cache).is_none());
    }
}
