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

use cda_core::{OfflineServiceInfo, ServiceAudience};

use crate::extension::{FilterContext, ServiceFilter};

/// The standard ODX audiences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum StandardAudience {
    Supplier,
    Development,
    Manufacturing,
    #[value(name = "aftersales")]
    AfterSales,
    #[value(name = "aftermarket")]
    AfterMarket,
}

impl StandardAudience {
    fn is_set(self, audience: &ServiceAudience) -> bool {
        match self {
            Self::Supplier => audience.is_supplier,
            Self::Development => audience.is_development,
            Self::Manufacturing => audience.is_manufacturing,
            Self::AfterSales => audience.is_after_sales,
            Self::AfterMarket => audience.is_after_market,
        }
    }
}

/// [[ dimpl~openapi-gen-audience-filter, Default audience filter ]]
///
/// Default [`ServiceFilter`] based on the ODX audience of a service.
///
/// - Without any selected audience, every service is included.
/// - Services without an audience are not restricted and always included.
/// - Otherwise a service is included if one of the selected standard audiences
///   is set on it, or one of the selected additional audiences is enabled and
///   not disabled for it.
#[derive(Debug, Clone, Default)]
pub struct AudienceFilter {
    standard: Vec<StandardAudience>,
    additional: Vec<String>,
}

impl AudienceFilter {
    #[must_use]
    pub fn new(standard: Vec<StandardAudience>, additional: Vec<String>) -> Self {
        Self {
            standard,
            additional,
        }
    }

    /// Whether the filter has no audience selected and includes everything.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.standard.is_empty() && self.additional.is_empty()
    }

    fn matches(&self, audience: &ServiceAudience) -> bool {
        self.standard.iter().any(|a| a.is_set(audience))
            || self.additional.iter().any(|name| {
                audience.enabled_audiences.contains(name)
                    && !audience.disabled_audiences.contains(name)
            })
    }
}

impl ServiceFilter for AudienceFilter {
    fn include(&self, _ctx: &FilterContext<'_>, service: &OfflineServiceInfo) -> bool {
        match &service.audience {
            _ if self.is_unrestricted() => true,
            None => true,
            Some(audience) => self.matches(audience),
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_core::VariantInfo;

    use super::*;

    fn service(audience: Option<ServiceAudience>) -> OfflineServiceInfo {
        OfflineServiceInfo {
            short_name: "Svc".to_owned(),
            service_id: Some(0x22),
            semantic: None,
            functional_classes: Vec::new(),
            audience,
        }
    }

    fn include(filter: &AudienceFilter, svc: &OfflineServiceInfo) -> bool {
        let variant = VariantInfo {
            name: "V".to_owned(),
            is_base_variant: true,
        };
        filter.include(
            &FilterContext {
                ecu_name: "Ecu",
                variant: &variant,
            },
            svc,
        )
    }

    fn supplier_workshop() -> ServiceAudience {
        ServiceAudience {
            is_supplier: true,
            enabled_audiences: vec!["Workshop".to_owned()],
            disabled_audiences: vec!["Hidden".to_owned()],
            ..Default::default()
        }
    }

    /// [[ test~openapi-gen-audience-no-selection, No audience selected includes every service, test ]]
    #[test]
    fn no_selection_includes_everything() {
        let f = AudienceFilter::default();
        assert!(include(&f, &service(None)));
        assert!(include(&f, &service(Some(ServiceAudience::default()))));
    }

    #[test]
    fn unrestricted_service_is_always_included() {
        let f = AudienceFilter::new(vec![StandardAudience::AfterMarket], Vec::new());
        assert!(include(&f, &service(None)));
    }

    /// [[ test~openapi-gen-audience-standard, Standard audiences match the ODX flags, test ]]
    #[test]
    fn standard_audience_matches_flag() {
        let svc = service(Some(supplier_workshop()));
        assert!(include(
            &AudienceFilter::new(vec![StandardAudience::Supplier], Vec::new()),
            &svc
        ));
        assert!(!include(
            &AudienceFilter::new(vec![StandardAudience::Development], Vec::new()),
            &svc
        ));
    }

    /// [[ test~openapi-gen-audience-additional, Additional audiences respect enabled and disabled lists, test ]]
    #[test]
    fn additional_audience_respects_enabled_and_disabled() {
        let svc = service(Some(supplier_workshop()));
        assert!(include(
            &AudienceFilter::new(Vec::new(), vec!["Workshop".to_owned()]),
            &svc
        ));
        assert!(!include(
            &AudienceFilter::new(Vec::new(), vec!["Hidden".to_owned()]),
            &svc
        ));
        assert!(!include(
            &AudienceFilter::new(Vec::new(), vec!["Unknown".to_owned()]),
            &svc
        ));
    }
}
