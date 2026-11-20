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

//! Offline access to the ECU description.
//!
//! These functions work without any ECU communication and are intended for tools
//! like the standalone `OpenAPI` generator, which need to inspect a single variant
//! of an MDD file without performing a variant detection.

use cda_database::datatypes;
use cda_interfaces::{
    DiagServiceError, HashMap, VariantState,
    datatypes::{ComponentConfigurationsInfo, ComponentDataInfo, ComponentOperationsInfo},
    service_ids,
    util::std_ext,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

/// A variant contained in the ECU description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantInfo {
    /// Short name of the variant.
    pub name: String,
    /// Whether this is the base variant of the ECU.
    pub is_base_variant: bool,
}

/// Owned copy of the ODX audience of a diagnostic service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Mirrors the boolean audience flags defined by ODX"
)]
pub struct ServiceAudience {
    pub is_supplier: bool,
    pub is_development: bool,
    pub is_manufacturing: bool,
    pub is_after_sales: bool,
    pub is_after_market: bool,
    /// Short names of the enabled additional audiences.
    pub enabled_audiences: Vec<String>,
    /// Short names of the disabled additional audiences.
    pub disabled_audiences: Vec<String>,
}

/// Owned description of a diagnostic service, used to decide offline whether a
/// service is visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineServiceInfo {
    /// Untrimmed short name of the service.
    pub short_name: String,
    /// UDS service identifier of the request, if known.
    pub service_id: Option<u8>,
    /// Semantic of the service, if defined.
    pub semantic: Option<String>,
    /// Short names of the functional classes the service belongs to.
    pub functional_classes: Vec<String>,
    /// The audience of the service. `None` means the service is not restricted.
    pub audience: Option<ServiceAudience>,
}

impl OfflineServiceInfo {
    fn from_service(service: &datatypes::DiagService<'_>) -> Self {
        Self::from_diag_comm(
            service.diag_comm().map(datatypes::DiagComm).as_ref(),
            service.request_id(),
        )
    }

    fn from_single_ecu_job(job: &datatypes::SingleEcuJob<'_>) -> Self {
        Self::from_diag_comm(job.diag_comm().map(datatypes::DiagComm).as_ref(), None)
    }

    fn from_diag_comm(diag_comm: Option<&datatypes::DiagComm<'_>>, service_id: Option<u8>) -> Self {
        let audience = diag_comm.and_then(|dc| dc.audience()).map(|a| {
            // The flatbuffer vector type is not exported by cda-database, hence a macro.
            macro_rules! names {
                ($v:expr) => {
                    $v.into_iter()
                        .flatten()
                        .filter_map(|aa| aa.short_name().map(ToOwned::to_owned))
                        .collect()
                };
            }
            ServiceAudience {
                is_supplier: a.is_supplier(),
                is_development: a.is_development(),
                is_manufacturing: a.is_manufacturing(),
                is_after_sales: a.is_after_sales(),
                is_after_market: a.is_after_market(),
                enabled_audiences: names!(a.enabled_audiences()),
                disabled_audiences: names!(a.disabled_audiences()),
            }
        });
        Self {
            short_name: diag_comm
                .and_then(|dc| dc.short_name())
                .unwrap_or_default()
                .to_owned(),
            service_id,
            semantic: diag_comm
                .and_then(|dc| dc.semantic())
                .map(ToOwned::to_owned),
            functional_classes: diag_comm
                .and_then(|dc| dc.funct_class())
                .into_iter()
                .flatten()
                .filter_map(|fc| fc.short_name().map(ToOwned::to_owned))
                .collect(),
            audience,
        }
    }
}

/// [[ dimpl~openapi-gen-offline-ecu-access, Offline variant selection and service listing ]]
impl<S: SecurityPlugin> EcuManager<S> {
    /// Returns all variants contained in the ECU description.
    #[must_use]
    pub fn variants(&self) -> Vec<VariantInfo> {
        let Ok(ecu_data) = self.diag_database.ecu_data() else {
            return Vec::new();
        };
        ecu_data
            .variants()
            .into_iter()
            .flatten()
            .filter_map(|v| {
                Some(VariantInfo {
                    name: v.diag_layer()?.short_name()?.to_owned(),
                    is_base_variant: v.is_base_variant(),
                })
            })
            .collect()
    }

    /// Selects the given variant without communicating with the ECU.
    ///
    /// All following lookups (services, schemas, component infos) are done
    /// against the selected variant and its parent references.
    ///
    /// # Errors
    /// Returns [`DiagServiceError::NotFound`] if no variant with the given short
    /// name exists. The error message lists the available variants.
    pub async fn select_variant_offline(&self, name: &str) -> Result<(), DiagServiceError> {
        let variants = self.variants();
        let Some(variant) = variants.iter().find(|v| v.name == name) else {
            return Err(DiagServiceError::NotFound(format!(
                "Variant '{name}' not found in ECU '{}', available variants: [{}]",
                self.ecu_name,
                variants
                    .iter()
                    .map(|v| v.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        let variant_index = variants.iter().position(|v| v.name == name);
        // Not using `set_variant`, as that also initializes the session and security
        // states from the state charts, which is not needed offline and would fail for
        // databases without state charts.
        // The cache must be reset, as lookup names may be identical between variants.
        self.db_cache.reset().await;
        let mut ecu_state = std_ext::lock_write(&self.runtime_state.ecu_state);
        ecu_state.variant_index = variant_index;
        ecu_state.variant_state = VariantState::Detected {
            name: variant.name.clone(),
            is_base_variant: variant.is_base_variant,
            is_fallback: false,
        };
        Ok(())
    }

    /// Returns all data services (0x22) of the selected variant for which `visible` returns true.
    #[must_use]
    pub fn offline_data_info(
        &self,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
    ) -> Vec<ComponentDataInfo> {
        self.components_data_info_with(|s| visible(&OfflineServiceInfo::from_service(s)))
    }

    /// Returns all configuration services of the selected variant for which `visible`
    /// returns true.
    #[must_use]
    pub fn offline_configurations_info(
        &self,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
    ) -> Vec<ComponentConfigurationsInfo> {
        self.components_configurations_info_with(|s| visible(&OfflineServiceInfo::from_service(s)))
    }

    /// Returns all routine control operations of the selected variant for which `visible`
    /// returns true.
    #[must_use]
    pub fn offline_operations_info(
        &self,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
    ) -> Vec<ComponentOperationsInfo> {
        self.components_operations_info_with(|s| visible(&OfflineServiceInfo::from_service(s)))
    }

    /// Returns the diagnostic services of the selected variant (and its parent refs)
    /// behind the endpoints of the given kind, grouped by endpoint id.
    ///
    /// The ids are the same as the ones returned by [`Self::offline_data_info`],
    /// [`Self::offline_configurations_info`] and [`Self::offline_operations_info`]:
    /// * [`OfflineEndpointKind::Data`]: the `ReadDataByIdentifier` and
    ///   `WriteDataByIdentifier` services, keyed by their trimmed short name.
    /// * [`OfflineEndpointKind::Configuration`]: as data, restricted to services of a
    ///   configuration functional class.
    /// * [`OfflineEndpointKind::Operation`]: the `RoutineControl` services, keyed by
    ///   their trimmed routine name.
    ///
    /// Only services for which `visible` returns true are included.
    #[must_use]
    pub fn offline_endpoint_services(
        &self,
        kind: OfflineEndpointKind,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
    ) -> HashMap<String, Vec<datatypes::DiagService<'_>>> {
        let naming = &self.database_naming_convention;
        let data_sids = [
            service_ids::READ_DATA_BY_IDENTIFIER,
            service_ids::WRITE_DATA_BY_IDENTIFIER,
        ];
        let services = self.get_services_from_variant_and_parent_refs(|service| {
            let Some(sid) = service.request_id() else {
                return false;
            };
            match kind {
                OfflineEndpointKind::Data => data_sids.contains(&sid),
                OfflineEndpointKind::Configuration => {
                    data_sids.contains(&sid)
                        && service
                            .diag_comm()
                            .and_then(|dc| dc.funct_class())
                            .is_some_and(|fcs| {
                                fcs.iter().any(|fc| {
                                    fc.short_name().is_some_and(|n| {
                                        naming.is_configuration_functional_class(n)
                                    })
                                })
                            })
                }
                OfflineEndpointKind::Operation => sid == service_ids::ROUTINE_CONTROL,
            }
        });

        let mut result: HashMap<String, Vec<datatypes::DiagService<'_>>> = HashMap::default();
        for service in services {
            if !visible(&OfflineServiceInfo::from_service(&service)) {
                continue;
            }
            let Some(short_name) = service.diag_comm().and_then(|dc| dc.short_name()) else {
                continue;
            };
            let id = match kind {
                OfflineEndpointKind::Data | OfflineEndpointKind::Configuration => {
                    naming.trim_short_name_affixes(short_name)
                }
                OfflineEndpointKind::Operation => naming.trim_routine_name(short_name),
            };
            result.entry(id).or_default().push(service);
        }
        result
    }

    /// Returns the single ECU jobs of the selected variant (and its parent refs) for
    /// which `visible` returns true, keyed by the id used in
    /// `/x-single-ecu-jobs/{id}`.
    ///
    /// Uses the same ids and the same selection as the job listing of the CDA, i.e.
    /// jobs without a semantic are not included.
    #[must_use]
    pub fn offline_single_ecu_jobs(
        &self,
        visible: &dyn Fn(&OfflineServiceInfo) -> bool,
    ) -> Vec<(String, datatypes::SingleEcuJob<'_>)> {
        let mut jobs: Vec<_> = self
            .get_single_ecu_jobs_from_variant_and_parent_refs(|_| true)
            .into_iter()
            .filter(|job| visible(&OfflineServiceInfo::from_single_ecu_job(job)))
            .filter_map(|job| {
                let diag_comm = job.diag_comm()?;
                diag_comm.semantic()?;
                let id = self
                    .database_naming_convention
                    .trim_short_name_affixes(diag_comm.short_name()?)
                    .to_lowercase();
                Some((id, job))
            })
            .collect();
        jobs.sort_by(|(a, _), (b, _)| a.cmp(b));
        jobs
    }

    /// Returns the diag layers of the selected variant followed by the ones of its
    /// parent refs, i.e. the complete ECU description the variant is built from.
    #[must_use]
    pub fn offline_diag_layers(&self) -> Vec<datatypes::DiagLayer<'_>> {
        self.get_diag_layers_from_variant_and_parent_refs()
    }
}

/// Kind of the endpoints the services of [`EcuManager::offline_endpoint_services`] are
/// grouped for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OfflineEndpointKind {
    /// `/data/{id}`
    Data,
    /// `/configurations/{id}`
    Configuration,
    /// `/operations/{id}`
    Operation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag_kernel::test_utils::ecu_manager_builder::create_ecu_manager_for_offline;

    fn ids(infos: &[ComponentDataInfo]) -> Vec<String> {
        let mut ids: Vec<_> = infos.iter().map(|i| i.id.clone()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn lists_variants() {
        let ecu = create_ecu_manager_for_offline();
        assert_eq!(
            ecu.variants(),
            vec![
                VariantInfo {
                    name: "BaseVariant".to_owned(),
                    is_base_variant: true,
                },
                VariantInfo {
                    name: "SpecificVariant".to_owned(),
                    is_base_variant: false,
                },
            ]
        );
    }

    #[tokio::test]
    async fn unknown_variant_lists_available_variants() {
        let ecu = create_ecu_manager_for_offline();
        let err = ecu
            .select_variant_offline("DoesNotExist")
            .await
            .expect_err("Unknown variant must fail");
        let msg = err.to_string();
        assert!(msg.contains("BaseVariant"), "{msg}");
        assert!(msg.contains("SpecificVariant"), "{msg}");
    }

    /// [[ test~openapi-gen-offline-variant-selection, Selected variant determines the services, test ]]
    #[tokio::test]
    async fn selected_variant_determines_services() {
        let ecu = create_ecu_manager_for_offline();

        // Without a selected variant the base variant is used.
        assert_eq!(
            ids(&ecu.offline_data_info(&|_| true)),
            vec!["ReadSupplierOnly", "ReadUnrestricted"]
        );

        ecu.select_variant_offline("SpecificVariant")
            .await
            .expect("Variant must exist");
        assert_eq!(
            ids(&ecu.offline_data_info(&|_| true)),
            vec!["ReadSpecific", "ReadUnrestricted"]
        );
        assert!(ecu.offline_operations_info(&|_| true).is_empty());
    }

    /// [[ test~openapi-gen-offline-audience, Audience of a service is exposed to filters, test ]]
    #[tokio::test]
    async fn audience_is_exposed_to_filter() {
        let ecu = create_ecu_manager_for_offline();
        ecu.select_variant_offline("BaseVariant")
            .await
            .expect("Variant must exist");

        let not_supplier =
            |s: &OfflineServiceInfo| s.audience.as_ref().is_none_or(|a| !a.is_supplier);
        assert_eq!(
            ids(&ecu.offline_data_info(&not_supplier)),
            vec!["ReadUnrestricted"]
        );

        let workshop = |s: &OfflineServiceInfo| {
            s.audience
                .as_ref()
                .is_some_and(|a| a.enabled_audiences.iter().any(|n| n == "Workshop"))
        };
        assert_eq!(
            ids(&ecu.offline_data_info(&workshop)),
            vec!["ReadSupplierOnly"]
        );

        let ops =
            ecu.offline_operations_info(&|s| s.audience.as_ref().is_some_and(|a| a.is_development));
        assert_eq!(ops.len(), 1);
        assert!(
            ecu.offline_operations_info(&|s| s.audience.is_none())
                .is_empty()
        );
    }

    /// [[ test~openapi-gen-offline-endpoint-services, Services are grouped by endpoint id, test ]]
    #[tokio::test]
    async fn endpoint_services_match_data_ids() {
        let ecu = create_ecu_manager_for_offline();
        ecu.select_variant_offline("BaseVariant")
            .await
            .expect("Variant must exist");

        let not_supplier =
            |s: &OfflineServiceInfo| s.audience.as_ref().is_none_or(|a| !a.is_supplier);
        let services = ecu.offline_endpoint_services(OfflineEndpointKind::Data, &not_supplier);
        let mut keys: Vec<_> = services.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ids(&ecu.offline_data_info(&not_supplier)));
        let unrestricted = services
            .get("ReadUnrestricted")
            .expect("Service must exist");
        assert_eq!(unrestricted.len(), 1);
        assert_eq!(
            unrestricted
                .first()
                .and_then(datatypes::DiagService::request_id),
            Some(service_ids::READ_DATA_BY_IDENTIFIER)
        );
        let mut operation_keys: Vec<_> = ecu
            .offline_endpoint_services(OfflineEndpointKind::Operation, &|_| true)
            .into_keys()
            .collect();
        operation_keys.sort();
        let mut operation_ids: Vec<_> = ecu
            .offline_operations_info(&|_| true)
            .into_iter()
            .map(|o| o.id)
            .collect();
        operation_ids.sort();
        assert_eq!(operation_keys, operation_ids);
    }
}
