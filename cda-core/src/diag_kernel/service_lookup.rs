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

//! Service lookup and database traversal for [`EcuManager`].
//!
//! This module contains the [`DbCache`] and [`CacheLocation`] types used to cache
//! service lookups, as well as the methods on [`EcuManager`] responsible for
//! traversing the diagnostic database hierarchy and resolving services.

use cda_database::datatypes;
use cda_interfaces::{
    DiagServiceError, HashMap, STRINGS, StringId, util::starts_with_ignore_ascii_case,
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

use super::ecumanager::EcuManager;

#[derive(Default)]
pub(in crate::diag_kernel) struct DbCache {
    diag_services: RwLock<HashMap<StringId, Option<CacheLocation>>>,
}

impl DbCache {
    pub(in crate::diag_kernel) async fn reset(&self) {
        self.diag_services.write().await.clear();
    }

    /// Synchronous cache reset. Used when the DB is unloaded (no async context needed
    /// because no one should be concurrently reading the cache during unload).
    pub(in crate::diag_kernel) fn reset_sync(&self) {
        if let Ok(mut guard) = self.diag_services.try_write() {
            guard.clear();
        }
    }
}

pub(in crate::diag_kernel) enum CacheLocation {
    Variant(usize),
    ParentRef(usize),
}

fn diag_comm_short_name_starts_with(
    service: &datatypes::DiagService<'_>,
    name_prefix: &str,
) -> bool {
    service.diag_comm().is_some_and(|dc| {
        dc.short_name()
            .is_some_and(|name| starts_with_ignore_ascii_case(name, name_prefix))
    })
}

impl<S: SecurityPlugin> EcuManager<S> {
    /// Lookup a diagnostic service by its diag comm definition.
    ///
    /// When `functional_group_name` is `Some`, the service is looked up in the
    /// named functional group's `DiagLayer` and its parent references instead of
    /// the ECU variant. When `None`, the lookup uses the ECU variant (with
    /// caching, because it is used for *every* UDS request).
    ///
    /// `subfunction_mask` is an optional bitmask applied to both the incoming
    /// `DiagComm::subfunction_id` and the database service's subfunction value
    /// before comparing.  When it is `None`, [`DEFAULT_SUBFUNCTION_MASK`] (`0x7F`) is
    /// used, which masks out the suppress-positive-response bit (bit 7).
    pub(in crate::diag_kernel) async fn lookup_diag_service(
        &self,
        diag_comm: &cda_interfaces::DiagComm,
        functional_group_name: Option<&str>,
        subfunction_mask: Option<u8>,
    ) -> Result<datatypes::DiagService<'_>, DiagServiceError> {
        // When a subfunction id is provided, match on base name + subfunction id
        // rather than constructing a name suffix. The cache key encodes both so
        // that a subfunction-id lookup and a plain name lookup for the same base
        // name never collide.
        if let Some(sf_id) = diag_comm.subfunction_id {
            let base_name = diag_comm.name.to_lowercase();
            let effective_mask =
                subfunction_mask.unwrap_or(cda_interfaces::DEFAULT_SUBFUNCTION_MASK);
            let mask_u32 = u32::from(effective_mask);

            let prefixes = diag_comm.type_.service_prefixes();
            let predicate = |service: &datatypes::DiagService<'_>| {
                diag_comm_short_name_starts_with(service, &base_name)
                    && service
                        .request_id()
                        .is_some_and(|sid| prefixes.contains(&sid))
                    && service
                        .request_sub_function_id()
                        .is_some_and(|(id, _)| (id & mask_u32) == (u32::from(sf_id) & mask_u32))
            };

            if let Some(fg_name) = functional_group_name {
                return self
                    .get_services_from_functional_group_and_parent_refs(fg_name, predicate)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        DiagServiceError::NotFound(format!(
                            "Diagnostic service '{base_name}' with subfunction {sf_id:#04X} not \
                             found in functional group '{fg_name}'"
                        ))
                    });
            }

            let cache_key = format!("{base_name}:sf{sf_id}:m{effective_mask:02X}");
            let lookup_id = STRINGS.get_or_insert(&cache_key);

            if let Some(Some(location)) = self.db_cache.diag_services.read().await.get(&lookup_id) {
                return match self.get_service_by_location(location) {
                    Some(service) => Ok(service),
                    None => Err(DiagServiceError::NotFound(format!(
                        "Cached diagnostic service '{base_name}' with subfunction {sf_id:#04X} \
                         not found at stored location"
                    ))),
                };
            }

            if let Some(service) = self.search_and_cache_location(lookup_id, &predicate).await {
                return Ok(service);
            }

            self.db_cache
                .diag_services
                .write()
                .await
                .insert(lookup_id, None);

            return Err(DiagServiceError::NotFound(format!(
                "Diagnostic service '{base_name}' with subfunction {sf_id:#04X} not found in \
                 variant or parent refs"
            )));
        }

        let lookup_name = diag_comm
            .lookup_name
            .clone()
            .unwrap_or_else(|| {
                self.database_naming_convention
                    .apply_action_affix(&diag_comm.name, &diag_comm.action())
            })
            .to_lowercase();

        let prefixes = diag_comm.type_.service_prefixes();
        let predicate = |service: &datatypes::DiagService<'_>| {
            diag_comm_short_name_starts_with(service, &lookup_name)
                && service
                    .request_id()
                    .is_some_and(|sid| prefixes.contains(&sid))
        };

        if let Some(fg_name) = functional_group_name {
            return self
                .get_services_from_functional_group_and_parent_refs(fg_name, predicate)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    DiagServiceError::NotFound(format!(
                        "Diagnostic service '{lookup_name}' not found in functional group \
                         '{fg_name}'"
                    ))
                });
        }

        let lookup_id = STRINGS.get_or_insert(&lookup_name);

        if let Some(Some(location)) = self.db_cache.diag_services.read().await.get(&lookup_id) {
            return match self.get_service_by_location(location) {
                Some(service) => Ok(service),
                None => Err(DiagServiceError::NotFound(format!(
                    "Cached diagnostic service '{lookup_name}' not found at stored location"
                ))),
            };
        }

        if let Some(service) = self.search_and_cache_location(lookup_id, &predicate).await {
            return Ok(service);
        }

        self.db_cache
            .diag_services
            .write()
            .await
            .insert(lookup_id, None);

        Err(DiagServiceError::NotFound(format!(
            "Diagnostic service '{lookup_name}' not found in variant, base variant, or ECU shared \
             data"
        )))
    }

    async fn search_and_cache_location<F>(
        &self,
        lookup_id: StringId,
        predicate: &F,
    ) -> Option<datatypes::DiagService<'_>>
    where
        F: Fn(&datatypes::DiagService<'_>) -> bool,
    {
        if let Some((service, location)) = self.search_with_location(predicate) {
            self.db_cache
                .diag_services
                .write()
                .await
                .insert(lookup_id, Some(location));
            Some(service)
        } else {
            None
        }
    }

    fn search_with_location<F>(
        &self,
        predicate: &F,
    ) -> Option<(datatypes::DiagService<'_>, CacheLocation)>
    where
        F: Fn(&datatypes::DiagService<'_>) -> bool,
    {
        // Search in variant
        if let Some((idx, service)) = self
            .variant()
            // This is necessary, so we are able to lookup services
            // _before_ a variant has been found i.e. for variant detection.
            .or_else(|| self.diag_database.base_variant().ok())
            .and_then(|v| v.diag_layer())
            .and_then(|dl| dl.diag_services())
            .and_then(|services| {
                services.iter().enumerate().find_map(|(idx, s)| {
                    let service = datatypes::DiagService(s);
                    predicate(&service).then_some((idx, service))
                })
            })
        {
            return Some((service, CacheLocation::Variant(idx)));
        }

        // Search in Parent Refs
        if let Some((idx, service)) = self.get_variant_parent_ref_services().and_then(|services| {
            services
                .iter()
                .enumerate()
                .find_map(|(idx, s)| predicate(s).then_some((idx, s.clone())))
        }) {
            return Some((service, CacheLocation::ParentRef(idx)));
        }

        None
    }

    fn get_services_from_diag_layer_and_parent_refs<'a, F>(
        diag_layer: &datatypes::DiagLayer<'a>,
        parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
        service_filter: F,
    ) -> Vec<datatypes::DiagService<'a>>
    where
        F: Fn(&datatypes::DiagService) -> bool,
    {
        diag_layer
            .diag_services()
            .into_iter()
            .flatten()
            .map(datatypes::DiagService)
            .chain(
                Self::get_parent_ref_services_recursive(parent_refs)
                    .into_iter()
                    .flatten(),
            )
            .filter(service_filter)
            .collect()
    }

    /// Retrieves single ECU jobs from a given `DiagLayer` and its parent references,
    /// filtered by the provided predicate. Jobs from the `DiagLayer` are returned first,
    /// followed by jobs resolved recursively from parent references.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let jobs = EcuManager::get_single_ecu_jobs_from_diag_layer_and_parent_refs(
    ///     &diag_layer,
    ///     parent_refs.into_iter().map(datatypes::ParentRef),
    ///     |job| job.diag_comm().and_then(|dc| dc.short_name()) == Some("MyJob"),
    /// );
    /// ```
    fn get_single_ecu_jobs_from_diag_layer_and_parent_refs<'a, F>(
        diag_layer: &datatypes::DiagLayer<'a>,
        parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
        service_filter: F,
    ) -> Vec<datatypes::SingleEcuJob<'a>>
    where
        F: Fn(&datatypes::SingleEcuJob) -> bool,
    {
        diag_layer
            .single_ecu_jobs()
            .into_iter()
            .flatten()
            .map(datatypes::SingleEcuJob)
            .chain(
                Self::get_parent_ref_jobs_recursive(parent_refs)
                    .into_iter()
                    .flatten(),
            )
            .filter(service_filter)
            .collect()
    }

    /// Retrieves diagnostic services from the current variants `DiagLayer` and its parent
    /// references, filtered by the provided predicate. Falls back to the base variant when no
    /// specific variant has been detected yet (e.g. before first UDS contact with the ECU or
    /// while the ECU is offline), so that info-listing endpoints return meaningful data
    /// regardless of the current connectivity or detection state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let read_services = ecu_manager.get_services_from_variant_and_parent_refs(|service| {
    ///     service
    ///         .request_id()
    ///         .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
    /// });
    /// for service in &read_services {
    ///     println!("{:?}", service.diag_comm().and_then(|dc| dc.short_name()));
    /// }
    /// ```
    pub(in crate::diag_kernel) fn get_services_from_variant_and_parent_refs<F>(
        &self,
        service_filter: F,
    ) -> Vec<datatypes::DiagService<'_>>
    where
        F: Fn(&datatypes::DiagService) -> bool,
    {
        self.variant()
            // This is necessary, so we are able to lookup services
            // _before_ a variant has been found i.e. for variant detection.
            .or_else(|| self.diag_database.base_variant().ok())
            .and_then(|v| v.diag_layer().map(|dl| (dl, v.parent_refs())))
            .map_or(<_>::default(), |(diag_layer, parent_refs)| {
                Self::get_services_from_diag_layer_and_parent_refs(
                    &(diag_layer.into()),
                    parent_refs.into_iter().flatten().map(datatypes::ParentRef),
                    service_filter,
                )
            })
    }

    /// Retrieves diagnostic services from a given functional group and its parent
    /// references, filtered by the provided predicate.
    ///
    /// # Errors
    /// Will return `Err` if the database has no functional groups or the specified
    /// group is not found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let read_services = ecu_manager.get_services_from_functional_group_and_parent_refs(
    ///     "FunctionalGroupName",
    ///     |service| {
    ///         service
    ///             .request_id()
    ///             .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
    ///     },
    /// )?;
    /// for service in &read_services {
    ///     println!("{:?}", service.diag_comm().and_then(|dc| dc.short_name()));
    /// }
    /// ```
    pub(in crate::diag_kernel) fn get_services_from_functional_group_and_parent_refs<F>(
        &self,
        group_name: &str,
        service_filter: F,
    ) -> Result<Vec<datatypes::DiagService<'_>>, DiagServiceError>
    where
        F: Fn(&datatypes::DiagService) -> bool,
    {
        let Ok(groups) = self.diag_database.functional_groups() else {
            return Err(DiagServiceError::InvalidDatabase(
                "Database has no functional groups".to_owned(),
            ));
        };

        let matching_group = groups
            .into_iter()
            .find(|group| {
                group
                    .diag_layer()
                    .and_then(|dl| dl.short_name())
                    .is_some_and(|name| name.eq_ignore_ascii_case(group_name))
            })
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!("Functional group '{group_name}' not found"))
            })?;

        Ok(matching_group
            .diag_layer()
            .map(|dl| (dl, matching_group.parent_refs()))
            .map_or(<_>::default(), |(diag_layer, parent_refs)| {
                Self::get_services_from_diag_layer_and_parent_refs(
                    &(diag_layer.into()),
                    parent_refs.into_iter().flatten().map(datatypes::ParentRef),
                    service_filter,
                )
            }))
    }

    /// Retrieves single ECU jobs from the current variants `DiagLayer` and its parent
    /// references, filtered by the provided predicate. Falls back to the base variant when no
    /// specific variant has been detected yet (e.g. before first UDS contact with the ECU or
    /// while the ECU is offline), so that info-listing endpoints return meaningful data
    /// regardless of the current connectivity or detection state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let jobs = ecu_manager.get_single_ecu_jobs_from_variant_and_parent_refs(
    ///     |job| job.diag_comm().and_then(|dc| dc.short_name()) == Some("ReadSerialNumber"),
    /// );
    /// ```
    pub(in crate::diag_kernel) fn get_single_ecu_jobs_from_variant_and_parent_refs<F>(
        &self,
        service_filter: F,
    ) -> Vec<datatypes::SingleEcuJob<'_>>
    where
        F: Fn(&datatypes::SingleEcuJob) -> bool,
    {
        self.variant()
            // This is necessary, so we are able to lookup services
            // _before_ a variant has been found i.e. for variant detection.
            .or_else(|| self.diag_database.base_variant().ok())
            .and_then(|v| v.diag_layer().map(|dl| (dl, v.parent_refs())))
            .map_or(<_>::default(), |(diag_layer, parent_refs)| {
                Self::get_single_ecu_jobs_from_diag_layer_and_parent_refs(
                    &(diag_layer.into()),
                    parent_refs.into_iter().flatten().map(datatypes::ParentRef),
                    service_filter,
                )
            })
    }

    pub(in crate::diag_kernel) fn get_service_by_location(
        &self,
        location: &CacheLocation,
    ) -> Option<datatypes::DiagService<'_>> {
        match location {
            CacheLocation::Variant(idx) => self
                .variant()
                // This is necessary, so we are able to lookup services
                // _before_ a variant has been found i.e. for variant detection.
                .or_else(|| self.diag_database.base_variant().ok())
                .and_then(|v| v.diag_layer())
                .and_then(|dl| dl.diag_services())
                .map(|s| s.get(*idx))
                .map(datatypes::DiagService),
            CacheLocation::ParentRef(idx) => self
                .get_variant_parent_ref_services()
                .and_then(|services| services.get(*idx).cloned()),
        }
    }

    /// Recursively resolves parent references and collects their associated `DiagComm` entries.
    /// Traverses the parent reference hierarchy to gather `DiagComms` from
    /// inherited `DiagLayers`. Items whose short name appears in a parent references
    /// `not_inherited_diag_comm_short_names` list are excluded.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let services = EcuManager::get_parent_ref_diag_comms_recursive(
    ///     parent_refs.into_iter().map(datatypes::ParentRef),
    ///     |dl| dl.diag_services().map(|s| s.iter().map(datatypes::DiagService).collect()),
    ///     |service| service.diag_comm().and_then(|dc| dc.short_name()),
    /// );
    /// ```
    pub(in crate::diag_kernel) fn get_parent_ref_diag_comms_recursive<'a, T>(
        parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
        extract: impl Fn(&datatypes::DiagLayer<'a>) -> Option<Vec<T>>,
        get_name: impl Fn(&T) -> Option<&str>,
    ) -> Option<Vec<T>> {
        let all_items: Vec<T> = get_parent_ref_diag_layers_with_refs_recursive(parent_refs)
            .into_iter()
            .filter_map(|(parent_ref, diag_layer)| {
                let not_inherited_names: Vec<&str> = parent_ref
                    .not_inherited_diag_comm_short_names()
                    .map_or(<_>::default(), |names| names.iter().collect());

                extract(&diag_layer).map(|items| {
                    items
                        .into_iter()
                        .filter(|item| {
                            get_name(item).is_none_or(|name| !not_inherited_names.contains(&name))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .flatten()
            .collect();

        if all_items.is_empty() {
            None
        } else {
            Some(all_items)
        }
    }

    /// Recursively resolves parent references and collects their single ECU jobs.
    /// Traverses the parent reference hierarchy to gather jobs from inherited `DiagLayers`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let jobs = EcuManager::get_parent_ref_jobs_recursive(
    ///     parent_refs.into_iter().map(datatypes::ParentRef),
    /// );
    /// // jobs: Option<Vec<datatypes::SingleEcuJob>>
    /// ```
    pub(in crate::diag_kernel) fn get_parent_ref_jobs_recursive<'a>(
        parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
    ) -> Option<Vec<datatypes::SingleEcuJob<'a>>> {
        Self::get_parent_ref_diag_comms_recursive(
            parent_refs,
            |dl| {
                dl.single_ecu_jobs()
                    .map(|jobs| jobs.iter().map(datatypes::SingleEcuJob).collect())
            },
            |job| job.diag_comm().and_then(|dc| dc.short_name()),
        )
    }

    /// Recursively resolves parent references and collects their diagnostic services.
    /// Traverses the parent reference hierarchy to gather services
    /// from inherited `DiagLayers`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let services = EcuManager::get_parent_ref_services_recursive(
    ///     parent_refs.into_iter().map(datatypes::ParentRef),
    /// );
    /// // services: Option<Vec<datatypes::DiagService>>
    /// ```
    pub(in crate::diag_kernel) fn get_parent_ref_services_recursive<'a>(
        parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
    ) -> Option<Vec<datatypes::DiagService<'a>>> {
        Self::get_parent_ref_diag_comms_recursive(
            parent_refs,
            |dl| {
                dl.diag_services()
                    .map(|s| s.iter().map(datatypes::DiagService).collect())
            },
            |service| service.diag_comm().and_then(|dc| dc.short_name()),
        )
    }

    /// Retrieves `DiagServices` inherited from the current variants parent references.
    /// Falls back to the base variant if no variant has been identified yet, which allows
    /// service lookups during variant detection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let inherited_services: Option<Vec<datatypes::DiagService>> =
    ///     ecu_manager.get_variant_parent_ref_services();
    /// if let Some(services) = inherited_services {
    ///     for service in &services {
    ///         println!("{:?}", service.diag_comm().and_then(|dc| dc.short_name()));
    ///     }
    /// }
    /// ```
    pub(in crate::diag_kernel) fn get_variant_parent_ref_services(
        &self,
    ) -> Option<Vec<datatypes::DiagService<'_>>> {
        self.variant()
            // This is necessary, so we are able to lookup services
            // _before_ a variant has been found i.e. for variant detection.
            .or_else(|| self.diag_database.base_variant().ok())
            .and_then(|v| v.parent_refs())
            .and_then(|parent_refs| {
                Self::get_parent_ref_services_recursive(
                    parent_refs.iter().map(datatypes::ParentRef::from),
                )
            })
    }

    /// Collects all `DiagLayers` from the current variant and its parent references.
    /// The variants own `DiagLayer` is placed first to give it higher priority in
    /// subsequent operations, followed by layers resolved recursively from parent references.
    /// Falls back to the base variant when no specific variant has been detected yet
    /// (e.g. before first UDS contact with the ECU or while the ECU is offline), so that
    /// info-listing endpoints return meaningful data regardless of the current connectivity
    /// or detection state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let diag_layers: Vec<datatypes::DiagLayer> =
    ///     ecu_manager.get_diag_layers_from_variant_and_parent_refs();
    /// // The first element (if present) is the variants own diagnostic layer.
    /// for layer in &diag_layers {
    ///     println!("{:?}", layer.short_name());
    /// }
    /// ```
    pub(in crate::diag_kernel) fn get_diag_layers_from_variant_and_parent_refs(
        &self,
    ) -> Vec<datatypes::DiagLayer<'_>> {
        let Some(variant) = self
            .variant()
            // This is necessary, so we are able to lookup services
            // _before_ a variant has been found i.e. for variant detection.
            .or_else(|| self.diag_database.base_variant().ok())
        else {
            return Vec::new();
        };

        // Start with the diag layer of the current variant, to give it a higher
        // prio in later operations
        variant
            .diag_layer()
            .map(datatypes::DiagLayer)
            .into_iter()
            .chain(
                variant
                    .parent_refs()
                    .map(|refs| get_parent_ref_diag_layers_recursive(refs.iter()))
                    .unwrap_or_default(),
            )
            .collect()
    }

    pub(in crate::diag_kernel) fn lookup_services_by_sid(
        &self,
        service_id: u8,
    ) -> Result<Vec<datatypes::DiagService<'_>>, DiagServiceError> {
        let services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|req_id| req_id == service_id)
        });

        if services.is_empty() {
            Err(DiagServiceError::NotFound(format!(
                "No services with SID {service_id:#04X} found in variant, base variant, or ECU \
                 shared data"
            )))
        } else {
            Ok(services)
        }
    }
}

/// Recursively resolves parent references and collects their `DiagLayers`.
/// This is a convenience wrapper around [`get_parent_ref_diag_layers_with_refs_recursive`]
/// that discards the associated `ParentRef` and returns only the `DiagLayer` values.
///
/// # Example
///
/// ```ignore
/// let layers: Vec<datatypes::DiagLayer> = EcuManager::get_parent_ref_diag_layers_recursive(
///     parent_refs.iter().map(datatypes::ParentRef),
/// );
/// ```
pub(in crate::diag_kernel) fn get_parent_ref_diag_layers_recursive<'a>(
    parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
) -> Vec<datatypes::DiagLayer<'a>> {
    get_parent_ref_diag_layers_with_refs_recursive(parent_refs)
        .into_iter()
        .map(|(_, diag_layer)| diag_layer)
        .collect()
}

/// Recursively resolves parent references and returns `(ParentRef, DiagLayer)` pairs.
/// Uses a stack-based traversal to handle the parent reference hierarchy:
/// - **`FunctionalGroup`**: extracts the `DiagLayer` and pushes its nested `ParentRef`s
///   onto the stack for further traversal.
/// - **`Variant`**: extracts the `DiagLayer` and pushes its nested `ParentRef`s
///   onto the stack for further traversal.
/// - **`Protocol`**: extracts the `DiagLayer` and pushes its nested `ParentRef`
///   items onto the stack for further traversal.
/// - **`EcuSharedData`**: extracts the `DiagLayer` (leaf node, no `parent_refs`).
///
/// # Example
///
/// ```ignore
/// let pairs: Vec<(datatypes::ParentRef, datatypes::DiagLayer)> =
///     EcuManager::get_parent_ref_diag_layers_with_refs_recursive(
///         parent_refs.iter().map(datatypes::ParentRef),
///     );
/// for (parent_ref, diag_layer) in &pairs {
///     println!("ref type: {:?}, layer: {:?}", parent_ref.ref_type(), diag_layer.short_name());
/// }
/// ```
fn get_parent_ref_diag_layers_with_refs_recursive<'a>(
    parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
) -> Vec<(datatypes::ParentRef<'a>, datatypes::DiagLayer<'a>)> {
    let mut result = Vec::new();
    let mut stack: Vec<datatypes::ParentRef<'a>> =
        parent_refs.into_iter().map(Into::into).collect();

    while let Some(parent_ref) = stack.pop() {
        match parent_ref.ref_type().try_into() {
            Ok(datatypes::ParentRefType::FunctionalGroup) => {
                if let Some(fg) = parent_ref.ref__as_functional_group() {
                    if let Some(nested_refs) = fg.parent_refs() {
                        stack.extend(nested_refs.iter().map(datatypes::ParentRef));
                    }
                    if let Some(dl) = fg.diag_layer() {
                        result.push((parent_ref, datatypes::DiagLayer(dl)));
                    }
                }
            }
            Ok(datatypes::ParentRefType::EcuSharedData) => {
                if let Some(dl) = parent_ref
                    .ref__as_ecu_shared_data()
                    .and_then(|esd| esd.diag_layer())
                {
                    result.push((parent_ref, datatypes::DiagLayer(dl)));
                }
            }
            Ok(datatypes::ParentRefType::Protocol) => {
                if let Some(p) = parent_ref.ref__as_protocol() {
                    if let Some(nested_refs) = p.parent_refs() {
                        stack.extend(nested_refs.iter().map(datatypes::ParentRef));
                    }
                    if let Some(dl) = p.diag_layer() {
                        result.push((parent_ref, datatypes::DiagLayer(dl)));
                    }
                }
            }
            Ok(datatypes::ParentRefType::Variant) => {
                if let Some(v) = parent_ref.ref__as_variant() {
                    if let Some(nested_refs) = v.parent_refs() {
                        stack.extend(nested_refs.iter().map(datatypes::ParentRef));
                    }
                    if let Some(dl) = v.diag_layer() {
                        result.push((parent_ref, datatypes::DiagLayer(dl)));
                    }
                }
            }
            _ => {
                tracing::error!("Unsupported ParentRefType in ECU shared service lookup.");
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::database_builder::{
        DataFormatParentRefType, DiagLayerParams, EcuDataBuilder, EcuDataParams,
    };
    use cda_interfaces::{DiagComm, DiagCommLookup, DiagServiceError, subfunction_ids};

    use super::*;
    use crate::diag_kernel::test_utils::ecu_manager_builder::create_ecu_manager_with_routine_control_service;

    /// Tests that `get_parent_ref_diag_layers_with_refs_recursive` correctly resolves a
    /// mixed parent-ref hierarchy with the following structure:
    ///
    /// ```text
    /// Variant("RootVariant")
    /// +-- Variant("InnerVariant")
    /// |   \-- FunctionalGroup("FgLayer")
    /// |       \-- EcuSharedData("SharedInFg")
    /// +-- Protocol("Proto")
    /// |   \-- Protocol("ParentProto")
    /// \-- EcuSharedData("TopShared")
    /// ```
    ///
    /// Expected collected layers (order is stack-based, not guaranteed):
    ///   `TopShared`, Proto, `ParentProto`, `InnerVariant`, `FgLayer`, `SharedInFg`
    #[test]
    fn test_parent_ref_recursive_mixed_hierarchy() {
        let mut b = EcuDataBuilder::new();

        // - leaf: EcuSharedData inside a FunctionalGroup -
        let shared_in_fg_dl = b.create_diag_layer(DiagLayerParams {
            short_name: "SharedInFg",
            ..Default::default()
        });
        let esd_in_fg = b.create_ecu_shared_data(shared_in_fg_dl);
        let esd_in_fg_pr = b.create_parent_ref(
            DataFormatParentRefType::EcuSharedData,
            Some(DataFormatParentRefType::tag_as_ecu_shared_data(esd_in_fg)),
        );

        let fg_dl = b.create_diag_layer(DiagLayerParams {
            short_name: "FgLayer",
            ..Default::default()
        });
        let fg = b.create_functional_group(fg_dl, Some(vec![esd_in_fg_pr]));
        let fg_pr = b.create_parent_ref(
            DataFormatParentRefType::FunctionalGroup,
            Some(DataFormatParentRefType::tag_as_functional_group(fg)),
        );

        // - inner Variant whose parent-ref is the FunctionalGroup -
        let inner_variant_dl = b.create_diag_layer(DiagLayerParams {
            short_name: "InnerVariant",
            ..Default::default()
        });
        let inner_variant = b.create_variant(inner_variant_dl, false, None, Some(vec![fg_pr]));
        let variant_pr = b.create_parent_ref(
            DataFormatParentRefType::Variant,
            Some(DataFormatParentRefType::tag_as_variant(inner_variant)),
        );

        // - Protocol with a parent protocol -
        let parent_proto = b.create_protocol("ParentProto", None, None, None);
        let parent_proto_pr = b.create_parent_ref(
            DataFormatParentRefType::Protocol,
            Some(DataFormatParentRefType::tag_as_protocol(parent_proto)),
        );
        let proto = b.create_protocol("Proto", None, None, Some(vec![parent_proto_pr]));
        let proto_pr = b.create_parent_ref(
            DataFormatParentRefType::Protocol,
            Some(DataFormatParentRefType::tag_as_protocol(proto)),
        );

        // - top-level EcuSharedData sibling -
        let top_shared_dl = b.create_diag_layer(DiagLayerParams {
            short_name: "TopShared",
            ..Default::default()
        });
        let top_esd = b.create_ecu_shared_data(top_shared_dl);
        let top_esd_pr = b.create_parent_ref(
            DataFormatParentRefType::EcuSharedData,
            Some(DataFormatParentRefType::tag_as_ecu_shared_data(top_esd)),
        );

        // - root variant carrying all three sibling parent-refs -
        let root_dl = b.create_diag_layer(DiagLayerParams {
            short_name: "RootVariant",
            ..Default::default()
        });
        let root = b.create_variant(
            root_dl,
            true,
            None,
            Some(vec![variant_pr, proto_pr, top_esd_pr]),
        );
        let db = b.finish(EcuDataParams {
            ecu_name: "TestEcu",
            revision: "1",
            version: "1.0.0",
            variants: Some(vec![root]),
            ..Default::default()
        });

        let ecu_data = db.ecu_data().unwrap();
        let variant = ecu_data.variants().unwrap().get(0);
        let parent_refs = variant.parent_refs().unwrap();

        let names: Vec<_> = get_parent_ref_diag_layers_with_refs_recursive(
            parent_refs.iter().map(datatypes::ParentRef),
        )
        .into_iter()
        .filter_map(|(_, dl)| dl.short_name().map(str::to_owned))
        .collect();

        // every layer from every level must be present
        for expected in [
            "TopShared",
            "Proto",
            "ParentProto",
            "InnerVariant",
            "FgLayer",
            "SharedInFg",
        ] {
            assert!(
                names.contains(&expected.to_owned()),
                "Missing expected layer {expected:?}, got {names:?}"
            );
        }
        assert_eq!(names.len(), 6, "Unexpected extra layers: {names:?}");
    }

    /// Test `lookup_service_by_request_prefix` with a routine control service.
    #[test]
    fn test_lookup_service_by_request_prefix_routine_control() {
        const SERVICE_ID: u8 = 0x31;
        const SERVICE_NAME: &str = "Test";

        fn assert_success(result: Result<Vec<DiagComm>, DiagServiceError>) {
            assert!(result.is_ok(), "Expected successful lookup");
            let services = result.unwrap();
            assert_eq!(services.len(), 1, "Expected exactly one matching service");
            assert_eq!(
                services
                    .first()
                    .expect("Expected at least one service")
                    .lookup_name
                    .as_ref()
                    .expect("Expected lookup name in DiagComm to be set"),
                SERVICE_NAME,
                "Expected service name to match"
            );
        }

        let ecu_manager = create_ecu_manager_with_routine_control_service();

        // Lookup with complete prefix (all 4 bytes)
        let full_prefix = vec![
            SERVICE_ID,
            subfunction_ids::routine::REQUEST_RESULTS,
            0x0A,
            0x5C,
        ];
        let result = ecu_manager.lookup_diagcomms_by_request_prefix(&full_prefix);
        assert_success(result);

        // Lookup with partial request
        // (first 3 bytes - SID + subfunction + first byte of routine ID)
        let partial_prefix = vec![SERVICE_ID, subfunction_ids::routine::REQUEST_RESULTS, 0x0A];
        let result = ecu_manager.lookup_diagcomms_by_request_prefix(&partial_prefix);
        assert_success(result);

        // Lookup with wrong subfunction
        let wrong_subfunction = vec![SERVICE_ID, subfunction_ids::routine::STOP, 0x0A, 0x5C];
        let result = ecu_manager.lookup_diagcomms_by_request_prefix(&wrong_subfunction);
        assert!(
            result.is_err(),
            "Expected lookup to fail with wrong subfunction"
        );

        // Lookup with empty prefix
        let result = ecu_manager.lookup_diagcomms_by_request_prefix(&[]);
        assert!(result.is_err(), "Expected lookup to fail with empty prefix");
        match result.unwrap_err() {
            DiagServiceError::NotFound { .. } => {
                // Expected error type
            }
            other => panic!("Expected NotFound error, got: {other:?}"),
        }
    }
}
