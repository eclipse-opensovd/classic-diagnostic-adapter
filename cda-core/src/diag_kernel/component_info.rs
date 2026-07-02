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

use cda_database::datatypes;
use cda_interfaces::{
    ComponentInfos, DiagServiceError, DynamicPlugin, HashMap, HashSet,
    datatypes::{
        ComponentConfigurationsInfo, ComponentDataInfo, ComponentOperationsInfo,
        DiagnosticServiceAffixPosition, RoutineSubfunctions,
    },
    service_ids, subfunction_ids,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;
use crate::diag_kernel::security::is_service_visible;

impl<S: SecurityPlugin> ComponentInfos for EcuManager<S> {
    fn get_components_data_info(&self, security_plugin: &DynamicPlugin) -> Vec<ComponentDataInfo> {
        self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
        })
        .into_iter()
        .filter(|service| is_service_visible::<S>(security_plugin, service))
        .filter_map(|service| {
            let diag_comm = service.diag_comm()?;
            Some(self.diag_comm_to_component_data_info(&(diag_comm.into())))
        })
        .collect()
    }

    fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        Ok(self
            .get_services_from_functional_group_and_parent_refs(functional_group_name, |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
            })?
            .into_iter()
            .filter(|service| is_service_visible::<S>(security_plugin, service))
            .filter_map(|service| {
                let diag_comm = service.diag_comm()?;
                Some(self.diag_comm_to_component_data_info(&(diag_comm.into())))
            })
            .collect())
    }

    /// Returns all services in /configuration,
    /// i.e. 0x22 (`ReadDataByIdentifier`) and 0x2E (`WriteDataByIdentifier`)
    /// that are in the functional group varcoding.
    fn get_components_configurations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        let diag_layers = self.get_diag_layers_from_variant_and_parent_refs();
        let var_coding_func_class_short_name = diag_layers
            .iter()
            .filter_map(|dl| dl.funct_classes())
            .flat_map(|fc_vec| fc_vec.iter())
            .find_map(|fc| {
                fc.short_name().filter(|name| {
                    name.eq_ignore_ascii_case(
                        &self.database_naming_convention.functional_class_varcoding,
                    )
                })
            })
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "Functional class '{}' for varcoding not found in any diagnostic layer",
                    self.database_naming_convention.functional_class_varcoding
                ))
            })?;

        let configuration_sids = [
            service_ids::READ_DATA_BY_IDENTIFIER,
            service_ids::WRITE_DATA_BY_IDENTIFIER,
        ];

        // Maps a common abbreviated service short name (using the configured affixes) to
        // a vector of bytes of: service_id, ID_parameter_coded_const
        let mut result_map: HashMap<String, HashSet<Vec<u8>>> = HashMap::default();

        // Maps common short name to long name
        let mut long_name_map: HashMap<String, String> = HashMap::default();

        // Iterate over all services of the variant and the base
        diag_layers
            .iter()
            .filter_map(|dl| dl.diag_services())
            .flat_map(|services| services.iter())
            .map(datatypes::DiagService)
            .filter(|service| is_service_visible::<S>(security_plugin, service))
            .filter(|service| {
                service
                    .request_id()
                    .is_some_and(|id| configuration_sids.contains(&id))
            })
            .filter_map(|service| {
                service
                    .diag_comm()
                    .map(|dc| (service, datatypes::DiagComm(dc)))
            })
            .filter(|(_, dc)| {
                dc.funct_class().is_some_and(|fc| {
                    fc.iter().any(|fc| {
                        fc.short_name()
                            .is_some_and(|n| n == var_coding_func_class_short_name)
                    })
                })
            })
            .for_each(|(service, diag_comm)| {
                // trim short names so write and read services are grouped together
                let common_short_name = diag_comm
                    .short_name()
                    .map(|short_name| {
                        self.database_naming_convention
                            .trim_short_name_affixes(short_name)
                    })
                    .unwrap_or_default();

                // trim the long name so we can return a descriptive name
                if !long_name_map.contains_key(&common_short_name)
                    && let Some(long_name) = diag_comm.long_name().and_then(|ln| {
                        ln.value().map(|long_name| {
                            self.database_naming_convention
                                .trim_long_name_affixes(long_name)
                        })
                    })
                {
                    long_name_map.insert(common_short_name.clone(), long_name);
                }

                let Some(service_id) = service.request_id() else {
                    return;
                };
                let Some((sub_function_id, sub_func_id_bit_len)) =
                    service.request_sub_function_id()
                else {
                    return;
                };

                // collect the coded const bytes of the parameter expressing the ID
                let bytes = sub_function_id.to_be_bytes();
                let Some(id_param_bytes) =
                    bytes.get(4usize.saturating_sub(sub_func_id_bit_len as usize / 8)..)
                else {
                    return;
                };
                // compile the first bytes of the raw uds payload
                let mut service_abstract_entry =
                    Vec::with_capacity(1usize.saturating_add(id_param_bytes.len()));
                service_abstract_entry.push(service_id);
                service_abstract_entry.extend_from_slice(id_param_bytes);

                result_map
                    .entry(common_short_name)
                    .or_default()
                    .insert(service_abstract_entry);
            });

        let mut result: Vec<_> = result_map
            .into_iter()
            .map(
                |(common_short_name, abstracts)| ComponentConfigurationsInfo {
                    name: long_name_map
                        .get(&common_short_name)
                        .cloned()
                        .unwrap_or_default(),
                    id: common_short_name,
                    configurations_type: "parameter".to_owned(),
                    service_abstract: abstracts.into_iter().collect(),
                },
            )
            .collect();
        result.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(result)
    }

    /// Returns all `RoutineControl` (SID 0x31) services for the given ECU,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_components_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Vec<ComponentOperationsInfo> {
        let routine_control_services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                && is_service_visible::<S>(security_plugin, service)
        });

        self.filter_and_transform_operations(routine_control_services)
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine.
    /// Looks for services named `{service_name}_Stop` (0x02) and
    /// `{service_name}_RequestResults` (0x03).
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the Start (0x01) subfunction for the given
    /// service name is not found in the ECU description.
    fn get_routine_subfunctions(
        &self,
        service_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        let all_rc_services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                && is_service_visible::<S>(security_plugin, service)
                && service.diag_comm().is_some_and(|dc| {
                    dc.short_name().is_some_and(|name| {
                        self.trim_routine_name(name)
                            .eq_ignore_ascii_case(service_name)
                    })
                })
        });

        if all_rc_services.is_empty() {
            return Err(DiagServiceError::NotFound(format!(
                "No RoutineControl service found for routine '{service_name}'"
            )));
        }

        Ok(subfunction_flags_from_services(&all_rc_services))
    }

    /// Returns all `RoutineControl` (SID 0x31) services for the functional group,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_functional_group_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        let routine_ctrl_services = self.get_services_from_functional_group_and_parent_refs(
            functional_group_name,
            |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                    && is_service_visible::<S>(security_plugin, service)
            },
        )?;

        Ok(self.filter_and_transform_operations(routine_ctrl_services))
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine
    /// within a functional group.
    ///
    /// Mirrors `get_routine_subfunctions` but scopes the lookup to the given functional group's
    /// diag layer instead of the ECU variant.
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the functional group does not exist, or if the
    /// Start (0x01) subfunction for the given service name is not found within it.
    fn get_functional_group_routine_subfunctions(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        let all_rc_services = self.get_services_from_functional_group_and_parent_refs(
            functional_group_name,
            |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                    && is_service_visible::<S>(security_plugin, service)
                    && service.diag_comm().is_some_and(|dc| {
                        dc.short_name().is_some_and(|name| {
                            self.trim_routine_name(name)
                                .eq_ignore_ascii_case(service_name)
                        })
                    })
            },
        )?;

        if all_rc_services.is_empty() {
            return Err(DiagServiceError::NotFound(format!(
                "No RoutineControl service with name '{service_name}' found in functional group \
                 '{functional_group_name}'"
            )));
        }

        Ok(subfunction_flags_from_services(&all_rc_services))
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        self.get_single_ecu_jobs_from_variant_and_parent_refs(|_| true)
            .into_iter()
            .filter_map(|job: datatypes::SingleEcuJob<'_>| {
                let diag_comm = job.diag_comm()?;
                let semantic = diag_comm.semantic()?;
                Some(ComponentDataInfo {
                    category: semantic.to_lowercase(),
                    id: diag_comm.short_name().map_or(<_>::default(), |n| {
                        self.database_naming_convention
                            .trim_short_name_affixes(n)
                            .to_lowercase()
                    }),
                    name: diag_comm
                        .long_name()
                        .and_then(|ln| ln.value().map(ToOwned::to_owned))
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    fn get_request_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
        use cda_interfaces::ServiceParameterMetadata;

        use crate::diag_kernel::param_metadata::extract_request_param_type;

        let service = self.get_meta_data_service(service_name)?;
        let Some(request) = service.request() else {
            tracing::warn!("Service '{}' has no request definition", service_name);
            return Ok(Vec::new());
        };

        let Some(params) = request.params() else {
            return Ok(Vec::new());
        };

        tracing::debug!(
            "Service '{}' has {} request parameters",
            service_name,
            params.len()
        );

        let metadata = params
            .into_iter()
            .map(datatypes::Parameter)
            .filter_map(|param| {
                let name = param.short_name().map(ToOwned::to_owned).or_else(|| {
                    tracing::warn!(
                        "Service '{}' has a parameter with no short name, skipping",
                        service_name
                    );
                    None
                })?;

                let semantic = param.semantic().map(ToOwned::to_owned);
                let param_type = extract_request_param_type(&param, service_name, &name).ok()?;

                Some(ServiceParameterMetadata {
                    name,
                    semantic,
                    param_type,
                })
            })
            .collect();

        Ok(metadata)
    }

    /// Get parameter metadata for the POS-RESPONSE of a service.
    ///
    /// Returns one [`ResponseParameterInfo`] per parameter in the first positive
    /// response definition, including byte layout (position, size) and type
    /// information. This is the response-side counterpart of
    /// [`get_request_parameter_metadata`] (which returns request parameters).
    ///
    /// For MUX DOP parameters, the MUX cases are expanded: each case's inner
    /// structure parameters are returned with their names prefixed by the case
    /// short name
    fn get_response_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        use cda_interfaces::ResponseParameterInfo;

        use crate::diag_kernel::param_metadata::{
            byte_size_from_coded_const, byte_size_from_value_param, expand_mux_cases,
            extract_response_param_type,
        };

        let service = self.get_meta_data_service(service_name)?;
        let pos_responses = match service.pos_responses() {
            Some(r) if !r.is_empty() => r,
            _ => return Ok(Vec::new()),
        };

        let Some(params) = pos_responses.iter().next().and_then(|r| r.params()) else {
            return Ok(Vec::new());
        };

        let mut metadata: Vec<ResponseParameterInfo> = Vec::new();
        for raw_param in params {
            let param = datatypes::Parameter(raw_param);
            let Some(name) = param.short_name().map(ToOwned::to_owned) else {
                continue;
            };
            let semantic = param.semantic().map(ToOwned::to_owned);
            let param_type = extract_response_param_type(&param);

            let byte_size = match &param_type {
                cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                    let (size, is_mux) = byte_size_from_value_param(&param);
                    if is_mux {
                        metadata.extend(expand_mux_cases(&param, param.byte_position()));
                        continue;
                    }
                    size
                }
                cda_interfaces::ParameterTypeMetadata::CodedConst { .. } => {
                    byte_size_from_coded_const(&param)
                }
                cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { byte_length } => {
                    Some(*byte_length)
                }
                cda_interfaces::ParameterTypeMetadata::PhysConst { .. } => None,
            };
            metadata.push(ResponseParameterInfo {
                name,
                semantic,
                param_type,
                byte_position: param.byte_position(),
                bit_position: param.bit_position(),
                byte_size,
            });
        }

        tracing::debug!(
            "Service '{}' has {} positive-response parameters (MUX-expanded)",
            service_name,
            metadata.len()
        );
        Ok(metadata)
    }

    fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::MuxCaseInfo>, DiagServiceError> {
        use cda_interfaces::MuxCaseInfo;

        let service = self.get_meta_data_service(service_name)?;
        let Some(pos_responses) = service.pos_responses() else {
            return Ok(Vec::new());
        };

        tracing::debug!(
            "Service '{}' has {} positive responses",
            service_name,
            pos_responses.len()
        );

        let mux_cases: Vec<_> = pos_responses
            .into_iter()
            .filter_map(|pr| pr.params())
            .flatten()
            .filter_map(|param| param.specific_data_as_value()?.dop())
            .map(datatypes::DataOperation)
            .flat_map(|dop| -> Vec<MuxCaseInfo> {
                let Ok(datatypes::DataOperationVariant::Mux(mux_dop)) = dop.variant() else {
                    return Vec::new();
                };
                let Some(cases) = mux_dop.cases() else {
                    return Vec::new();
                };
                cases
                    .into_iter()
                    .map(|case| MuxCaseInfo {
                        short_name: case.short_name().unwrap_or_default().to_owned(),
                        long_name: case
                            .long_name()
                            .and_then(|ln| ln.value())
                            .map(ToOwned::to_owned),
                        lower_limit: case
                            .lower_limit()
                            .and_then(|ll| ll.value())
                            .map(ToOwned::to_owned),
                        upper_limit: case
                            .upper_limit()
                            .and_then(|ul| ul.value())
                            .map(ToOwned::to_owned),
                    })
                    .collect()
            })
            .collect();

        tracing::debug!(
            "Service '{}' has {} MUX cases",
            service_name,
            mux_cases.len()
        );
        Ok(mux_cases)
    }

    fn functional_groups(&self) -> Vec<String> {
        let Ok(groups) = self.diag_database.functional_groups() else {
            return Vec::new();
        };
        groups
            .into_iter()
            .filter_map(|group| {
                group
                    .diag_layer()
                    .and_then(|dl| dl.short_name())
                    .and_then(|name| {
                        let protocol_value = self.protocol.str();
                        let matches = match self.fg_protocol_position {
                            DiagnosticServiceAffixPosition::Prefix => {
                                cda_interfaces::util::starts_with_ignore_ascii_case(
                                    name,
                                    protocol_value,
                                )
                            }
                            DiagnosticServiceAffixPosition::Suffix => {
                                cda_interfaces::util::ends_with_ignore_ascii_case(
                                    name,
                                    protocol_value,
                                )
                            }
                        };
                        if matches {
                            Some(name.to_lowercase())
                        } else {
                            None
                        }
                    })
            })
            .collect::<Vec<_>>()
    }
}

impl<S: SecurityPlugin> EcuManager<S> {
    fn diag_comm_to_component_data_info(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> ComponentDataInfo {
        ComponentDataInfo {
            category: diag_comm.semantic().unwrap_or_default().to_owned(),
            id: diag_comm.short_name().map_or(<_>::default(), |s| {
                self.database_naming_convention.trim_short_name_affixes(s)
            }),
            name: diag_comm
                .long_name()
                .and_then(|ln| ln.value())
                .map_or(<_>::default(), |v| {
                    self.database_naming_convention.trim_long_name_affixes(v)
                }),
        }
    }

    /// Trims affixes from a routine control service name to derive the base routine name.
    fn trim_routine_name(&self, name: &str) -> String {
        let name_trimmed = self
            .database_naming_convention
            .trim_service_name_affixes(service_ids::ROUTINE_CONTROL, name.to_owned());
        self.database_naming_convention
            .trim_short_name_affixes(&name_trimmed)
    }

    /// Filter and transform services into `ComponentOperationsInfo`
    /// This is used for operation lookup and metadata.
    fn filter_and_transform_operations(
        &self,
        services: Vec<datatypes::DiagService<'_>>,
    ) -> Vec<ComponentOperationsInfo> {
        services
            .into_iter()
            // filter out services that don't have a DiagComm with a short name
            // and crate a tuple of (id, service) where id is the trimmed short name
            // without any affixes
            .filter_map(|service| {
                let diag_comm = service.diag_comm()?;
                let id = self.trim_routine_name(diag_comm.short_name()?);
                Some((id, service))
            })
            // fold over the id of the previous steps creating a map of
            // ids to a list of services with the same trimmed short name
            .fold(
                HashMap::default(),
                |mut acc: HashMap<String, Vec<datatypes::DiagService>>, (id, service)| {
                    acc.entry(id).or_default().push(service);
                    acc
                },
            )
            .into_iter()
            .filter_map(|(id, services)| {
                // filter out entries that have an empty list of services (shouldn't happen)
                let first_service = services.first()?;
                // map to a struct of `ComponentOperationsInfo`
                let name = first_service
                    .diag_comm()
                    .expect(
                        "DiagComm has to be present as otherwise it would be filtered out before",
                    )
                    .long_name()
                    .and_then(|ln| ln.value())
                    .map(|v| self.database_naming_convention.trim_long_name_affixes(v))
                    .unwrap_or_default();
                let RoutineSubfunctions {
                    has_stop,
                    has_request_results,
                } = subfunction_flags_from_services(&services);
                Some(ComponentOperationsInfo {
                    id,
                    name,
                    has_stop,
                    has_request_results,
                })
            })
            .collect()
    }

    fn get_meta_data_service(
        &self,
        service_name: &str,
    ) -> Result<datatypes::DiagService<'_>, DiagServiceError> {
        cda_interfaces::SERVICE_IDS_PARAMETER_META_DATA
            .into_iter()
            .find_map(|sid| {
                self.lookup_services_by_sid(sid)
                    .ok()?
                    .into_iter()
                    .find(|s| {
                        s.diag_comm()
                            .and_then(|dc| dc.short_name())
                            .is_some_and(|n| n == service_name)
                    })
            })
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!("Service '{service_name}' not found"))
            })
    }
}

/// Derives `has_stop` / `has_request_results` flags by folding over an
/// already-fetched slice of `DiagService`s.
///
/// The caller is responsible for pre-filtering the slice to only the
/// services that belong to the routine of interest. This helper does not
/// perform any database traversal.
fn subfunction_flags_from_services(services: &[datatypes::DiagService<'_>]) -> RoutineSubfunctions {
    let mask = u32::from(cda_interfaces::DEFAULT_SUBFUNCTION_MASK);
    let mut has_stop = false;
    let mut has_request_results = false;
    for service in services {
        if let Some((sf, _)) = service.request_sub_function_id() {
            let masked = sf & mask;
            if masked == u32::from(subfunction_ids::routine::STOP) {
                has_stop = true;
            } else if masked == u32::from(subfunction_ids::routine::REQUEST_RESULTS) {
                has_request_results = true;
            }
        }
    }
    RoutineSubfunctions {
        has_stop,
        has_request_results,
    }
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        DataType,
        database_builder::{DiagClassType, DiagCommParams, DiagLayerParams, EcuDataBuilder},
    };
    use cda_interfaces::{DiagComm, DiagCommType, Protocol};
    use cda_plugin_security::DefaultSecurityPluginData;

    use super::*;
    use crate::diag_kernel::test_utils::{
        db_builder::{finish_db, finish_db_with_functional_groups},
        ecu_manager_builder::{
            SID_PARM_NAME, create_ecu_manager_with_mixed_functional_group,
            create_ecu_manager_with_mux_service, create_ecu_manager_with_parameter_metadata,
            create_ecu_manager_with_phys_const_normal_dop_service,
            create_ecu_manager_with_struct_service, new_ecu_manager,
        },
        mdd_type_builder::{create_sid_only_request, new_diag_comm, new_diag_service},
    };

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    #[test]
    fn test_get_request_parameter_metadata_success() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        let result = ecu_manager.get_request_parameter_metadata("RDBI_TestService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 3); // sid, RDBI_DID, data

        let sid_param = metadata.iter().find(|m| m.name == SID_PARM_NAME).unwrap();
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        if let ParameterTypeMetadata::CodedConst { coded_value } = &sid_param.param_type {
            assert_eq!(coded_value, "34");
        }

        let did_param = metadata.iter().find(|m| m.name == "RDBI_DID").unwrap();
        if let ParameterTypeMetadata::CodedConst { coded_value } = &did_param.param_type {
            assert_eq!(coded_value, "0xF190");
        } else {
            panic!("Expected CODED-CONST parameter type for RDBI_DID");
        }

        let data_param = metadata.iter().find(|m| m.name == "data").unwrap();
        assert!(matches!(
            data_param.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
    }

    #[test]
    fn test_get_request_parameter_metadata_service_not_found() {
        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        let result = ecu_manager.get_request_parameter_metadata("NonExistentService");
        assert!(result.is_err());
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_mux_cases_for_service_success() {
        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        let result = ecu_manager.get_mux_cases_for_service("TestMuxService");
        assert!(result.is_ok());

        let mux_cases = result.unwrap();
        assert_eq!(mux_cases.len(), 3);

        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_1"));
        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_2"));
        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_3"));

        let case_1 = mux_cases
            .iter()
            .find(|c| c.short_name == "mux_1_case_1")
            .unwrap();
        assert!(case_1.lower_limit.is_some());

        let case_2 = mux_cases
            .iter()
            .find(|c| c.short_name == "mux_1_case_2")
            .unwrap();
        assert!(case_2.lower_limit.is_some());
    }

    #[test]
    fn test_get_mux_cases_for_service_not_found() {
        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        let result = ecu_manager.get_mux_cases_for_service("NonExistentService");
        assert!(result.is_err());
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_mux_cases_for_service_no_mux_cases() {
        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        let result = ecu_manager.get_mux_cases_for_service("RDBI_TestService");
        assert!(result.is_ok());

        let mux_cases = result.unwrap();
        assert_eq!(mux_cases.len(), 0);
    }

    #[test]
    fn test_get_request_parameter_metadata_extracts_coded_const_did_value() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        let result = ecu_manager.get_request_parameter_metadata("RDBI_TestService");
        assert!(result.is_ok());

        let metadata = result.unwrap();

        let did_param = metadata.iter().find(|m| m.name == "RDBI_DID").unwrap();

        if let ParameterTypeMetadata::CodedConst { coded_value } = &did_param.param_type {
            let did_value = if coded_value.starts_with("0x") || coded_value.starts_with("0X") {
                u16::from_str_radix(coded_value.get(2..).unwrap_or(""), 16).ok()
            } else {
                coded_value.parse::<u16>().ok()
            };

            assert!(
                did_value.is_some(),
                "CODED-CONST value '{coded_value}' should be parseable as DID"
            );
            assert_eq!(did_value.unwrap(), 0xF190);
        } else {
            panic!("Expected CODED-CONST parameter type");
        }
    }

    /// Verifies that `get_request_parameter_metadata` resolves `coded_value` for a
    /// PHYS-CONST parameter backed by a `NormalDOP` with an Identical `CompuMethod`.
    #[test]
    fn test_get_request_parameter_metadata_phys_const_coded_value_resolved() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_request_parameter_metadata("TestPhysConstNormalService");
        assert!(result.is_ok());

        let metadata = result.unwrap();

        let did_param = metadata
            .iter()
            .find(|m| m.name == "DID")
            .expect("DID parameter should be present");

        if let ParameterTypeMetadata::PhysConst {
            phys_constant_value,
            coded_value,
        } = &did_param.param_type
        {
            assert_eq!(phys_constant_value, "61840");
            assert_eq!(
                *coded_value,
                Some(61840u64),
                "PHYS-CONST with Identical CompuMethod must resolve coded_value"
            );
        } else {
            panic!(
                "Expected PhysConst parameter type for DID, got {:?}",
                did_param.param_type
            );
        }
    }

    #[test]
    fn test_get_response_parameter_metadata_service_not_found() {
        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_response_parameter_metadata("NonExistentService");
        assert!(result.is_err());
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_response_parameter_metadata_empty_for_no_pos_response() {
        let (ecu_manager, _dc, _sid, _) = create_ecu_manager_with_struct_service(1);

        let result = ecu_manager.get_response_parameter_metadata("TestStructService");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    /// Covers `CodedConst` (SID), `PhysConst` (DID), and `Value` (data) response parameters.
    #[test]
    fn test_get_response_parameter_metadata_phys_const_and_value_params() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_response_parameter_metadata("TestPhysConstNormalService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 3, "Expected sid, DID, data_param");

        let sid_param = metadata
            .iter()
            .find(|m| m.name == "sid")
            .expect("sid param should be present");
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(sid_param.byte_position, 0);
        assert_eq!(sid_param.byte_size, Some(1));

        let did_param = metadata
            .iter()
            .find(|m| m.name == "DID")
            .expect("DID param should be present");
        if let ParameterTypeMetadata::PhysConst {
            phys_constant_value,
            coded_value,
        } = &did_param.param_type
        {
            assert_eq!(phys_constant_value, "61840");
            assert!(
                coded_value.is_none(),
                "get_response_parameter_metadata does not resolve PhysConst coded_value"
            );
        } else {
            panic!(
                "Expected PhysConst type for DID, got {:?}",
                did_param.param_type
            );
        }
        assert_eq!(did_param.byte_position, 1);
        assert!(did_param.byte_size.is_none());

        let data_param = metadata
            .iter()
            .find(|m| m.name == "data_param")
            .expect("data_param should be present");
        assert!(matches!(
            data_param.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        assert_eq!(data_param.byte_position, 3);
        assert_eq!(data_param.byte_size, Some(1));
    }

    #[test]
    fn test_get_response_parameter_metadata_mux_expansion() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        let result = ecu_manager.get_response_parameter_metadata("TestMuxService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(
            metadata.len(),
            7,
            "Expected SID + case-1 entries (2+marker) + case-2 entries (2+marker)"
        );

        let sid_param = metadata
            .iter()
            .find(|m| m.name == "test_service_pos_sid")
            .expect("test_service_pos_sid should be present");
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(sid_param.byte_position, 0);

        let c1p1 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_1/mux_1_case_1_param_1")
            .expect("mux_1_case_1/mux_1_case_1_param_1 should be present");
        assert!(matches!(
            c1p1.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        assert_eq!(c1p1.byte_position, 4);
        assert_eq!(c1p1.byte_size, Some(4));

        let c1p2 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_1/mux_1_case_1_param_2")
            .expect("mux_1_case_1/mux_1_case_1_param_2 should be present");
        assert!(matches!(
            c1p2.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        assert_eq!(c1p2.byte_position, 8);
        assert_eq!(c1p2.byte_size, Some(1));

        let marker_1 = metadata
            .iter()
            .find(|m| m.name == "__mux_case__/mux_1_case_1")
            .expect("__mux_case__/mux_1_case_1 marker should be present");
        assert!(matches!(
            marker_1.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(marker_1.byte_position, 4);
        assert_eq!(marker_1.byte_size, Some(7));
    }

    #[test]
    fn test_get_functional_group_data_info_filters_non_read_services() {
        let ecu_manager = create_ecu_manager_with_mixed_functional_group();

        let result = ecu_manager
            .get_functional_group_data_info(&skip_sec_plugin!(), "MixedGroup")
            .expect("should return Ok");

        assert_eq!(result.len(), 1, "only read services should be returned");
        assert_eq!(
            result.first().expect("Expected element at index 0").id,
            "ReadService"
        );
    }

    #[test]
    fn test_get_functional_group_data_info_no_functional_groups() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let db = finish_db!(db_builder, protocol, vec![]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager.get_functional_group_data_info(&skip_sec_plugin!(), "AnyGroup");

        assert!(
            result.is_err(),
            "should fail when database has no functional groups"
        );
        assert!(
            matches!(result, Err(DiagServiceError::InvalidDatabase(_))),
            "expected InvalidDatabase error"
        );
    }

    /// Build an `EcuManager` whose database contains `RoutineControl` services for a
    /// routine named `routine_name`.  `subfunctions` controls which subfunction bytes
    /// (0x01 = Start, 0x02 = Stop, 0x03 = `RequestResults`) are included.
    fn build_ecu_manager_with_routine_subfunctions(
        routine_name: &str,
        subfunctions: &[u8],
    ) -> super::super::ecumanager::EcuManager<DefaultSecurityPluginData> {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut services = vec![];
        for &sf in subfunctions {
            let sid_param = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_param = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
            let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                short_name: routine_name,
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            services.push(new_diag_service!(
                db_builder,
                diag_comm,
                request,
                vec![],
                vec![]
            ));
        }

        let db = finish_db!(db_builder, protocol, services);
        new_ecu_manager(db)
    }

    /// Build an `EcuManager` with a functional group `fg_name` that contains `RoutineControl`
    /// services for `routine_name` with the given `subfunctions`.
    fn build_ecu_manager_with_fg_routine(
        fg_name: &str,
        routine_name: &str,
        subfunctions: &[u8],
    ) -> super::super::ecumanager::EcuManager<DefaultSecurityPluginData> {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut services = vec![];
        for &sf in subfunctions {
            let sid_param = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_param = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
            let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                short_name: routine_name,
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            services.push(new_diag_service!(
                db_builder,
                diag_comm,
                request,
                vec![],
                vec![]
            ));
        }

        let fg_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: fg_name,
            diag_services: if services.is_empty() {
                None
            } else {
                Some(services)
            },
            ..Default::default()
        });
        let fg = db_builder.create_functional_group(fg_diag_layer, None);
        let db = finish_db_with_functional_groups!(db_builder, protocol, vec![], vec![fg]);
        new_ecu_manager(db)
    }

    #[test]
    fn test_get_components_operations_info_start_only() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[subfunction_ids::routine::START],
        );

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());

        assert_eq!(result.len(), 1, "Expected exactly one operation");
        let op = result.first().expect("Expected at least one operation");
        assert_eq!(op.id, "MyRoutine");
        assert!(!op.has_stop, "Expected has_stop = false");
        assert!(
            !op.has_request_results,
            "Expected has_request_results = false"
        );
    }

    #[test]
    fn test_get_components_operations_info_with_stop_and_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
                subfunction_ids::routine::REQUEST_RESULTS,
            ],
        );

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());

        assert_eq!(result.len(), 1, "Expected exactly one operation");
        let op = result.first().expect("Expected at least one operation");
        assert_eq!(op.id, "MyRoutine");
        assert!(op.has_stop, "Expected has_stop = true");
        assert!(
            op.has_request_results,
            "Expected has_request_results = true"
        );
    }

    #[test]
    fn test_get_components_operations_info_multiple_routines() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut services = vec![];
        for (name, sfs) in [
            (
                "RoutineA",
                &[
                    subfunction_ids::routine::START,
                    subfunction_ids::routine::STOP,
                ][..],
            ),
            ("RoutineB", &[subfunction_ids::routine::START][..]),
        ] {
            for &sf in sfs {
                let sid_param = db_builder.create_coded_const_param(
                    "SID_RQ",
                    &service_ids::ROUTINE_CONTROL.to_string(),
                    0,
                    0,
                    8,
                    DataType::UInt32,
                );
                let sf_param = db_builder.create_coded_const_param(
                    "RoutineControlType",
                    &sf.to_string(),
                    1,
                    0,
                    8,
                    DataType::UInt32,
                );
                let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
                let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                    short_name: name,
                    diag_class_type: DiagClassType::START_COMM,
                    protocols: Some(vec![protocol]),
                    ..Default::default()
                });
                services.push(new_diag_service!(
                    db_builder,
                    diag_comm,
                    request,
                    vec![],
                    vec![]
                ));
            }
        }

        let db = finish_db!(db_builder, protocol, services);
        let ecu_manager = new_ecu_manager(db);

        let mut result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());
        result.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(result.len(), 2);

        let a = result.first().expect("Expected RoutineA");
        assert_eq!(a.id, "RoutineA");
        assert!(a.has_stop);
        assert!(!a.has_request_results);

        let b = result.get(1).expect("Expected RoutineB");
        assert_eq!(b.id, "RoutineB");
        assert!(!b.has_stop);
        assert!(!b.has_request_results);
    }

    #[test]
    fn test_get_components_operations_info_empty_when_no_routine_control() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
        let read_request =
            create_sid_only_request!(db_builder, service_ids::READ_DATA_BY_IDENTIFIER);
        let read_diag_comm = new_diag_comm!(db_builder, "SomeData", protocol);
        let service = new_diag_service!(db_builder, read_diag_comm, read_request, vec![], vec![]);
        let db = finish_db!(db_builder, protocol, vec![service]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());
        assert!(
            result.is_empty(),
            "Expected no operations for non-routine-control DB"
        );
    }

    #[test]
    fn test_get_routine_subfunctions_detects_stop_and_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
                subfunction_ids::routine::REQUEST_RESULTS,
            ],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("Routine1", &skip_sec_plugin!())
            .expect("Expected Ok for known routine");
        assert!(subs.has_stop, "Expected has_stop = true");
        assert!(
            subs.has_request_results,
            "Expected has_request_results = true"
        );
    }

    #[test]
    fn test_get_routine_subfunctions_no_stop_no_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[subfunction_ids::routine::START],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("Routine1", &skip_sec_plugin!())
            .expect("Expected Ok for known routine");
        assert!(!subs.has_stop, "Expected has_stop = false");
        assert!(
            !subs.has_request_results,
            "Expected has_request_results = false"
        );
    }

    #[test]
    fn test_get_routine_subfunctions_case_insensitive() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
            ],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("myroutine", &skip_sec_plugin!())
            .expect("Expected Ok (case-insensitive match)");
        assert!(
            subs.has_stop,
            "Expected has_stop = true (case-insensitive match)"
        );
    }

    #[test]
    fn test_get_routine_subfunctions_returns_not_found_for_unknown_service() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[subfunction_ids::routine::START],
        );

        let result =
            ecu_manager.get_routine_subfunctions("NonExistentRoutine", &skip_sec_plugin!());
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound for unknown service, got: {result:?}"
        );
    }

    #[test]
    fn test_get_functional_group_operations_info_returns_start_service() {
        let ecu_manager = build_ecu_manager_with_fg_routine(
            "TestFG",
            "FgRoutine",
            &[subfunction_ids::routine::START],
        );

        let result = ecu_manager
            .get_functional_group_operations_info(&skip_sec_plugin!(), "TestFG")
            .expect("Expected successful lookup");

        assert_eq!(result.len(), 1, "Expected exactly one FG operation");
        let op = result.first().expect("Expected at least one FG operation");
        assert_eq!(op.id, "FgRoutine");
        assert!(!op.has_stop);
        assert!(!op.has_request_results);
    }

    #[test]
    fn test_get_functional_group_operations_info_with_stop_and_request_results() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut fg_services = vec![];
        for &sf in &[
            subfunction_ids::routine::START,
            subfunction_ids::routine::STOP,
            subfunction_ids::routine::REQUEST_RESULTS,
        ] {
            let sid_p = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_p = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let req = db_builder.create_request(Some(vec![sid_p, sf_p]), None);
            let dc = db_builder.create_diag_comm(DiagCommParams {
                short_name: "FgRoutine",
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            fg_services.push(new_diag_service!(db_builder, dc, req, vec![], vec![]));
        }

        let fg_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestFG",
            diag_services: Some(fg_services),
            ..Default::default()
        });
        let fg = db_builder.create_functional_group(fg_diag_layer, None);
        let db = finish_db_with_functional_groups!(db_builder, protocol, vec![], vec![fg]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager
            .get_functional_group_operations_info(&skip_sec_plugin!(), "TestFG")
            .expect("Expected successful lookup");

        assert_eq!(result.len(), 1);
        let op = result.first().expect("Expected at least one FG operation");
        assert_eq!(op.id, "FgRoutine");
        assert!(op.has_stop);
        assert!(op.has_request_results);
    }

    #[test]
    fn test_get_functional_group_operations_info_unknown_group() {
        let ecu_manager = build_ecu_manager_with_fg_routine(
            "SomeFG",
            "SomeRoutine",
            &[subfunction_ids::routine::START],
        );

        let result =
            ecu_manager.get_functional_group_operations_info(&skip_sec_plugin!(), "NonExistent");
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound error for unknown group"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_request_results_via_subfunction_id() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find RequestResults service, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_stop_via_subfunction_id() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Stop",
            &[subfunction_ids::routine::STOP],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::STOP),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find Stop service, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_request_results_not_found() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Start",
            &[subfunction_ids::routine::START],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_matches_with_sprmib_set() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS | 0x80),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find RequestResults service even with SPRMIB set, \
             got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_no_match_with_full_mask() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS | 0x80),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, Some(0xFF))
            .await;
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound when using mask 0xFF with SPRMIB-set subfunction, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_lookup_diag_service_clean_subfunction_still_matches() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Stop",
            &[subfunction_ids::routine::STOP],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::STOP),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected clean subfunction to still match with default mask, got: {result:?}"
        );
    }
}
