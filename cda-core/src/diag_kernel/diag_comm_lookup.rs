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

use cda_interfaces::{
    DiagComm, DiagCommLookup, DiagCommType, DiagServiceError, HashSet,
    datatypes::{DiagnosticServiceAffixPosition, single_ecu},
    dlt_ctx,
    util::{ends_with_ignore_ascii_case, starts_with_ignore_ascii_case},
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> DiagCommLookup for EcuManager<S> {
    #[tracing::instrument(skip(self),
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
            job_name
        )
    )]
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError> {
        tracing::debug!("Looking up single ECU job");
        self.get_single_ecu_jobs_from_variant_and_parent_refs(|job| {
            job.diag_comm().is_some_and(|dc| {
                dc.short_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case(job_name))
            })
        })
        .into_iter()
        .next()
        .map(|job| (*job).into())
        .ok_or(DiagServiceError::NotFound(format!(
            "Single ECU job with name '{job_name}' not found"
        )))
    }

    fn lookup_service_through_func_class(
        &self,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<DiagComm, DiagServiceError> {
        self.get_services_from_variant_and_parent_refs(|service| {
            service
                .diag_comm()
                .and_then(|dc| {
                    dc.funct_class().and_then(|classes| {
                        classes.iter().find(|fc| {
                            fc.short_name()
                                .is_some_and(|name| name.eq_ignore_ascii_case(func_class_name))
                        })
                    })
                })
                .as_ref()
                .is_some_and(|_| service.request_id().is_some_and(|id| id == service_id))
        })
        .into_iter()
        .next()
        .and_then(|service| service.try_into().ok())
        .ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "Service with functional class '{func_class_name}' and SID {service_id:#04X} not \
                 found"
            ))
        })
    }

    fn lookup_diagcomms_by_request_prefix(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<DiagComm>, DiagServiceError> {
        let service_id = *request_bytes.first().ok_or(DiagServiceError::NotFound(
            "cannot lookup service by empty prefix".to_owned(),
        ))?;
        let services: Vec<_> = self
            .lookup_services_by_sid(service_id)?
            .iter()
            .filter(|service| {
                let mut byte_idx = 0usize;
                for param in service.extract_sequential_coded_consts() {
                    let param_byte_count = param.byte_count();
                    if param_byte_count > 4 {
                        return false;
                    }
                    let Some(end_idx) = byte_idx.checked_add(param_byte_count) else {
                        return false;
                    };
                    // Ran out of caller-provided bytes, all provided bytes matched, accept
                    if end_idx > request_bytes.len() {
                        return true;
                    }
                    let Some(param_slice) = request_bytes.get(byte_idx..end_idx) else {
                        return false;
                    };

                    let mut buf = [0u8; 4];
                    // calculate where in the 4-byte buffer to place the parameter bytes.
                    // i.e. a 2 byte param goes into buf[2..4],
                    // leaving buf[0..2] as zero-padding,
                    // copy this into the buffer and convert into u32 big endian.
                    let start = 4usize.saturating_sub(param_byte_count);
                    let Some(buf_slice) = buf.get_mut(start..) else {
                        return false;
                    };
                    buf_slice.copy_from_slice(param_slice);

                    let expected_value = u32::from_be_bytes(buf);
                    if param.value != expected_value {
                        return false;
                    }
                    byte_idx = end_idx;
                }
                true // all consts iterated and all matched
            })
            .filter_map(|service| service.diag_comm())
            .filter_map(|dc| {
                let short_name = dc.short_name()?;
                let type_ = DiagCommType::try_from(service_id).ok()?;

                Some(DiagComm {
                    name: self
                        .database_naming_convention
                        .trim_short_name_affixes(short_name),
                    type_,
                    lookup_name: Some(short_name.to_owned()),
                    subfunction_id: None,
                })
            })
            .collect();

        if services.is_empty() {
            Err(DiagServiceError::NotFound(format!(
                "No service found matching request prefix: {request_bytes:02X?}"
            )))
        } else {
            Ok(services)
        }
    }

    fn lookup_service_by_sid_and_name(
        &self,
        service_id: u8,
        name: &str,
        functional_group_name: Option<&str>,
    ) -> Result<DiagComm, DiagServiceError> {
        let services = if let Some(fg_name) = functional_group_name {
            self.get_services_from_functional_group_and_parent_refs(fg_name, |service| {
                service
                    .request_id()
                    .is_some_and(|req_id| req_id == service_id)
            })?
        } else {
            self.lookup_services_by_sid(service_id)?
        };

        let result = services.iter().find_map(|service| {
            let diag_comm = service.diag_comm()?;
            let short_name = diag_comm.short_name()?;

            let short_name_no_affix = self
                .database_naming_convention
                .trim_service_name_affixes(service_id, short_name.to_owned());
            let matches = match self.database_naming_convention.short_name_affix_position {
                DiagnosticServiceAffixPosition::Suffix => {
                    starts_with_ignore_ascii_case(&short_name_no_affix, name)
                }
                DiagnosticServiceAffixPosition::Prefix => {
                    ends_with_ignore_ascii_case(&short_name_no_affix, name)
                }
            };

            if !matches {
                return None;
            }

            Some(DiagComm {
                name: short_name.to_owned(),
                type_: DiagCommType::try_from(service_id).ok()?,
                lookup_name: Some(short_name.to_owned()),
                subfunction_id: None,
            })
        });

        if let Some(diag_comm) = result {
            Ok(diag_comm)
        } else {
            let alternatives: HashSet<String> = services
                .iter()
                .filter_map(|service| {
                    let diag_comm = service.diag_comm()?;
                    let short_name = diag_comm.short_name()?;
                    let short_name_no_affix =
                        self.database_naming_convention.trim_short_name_affixes(
                            &self
                                .database_naming_convention
                                .trim_service_name_affixes(service_id, short_name.to_owned()),
                        );
                    Some(short_name_no_affix)
                })
                .collect();

            Err(DiagServiceError::InvalidParameter {
                possible_values: alternatives,
            })
        }
    }
}
