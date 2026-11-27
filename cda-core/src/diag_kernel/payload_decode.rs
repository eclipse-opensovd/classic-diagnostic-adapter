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
    DiagComm, DiagServiceError, EcuStateManager, HashMap, HashSet, PayloadDecoder, ServicePayload,
    datatypes::CLEAR_FAULT_MEM_POS_RESPONSE_SID,
    diagservices::{DiagServiceResponseType, FieldParseError},
    dlt_ctx, service_ids,
    util::{self},
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;
use crate::{
    MappedResponseData,
    diag_kernel::{
        DiagDataValue,
        diagservices::{
            DiagDataTypeContainer, DiagDataTypeContainerRaw, DiagServiceResponseStruct,
            MappedDiagServiceResponsePayload,
        },
        operations,
        payload::{Payload, str_to_json_value},
    },
};

#[derive(Clone, Copy)]
struct ParamContext<'a> {
    parameter: &'a datatypes::Parameter<'a>,
    base_offset: usize,
    outer_context: Option<&'a MappedDiagServiceResponsePayload>,
    /// When `true`, a missing BYTE-POSITION means byte 0 relative to
    /// `base_offset` instead of "follows the previous param". Used when a
    /// request param is decoded from a response slice (MATCHING-REQUEST-PARAM)
    /// and for response params whose position was determined beforehand.
    relative_position: bool,
}

impl<'a> ParamContext<'a> {
    fn new(parameter: &'a datatypes::Parameter<'a>, base_offset: usize) -> Self {
        Self {
            parameter,
            base_offset,
            outer_context: None,
            relative_position: false,
        }
    }

    fn with_relative_position(self) -> Self {
        Self {
            relative_position: true,
            ..self
        }
    }

    /// Byte position to read from. Params without BYTE-POSITION start where
    /// the previous param ended, unless `relative_position` is set.
    fn read_byte_pos(self, uds_payload: &Payload) -> usize {
        if self.parameter.has_byte_position() || self.relative_position {
            self.abs_byte_pos()
        } else {
            uds_payload.last_read_byte_pos()
        }
    }

    fn with_outer_context(
        self,
        outer_context: Option<&'a MappedDiagServiceResponsePayload>,
    ) -> Self {
        Self {
            outer_context,
            ..self
        }
    }

    fn abs_byte_pos(self) -> usize {
        self.base_offset
            .saturating_add(self.parameter.byte_position() as usize)
    }
}

impl<S: SecurityPlugin> PayloadDecoder for EcuManager<S> {
    type Response = DiagServiceResponseStruct;

    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn't match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    #[tracing::instrument(
        target = "convert_from_uds",
        skip(self, diag_service, payload),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(&payload.data, 10),
            output = tracing::field::Empty,
            dlt_context = dlt_ctx!("CORE"),
        ),
        err
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "Keeping the function together makes structural sense. Splitting would hurt \
                  readability"
    )]
    async fn convert_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
        functional_group_name: Option<&str>,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self
            .lookup_diag_service(diag_service, functional_group_name, None)
            .await?;
        let mapped_diag_comm = mapped_service
            .diag_comm()
            .map(datatypes::DiagComm)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("No DiagComm found".to_owned()))?;

        let sid = util::try_extract_sid_from_payload(payload.data.as_slice())?;

        let uds_payload = Payload::new(&payload.data);
        let response_first_byte = uds_payload.first().ok_or_else(|| {
            DiagServiceError::BadPayload("Payload too short to read first byte".to_owned())
        })?;
        let response_first_byte_value = response_first_byte.to_string();

        let responses: Vec<_> = mapped_service
            .pos_responses()
            .into_iter()
            .flatten()
            .chain(mapped_service.neg_responses().into_iter().flatten())
            .collect();

        if let Some((response, params)) = responses.iter().find_map(|r| {
            r.params().and_then(|params| {
                let params: Vec<datatypes::Parameter> =
                    params.iter().map(datatypes::Parameter).collect();
                if params.iter().any(|p| {
                    p.byte_position() == 0
                        && p.specific_data_as_coded_const().is_some_and(|c| {
                            c.coded_value()
                                .is_some_and(|v| v == response_first_byte_value)
                        })
                }) {
                    Some((r, params))
                } else {
                    None
                }
            })
        }) {
            let response_type = response.response_type().try_into()?;
            // in case of a positive response update potential session or security access changes
            if response_type == datatypes::ResponseType::Positive {
                let (new_session, new_security) =
                    self.lookup_state_transition_by_diagcomm_for_active(&mapped_diag_comm);

                if let Some(new_session) = new_session {
                    self.set_service_state(service_ids::SESSION_CONTROL, new_session)
                        .await;
                }
                if let Some(new_security_access) = new_security {
                    self.set_service_state(service_ids::SECURITY_ACCESS, new_security_access)
                        .await;
                }
            }

            let raw_only = response_type == datatypes::ResponseType::Positive && !map_to_json;
            let static_offset = self.raw_payload_offset(&params);
            // Without a mapping the payload is only decoded if the offset of
            // the raw data depends on it.
            let walk = match static_offset {
                Some(_) if raw_only => None,
                _ => {
                    let walk = if raw_only {
                        // The DATA params are decoded as well, so a payload too
                        // short for them is rejected instead of returned.
                        self.walk_response_params(
                            &mapped_service,
                            &params,
                            &payload.data,
                            params
                                .iter()
                                .rposition(|param| self.is_data_param(param))
                                .map(|index| index.saturating_add(1)),
                            |param| self.is_data_param(param),
                            |param| self.is_data_param(param),
                        )?
                    } else {
                        let is_mapped = |param: &datatypes::Parameter<'_>| {
                            param.semantic().is_none_or(|semantic| {
                                semantic == self.database_naming_convention.semantics.data
                                    || semantic
                                        == self.database_naming_convention.semantics.service_id_rq
                            })
                        };
                        self.walk_response_params(
                            &mapped_service,
                            &params,
                            &payload.data,
                            None,
                            is_mapped,
                            is_mapped,
                        )?
                    };
                    Some(walk)
                }
            };
            let (data, mapping_errors, positions) = match walk {
                Some(ResponseWalk {
                    failure: Some(error),
                    ..
                }) => return Err(error),
                Some(walk) => (walk.data, walk.mapping_errors, walk.positions),
                None => (HashMap::default(), Vec::new(), Vec::new()),
            };
            let base_offset = static_offset.map_or_else(
                || {
                    params
                        .iter()
                        .zip(&positions)
                        .filter(|(param, _)| self.is_data_param(param))
                        .filter_map(|(_, position)| *position)
                        .min()
                        .unwrap_or(0)
                },
                |offset| offset as usize,
            );
            let raw_uds_payload = uds_payload
                .data()?
                .get(base_offset..)
                .ok_or(DiagServiceError::BadPayload(
                    "Payload offset out of bounds".to_owned(),
                ))?
                .to_vec();

            if raw_only {
                return Ok(DiagServiceResponseStruct {
                    service: diag_service.clone(),
                    data: raw_uds_payload,
                    mapped_data: None,
                    response_type: DiagServiceResponseType::Positive,
                });
            }

            let resp = create_diag_service_response(
                diag_service,
                data,
                response_type,
                raw_uds_payload,
                mapping_errors,
            );
            tracing::Span::current()
                .record("output", format!("Response: {:?}", resp.response_type));

            Ok(resp)
        } else {
            // Returning a response here, because even valid databases may not define a
            // response for a service.
            tracing::warn!("No matching response found for SID: {sid}");
            Ok(DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: payload.data.clone(),
                mapped_data: None,
                response_type: if *response_first_byte == service_ids::NEGATIVE_RESPONSE {
                    DiagServiceResponseType::Negative
                } else {
                    DiagServiceResponseType::Positive
                },
            })
        }
    }

    #[tracing::instrument(
        target = "convert_request_from_uds",
        skip(self, diag_service, payload),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(&payload.data, 10),
            output = tracing::field::Empty,
            dlt_context = dlt_ctx!("CORE"),
        ),
        err
    )]
    async fn convert_request_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service, None, None).await?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::RequestNotSupported(format!(
                "Service '{}' is not supported",
                diag_service.name
            )))?;

        let mut uds_payload = Payload::new(&payload.data);
        let mut data = HashMap::default();
        let mut mapping_errors = Vec::new();

        let params: Vec<datatypes::Parameter> = request
            .params()
            .map(|params| params.iter().map(datatypes::Parameter).collect())
            .unwrap_or_default();

        for param in hoist_positioned_keys(&params) {
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "Unable to find short name for request param".to_owned(),
                )
            })?;

            uds_payload.set_last_read_byte_pos(if param.has_byte_position() {
                param.byte_position() as usize
            } else {
                uds_payload.last_read_byte_pos()
            });
            match self.map_param_from_uds(
                &mapped_service,
                short_name,
                &mut uds_payload,
                &mut data,
                ParamContext::new(&param, 0),
            ) {
                Ok(()) => {}
                Err(DiagServiceError::DataError(error)) => {
                    mapping_errors.push(FieldParseError {
                        path: format!("/{short_name}"),
                        error,
                    });
                }
                Err(e) => return Err(e),
            }
        }

        let raw_uds_payload = payload.data.clone();

        if !map_to_json {
            return Ok(DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: raw_uds_payload,
                mapped_data: None,
                response_type: DiagServiceResponseType::Positive,
            });
        }

        let resp = create_diag_service_response(
            diag_service,
            data,
            datatypes::ResponseType::Positive,
            raw_uds_payload,
            mapping_errors,
        );

        tracing::Span::current().record("output", "RequestMapped");
        Ok(resp)
    }

    fn convert_service_14_response(
        diag_comm: DiagComm,
        response: ServicePayload,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let sid = util::try_extract_sid_from_payload(response.data.as_slice())?;
        let response_type = match sid {
            CLEAR_FAULT_MEM_POS_RESPONSE_SID => DiagServiceResponseType::Positive,
            service_ids::NEGATIVE_RESPONSE => DiagServiceResponseType::Negative,
            unknown => {
                return Err(DiagServiceError::UnexpectedResponse(Some(format!(
                    "received unexpected response with SID {unknown:04x}"
                ))));
            }
        };
        Ok(DiagServiceResponseStruct {
            service: diag_comm,
            data: response.data,
            mapped_data: None,
            response_type,
        })
    }
}

/// Returns the params in database order, except that a positioned key param
/// (LENGTH-KEY or TABLE-KEY) declared after the param referencing it is moved
/// directly in front of that param. ISO 22901-1:2008 §7.3.5.4 (and checker
/// rule 254) allows such a forward reference if the key is positioned; its
/// value must be decoded before the referencing param. Unpositioned params
/// keep their order, so "follows the preceding param" is unchanged for them.
fn hoist_positioned_keys<'a>(params: &[datatypes::Parameter<'a>]) -> Vec<datatypes::Parameter<'a>> {
    let mut hoisted = vec![false; params.len()];
    let mut ordered = Vec::with_capacity(params.len());
    for (index, param) in params.iter().enumerate() {
        if hoisted.get(index).copied().unwrap_or(false) {
            continue;
        }
        if let Some((key_index, key)) = later_positioned_key(params, index)
            && let Some(flag) = hoisted.get_mut(key_index)
        {
            *flag = true;
            ordered.push(key.clone());
        }
        ordered.push(param.clone());
    }
    ordered
}

/// Result of decoding the parameters of a response in database order.
struct ResponseWalk {
    /// Byte position of each parameter, by index. `None` if not determined.
    positions: Vec<Option<usize>>,
    /// Decoded values of the output parameters.
    data: MappedDiagServiceResponsePayload,
    mapping_errors: Vec<FieldParseError>,
    /// Why the walk stopped before it reached all required parameters.
    failure: Option<DiagServiceError>,
}

/// A decoded response parameter.
struct DecodedParam {
    /// Position following the parameter, if it could be determined.
    end: Option<usize>,
    /// Reported if a following parameter without BYTE-POSITION is required:
    /// why this parameter could not be decoded, or why its end is unknown.
    error: Option<DiagServiceError>,
}

/// Param types that are referenced by another param of the same PDU.
#[derive(Clone, Copy)]
enum KeyType {
    Length,
    Table,
}

impl KeyType {
    fn matches(self, param_type: &datatypes::ParamType) -> bool {
        match self {
            Self::Length => matches!(param_type, datatypes::ParamType::LengthKey),
            Self::Table => matches!(param_type, datatypes::ParamType::TableKey),
        }
    }
}

/// Type and short name of the key param referenced by `param`: the
/// LENGTH-KEY of a VALUE param with PARAM-LENGTH-INFO, or the TABLE-KEY of a
/// TABLE-STRUCT param.
fn referenced_key(param: &datatypes::Parameter<'_>) -> Option<(KeyType, String)> {
    if let Some(table_struct) = param.specific_data_as_table_struct() {
        let key = datatypes::Parameter(table_struct.table_key()?);
        return Some((KeyType::Table, key.short_name()?.to_owned()));
    }
    let dop = param
        .specific_data_as_value()?
        .dop()?
        .specific_data_as_normal_dop()
        .map(datatypes::NormalDop)?;
    dop.diag_coded_type()
        .ok()?
        .length_key_name()
        .map(|name| (KeyType::Length, name.to_owned()))
}

impl<S: SecurityPlugin> EcuManager<S> {
    /// Offset at which the raw payload of a positive response starts
    /// ([`cda_interfaces::diagservices::DiagServiceResponse::get_raw`]): the lowest byte position of the
    /// parameters with DATA semantic, i.e. the SID and sub-function are cut off.
    pub(in crate::diag_kernel) fn raw_payload_offset(
        &self,
        params: &[datatypes::Parameter],
    ) -> Option<u32> {
        let positions = super::param_metadata::effective_byte_positions(params);
        let offset = super::param_metadata::resolved_data_offset(positions.iter().map(
            |(param, position)| {
                (
                    param.semantic().is_some_and(|semantic| {
                        semantic == self.database_naming_convention.semantics.data
                    }),
                    *position,
                )
            },
        ));
        match offset {
            super::param_metadata::DataOffset::NoData => Some(0),
            super::param_metadata::DataOffset::Known(position) => Some(position),
            super::param_metadata::DataOffset::Unknown => None,
        }
    }

    fn is_data_param(&self, param: &datatypes::Parameter<'_>) -> bool {
        param
            .semantic()
            .is_some_and(|semantic| semantic == self.database_naming_convention.semantics.data)
    }

    /// Decodes response parameters in database order. A parameter without
    /// BYTE-POSITION starts where the preceding one ends (ISO 22901-1
    /// 7.3.5.4), so raw offsets and mapped values both derive from this pass.
    ///
    /// The walk ends in front of the parameter at `stop_at`, or if the position
    /// of an `is_required` parameter is unknown. Parameters which are not
    /// `is_output` are decoded as far as possible, because others may refer to
    /// them or follow them, and their errors only matter in these cases.
    ///
    /// # Errors
    /// Returns the error of an output parameter which cannot be decoded.
    fn walk_response_params(
        &self,
        service: &datatypes::DiagService<'_>,
        params: &[datatypes::Parameter<'_>],
        bytes: &[u8],
        stop_at: Option<usize>,
        is_required: impl Fn(&datatypes::Parameter<'_>) -> bool,
        is_output: impl Fn(&datatypes::Parameter<'_>) -> bool,
    ) -> Result<ResponseWalk, DiagServiceError> {
        let mut walk = ResponseWalk {
            positions: vec![None; params.len()],
            data: HashMap::default(),
            mapping_errors: Vec::new(),
            failure: None,
        };
        // Names which were only decoded because other parameters depend on them.
        let mut hidden = Vec::new();
        // Ends of keys which were decoded ahead of their declaration.
        let mut hoisted: HashMap<usize, Option<usize>> = HashMap::default();
        let mut next_position = Some(0usize);
        let mut unknown_cause = None;

        for (index, param) in params.iter().enumerate() {
            if let Some(end) = hoisted.get(&index) {
                next_position = *end;
                continue;
            }
            let position = if param.has_byte_position() {
                Some(param.byte_position() as usize)
            } else {
                next_position
            };
            if let Some(slot) = walk.positions.get_mut(index) {
                *slot = position;
            }
            if stop_at == Some(index) {
                if position.is_none() && is_required(param) {
                    walk.failure = Some(unknown_cause.unwrap_or_else(|| unknown_position(param)));
                }
                break;
            }
            let Some(position) = position else {
                if is_required(param) {
                    walk.failure = Some(unknown_cause.unwrap_or_else(|| unknown_position(param)));
                    break;
                }
                next_position = None;
                continue;
            };

            // A positioned key may be declared after the parameter using it.
            if let Some((key_index, key)) = later_positioned_key(params, index)
                && !hoisted.contains_key(&key_index)
            {
                let key_position = key.byte_position() as usize;
                let decoded = self.decode_response_param(
                    service,
                    key,
                    key_position,
                    is_output(key),
                    bytes,
                    &mut walk,
                    &mut hidden,
                )?;
                if let Some(slot) = walk.positions.get_mut(key_index) {
                    *slot = Some(key_position);
                }
                hoisted.insert(key_index, decoded.end);
            }

            let decoded = self.decode_response_param(
                service,
                param,
                position,
                is_output(param),
                bytes,
                &mut walk,
                &mut hidden,
            )?;
            next_position = decoded.end;
            unknown_cause = decoded.error;
        }
        for name in hidden {
            walk.data.remove(&name);
        }
        Ok(walk)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Only splits up the loop of walk_response_params"
    )]
    fn decode_response_param(
        &self,
        service: &datatypes::DiagService<'_>,
        param: &datatypes::Parameter<'_>,
        position: usize,
        is_output: bool,
        bytes: &[u8],
        walk: &mut ResponseWalk,
        hidden: &mut Vec<String>,
    ) -> Result<DecodedParam, DiagServiceError> {
        let static_end = super::param_metadata::static_byte_length(param)
            .and_then(|length| position.checked_add(length as usize));
        let Some(name) = param.short_name() else {
            if is_output {
                return Err(DiagServiceError::InvalidDatabase(
                    "Unable to find short name for param".to_owned(),
                ));
            }
            return Ok(DecodedParam {
                end: static_end,
                error: None,
            });
        };
        let known: Option<HashSet<String>> =
            (!is_output).then(|| walk.data.keys().cloned().collect());

        // A failed decoder can leave a restricted view behind, which must not
        // affect other parameters.
        let mut payload = Payload::new(bytes);
        payload.set_last_read_byte_pos(position);
        let context = if param.has_byte_position() {
            ParamContext::new(param, 0)
        } else {
            ParamContext::new(param, position).with_relative_position()
        };
        let result = self.map_param_from_uds(service, name, &mut payload, &mut walk.data, context);
        if let Some(known) = known {
            hidden.extend(
                walk.data
                    .keys()
                    .filter(|key| !known.contains(*key))
                    .cloned(),
            );
        }

        let end = match static_end {
            Some(end) => Some(end),
            None => match param.param_type()? {
                datatypes::ParamType::Dynamic | datatypes::ParamType::TableEntry => None,
                datatypes::ParamType::NrcConst | datatypes::ParamType::System => {
                    unmapped_param_end(&mut payload, param, position)
                }
                _ => result.is_ok().then(|| payload.last_read_byte_pos()),
            },
        };
        let error = match result {
            Ok(()) => end.is_none().then(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "The end of response parameter '{name}' cannot be determined, so a following \
                     parameter without BYTE-POSITION cannot be located"
                ))
            }),
            Err(DiagServiceError::DataError(error)) if is_output => {
                let cause = end
                    .is_none()
                    .then(|| DiagServiceError::DataError(error.clone()));
                walk.mapping_errors.push(FieldParseError {
                    path: format!("/{name}"),
                    error,
                });
                cause
            }
            Err(error) if is_output => return Err(error),
            Err(error) => Some(error),
        };
        Ok(DecodedParam { end, error })
    }

    /// Looks up the first positive response and resolves its raw payload layout.
    /// Returns `None` when the response has no DATA parameter or its offset is unknown.
    pub(in crate::diag_kernel) async fn get_positive_response_raw_layout(
        &self,
        diag_service: &DiagComm,
    ) -> Result<Option<super::param_metadata::RawResponseLayout>, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service, None, None).await?;
        let Some(params) = mapped_service
            .pos_responses()
            .and_then(|responses| responses.iter().next())
            .and_then(|response| response.params())
        else {
            return Ok(None);
        };
        let params: Vec<_> = params.iter().map(datatypes::Parameter).collect();
        super::param_metadata::raw_response_layout(
            &params,
            &self.database_naming_convention.semantics.data,
        )
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_param_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        match param_ctx.parameter.param_type()? {
            datatypes::ParamType::CodedConst => {
                map_param_coded_const_from_uds(param_name, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::MatchingRequestParam => {
                self.map_param_matching_request_from_uds(
                    mapped_service,
                    param_name,
                    uds_payload,
                    data,
                    param_ctx,
                )?;
            }
            datatypes::ParamType::Value => {
                self.map_param_value_from_uds(mapped_service, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::Reserved => {
                map_param_reserved_from_uds(param_name, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::TableEntry => {
                tracing::error!("TableStructParam not implemented.");
            }
            datatypes::ParamType::Dynamic => {
                tracing::error!("Dynamic ParamType not implemented.");
            }
            datatypes::ParamType::LengthKey => {
                self.map_param_length_key_from_uds(mapped_service, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::NrcConst => {
                tracing::error!("NrcConst ParamType not implemented.");
                skip_unmapped_param(uds_payload, param_ctx);
            }
            datatypes::ParamType::PhysConst => {
                self.map_param_phys_const_from_uds(
                    mapped_service,
                    param_name,
                    uds_payload,
                    data,
                    param_ctx,
                )?;
            }
            datatypes::ParamType::System => {
                tracing::error!("System ParamType not implemented.");
                skip_unmapped_param(uds_payload, param_ctx);
            }
            datatypes::ParamType::TableKey => {
                Self::map_table_key_from_uds(param_name, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::TableStruct => {
                self.map_table_struct_from_uds(
                    mapped_service,
                    param_name,
                    uds_payload,
                    data,
                    param_ctx,
                )?;
            }
        }
        Ok(())
    }

    fn map_param_value_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let v = param_ctx.parameter.specific_data_as_value().ok_or(
            DiagServiceError::InvalidDatabase("Expected Value specific data".to_owned()),
        )?;

        let dop =
            v.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Value DoP is None".to_owned(),
                ))?;
        self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)?;
        Ok(())
    }

    fn map_param_length_key_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let length_key = param_ctx
            .parameter
            .specific_data_as_length_key_ref()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected LengthKeyRef specific data".to_owned(),
            ))?;

        let dop = length_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("LengthKey DoP is None".to_owned()),
        )?;

        self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)
    }

    fn map_param_matching_request_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let matching_req_param = param_ctx
            .parameter
            .specific_data_as_matching_request_param()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected MatchingRequestParam specific data".to_owned(),
            ))?;

        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected request for service".to_owned(),
            ))?;

        let matching_req_param_byte_pos = u32::try_from(matching_req_param.request_byte_pos())
            .map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "Matching request param byte position conversion error: {e},"
                ))
            })?;

        let matching_request_param = request
            .params()
            .and_then(|params| {
                params
                    .iter()
                    .map(datatypes::Parameter)
                    .find(|p| p.byte_position() == matching_req_param_byte_pos)
            })
            .ok_or_else(|| {
                DiagServiceError::UdsLookupError(format!(
                    "No matching request parameter found for {}",
                    param_ctx.parameter.short_name().unwrap_or_default()
                ))
            })?;

        let matching_req_param_byte_pos = u32::try_from(matching_req_param.request_byte_pos())
            .map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "Matching request param byte position conversion error: {e}",
                ))
            })?;

        let response_end = param_ctx
            .read_byte_pos(uds_payload)
            .saturating_add(matching_req_param.byte_length() as usize);
        let pop = matching_req_param_byte_pos < param_ctx.parameter.byte_position();
        if pop {
            uds_payload.push_slice(param_ctx.abs_byte_pos(), uds_payload.len())?;
        }

        self.map_param_from_uds(
            mapped_service,
            param_name,
            uds_payload,
            data,
            ParamContext::new(&matching_request_param, 0).with_relative_position(),
        )?;

        if pop {
            uds_payload.pop_slice()?;
        }
        uds_payload.set_last_read_byte_pos(response_end);
        Ok(())
    }

    fn map_param_phys_const_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let p = param_ctx.parameter.specific_data_as_phys_const().ok_or(
            DiagServiceError::InvalidDatabase("Expected PhysConst specific data".to_owned()),
        )?;

        let dop =
            p.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "PhysConst has no DOP".to_owned(),
                ))?;

        // Handle different DOP variants - PhysConst can have Normal or Structure DOPs
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let value = operations::extract_diag_data_container(
                    param_ctx.parameter.short_name(),
                    param_ctx.abs_byte_pos(),
                    param_ctx.parameter.bit_position() as usize,
                    uds_payload,
                    &diag_type,
                    None,
                    None,
                )?;

                let value = match value {
                    DiagDataTypeContainer::RawContainer(raw) => raw,
                    DiagDataTypeContainer::Struct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "Struct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                    DiagDataTypeContainer::RepeatingStruct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "RepeatingStruct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                    DiagDataTypeContainer::DtcStruct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "DtcStruct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                };

                data.insert(
                    param_name.to_owned(),
                    DiagDataTypeContainer::RawContainer(value),
                );
            }
            // Structure DOP - delegate to the full DOP handler which handles nested params
            datatypes::DataOperationVariant::Structure(_)
            | datatypes::DataOperationVariant::EndOfPdu(_)
            | datatypes::DataOperationVariant::StaticField(_)
            | datatypes::DataOperationVariant::Mux(_)
            | datatypes::DataOperationVariant::DynamicLengthField(_) => {
                self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)?;
            }
            _ => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "PhysConst has unsupported DOP variant: {:?}",
                    dop.specific_data_type().variant_name().unwrap_or("Unknown")
                )));
            }
        }

        Ok(())
    }

    /// Decode a TABLE-KEY parameter from a UDS response payload.
    /// Reads the key byte(s), resolves through the key DOP's compu method
    /// to the physical representation (row key string), and stores it in `data`.
    fn map_table_key_from_uds(
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let table_key_data = param_ctx.parameter.specific_data_as_table_key().ok_or(
            DiagServiceError::InvalidDatabase(
                "TABLE-KEY param missing TableKey specific data".to_owned(),
            ),
        )?;

        let table_dop = table_key_data.table_key_reference_as_table_dop().ok_or(
            DiagServiceError::InvalidDatabase("TABLE-KEY has no TableDop reference".to_owned()),
        )?;

        let key_dop = table_dop.key_dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("TableDop missing key_dop".to_owned()),
        )?;

        match key_dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let compu_method: Option<datatypes::CompuMethod> =
                    normal_dop.compu_method().map(Into::into);
                let physical_type = physical_base_type(&normal_dop);

                data.insert(
                    param_name.to_owned(),
                    operations::extract_diag_data_container(
                        param_ctx.parameter.short_name(),
                        param_ctx.read_byte_pos(uds_payload),
                        param_ctx.parameter.bit_position() as usize,
                        uds_payload,
                        &diag_type,
                        compu_method,
                        physical_type,
                    )?,
                );
                Ok(())
            }
            _ => Err(DiagServiceError::InvalidDatabase(
                "TABLE-KEY key_dop must be a NormalDOP".to_owned(),
            )),
        }
    }

    /// Decode a TABLE-STRUCT parameter from a UDS response payload.
    /// Looks up which row was selected by the companion TABLE-KEY (already
    /// decoded and stored in `data`), then decodes that row's structure.
    fn map_table_struct_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let table_struct_data = param_ctx.parameter.specific_data_as_table_struct().ok_or(
            DiagServiceError::InvalidDatabase(
                "TABLE-STRUCT param missing TableStruct specific data".to_owned(),
            ),
        )?;

        // Follow back-reference to the TABLE-KEY param
        let table_key_param =
            table_struct_data
                .table_key()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-STRUCT missing table_key back-reference".to_owned(),
                ))?;
        let table_key_param = datatypes::Parameter(table_key_param);

        let key_param_name =
            table_key_param
                .short_name()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-KEY param referenced by TABLE-STRUCT has no short_name".to_owned(),
                ))?;

        // Look up the TABLE-KEY's decoded value from data. It was already
        // decoded: it is declared before this param or, if declared after, it
        // is positioned and therefore decoded ahead of this param.
        let key_container = data.get(key_param_name).ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "TABLE-STRUCT references TABLE-KEY '{key_param_name}' but it was not decoded"
            ))
        })?;

        // Extract the physical key string from the decoded TABLE-KEY value
        let key_str = match key_container {
            DiagDataTypeContainer::RawContainer(raw) => {
                let value = operations::uds_data_to_serializable(
                    raw.data_type,
                    raw.compu_method.as_ref(),
                    false,
                    &raw.data,
                )?;
                match value {
                    DiagDataValue::String(s) => s,
                    DiagDataValue::UInt32(n) => n.to_string(),
                    DiagDataValue::Int32(n) => n.to_string(),
                    other => {
                        return Err(DiagServiceError::ParameterConversionError(format!(
                            "TABLE-KEY '{key_param_name}' decoded to unexpected type: {other:?}"
                        )));
                    }
                }
            }
            _ => {
                return Err(DiagServiceError::ParameterConversionError(format!(
                    "TABLE-KEY '{key_param_name}' expected RawContainer, got complex type"
                )));
            }
        };

        // Resolve the TableDop and find the selected row
        let table_key_specific = table_key_param.specific_data_as_table_key().ok_or(
            DiagServiceError::InvalidDatabase(
                "TABLE-KEY param missing TableKey specific data".to_owned(),
            ),
        )?;
        let table_dop = table_key_specific
            .table_key_reference_as_table_dop()
            .ok_or(DiagServiceError::InvalidDatabase(
                "TABLE-KEY has no TableDop reference".to_owned(),
            ))?;
        let rows = table_dop.rows().ok_or(DiagServiceError::InvalidDatabase(
            "TableDop missing rows".to_owned(),
        ))?;

        let selected_row = rows
            .iter()
            .find(|row| {
                row.short_name().is_some_and(|name| name == key_str)
                    || row.key().is_some_and(|k| k == key_str)
            })
            .ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "TABLE-KEY value '{key_str}' does not match any table row"
                ))
            })?;

        let row_name = selected_row.short_name().unwrap_or_default().to_owned();

        // Get the row's structure DOP
        match selected_row.structure() {
            None => {
                let struct_start = param_ctx.abs_byte_pos();
                uds_payload.set_last_read_byte_pos(struct_start);
                // No structure for this row - store an empty struct
                data.insert(
                    param_name.to_owned(),
                    DiagDataTypeContainer::Struct(HashMap::default()),
                );
                Ok(())
            }
            Some(structure_dop_ref) => {
                let structure_dop = datatypes::DataOperation(structure_dop_ref);
                match structure_dop.variant()? {
                    datatypes::DataOperationVariant::Structure(struct_dop) => {
                        let struct_start = param_ctx.abs_byte_pos();
                        uds_payload.push_slice(struct_start, uds_payload.len())?;
                        uds_payload.set_last_read_byte_pos(0);
                        let struct_data = self.map_struct_from_uds(
                            &struct_dop,
                            mapped_service,
                            uds_payload,
                            data,
                        )?;
                        let row_length = uds_payload.last_read_byte_pos();
                        uds_payload.pop_slice()?;
                        uds_payload.set_last_read_byte_pos(struct_start.saturating_add(row_length));

                        // Wrap in row name, matching the encode convention:
                        // {<row_short_name>: {<struct_params>}}
                        let mut wrapper = HashMap::default();
                        wrapper.insert(row_name, DiagDataTypeContainer::Struct(struct_data));
                        data.insert(
                            param_name.to_owned(),
                            DiagDataTypeContainer::Struct(wrapper),
                        );
                        Ok(())
                    }
                    _ => Err(DiagServiceError::InvalidDatabase(format!(
                        "TABLE-STRUCT row '{row_name}' structure DOP is not a Structure variant"
                    ))),
                }
            }
        }
    }

    fn map_struct_from_uds(
        &self,
        structure: &datatypes::StructureDop,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        outer_context: &MappedDiagServiceResponsePayload,
    ) -> Result<HashMap<String, DiagDataTypeContainer>, DiagServiceError> {
        let mut data = HashMap::default();
        let start = uds_payload.last_read_byte_pos();
        let mut end = start;

        for param in structure.params().into_iter().flatten() {
            let param = datatypes::Parameter(param);
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Unable to find short name for param".to_owned())
            })?;
            self.map_param_from_uds(
                mapped_service,
                short_name,
                uds_payload,
                &mut data,
                ParamContext::new(&param, 0).with_outer_context(Some(outer_context)),
            )?;
            end = end.max(uds_payload.last_read_byte_pos());
        }
        // BYTE-SIZE, otherwise the furthest parameter, determines the length.
        uds_payload.set_last_read_byte_pos(
            structure
                .byte_size()
                .map_or(end, |size| start.saturating_add(size as usize)),
        );
        Ok(data)
    }

    fn map_nested_struct_from_uds(
        &self,
        structure: &datatypes::StructureDop,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        nested_structs: &mut Vec<HashMap<String, DiagDataTypeContainer>>,
        outer_context: &MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        nested_structs.push(self.map_struct_from_uds(
            structure,
            mapped_service,
            uds_payload,
            outer_context,
        )?);
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        dop: &datatypes::DataOperation,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let short_name = param_ctx
            .parameter
            .short_name()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "Unable to find short name for param in Strings".to_string(),
                )
            })?
            .to_owned();

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_coded_type = normal_dop.diag_coded_type()?;
                if let Some(length_key_name) = diag_coded_type.length_key_name() {
                    Self::map_param_length_info_dop_from_uds(
                        uds_payload,
                        data,
                        short_name,
                        &normal_dop,
                        length_key_name,
                        param_ctx,
                    )?;
                } else {
                    Self::map_normal_dop_from_uds(
                        uds_payload,
                        data,
                        short_name,
                        &normal_dop,
                        param_ctx,
                    )?;
                }
            }
            datatypes::DataOperationVariant::EndOfPdu(end_of_pdu_dop) => {
                self.map_end_of_pdu_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &end_of_pdu_dop,
                    param_ctx,
                )?;
            }

            datatypes::DataOperationVariant::Structure(structure_dop) => {
                self.map_structure_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    &short_name,
                    &structure_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::Dtc(dtc_dop) => {
                map_dtc_dop_from_uds(&short_name, uds_payload, data, &dtc_dop, param_ctx)?;
            }
            datatypes::DataOperationVariant::EnvDataDesc(env_data_desc_dop) => {
                let start = param_ctx.abs_byte_pos();
                let item = self.map_env_data_desc_item_from_uds(
                    mapped_service,
                    uds_payload,
                    param_ctx.outer_context.unwrap_or(&*data),
                    &env_data_desc_dop,
                    start,
                )?;
                data.extend(item);
            }
            datatypes::DataOperationVariant::EnvData(env_data_dop) => {
                let mut end = param_ctx.abs_byte_pos();
                uds_payload.set_last_read_byte_pos(end);
                if let Some(params) = env_data_dop.params() {
                    for param in params {
                        let param = datatypes::Parameter(param);
                        let name = param.short_name().ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(
                                "EnvData param missing short_name".to_owned(),
                            )
                        })?;
                        self.map_param_from_uds(
                            mapped_service,
                            name,
                            uds_payload,
                            data,
                            ParamContext::new(&param, param_ctx.base_offset)
                                .with_outer_context(param_ctx.outer_context),
                        )?;
                        end = end.max(uds_payload.last_read_byte_pos());
                    }
                }
                uds_payload.set_last_read_byte_pos(end);
            }
            datatypes::DataOperationVariant::StaticField(static_field_dop) => {
                self.map_static_field_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &static_field_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &mux_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field_dop) => {
                self.map_dynamic_length_field_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &dynamic_length_field_dop,
                    param_ctx,
                )?;
            }
        }

        Ok(())
    }

    fn map_param_length_info_dop_from_uds(
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        normal_dop: &datatypes::NormalDop,
        length_key_name: &str,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let bit_count = match data.get(length_key_name) {
            Some(DiagDataTypeContainer::RawContainer(raw)) => {
                let phys_val = operations::uds_data_to_serializable(
                    raw.data_type,
                    raw.compu_method.as_ref(),
                    false,
                    &raw.data,
                )?;
                match phys_val {
                    DiagDataValue::UInt32(n) => n as usize,
                    DiagDataValue::Int32(n) => usize::try_from(n).unwrap_or_else(|_| {
                        tracing::warn!("LENGTH-KEY resolved to negative value {n}, treating as 0");
                        0
                    }),
                    _ => {
                        return Err(DiagServiceError::ParameterConversionError(format!(
                            "LENGTH-KEY '{length_key_name}' resolved to unsupported type: \
                             {phys_val:?}"
                        )));
                    }
                }
            }
            None => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "LENGTH-KEY '{length_key_name}' not yet decoded when processing '{short_name}'"
                )));
            }
            _ => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "LENGTH-KEY '{length_key_name}' has unexpected container type"
                )));
            }
        };

        let diag_coded_type = normal_dop.diag_coded_type()?;
        let compu_method: Option<datatypes::CompuMethod> =
            normal_dop.compu_method().map(Into::into);
        let physical_type = physical_base_type(normal_dop);
        let data_type = diag_coded_type.base_datatype();

        if bit_count == 0 {
            tracing::debug!(
                "PARAM-LENGTH-INFO-TYPE resolved bit_count=0; inserting empty value (possible \
                 database anomaly)"
            );
            data.insert(
                short_name,
                DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                    data: vec![],
                    bit_len: 0,
                    data_type,
                    compu_method,
                    physical_type,
                }),
            );
            return Ok(());
        }

        let byte_pos = param_ctx.read_byte_pos(uds_payload);
        let uds_bytes = uds_payload.data()?;
        let (decoded_bytes, end) = diag_coded_type.decode_with_runtime_bit_length(
            uds_bytes,
            byte_pos,
            param_ctx.parameter.bit_position() as usize,
            bit_count,
        )?;

        uds_payload.set_last_read_byte_pos(end);

        data.insert(
            short_name,
            DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                data: decoded_bytes,
                bit_len: bit_count,
                data_type,
                compu_method,
                physical_type,
            }),
        );
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_dynamic_length_field_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        dynamic_length_field_dop: &datatypes::DynamicLengthDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let determine_num_items = dynamic_length_field_dop.determine_number_of_items().ok_or(
            DiagServiceError::InvalidDatabase(
                "DynamicLengthField determine_number_of_items_of_items is None".to_owned(),
            ),
        )?;

        let determine_num_items_dop = determine_num_items
            .dop()
            .map(datatypes::DataOperation)
            .ok_or(DiagServiceError::InvalidDatabase(
                "DynamicLengthField determine_number_of_items DoP is None".to_owned(),
            ))?;

        let num_items_dop = determine_num_items_dop
            .specific_data_as_normal_dop()
            .map(datatypes::NormalDop)
            .ok_or(DiagServiceError::InvalidDatabase(
                "DynamicLengthField num_items DoP is not a NormalDoP".to_owned(),
            ))?;

        let num_items_diag_type: datatypes::DiagCodedType = num_items_dop.diag_coded_type()?;

        // ISO 22901-1 7.3.5.4: without BYTE-POSITION the field starts at the byte edge
        // following the previously extracted parameter. DETERMINE-NUMBER-OF-ITEMS and
        // OFFSET are relative to this position (7.3.6.10.4).
        let param_abs_byte_pos = if param_ctx.parameter.has_byte_position() {
            param_ctx.abs_byte_pos()
        } else {
            uds_payload.last_read_byte_pos()
        };
        let (num_items_data, _count_field_bit_len) = num_items_diag_type.decode(
            uds_payload
                .data()?
                .get(param_abs_byte_pos..)
                .ok_or(DiagServiceError::BadPayload(
                    "Not enough bytes to get DynamicLengthField item count".to_owned(),
                ))?,
            determine_num_items.byte_position() as usize,
            determine_num_items.bit_position() as usize,
        )?;

        // ISO 22901-1 7.3.6.10.4: the number of items is the *physical* value of the
        // DETERMINE-NUMBER-OF-ITEMS DOP (of type A_UINT32), so its compu method applies.
        let num_items_compu: Option<datatypes::CompuMethod> =
            num_items_dop.compu_method().map(Into::into);
        let num_items_diag_val = operations::uds_data_to_serializable(
            datatypes::DataType::UInt32,
            num_items_compu.as_ref(),
            false,
            &num_items_data,
        )?;

        let repeated_dop = datatypes::DopField(dynamic_length_field_dop.field().ok_or(
            DiagServiceError::InvalidDatabase("DynamicLengthField field is None".to_owned()),
        )?);
        let num_items: u32 = num_items_diag_val.try_into()?;
        let num_items_byte_pos =
            param_abs_byte_pos.saturating_add(determine_num_items.byte_position() as usize);
        uds_payload.set_last_read_byte_pos(num_items_byte_pos.saturating_add(num_items_data.len()));

        let mut repeated_data = Vec::new();

        let items_abs_start =
            param_abs_byte_pos.saturating_add(dynamic_length_field_dop.offset() as usize);

        tracing::debug!(
            num_items,
            items_abs_start,
            payload_len = uds_payload.len(),
            count_bytes = ?num_items_data,
            "DynamicLengthField items loop start"
        );

        uds_payload.push_slice(items_abs_start, uds_payload.len())?;

        let mut start = 0usize;
        let mut truncated = false;

        for _ in 0..num_items {
            let (item_data, item_size) = match self.decode_dynamic_length_field_item(
                mapped_service,
                uds_payload,
                data,
                &repeated_dop,
                start,
            ) {
                Ok(result) => result,
                Err(DiagServiceError::NotEnoughData { .. }) => {
                    // ECU sent fewer bytes than the item count implied; treat as end of list.
                    tracing::warn!("Not enough data for next DynamicLengthField item, truncating");
                    truncated = true;
                    break;
                }
                Err(e) => return Err(e),
            };
            tracing::debug!(
                item_index = repeated_data.len(),
                item_size,
                next_start = start.saturating_add(item_size),
                keys = ?item_data.keys().collect::<Vec<_>>(),
                "DynamicLengthField item decoded"
            );
            repeated_data.push(item_data);
            start = start.saturating_add(item_size);
        }
        tracing::debug!(
            total_items = repeated_data.len(),
            final_start = start,
            last_read_byte_pos = items_abs_start.saturating_add(start),
            "DynamicLengthField decode complete"
        );
        uds_payload.pop_slice()?;
        let count_end = num_items_byte_pos.saturating_add(num_items_data.len());
        // A truncated item extends to the end of the payload, so nothing
        // following the field may start inside it.
        let end = if truncated {
            uds_payload.len()
        } else {
            items_abs_start.saturating_add(start)
        };
        uds_payload.set_last_read_byte_pos(count_end.max(end));
        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(repeated_data),
        );
        Ok(())
    }

    fn decode_dynamic_length_field_item(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &MappedDiagServiceResponsePayload,
        repeated_dop: &datatypes::DopField,
        start: usize,
    ) -> Result<(HashMap<String, DiagDataTypeContainer>, usize), DiagServiceError> {
        uds_payload.push_slice(start, uds_payload.len())?;
        // Inner item params may omit BYTE-POSITION, falling back to last_read_byte_pos.
        // Reset it to 0 so stale state from count decode doesn't corrupt item decoding.
        uds_payload.set_last_read_byte_pos(0);

        tracing::debug!(
            has_basic_structure = repeated_dop.basic_structure().is_some(),
            has_env_data_desc = repeated_dop.env_data_desc().is_some(),
            basic_struct_specific_data_type = ?repeated_dop
                .basic_structure()
                .map(|d| d.specific_data_type()),
            "DynamicLengthField item decode metadata"
        );

        if let Some(s) = repeated_dop
            .basic_structure()
            .and_then(|d| d.specific_data_as_structure().map(datatypes::StructureDop))
        {
            // The view is restored before an error is returned, so the caller
            // still sees the field's view when it stops at a truncated item.
            let struct_data = self.map_struct_from_uds(&s, mapped_service, uds_payload, data);
            let item_size = s
                .byte_size()
                .map_or_else(|| uds_payload.last_read_byte_pos(), |s| s as usize);
            uds_payload.pop_slice()?;
            Ok((struct_data?, item_size))
        } else if let Some(env_data_desc_dop) = repeated_dop.env_data_desc() {
            let env_data_desc = env_data_desc_dop.specific_data_as_env_data_desc().ok_or(
                DiagServiceError::InvalidDatabase(
                    "DynamicLengthField env_data_desc DOP is not EnvDataDesc type".to_owned(),
                ),
            )?;
            let env_data_desc = datatypes::EnvDataDescDop(env_data_desc);
            let item_data = self.map_env_data_desc_item_from_uds(
                mapped_service,
                uds_payload,
                data,
                &env_data_desc,
                0,
            );
            let item_size = uds_payload.last_read_byte_pos();
            uds_payload.pop_slice()?;
            Ok((item_data?, item_size))
        } else {
            uds_payload.pop_slice()?;
            Err(DiagServiceError::InvalidDatabase(
                "DynamicLengthField repeated_dop is neither Structure nor EnvDataDesc".to_owned(),
            ))
        }
    }

    fn map_mux_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &datatypes::MuxDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let start = param_ctx.abs_byte_pos();
        uds_payload.push_slice(start, uds_payload.len())?;
        self.map_mux_from_uds(mapped_service, uds_payload, data, short_name, mux_dop)?;
        let mux_length = uds_payload.last_read_byte_pos();
        uds_payload.pop_slice()?;
        uds_payload.set_last_read_byte_pos(start.saturating_add(mux_length));
        Ok(())
    }

    fn map_static_field_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        static_field_dop: &datatypes::StaticFieldDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let static_field_size = static_field_dop
            .item_byte_size()
            .saturating_mul(static_field_dop.fixed_number_of_items())
            as usize;

        if uds_payload.len() < static_field_size {
            return Err(DiagServiceError::BadPayload(format!(
                "Not enough data for static field: {} < {static_field_size}",
                uds_payload.len(),
            )));
        }
        let basic_structure =
            extract_struct_dop_from_field(static_field_dop.field().map(datatypes::DopField))?;
        let mut nested_structs = Vec::new();

        let field_start = param_ctx.abs_byte_pos();
        for i in 0..static_field_dop.fixed_number_of_items() {
            let start = field_start
                .saturating_add(i.saturating_mul(static_field_dop.item_byte_size()) as usize);
            let end = start.saturating_add(static_field_dop.item_byte_size() as usize);
            uds_payload.push_slice(start, end)?;
            uds_payload.set_last_read_byte_pos(0);

            self.map_nested_struct_from_uds(
                &basic_structure,
                mapped_service,
                uds_payload,
                &mut nested_structs,
                data,
            )?;

            uds_payload.pop_slice()?;
        }
        uds_payload.set_last_read_byte_pos(field_start.saturating_add(static_field_size));

        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(nested_structs),
        );
        Ok(())
    }

    /// Extracts the discriminator value from already-decoded outer data by name.
    /// Handles both `DtcStruct` (returns `.code`) and `RawContainer` (converts bytes to u32).
    fn discriminator_value_from_outer_data(
        outer_data: &MappedDiagServiceResponsePayload,
        param_short_name: &str,
    ) -> Result<u32, DiagServiceError> {
        match outer_data.get(param_short_name) {
            Some(DiagDataTypeContainer::DtcStruct(dtc)) => Ok(dtc.code),
            Some(DiagDataTypeContainer::RawContainer(raw)) => {
                let val = operations::uds_data_to_serializable(
                    raw.data_type,
                    raw.compu_method.as_ref(),
                    false,
                    &raw.data,
                )?;
                match val {
                    DiagDataValue::UInt32(n) => Ok(n),
                    DiagDataValue::Int32(n) => u32::try_from(n).map_err(|_| {
                        DiagServiceError::ParameterConversionError(format!(
                            "EnvDataDesc discriminator '{param_short_name}' is negative: {n}"
                        ))
                    }),
                    _ => Err(DiagServiceError::ParameterConversionError(format!(
                        "EnvDataDesc discriminator '{param_short_name}' resolved to unexpected \
                         type: {val:?}"
                    ))),
                }
            }
            _ => Err(DiagServiceError::InvalidDatabase(format!(
                "EnvDataDesc selector param '{param_short_name}' not found in decoded data"
            ))),
        }
    }

    /// Looks up the discriminator value from `outer_data`, finds the matching `EnvData` in
    /// `env_data_desc`, decodes its params and returns them as a new payload map.
    fn map_env_data_desc_item_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        outer_data: &MappedDiagServiceResponsePayload,
        env_data_desc: &datatypes::EnvDataDescDop,
        base_offset: usize,
    ) -> Result<MappedDiagServiceResponsePayload, DiagServiceError> {
        let param_short_name = env_data_desc.param_short_name().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc missing param_short_name".to_owned())
        })?;
        let discriminator =
            Self::discriminator_value_from_outer_data(outer_data, param_short_name)?;

        let env_datas = env_data_desc.env_datas().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc has no env_datas".to_owned())
        })?;

        // First pass: exact match on dtc_values.
        // Second pass: wildcard (EnvData with empty/absent dtc_values matches any discriminator).
        let matching_env_data = env_datas
            .iter()
            .find_map(|dop| {
                let env_data = dop.specific_data_as_env_data()?;
                let dtc_values = env_data.dtc_values()?;
                if dtc_values.iter().any(|v| v == discriminator) {
                    Some(env_data)
                } else {
                    None
                }
            })
            .or_else(|| {
                env_datas.iter().find_map(|dop| {
                    let env_data = dop.specific_data_as_env_data()?;
                    let is_wildcard = env_data.dtc_values().is_none_or(|v| v.is_empty());
                    if is_wildcard { Some(env_data) } else { None }
                })
            });

        let mut item_data = HashMap::default();
        let mut end = base_offset;
        uds_payload.set_last_read_byte_pos(base_offset);
        let Some(env_data) = matching_env_data else {
            tracing::warn!(
                discriminator = format!("{discriminator:#X}"),
                "No EnvData matched discriminator in EnvDataDesc; returning empty map"
            );
            return Ok(item_data);
        };

        if let Some(params) = env_data.params() {
            for param in params {
                let param = datatypes::Parameter(param);
                let name = param.short_name().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("EnvData param missing short_name".to_owned())
                })?;
                self.map_param_from_uds(
                    mapped_service,
                    name,
                    uds_payload,
                    &mut item_data,
                    ParamContext::new(&param, base_offset).with_outer_context(Some(outer_data)),
                )?;
                end = end.max(uds_payload.last_read_byte_pos());
            }
        }
        uds_payload.set_last_read_byte_pos(end);

        Ok(item_data)
    }

    fn map_structure_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: &str,
        structure_dop: &datatypes::StructureDop,
        structure_param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let structure_start = structure_param_ctx.abs_byte_pos();

        if let Some(byte_size) = structure_dop.byte_size() {
            let end = structure_start
                .checked_add(byte_size as usize)
                .ok_or_else(|| {
                    DiagServiceError::BadPayload("Overflow in end calculation".to_owned())
                })?;
            if uds_payload.len() < end {
                return Err(DiagServiceError::NotEnoughData {
                    expected: end,
                    actual: uds_payload.len(),
                });
            }
        }

        let mut end = structure_start;
        uds_payload.set_last_read_byte_pos(structure_start);
        if let Some(params) = structure_dop.params() {
            for param in params.iter().map(datatypes::Parameter) {
                self.map_param_from_uds(
                    mapped_service,
                    short_name,
                    uds_payload,
                    data,
                    ParamContext::new(&param, structure_start),
                )?;
                end = end.max(uds_payload.last_read_byte_pos());
            }
        }
        uds_payload.set_last_read_byte_pos(
            structure_dop
                .byte_size()
                .map_or(end, |size| structure_start.saturating_add(size as usize)),
        );
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_end_of_pdu_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        end_of_pdu_dop: &datatypes::EndOfPdu,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        // When a response is read the values of `max-number-of-items`
        // and `min-number-of-items` are deliberately ignored,
        // according to ISO 22901:2008 7.3.6.10.6
        let struct_ =
            extract_struct_dop_from_field(end_of_pdu_dop.field().map(datatypes::DopField))?;
        let mut nested_structs = Vec::new();
        let mut offset = param_ctx.read_byte_pos(uds_payload);
        while offset < uds_payload.len() {
            uds_payload.push_slice(offset, uds_payload.len())?;
            uds_payload.set_last_read_byte_pos(0);
            let result = self.map_nested_struct_from_uds(
                &struct_,
                mapped_service,
                uds_payload,
                &mut nested_structs,
                data,
            );
            let consumed = uds_payload.last_read_byte_pos();
            uds_payload.pop_slice()?;
            match result {
                Ok(()) => {}
                Err(e @ DiagServiceError::NotEnoughData { .. }) => {
                    // Not enough data left to parse another struct, exit loop
                    // and ignore eventual leftover bytes
                    tracing::warn!(
                        error = %e,
                        "Not enough data left to parse another struct, ignoring leftover bytes"
                    );
                    offset = uds_payload.len();
                    break;
                }
                Err(e) => return Err(e),
            }
            if consumed == 0 {
                return Err(DiagServiceError::BadPayload(
                    "EndOfPdu did not consume any bytes, breaking potential infinite loop"
                        .to_owned(),
                ));
            }
            offset = offset.saturating_add(consumed);
        }
        uds_payload.set_last_read_byte_pos(offset);

        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(nested_structs),
        );
        Ok(())
    }

    fn map_normal_dop_from_uds(
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        normal_dop: &datatypes::NormalDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let diag_coded_type = normal_dop.diag_coded_type()?;
        let compu_method =
            normal_dop
                .compu_method()
                .map(Into::into)
                .ok_or(DiagServiceError::InvalidDatabase(format!(
                    "param {short_name} has no compu method"
                )))?;

        let byte_pos = param_ctx.read_byte_pos(uds_payload);

        data.insert(
            short_name,
            operations::extract_diag_data_container(
                param_ctx.parameter.short_name(),
                byte_pos,
                param_ctx.parameter.bit_position() as usize,
                uds_payload,
                &diag_coded_type,
                Some(compu_method),
                physical_base_type(normal_dop),
            )?,
        );
        Ok(())
    }

    fn map_mux_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &datatypes::MuxDop,
    ) -> Result<(), DiagServiceError> {
        // Byte pos is the relative position of the data in the uds_payload
        let byte_pos = mux_dop.byte_position() as usize;

        let switch_key = &mux_dop
            .switch_key()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Mux switch key not defined".to_owned(),
            ))?;

        // Byte position of the switch key is relative to the mux byte position
        let mut mux_data = HashMap::default();
        let dop = switch_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("Mux switch key DoP is None".to_owned()),
        )?;

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let switch_key_diag_type = normal_dop.diag_coded_type()?;

                let (switch_key_data, bit_len) = switch_key_diag_type.decode(
                    uds_payload
                        .data()?
                        .get(switch_key.byte_position() as usize..)
                        .ok_or(DiagServiceError::BadPayload(
                            "Not enough bytes to get switch key".to_owned(),
                        ))?,
                    switch_key.byte_position() as usize,
                    switch_key.bit_position().unwrap_or(0) as usize,
                )?;

                let switch_key_value = operations::uds_data_to_serializable(
                    switch_key_diag_type.base_datatype(),
                    normal_dop.compu_method().map(Into::into).as_ref(),
                    false,
                    &switch_key_data,
                )?;
                let switch_key_end = switch_key_diag_type.coded_end(
                    uds_payload.data()?,
                    switch_key.byte_position() as usize,
                    switch_key.bit_position().unwrap_or(0) as usize,
                    switch_key_data.len(),
                );
                let mut mux_end = switch_key_end;

                mux_data.insert(
                    "Selector".to_owned(),
                    DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                        data: switch_key_data.clone(),
                        data_type: switch_key_diag_type.base_datatype(),
                        bit_len,
                        compu_method: None,
                        physical_type: None,
                    }),
                );

                let (case_name, case_structure) =
                    mux_case_struct_from_selector_value(mux_dop, &switch_key_value)
                        .map(|(case, case_struct)| {
                            let name =
                                case.short_name().ok_or(DiagServiceError::InvalidDatabase(
                                    "Mux case short name not found".to_owned(),
                                ))?;
                            Ok::<_, DiagServiceError>((name.to_owned(), case_struct))
                        })
                        .transpose()?
                        .map_or_else(
                            || {
                                mux_dop
                                    .default_case()
                                    .and_then(|default| {
                                        let name = default.short_name()?.to_owned();
                                        let case_struct = default.structure().and_then(|s| {
                                            s.specific_data_as_structure()
                                                .map(datatypes::StructureDop)
                                        });
                                        Some((name, case_struct))
                                    })
                                    .ok_or_else(|| {
                                        DiagServiceError::BadPayload(format!(
                                            "Switch key value not found in mux cases and no \
                                             default case defined for MUX {short_name}"
                                        ))
                                    })
                            },
                            Ok,
                        )?;

                // Omitting the structure from a (default) case is valid and can be used
                // to have a valid switch key that is not connected with further data.
                if let Some(case_structure) = case_structure {
                    uds_payload.push_slice(byte_pos, uds_payload.len())?;
                    // Reset last_read_byte_pos for the case data sub-view.
                    // Inner case params may omit BYTE-POSITION, falling back
                    // to last_read_byte_pos; it must be 0 (start of case data)
                    // rather than stale from a previous context.
                    uds_payload.set_last_read_byte_pos(0);
                    let (case_data, case_length) = match self.map_struct_from_uds(
                        &case_structure,
                        mapped_service,
                        uds_payload,
                        data,
                    ) {
                        Ok(d) => (d, Some(uds_payload.last_read_byte_pos())),
                        Err(DiagServiceError::NotEnoughData { .. }) => {
                            // ECU payload is too short to contain the case structure;
                            // treat as absent (no case data decoded).
                            tracing::warn!(
                                "Not enough data to decode mux case structure, treating as empty"
                            );
                            (HashMap::default(), None)
                        }
                        Err(e) => return Err(e),
                    };
                    uds_payload.pop_slice()?;
                    // A truncated case extends to the end of the payload, so
                    // nothing following the MUX may start inside it.
                    mux_end = mux_end.max(case_length.map_or_else(
                        || uds_payload.len(),
                        |length| byte_pos.saturating_add(length),
                    ));
                    mux_data.insert(case_name, DiagDataTypeContainer::Struct(case_data));
                }
                uds_payload.set_last_read_byte_pos(mux_end);

                data.insert(short_name, DiagDataTypeContainer::Struct(mux_data));
                Ok(())
            }
            _ => Err(DiagServiceError::InvalidDatabase(
                "Mux switch key DoP is not a NormalDoP".to_owned(),
            )),
        }
    }
}

fn unknown_position(param: &datatypes::Parameter<'_>) -> DiagServiceError {
    DiagServiceError::InvalidDatabase(format!(
        "Cannot determine the position of response parameter '{}'",
        param.short_name().unwrap_or_default()
    ))
}

/// The positioned key which the parameter at `index` refers to, if it is
/// declared after that parameter.
fn later_positioned_key<'a, 'p>(
    params: &'p [datatypes::Parameter<'a>],
    index: usize,
) -> Option<(usize, &'p datatypes::Parameter<'a>)> {
    let (key_type, key_name) = referenced_key(params.get(index)?)?;
    params
        .iter()
        .enumerate()
        .skip(index.saturating_add(1))
        .find(|(_, key)| {
            key.has_byte_position()
                && key.param_type().is_ok_and(|kind| key_type.matches(&kind))
                && key.short_name() == Some(key_name.as_str())
        })
}

/// Determines where a SYSTEM or NRC-CONST parameter ends. Their values are not
/// mapped, but following parameters depend on their length.
fn unmapped_param_end(
    payload: &mut Payload,
    param: &datatypes::Parameter<'_>,
    position: usize,
) -> Option<usize> {
    let coded_type: datatypes::DiagCodedType = if let Some(system) = param.specific_data_as_system()
    {
        system
            .dop()
            .and_then(|dop| dop.specific_data_as_normal_dop())
            .map(datatypes::NormalDop)?
            .diag_coded_type()
            .ok()?
    } else {
        param
            .specific_data_as_nrc_const()?
            .diag_coded_type()?
            .try_into()
            .ok()?
    };
    operations::extract_diag_data_container(
        param.short_name(),
        position,
        param.bit_position() as usize,
        payload,
        &coded_type,
        None,
        None,
    )
    .ok()?;
    Some(payload.last_read_byte_pos())
}

fn skip_unmapped_param(uds_payload: &mut Payload, param_ctx: ParamContext<'_>) {
    let position = param_ctx.read_byte_pos(uds_payload);
    if unmapped_param_end(uds_payload, param_ctx.parameter, position).is_none() {
        tracing::debug!("Length of the unmapped parameter is unknown");
    }
}

fn map_param_reserved_from_uds(
    param_name: &str,
    uds_payload: &mut Payload,
    data: &mut MappedDiagServiceResponsePayload,
    param_ctx: ParamContext<'_>,
) -> Result<(), DiagServiceError> {
    let r = param_ctx.parameter.specific_data_as_reserved().ok_or(
        DiagServiceError::InvalidDatabase("Expected Reserved specific data".to_owned()),
    )?;

    let data_type = super::reserved_param_data_type(r.bit_length());
    let coded_type = datatypes::DiagCodedType::new_high_low_byte_order(
        data_type,
        datatypes::DiagCodedTypeVariant::StandardLength(datatypes::StandardLengthType {
            bit_length: r.bit_length(),
            bit_mask: None,
            condensed: false,
        }),
    )?;

    let byte_pos = param_ctx.abs_byte_pos();
    let bit_pos = param_ctx.parameter.bit_position() as usize;
    let (param_data, bit_len) = coded_type.decode(uds_payload.data()?, byte_pos, bit_pos)?;
    let end = coded_type.coded_end(uds_payload.data()?, byte_pos, bit_pos, param_data.len());
    uds_payload.set_last_read_byte_pos(end);

    data.insert(
        param_name.to_owned(),
        DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
            data: param_data,
            bit_len,
            data_type,
            compu_method: None,
            physical_type: None,
        }),
    );
    Ok(())
}

fn map_param_coded_const_from_uds(
    param_name: &str,
    uds_payload: &mut Payload,
    data: &mut MappedDiagServiceResponsePayload,
    param_ctx: ParamContext<'_>,
) -> Result<(), DiagServiceError> {
    let c = param_ctx.parameter.specific_data_as_coded_const().ok_or(
        DiagServiceError::InvalidDatabase("Expected CodedConst specific data".to_owned()),
    )?;

    let diag_type: datatypes::DiagCodedType = c
        .diag_coded_type()
        .map(TryInto::try_into)
        .transpose()?
        .ok_or(DiagServiceError::InvalidDatabase(
            "Expected DiagCodedType in CodedConst specific data".to_owned(),
        ))?;

    let byte_pos = param_ctx.read_byte_pos(uds_payload);
    let value = operations::extract_diag_data_container(
        param_ctx.parameter.short_name(),
        byte_pos,
        param_ctx.parameter.bit_position() as usize,
        uds_payload,
        &diag_type,
        None,
        None,
    )?;

    let value = match value {
        DiagDataTypeContainer::RawContainer(diag_data_type_container_raw) => {
            diag_data_type_container_raw
        }
        DiagDataTypeContainer::Struct(_hash_map) => {
            return Err(DiagServiceError::ParameterConversionError(
                "Struct not supported for UDS payload".to_owned(),
            ));
        }
        DiagDataTypeContainer::RepeatingStruct(_vec) => {
            return Err(DiagServiceError::ParameterConversionError(
                "RepeatingStruct not supported for UDS payload".to_owned(),
            ));
        }
        DiagDataTypeContainer::DtcStruct(_dtc) => {
            return Err(DiagServiceError::ParameterConversionError(
                "DtcStruct not supported for UDS payload".to_owned(),
            ));
        }
    };
    let const_value = c.coded_value().ok_or(DiagServiceError::InvalidDatabase(
        "CodedConst has no coded value".to_owned(),
    ))?;
    let const_json_value = str_to_json_value(const_value, diag_type.base_datatype())?;
    let expected = operations::json_value_to_uds_data(
        &diag_type,
        None,
        None,
        &const_json_value,
        cda_interfaces::BinaryEncoding::Hex,
    )
    .inspect_err(|e| {
        tracing::error!(
            error = ?e,
            "Failed to convert CodedConst coded value to UDS data for parameter '{}'",
            param_ctx.parameter.short_name().unwrap_or_default()
        );
    })?
    .into_iter()
    .collect::<Vec<_>>();
    let expected = expected
        .get(expected.len().saturating_sub(value.data.len())..)
        .ok_or(DiagServiceError::BadPayload(
            "Expected value slice out of bounds".to_owned(),
        ))?;
    if value.data != expected {
        return Err(DiagServiceError::BadPayload(format!(
            "{}: Expected {:?}, got {:?}",
            param_ctx.parameter.short_name().unwrap_or_default(),
            expected,
            value.data
        )));
    }
    data.insert(
        param_name.to_owned(),
        DiagDataTypeContainer::RawContainer(value),
    );
    Ok(())
}

fn map_dtc_dop_from_uds(
    param_name: &str,
    uds_payload: &mut Payload,
    data: &mut MappedDiagServiceResponsePayload,
    dtc_dop: &datatypes::DtcDop,
    param_ctx: ParamContext<'_>,
) -> Result<(), DiagServiceError> {
    use cda_interfaces::datatypes::DTC_CODE_BIT_LEN;

    use crate::{
        DiagDataContainerDtc,
        diag_kernel::{DiagDataValue, diagservices::DiagDataTypeContainer},
    };

    let coded_type: datatypes::DiagCodedType = dtc_dop.diag_coded_type()?;

    let byte_pos = param_ctx.abs_byte_pos();
    let bit_pos = param_ctx.parameter.bit_position() as usize;
    let (dtc_value, _size) = coded_type.decode(uds_payload.data()?, byte_pos, bit_pos)?;
    let end = coded_type.coded_end(uds_payload.data()?, byte_pos, bit_pos, dtc_value.len());
    uds_payload.set_last_read_byte_pos(end);

    let code: u32 = DiagDataValue::new(coded_type.base_datatype(), &dtc_value)?.try_into()?;

    let record = dtc_dop
        .dtcs()
        .and_then(|dtcs| dtcs.iter().find(|dtc| dtc.trouble_code() == code));

    data.insert(
        param_name.to_owned(),
        DiagDataTypeContainer::DtcStruct(DiagDataContainerDtc {
            code,
            display_code: record
                .and_then(|record| record.display_trouble_code())
                .map(ToOwned::to_owned),
            fault_name: record
                .and_then(|record| {
                    record
                        .text()
                        .and_then(|text| text.value().map(ToOwned::to_owned))
                })
                .unwrap_or_else(|| "DTC description not available".to_owned()),
            severity: record.and_then(|record| record.level()).unwrap_or_default(),
            bit_pos: param_ctx.parameter.bit_position(),
            bit_len: DTC_CODE_BIT_LEN,
            byte_pos: u32::try_from(byte_pos).map_err(|_| {
                DiagServiceError::InvalidDatabase("DTC byte position overflows u32".to_owned())
            })?,
        }),
    );
    Ok(())
}

pub(crate) fn mux_case_struct_from_selector_value<'a>(
    mux_dop: &'a datatypes::MuxDop,
    switch_key_value: &DiagDataValue,
) -> Option<(datatypes::Case<'a>, Option<datatypes::StructureDop<'a>>)> {
    mux_dop.cases().and_then(|cases| {
        cases
            .iter()
            .find(|case| {
                let lower_limit = case.lower_limit().map(Into::into);
                let upper_limit = case.upper_limit().map(Into::into);
                switch_key_value.within_limits(upper_limit.as_ref(), lower_limit.as_ref())
            })
            .map(|case| {
                let struct_dop = case
                    .structure()
                    .and_then(|s| s.specific_data_as_structure().map(datatypes::StructureDop));
                (case.into(), struct_dop)
            })
    })
}

fn extract_struct_dop_from_field(
    field: Option<datatypes::DopField>,
) -> Result<datatypes::StructureDop, DiagServiceError> {
    field
        .and_then(|f| {
            f.basic_structure()
                .and_then(|s| s.specific_data_as_structure().map(datatypes::StructureDop))
        })
        .ok_or(DiagServiceError::InvalidDatabase(
            "Field none or does not contain a struct".to_owned(),
        ))
}

fn create_diag_service_response(
    diag_service: &cda_interfaces::DiagComm,
    data: HashMap<String, DiagDataTypeContainer>,
    response_type: datatypes::ResponseType,
    raw_uds_payload: Vec<u8>,
    mapping_errors: Vec<FieldParseError>,
) -> DiagServiceResponseStruct {
    match response_type {
        datatypes::ResponseType::Negative | datatypes::ResponseType::GlobalNegative => {
            DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: raw_uds_payload,
                mapped_data: Some(MappedResponseData {
                    data,
                    errors: mapping_errors,
                }),
                response_type: DiagServiceResponseType::Negative,
            }
        }
        datatypes::ResponseType::Positive => DiagServiceResponseStruct {
            service: diag_service.clone(),
            data: raw_uds_payload,
            mapped_data: Some(MappedResponseData {
                data,
                errors: mapping_errors,
            }),
            response_type: DiagServiceResponseType::Positive,
        },
    }
}

/// Base type of a DOP's PHYSICAL-TYPE: the type of its computed physical value.
fn physical_base_type(normal_dop: &datatypes::NormalDop) -> Option<datatypes::DataType> {
    normal_dop
        .physical_type()
        .map(|physical| datatypes::PhysicalType::from(physical).base_type)
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        CompuCategory, DataType, DiagCodedTypeVariant, ResponseType,
        database_builder::{DataFormatDop, DataFormatParam, EcuDataBuilder},
    };
    use cda_interfaces::{
        DiagCommType, Protocol,
        diagservices::{DiagServiceResponse as _, DiagServiceResponseType},
    };
    use cda_plugin_security::DefaultSecurityPluginData;
    use flatbuffers::WIPOffset;
    use serde_json::json;

    use super::*;
    use crate::diag_kernel::test_utils::{
        db_builder::finish_db,
        ecu_manager_builder::{
            EndOfPduStructureType, SID_PARM_NAME, create_ecu_manager_dlf_sibling_no_byte_pos,
            create_ecu_manager_env_data_no_wildcard, create_ecu_manager_with_dtc,
            create_ecu_manager_with_dynamic_length_field_service,
            create_ecu_manager_with_dynamic_length_field_service_and_count_compu,
            create_ecu_manager_with_end_pdu_service, create_ecu_manager_with_env_data_desc,
            create_ecu_manager_with_env_data_desc_wildcard, create_ecu_manager_with_mux_service,
            create_ecu_manager_with_mux_service_and_default_case,
            create_ecu_manager_with_param_length_info_service,
            create_ecu_manager_with_param_length_info_service_ordered,
            create_ecu_manager_with_phys_const_normal_dop_service,
            create_ecu_manager_with_phys_const_structure_dop_service,
            create_ecu_manager_with_static_field_service, create_ecu_manager_with_struct_service,
            create_ecu_manager_with_table_struct_service, new_ecu_manager,
        },
        mdd_type_builder::{create_sid_param, new_diag_comm, new_diag_service},
    };

    #[tokio::test]
    async fn variable_predecessor_resolves_raw_data_offset() {
        for (later_positioned_data, first_data_is_positioned) in
            [(false, false), (true, false), (false, true)]
        {
            let mut db = EcuDataBuilder::new();
            let protocol_name = Protocol::default().to_string();
            let protocol = db.create_protocol(&protocol_name, None, None, None);
            let byte_type = db.create_diag_coded_type_standard_length(8, DataType::ByteField);
            let variable_type = db.create_diag_coded_type(
                None,
                DataType::ByteField,
                true,
                DiagCodedTypeVariant::LeadingLengthInfo(8),
            );
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let byte_dop = db.create_regular_normal_dop("byte", byte_type, compu);
            let variable_dop = db.create_regular_normal_dop("variable", variable_type, compu);
            let sid = create_sid_param!(db, "response_sid", 0x62u8);
            let variable = if first_data_is_positioned {
                db.create_value_param_with_semantic("variable", "DATA", variable_dop, 1)
            } else {
                db.create_value_param_with_semantic("variable", "PREAMBLE", variable_dop, 1)
            };
            let data =
                db.create_value_param_no_byte_pos_with_semantic("data", byte_dop, Some("DATA"));
            let mut params = vec![sid, variable, data];
            if later_positioned_data {
                params.push(db.create_value_param_with_semantic("later", "DATA", byte_dop, 5));
            }
            let response = db.create_response(ResponseType::Positive, Some(params), None);
            let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
            let request = db.create_request(Some(vec![request_sid]), None);
            let comm = new_diag_comm!(db, "TestRawOffset", protocol);
            let service = new_diag_service!(db, comm, request, vec![response], vec![]);
            let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
            let diag_comm = DiagComm::new("TestRawOffset".to_owned(), DiagCommType::Data);
            let payload = create_payload(vec![0x62, 2, 0xAA, 0xBB, 0xCC, 0xDD]);

            for map_to_json in [false, true] {
                let case = format!(
                    "later_positioned_data={later_positioned_data}, \
                     first_data_is_positioned={first_data_is_positioned}, \
                     map_to_json={map_to_json}"
                );
                let result = ecu
                    .convert_from_uds(&diag_comm, &payload, map_to_json, None)
                    .await;
                let expected = if first_data_is_positioned {
                    vec![2, 0xAA, 0xBB, 0xCC, 0xDD]
                } else {
                    vec![0xCC, 0xDD]
                };
                let response = result.expect("valid response should be accepted");
                assert_eq!(response.get_raw(), expected, "{case}");
                if map_to_json {
                    let mapped = response
                        .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
                        .unwrap();
                    assert_eq!(mapped.data.get("data"), Some(&json!("0xCC")), "{case}");
                    // Only a DATA param is part of the output.
                    let variable = first_data_is_positioned.then(|| json!("0xAA 0xBB"));
                    assert_eq!(mapped.data.get("variable"), variable.as_ref(), "{case}");
                }

                // A payload which ends before the last DATA param is rejected
                // instead of returning the bytes which are there.
                if !first_data_is_positioned {
                    let truncated_len = if later_positioned_data { 5 } else { 4 };
                    let truncated = create_payload(
                        payload
                            .data
                            .get(..truncated_len)
                            .expect("the full payload is longer")
                            .to_vec(),
                    );
                    let err = ecu
                        .convert_from_uds(&diag_comm, &truncated, map_to_json, None)
                        .await
                        .expect_err("truncated response should be rejected");
                    assert!(
                        matches!(err, DiagServiceError::NotEnoughData { .. }),
                        "{case}: unexpected error {err:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn runtime_data_offset_resolves_length_key_before_or_after_field() {
        for key_first in [true, false] {
            let mut db = EcuDataBuilder::new();
            let protocol_name = Protocol::default().to_string();
            let protocol = db.create_protocol(&protocol_name, None, None, None);
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let byte_type = db.create_diag_coded_type_standard_length(8, DataType::ByteField);
            let key_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let variable_type =
                db.create_diag_coded_type_param_length_info("length", DataType::ByteField);
            let byte_dop = db.create_regular_normal_dop("byte", byte_type, compu);
            let key_dop = db.create_regular_normal_dop("key", key_type, compu);
            let variable_dop = db.create_regular_normal_dop("variable", variable_type, compu);
            let sid = create_sid_param!(db, "response_sid", 0x62u8);
            let key = db.create_length_key_param("length", key_dop, 1, 0);
            let variable = db.create_value_param("variable", variable_dop, 2, 0);
            let data =
                db.create_value_param_no_byte_pos_with_semantic("data", byte_dop, Some("DATA"));
            let params = if key_first {
                vec![sid, key, variable, data]
            } else {
                vec![sid, variable, data, key]
            };
            let response = db.create_response(ResponseType::Positive, Some(params), None);
            let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
            let request = db.create_request(Some(vec![request_sid]), None);
            let comm = new_diag_comm!(db, "TestLengthKeyOffset", protocol);
            let service = new_diag_service!(db, comm, request, vec![response], vec![]);
            let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
            let diag_comm = DiagComm::new("TestLengthKeyOffset".to_owned(), DiagCommType::Data);

            for map_to_json in [false, true] {
                let case = format!("key_first={key_first}, map_to_json={map_to_json}");
                for (bytes, length, variable) in [
                    (vec![0x62, 0, 0xCC], 0, json!("")),
                    (vec![0x62, 16, 0xAA, 0xBB, 0xCC], 16, json!("0xAA 0xBB")),
                ] {
                    let response = ecu
                        .convert_from_uds(&diag_comm, &create_payload(bytes), map_to_json, None)
                        .await
                        .expect("length-key response should be accepted");
                    assert_eq!(response.get_raw(), [0xCC], "{case}");
                    if map_to_json {
                        let mapped = response
                            .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
                            .unwrap();
                        assert_eq!(mapped.data.get("data"), Some(&json!("0xCC")), "{case}");
                        assert_eq!(mapped.data.get("length"), Some(&json!(length)), "{case}");
                        assert_eq!(mapped.data.get("variable"), Some(&variable), "{case}");
                    }
                }
                let err = ecu
                    .convert_from_uds(
                        &diag_comm,
                        &create_payload(vec![0x62, 32, 0xAA]),
                        map_to_json,
                        None,
                    )
                    .await
                    .expect_err("a length beyond the payload should be rejected");
                assert!(
                    matches!(err, DiagServiceError::NotEnoughData { .. }),
                    "{case}: unexpected error {err:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn runtime_data_offset_skips_variable_field_terminator() {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let byte_type = db.create_diag_coded_type_standard_length(8, DataType::ByteField);
        let variable_type = db.create_diag_coded_type(
            None,
            DataType::ByteField,
            true,
            DiagCodedTypeVariant::MinMaxLength(datatypes::MinMaxLengthType {
                min_length: 0,
                max_length: Some(4),
                termination: datatypes::Termination::Zero,
            }),
        );
        let byte_dop = db.create_regular_normal_dop("byte", byte_type, compu);
        let variable_dop = db.create_regular_normal_dop("variable", variable_type, compu);
        let sid = create_sid_param!(db, "response_sid", 0x62u8);
        let variable = db.create_value_param("variable", variable_dop, 1, 0);
        let data = db.create_value_param_no_byte_pos_with_semantic("data", byte_dop, Some("DATA"));
        let response = db.create_response(
            ResponseType::Positive,
            Some(vec![sid, variable, data]),
            None,
        );
        let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
        let request = db.create_request(Some(vec![request_sid]), None);
        let comm = new_diag_comm!(db, "TestTerminatedOffset", protocol);
        let service = new_diag_service!(db, comm, request, vec![response], vec![]);
        let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
        let diag_comm = DiagComm::new("TestTerminatedOffset".to_owned(), DiagCommType::Data);

        for map_to_json in [false, true] {
            let response = ecu
                .convert_from_uds(
                    &diag_comm,
                    &create_payload(vec![0x62, 0xAA, 0xBB, 0, 0xCC]),
                    map_to_json,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(response.get_raw(), [0xCC]);
            if map_to_json {
                let mapped = response
                    .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
                    .unwrap();
                assert_eq!(mapped.data.get("data"), Some(&json!("0xCC")));
            }
        }
    }

    /// Decodes a response made of the SID, the parameters returned by `build`
    /// and an unpositioned one byte DATA parameter `data`, then expects both
    /// the raw payload and the mapped `data` to be the trailing byte.
    async fn assert_trailing_data_follows(
        bytes: Vec<u8>,
        build: impl for<'a> FnOnce(&mut EcuDataBuilder<'a>) -> Vec<WIPOffset<DataFormatParam<'a>>>,
    ) {
        let (ecu, diag_comm) = trailing_data_ecu(build);
        let expected = *bytes.last().unwrap();

        for map_to_json in [false, true] {
            let response = ecu
                .convert_from_uds(
                    &diag_comm,
                    &create_payload(bytes.clone()),
                    map_to_json,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(response.get_raw(), [expected]);
            if map_to_json {
                let mapped = response
                    .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
                    .unwrap();
                assert_eq!(
                    mapped.data.get("data"),
                    Some(&json!(format!("0x{expected:02X}")))
                );
            }
        }
    }

    /// Like [`assert_trailing_data_follows`], but expects `bytes` to be
    /// rejected because the trailing DATA param is not in the payload.
    async fn assert_trailing_data_is_missing(
        bytes: Vec<u8>,
        build: impl for<'a> FnOnce(&mut EcuDataBuilder<'a>) -> Vec<WIPOffset<DataFormatParam<'a>>>,
    ) {
        let (ecu, diag_comm) = trailing_data_ecu(build);
        for map_to_json in [false, true] {
            let err = ecu
                .convert_from_uds(
                    &diag_comm,
                    &create_payload(bytes.clone()),
                    map_to_json,
                    None,
                )
                .await
                .expect_err("response without trailing data should be rejected");
            assert!(
                matches!(err, DiagServiceError::NotEnoughData { .. }),
                "map_to_json={map_to_json}: unexpected error {err:?}"
            );
        }
    }

    fn trailing_data_ecu(
        build: impl for<'a> FnOnce(&mut EcuDataBuilder<'a>) -> Vec<WIPOffset<DataFormatParam<'a>>>,
    ) -> (
        super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
        DiagComm,
    ) {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let sid = create_sid_param!(db, "response_sid", 0x62u8);
        let mut params = vec![sid];
        params.extend(build(&mut db));
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let byte_type = db.create_diag_coded_type_standard_length(8, DataType::ByteField);
        let byte_dop = db.create_regular_normal_dop("trailing", byte_type, compu);
        params.push(db.create_value_param_no_byte_pos_with_semantic(
            "data",
            byte_dop,
            Some("DATA"),
        ));
        let response = db.create_response(ResponseType::Positive, Some(params), None);
        let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
        let request = db.create_request(Some(vec![request_sid]), None);
        let comm = new_diag_comm!(db, "TestTrailingData", protocol);
        let service = new_diag_service!(db, comm, request, vec![response], vec![]);
        let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
        let diag_comm = DiagComm::new("TestTrailingData".to_owned(), DiagCommType::Data);
        (ecu, diag_comm)
    }

    fn byte_dop<'a>(db: &mut EcuDataBuilder<'a>) -> WIPOffset<DataFormatDop<'a>> {
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let coded_type = db.create_diag_coded_type_standard_length(8, DataType::ByteField);
        db.create_regular_normal_dop("byte", coded_type, compu)
    }

    fn terminated_dop<'a>(
        db: &mut EcuDataBuilder<'a>,
        data_type: DataType,
        termination: datatypes::Termination,
    ) -> WIPOffset<DataFormatDop<'a>> {
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let coded_type = db.create_diag_coded_type(
            None,
            data_type,
            true,
            DiagCodedTypeVariant::MinMaxLength(datatypes::MinMaxLengthType {
                min_length: 0,
                max_length: Some(8),
                termination,
            }),
        );
        db.create_regular_normal_dop("terminated", coded_type, compu)
    }

    #[tokio::test]
    async fn unpositioned_data_follows_furthest_structure_child() {
        assert_trailing_data_follows(vec![0x62, 0xAA, 0xBB, 0xCC], |db| {
            let dop = byte_dop(db);
            let second = db.create_value_param("second", dop, 1, 0);
            let first = db.create_value_param("first", dop, 0, 0);
            let structure = db.create_structure(Some(vec![second, first]), None, true);
            let dop = db.create_structure_dop("structure", structure);
            vec![db.create_value_param_with_semantic("structure", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_static_field() {
        assert_trailing_data_follows(vec![0x62, 0xA0, 0xA1, 0xB0, 0xB1, 0xCC], |db| {
            let dop = byte_dop(db);
            let item = db.create_value_param("item", dop, 0, 0);
            let structure = db.create_structure(Some(vec![item]), None, true);
            let dop = db.create_static_field_dop(2, 2, structure);
            vec![db.create_value_param_with_semantic("field", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_terminated_phys_const() {
        for (termination, terminator) in [
            (datatypes::Termination::Zero, 0u8),
            (datatypes::Termination::HexFF, 0xFF),
        ] {
            assert_trailing_data_follows(vec![0x62, 0x41, terminator, 0xCC], |db| {
                let dop = terminated_dop(db, DataType::AsciiString, termination);
                vec![db.create_phys_const_param("constant", Some("A"), dop, 1, 0)]
            })
            .await;
        }
    }

    #[tokio::test]
    async fn unpositioned_data_follows_terminated_structure_child() {
        assert_trailing_data_follows(vec![0x62, 0x41, 0, 0xCC], |db| {
            let dop = terminated_dop(db, DataType::ByteField, datatypes::Termination::Zero);
            let child = db.create_value_param("child", dop, 0, 0);
            let structure = db.create_structure(Some(vec![child]), None, true);
            let dop = db.create_structure_dop("structure", structure);
            vec![db.create_value_param_with_semantic("structure", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_params_keep_distinct_positions_without_param_ids() {
        let mut db = EcuDataBuilder::new();
        db.without_param_ids();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let variable_type = db.create_diag_coded_type(
            None,
            DataType::ByteField,
            true,
            DiagCodedTypeVariant::LeadingLengthInfo(8),
        );
        let variable_dop = db.create_regular_normal_dop("variable", variable_type, compu);
        let dop = byte_dop(&mut db);
        let sid = create_sid_param!(db, "response_sid", 0x62u8);
        let params = vec![
            sid,
            db.create_value_param_with_semantic("variable", "PREAMBLE", variable_dop, 1),
            db.create_value_param_no_byte_pos_with_semantic("first", dop, Some("DATA")),
            db.create_value_param_no_byte_pos_with_semantic("second", dop, Some("DATA")),
        ];
        let response = db.create_response(ResponseType::Positive, Some(params), None);
        let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
        let request = db.create_request(Some(vec![request_sid]), None);
        let comm = new_diag_comm!(db, "TestParamIds", protocol);
        let service = new_diag_service!(db, comm, request, vec![response], vec![]);
        let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
        let diag_comm = DiagComm::new("TestParamIds".to_owned(), DiagCommType::Data);

        let response = ecu
            .convert_from_uds(
                &diag_comm,
                &create_payload(vec![0x62, 2, 0xAA, 0xBB, 0xCC, 0xDD]),
                true,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.get_raw(), [0xCC, 0xDD]);
        let mapped = response
            .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
            .unwrap();
        assert_eq!(mapped.data.get("first"), Some(&json!("0xCC")));
        assert_eq!(mapped.data.get("second"), Some(&json!("0xDD")));
    }

    #[tokio::test]
    async fn mapped_data_follows_positioned_terminated_field() {
        assert_trailing_data_follows(vec![0x62, 0xAA, 0, 0xCC], |db| {
            let dop = terminated_dop(db, DataType::ByteField, datatypes::Termination::Zero);
            vec![db.create_value_param_with_semantic("positioned", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn mapped_data_follows_params_without_data_semantic() {
        assert_trailing_data_follows(vec![0x62, 0xAA, 0xCC], |db| {
            let dop = byte_dop(db);
            vec![db.create_value_param_with_semantic("preamble", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_system_param() {
        assert_trailing_data_follows(vec![0x62, 0xAA, 0xCC], |db| {
            let dop = byte_dop(db);
            vec![db.create_system_param("system", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn env_data_selector_is_decoded_before_unpositioned_data() {
        assert_trailing_data_follows(vec![0x62, 0x01, 0xAA, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let selector_dop = db.create_regular_normal_dop("selector", coded_type, compu);
            let value_dop = byte_dop(db);
            let value = db.create_value_param("env_value", value_dop, 0, 0);
            let env_data = db.create_env_data_dop(&[1], &[value]);
            let env_dop = db.create_env_data_desc_dop("env_desc", "selector", &[env_data]);
            vec![
                db.create_value_param_with_semantic("selector", "PREAMBLE", selector_dop, 1),
                db.create_value_param_with_semantic("environment", "PREAMBLE", env_dop, 2),
            ]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_mux_case() {
        assert_trailing_data_follows(vec![0x62, 0x01, 0xAA, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let key_dop = db.create_regular_normal_dop("key", coded_type, compu);
            let switch_key = db.create_switch_key(0, Some(0), Some(key_dop));
            let dop = byte_dop(db);
            let item = db.create_value_param("item", dop, 0, 0);
            let structure = db.create_structure(Some(vec![item]), None, true);
            let limit = datatypes::Limit {
                value: "1".to_owned(),
                interval_type: datatypes::IntervalType::Closed,
            };
            let case = db.create_case("case", Some(limit.clone()), Some(limit), Some(structure));
            let dop = db.create_mux_dop("mux", 1, Some(switch_key), None, Some(vec![case]), true);
            vec![db.create_value_param_with_semantic("mux", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_table_struct_row() {
        assert_trailing_data_follows(vec![0x62, 0x05, 0xAA, 0xBB, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let key_dop = db.create_regular_normal_dop("key", coded_type, compu);
            let dop = byte_dop(db);
            let second = db.create_value_param("second", dop, 1, 0);
            let first = db.create_value_param("first", dop, 0, 0);
            let structure = db.create_structure(Some(vec![second, first]), None, true);
            let row = db.create_structure_dop("row_struct", structure);
            let key =
                db.create_table_key_param("table_key", key_dop, &[("row", "5", Some(row))], 1);
            let table_struct = db.create_table_struct_param("table_struct", key, 2);
            vec![key, table_struct]
        })
        .await;
    }

    #[tokio::test]
    async fn mapped_data_follows_reserved_param() {
        assert_trailing_data_follows(vec![0x62, 0xEE, 0xCC], |db| {
            vec![db.create_reserved_param("reserved", 1, 8)]
        })
        .await;
    }

    #[tokio::test]
    async fn mapped_data_follows_dtc() {
        assert_trailing_data_follows(vec![0x62, 0x12, 0x34, 0x56, 0xCC], |db| {
            let coded_type = db.create_diag_coded_type_standard_length(24, DataType::UInt32);
            let dop = db.create_dtc_dop(coded_type, None, None);
            vec![db.create_value_param_with_semantic("dtc", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    /// The case needs two bytes but only one is left. That byte belongs to the
    /// case, so it must not be returned as the following DATA param.
    #[tokio::test]
    async fn truncated_mux_case_is_not_read_as_following_data() {
        assert_trailing_data_is_missing(vec![0x62, 0x01, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let key_dop = db.create_regular_normal_dop("key", coded_type, compu);
            let switch_key = db.create_switch_key(0, Some(0), Some(key_dop));
            let item_type = db.create_diag_coded_type_standard_length(16, DataType::UInt32);
            let item_dop = db.create_regular_normal_dop("item", item_type, compu);
            let item = db.create_value_param("item", item_dop, 0, 0);
            let structure = db.create_structure(Some(vec![item]), None, true);
            let limit = datatypes::Limit {
                value: "1".to_owned(),
                interval_type: datatypes::IntervalType::Closed,
            };
            let case = db.create_case("case", Some(limit.clone()), Some(limit), Some(structure));
            let dop = db.create_mux_dop("mux", 1, Some(switch_key), None, Some(vec![case]), true);
            vec![db.create_value_param_with_semantic("mux", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    /// Three items are announced, the third is cut off after one byte. That
    /// byte belongs to the item, so it must not be returned as the following
    /// DATA param.
    #[tokio::test]
    async fn truncated_dynamic_length_field_is_not_read_as_following_data() {
        assert_trailing_data_is_missing(vec![0x62, 0x03, 0x11, 0x22, 0x33, 0x44, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let count_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let count_dop = db.create_regular_normal_dop("count", count_type, compu);
            let item_type = db.create_diag_coded_type_standard_length(16, DataType::UInt32);
            let item_dop = db.create_regular_normal_dop("item", item_type, compu);
            let item = db.create_value_param("item", item_dop, 0, 0);
            let structure = db.create_structure(Some(vec![item]), Some(2), true);
            let specific = db
                .create_dynamic_length_specific_dop_data(1, 0, 0, count_dop, Some(structure))
                .value_offset();
            let dop = db.create_dop(
                *cda_database::datatypes::database_builder::DopType::REGULAR,
                Some("dlf"),
                None,
                *cda_database::datatypes::database_builder::SpecificDOPData::DynamicLengthField,
                Some(specific),
            );
            vec![db.create_value_param_with_semantic("field", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn missing_data_after_variable_field_is_rejected() {
        assert_trailing_data_is_missing(vec![0x62, 2, 0xAA, 0xBB], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type(
                None,
                DataType::ByteField,
                true,
                DiagCodedTypeVariant::LeadingLengthInfo(8),
            );
            let dop = db.create_regular_normal_dop("variable", coded_type, compu);
            vec![db.create_value_param_with_semantic("variable", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    #[tokio::test]
    async fn unpositioned_data_follows_mux_case_without_params() {
        assert_trailing_data_follows(vec![0x62, 0x01, 0xAA, 0xBB, 0xCC], |db| {
            let compu = db.create_compu_method(CompuCategory::Identical, None, None);
            let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
            let key_dop = db.create_regular_normal_dop("key", coded_type, compu);
            let switch_key = db.create_switch_key(0, Some(0), Some(key_dop));
            let structure = db.create_structure(None, Some(2), true);
            let limit = datatypes::Limit {
                value: "1".to_owned(),
                interval_type: datatypes::IntervalType::Closed,
            };
            let case = db.create_case("case", Some(limit.clone()), Some(limit), Some(structure));
            let dop = db.create_mux_dop("mux", 1, Some(switch_key), None, Some(vec![case]), true);
            vec![db.create_value_param_with_semantic("mux", "PREAMBLE", dop, 1)]
        })
        .await;
    }

    /// The failing parameter is not part of the output, so its error is
    /// ignored and must not shift the parameters decoded afterwards.
    #[tokio::test]
    async fn failed_unmapped_mux_does_not_move_following_data() {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let coded_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let key_dop = db.create_regular_normal_dop("key", coded_type, compu);
        let switch_key = db.create_switch_key(0, Some(0), Some(key_dop));
        let mux_dop = db.create_mux_dop("mux", 1, Some(switch_key), None, Some(vec![]), true);
        let dop = byte_dop(&mut db);
        let sid = create_sid_param!(db, "response_sid", 0x62u8);
        let params = vec![
            sid,
            db.create_value_param_with_semantic("mux", "PREAMBLE", mux_dop, 1),
            db.create_value_param_with_semantic("data", "DATA", dop, 3),
        ];
        let response = db.create_response(ResponseType::Positive, Some(params), None);
        let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
        let request = db.create_request(Some(vec![request_sid]), None);
        let comm = new_diag_comm!(db, "TestFailedMux", protocol);
        let service = new_diag_service!(db, comm, request, vec![response], vec![]);
        let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
        let diag_comm = DiagComm::new("TestFailedMux".to_owned(), DiagCommType::Data);

        let response = ecu
            .convert_from_uds(
                &diag_comm,
                &create_payload(vec![0x62, 0x07, 0x00, 0xAA, 0xBB]),
                true,
                None,
            )
            .await
            .unwrap();
        let mapped = response
            .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
            .unwrap();
        assert_eq!(mapped.data.get("data"), Some(&json!("0xAA")));
    }

    /// The MDD converter omits a BYTE-POSITION of 0, so a complex parameter
    /// without position inside a structure starts at the structure.
    #[tokio::test]
    async fn mux_without_byte_position_in_structure_starts_at_the_structure() {
        let mut db = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db.create_protocol(&protocol_name, None, None, None);
        let compu = db.create_compu_method(CompuCategory::Identical, None, None);
        let u8_type = db.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_type = db.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let u8_dop = db.create_regular_normal_dop("u8", u8_type, compu);
        let u16_dop = db.create_regular_normal_dop("u16", u16_type, compu);
        let value = db.create_value_param("value", u16_dop, 0, 0);
        let case = db.create_structure(Some(vec![value]), None, true);
        let default_case = db.create_default_case("default", Some(case));
        let switch_key = db.create_switch_key(0, Some(0), Some(u8_dop));
        let mux_dop = db.create_mux_dop("mux", 1, Some(switch_key), Some(default_case), None, true);
        let number = db.create_value_param_no_byte_pos("number", u8_dop);
        let content = db.create_value_param_no_byte_pos("content", mux_dop);
        let record = db.create_structure(Some(vec![number, content]), None, true);
        let records_dop = db.create_end_of_pdu_field_dop(0, None, Some(record));
        let sid = create_sid_param!(db, "response_sid", 0x62u8);
        let records = db.create_value_param_with_semantic("records", "DATA", records_dop, 1);
        let response = db.create_response(ResponseType::Positive, Some(vec![sid, records]), None);
        let request_sid = create_sid_param!(db, "request_sid", 0x22u8);
        let request = db.create_request(Some(vec![request_sid]), None);
        let comm = new_diag_comm!(db, "TestRecords", protocol);
        let service = new_diag_service!(db, comm, request, vec![response], vec![]);
        let ecu = new_ecu_manager(finish_db!(db, protocol, vec![service]));
        let diag_comm = DiagComm::new("TestRecords".to_owned(), DiagCommType::Data);

        let response = ecu
            .convert_from_uds(
                &diag_comm,
                &create_payload(vec![0x62, 0xFF, 0x20, 0x21]),
                true,
                None,
            )
            .await
            .unwrap();
        let mapped = response
            .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
            .unwrap();
        assert_eq!(
            mapped.data.get("records"),
            Some(&json!([{
                "number": 255,
                "content": {"Selector": 255, "default": {"value": 0x2021}},
            }]))
        );
    }

    fn create_payload(data: Vec<u8>) -> cda_interfaces::ServicePayload {
        cda_interfaces::ServicePayload {
            data,
            source_address: 0,
            target_address: 0,
            new_session: None,
            new_security: None,
        }
    }

    async fn assert_uds_converts_to_json(
        ecu_manager: &super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
        expected_json: serde_json::Value,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await
            .unwrap();
        assert_eq!(
            response
                .serialize_to_json(cda_interfaces::BinaryEncoding::Hex)
                .unwrap()
                .data,
            expected_json
        );
    }

    async fn assert_uds_conversion_fails(
        ecu_manager: &super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
    ) -> DiagServiceError {
        ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await
            .unwrap_err()
    }

    async fn assert_uds_conversion_succeeds(
        ecu_manager: &super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await;
        assert!(response.is_ok(), "Expected convert_from_uds to succeed");
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_no_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        assert_uds_conversion_fails(&ecu_manager, &service, vec![sid, 0xFF, 0xFF, 0xFF]).await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_with_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service_and_default_case();
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0xFF, 0xFF, 0xFF, 0x42],
            json!({
                "mux_1_param": {
                        "Selector": 0xffff,
                        "default_case": {
                            "default_structure_param_1": 0x42,
                        }
                },
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_payload() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        assert_uds_conversion_succeeds(&ecu_manager, &service, vec![sid, 0xFF, 0x0, 0x0A]).await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_empty_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        assert_uds_conversion_succeeds(&ecu_manager, &service, vec![sid, 0xFF, 0x00, 0x0A]).await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_min_items_not_reached() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(3, Some(2), EndOfPduStructureType::FixedSize);
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x42, 0x12, 0x34, 0x99, 0x56, 0x78],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exact_max_items() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, Some(2), EndOfPduStructureType::FixedSize);
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x42, 0x12, 0x34, 0x99, 0x56, 0x78],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exceeds_max_items() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, Some(2), EndOfPduStructureType::FixedSize);
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x42, 0x12, 0x34, 0x99, 0x56, 0x78, 0xAA, 0xFF],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_max_no_min_no_data() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(0, None, EndOfPduStructureType::FixedSize);
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid],
            json!({
                "end_pdu_param": [],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_maximum() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, None, EndOfPduStructureType::FixedSize);
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid, 0x42, 0x12, 0x34, 0x99, 0x56, 0x78, 0xAA, 0x9A, 0xBC, 0xD0, 0x0F,
            ],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 },
                    { "item_param1": 0xAA, "item_param2": 0x9ABC }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_incomplete_second_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(
            0,
            None,
            EndOfPduStructureType::LeadingLengthDop,
        );

        let mut data = vec![sid];
        data.push(8);
        data.extend(vec![0xAA; 8]);
        data.push(42);
        data.extend(vec![0xBB; 10]);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            data,
            json!({
                "end_pdu_param": [
                    { "data": "0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA" },
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_zero_length_second_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(
            0,
            None,
            EndOfPduStructureType::LeadingLengthDop,
        );

        let mut data = vec![sid];
        data.push(8);
        data.extend(vec![0xAA; 8]);
        data.push(0);
        data.push(42);

        // The second structure has a leading length of zero and thus empty data,
        // the trailing byte 42 cannot form another structure and is ignored.
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            data,
            json!({
                "end_pdu_param": [
                    { "data": "0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA" },
                    { "data": "" }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dtc_from_uds() {
        let (ecu_manager, service, sid, dtc_code) = create_ecu_manager_with_dtc();

        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_code.to_be_bytes());

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "dtc_param": {
                    "code": dtc_code,
                    "display_code": "P1234",
                    "fault_name": "TestFault",
                    "severity": 2,
                },
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_env_data_desc_from_uds() {
        let (ecu_manager, service, sid, dtc_code) = create_ecu_manager_with_env_data_desc();

        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_code.to_be_bytes());
        payload.push(0x42);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "dtc_param": {
                    "code": dtc_code,
                    "display_code": "P0001",
                    "fault_name": "TestEnvFault",
                    "severity": 1,
                },
                "temperature": 0x42,
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            json!({
                "pos_response_param": [
                   { "item_param": 0x1122 },
                   { "item_param": 0x3344 },
                   { "item_param": 0x5566 },
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds_count_with_compu_method() {
        // phys = 2 * internal: the coded count 1 means 2 items
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_dynamic_length_field_service_and_count_compu(Some((0.0, 2.0)));
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x01, 0x11, 0x22, 0x33, 0x44],
            json!({
                "pos_response_param": [
                   { "item_param": 0x1122 },
                   { "item_param": 0x3344 },
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds_not_enough_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        // claims 3 items but only 2 worth of data
        assert_uds_conversion_succeeds(
            &ecu_manager,
            &service,
            vec![sid, 0x03, 0x11, 0x22, 0x33, 0x44],
        )
        .await;
    }

    #[tokio::test]
    async fn test_negative_response() {
        let (ecu_manager, service, _sid, _) = create_ecu_manager_with_struct_service(1);

        let payload = create_payload(vec![
            cda_interfaces::service_ids::NEGATIVE_RESPONSE,
            cda_interfaces::service_ids::WRITE_DATA_BY_IDENTIFIER,
            0x22,
        ]);

        let result = ecu_manager
            .convert_from_uds(&service, &payload, true, None)
            .await;

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().response_type,
            DiagServiceResponseType::Negative
        );
    }

    #[tokio::test]
    async fn test_negative_response_with_invalid_data_where_no_neg_response_is_defined() {
        let (ecu_manager, service, _sid, _) = create_ecu_manager_with_struct_service(1);

        let payload = create_payload(vec![
            cda_interfaces::service_ids::NEGATIVE_RESPONSE,
            0x01,
            0x02,
        ]);

        let result = ecu_manager
            .convert_from_uds(&service, &payload, true, None)
            .await;

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().response_type,
            DiagServiceResponseType::Negative
        );
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_success() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(1);

        let request_payload = vec![
            sid, 0x12, 0x34, 0x40, 0x49, 0x0F, 0xDB, b'T', b'e', b's', b't',
        ];

        let payload = create_payload(request_payload.clone());

        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, true)
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();

        assert_eq!(response.response_type, DiagServiceResponseType::Positive);
        assert_eq!(response.get_raw(), request_payload);
        assert!(response.mapped_data.is_some());

        let mapped = response.mapped_data.unwrap();
        assert_eq!(mapped.errors.len(), 0);
        assert!(mapped.data.contains_key(SID_PARM_NAME));
        assert!(mapped.data.contains_key("param1"));
        assert!(mapped.data.contains_key("param2"));
        assert!(mapped.data.contains_key("param3"));
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_with_map_to_json_false() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(1);

        let request_payload = vec![
            sid, 0x12, 0x34, 0x40, 0x49, 0x0F, 0xDB, b'T', b'e', b's', b't',
        ];

        let payload = create_payload(request_payload.clone());

        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, false)
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();

        assert_eq!(response.get_raw(), request_payload);
        assert!(response.mapped_data.is_none());
        assert_eq!(response.response_type, DiagServiceResponseType::Positive);
    }

    #[tokio::test]
    async fn test_phys_const_normal_dop_from_uds() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let response_data: Vec<u8> = vec![sid, 0xF1, 0x90, 0x42];
        let payload = create_payload(response_data.clone());

        let result = ecu_manager
            .convert_from_uds(&dc, &payload, true, None)
            .await;

        assert!(result.is_ok());
        let mapped = result.unwrap();
        assert_eq!(mapped.get_raw(), response_data);
        assert!(mapped.mapped_data.is_some());

        let mapped_data = mapped.mapped_data.unwrap();
        assert!(mapped_data.data.contains_key("DID"));
        assert!(mapped_data.data.contains_key("data_param"));
    }

    #[tokio::test]
    async fn test_phys_const_structure_dop_from_uds() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_structure_dop_service();

        let response_data: Vec<u8> = vec![sid, 0xF1, 0x90, 0x00, 0x0A, 0xFF];
        let payload = create_payload(response_data.clone());

        let result = ecu_manager
            .convert_from_uds(&dc, &payload, true, None)
            .await;

        assert!(result.is_ok());
        let mapped = result.unwrap();
        assert_eq!(mapped.get_raw(), response_data);
        assert!(mapped.mapped_data.is_some());

        let mapped_data = mapped.mapped_data.unwrap();
        assert!(mapped_data.data.contains_key("DID"));
        assert!(mapped_data.data.contains_key("sub_param1"));
        assert!(mapped_data.data.contains_key("sub_param2"));
    }

    #[tokio::test]
    async fn test_length_key_param_decode_zero_length() {
        let sid = cda_interfaces::service_ids::WRITE_DATA_BY_IDENTIFIER;
        let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_param_length_info_service();

        assert_uds_converts_to_json(
            &ecu_manager,
            &dc,
            vec![pos_sid, 0x00],
            json!({"pos_sid": u32::from(pos_sid), "len_key": 0, "var_data": ""}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_length_key_param_decode_nonzero_length() {
        let sid = cda_interfaces::service_ids::WRITE_DATA_BY_IDENTIFIER;
        let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_param_length_info_service();

        assert_uds_converts_to_json(
            &ecu_manager,
            &dc,
            vec![pos_sid, 0x18, 0xAA, 0xBB, 0xCC],
            json!({"pos_sid": u32::from(pos_sid), "len_key": 24, "var_data": "0xAA 0xBB 0xCC"}),
        )
        .await;
    }

    /// A positioned LENGTH-KEY declared after the field referencing it
    /// (ISO 22901-1 §7.3.5.4) is decoded first.
    #[tokio::test]
    async fn test_length_key_declared_after_referencing_param() {
        let sid = cda_interfaces::service_ids::WRITE_DATA_BY_IDENTIFIER;
        let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);
        let (ecu_manager, dc, _sid) =
            create_ecu_manager_with_param_length_info_service_ordered(false);

        assert_uds_converts_to_json(
            &ecu_manager,
            &dc,
            vec![pos_sid, 0x10, 0xAA, 0xBB],
            json!({"pos_sid": u32::from(pos_sid), "len_key": 16, "var_data": "0xAA 0xBB"}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_request_length_key_declared_after_referencing_param() {
        let (ecu_manager, dc, sid) =
            create_ecu_manager_with_param_length_info_service_ordered(false);
        let response = ecu_manager
            .convert_request_from_uds(&dc, &create_payload(vec![sid, 0x10, 0xAA, 0xBB]), true)
            .await
            .expect("request with forward-referenced length key must decode");
        let mapped = response.mapped_data.expect("mapped data");
        assert_eq!(
            mapped.errors,
            [] as [cda_interfaces::diagservices::FieldParseError; 0]
        );
        assert!(mapped.data.contains_key("var_data"));
        assert!(mapped.data.contains_key("len_key"));
    }

    /// A positioned TABLE-KEY declared after the TABLE-STRUCT referencing it
    /// (ISO 22901-1:2008 §7.3.5.4) is decoded first; declaration order does
    /// not change the result.
    #[tokio::test]
    async fn test_table_key_declared_after_table_struct() {
        for key_first in [true, false] {
            let (ecu_manager, dc, sid) = create_ecu_manager_with_table_struct_service(key_first);
            let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);
            assert_uds_converts_to_json(
                &ecu_manager,
                &dc,
                vec![pos_sid, 0x2A, 0x05],
                json!({
                    "pos_sid": u32::from(pos_sid),
                    "table_key": 5,
                    "table_struct": {"row_a": {"val": 0x2A}},
                }),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_and_check_structure() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(3);

        let request_payload = vec![
            sid, 0xF1, 0x00, 0x12, 0x34, 0x40, 0x49, 0x0F, 0xDB, 0x40, 0x49, 0x0F, 0xDB,
        ];

        let payload = create_payload(request_payload.clone());

        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, true)
            .await;

        assert!(result.is_ok());
        let response = result.expect("Expected successful conversion from UDS");

        assert_eq!(response.response_type, DiagServiceResponseType::Positive);
        assert_eq!(response.get_raw(), request_payload);
        assert!(response.mapped_data.is_some());

        let mapped = response.mapped_data.unwrap();
        assert_eq!(mapped.errors.len(), 0);
        assert!(mapped.data.contains_key(SID_PARM_NAME));

        let param1_bytes = request_payload.get(3..5).expect("param1 bytes missing");
        let param1_val = match mapped.data.get("param1") {
            Some(crate::diag_kernel::diagservices::DiagDataTypeContainer::RawContainer(raw)) => {
                raw.data.clone()
            }
            _ => panic!("param1 is not RawContainer"),
        };
        assert_eq!(param1_bytes, &param1_val[..]);

        let param2_bytes = request_payload.get(5..9).expect("param2 bytes missing");
        let param2_val = match mapped.data.get("param2") {
            Some(crate::diag_kernel::diagservices::DiagDataTypeContainer::RawContainer(raw)) => {
                raw.data.clone()
            }
            _ => panic!("param2 is not RawContainer"),
        };
        assert_eq!(param2_bytes, &param2_val[..]);
    }

    #[tokio::test]
    async fn test_map_static_field_from_uds() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_static_field_service();

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            json!({
                "test_service_pos_sid": sid,
                "items": [
                    { "item_val": 0x1122u32 },
                    { "item_val": 0x3344u32 },
                    { "item_val": 0x5566u32 },
                ]
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_static_field_from_uds_not_enough_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_static_field_service();

        let error =
            assert_uds_conversion_fails(&ecu_manager, &service, vec![sid, 0x11, 0x22, 0x33, 0x44])
                .await;
        assert!(
            matches!(error, DiagServiceError::BadPayload(_)),
            "Expected BadPayload, got: {error:?}"
        );
    }

    #[tokio::test]
    async fn test_env_data_desc_specific_match() {
        let (ecu_manager, service, sid, specific_dtc, _other_dtc) =
            create_ecu_manager_with_env_data_desc_wildcard();

        let mut payload = vec![sid];
        payload.extend_from_slice(&specific_dtc.to_be_bytes());
        payload.push(0x28);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": specific_dtc,
                    "display_code": "P0001",
                    "fault_name": "SpecificFault",
                    "severity": 1,
                },
                "temperature": 0x28u32,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_env_data_desc_wildcard_fallback() {
        let (ecu_manager, service, sid, _specific_dtc, other_dtc) =
            create_ecu_manager_with_env_data_desc_wildcard();

        let mut payload = vec![sid];
        payload.extend_from_slice(&other_dtc.to_be_bytes());
        payload.push(0x55);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": other_dtc,
                    "display_code": "P0002",
                    "fault_name": "OtherFault",
                    "severity": 2,
                },
                "humidity": 0x55u32,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_env_data_desc_no_match_no_wildcard_returns_empty() {
        let (ecu_manager, service, sid, dtc_in_db) = create_ecu_manager_env_data_no_wildcard();

        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_in_db.to_be_bytes());
        payload.push(0x42);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": dtc_in_db,
                    "display_code": "P9999",
                    "fault_name": "SomeFault",
                    "severity": 1,
                },
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_dlf_no_byte_pos_with_sibling_param() {
        let (ecu_manager, service, sid) = create_ecu_manager_dlf_sibling_no_byte_pos();

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0xAB, 0x02, 0x11, 0x22, 0x33, 0x44],
            json!({
                "test_service_pos_sid": sid,
                "sibling_val": 0xABu32,
                "dlf_items": [
                    { "item_val": 0x1122u32 },
                    { "item_val": 0x3344u32 },
                ],
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_dlf_no_byte_pos_with_sibling_zero_items() {
        let (ecu_manager, service, sid) = create_ecu_manager_dlf_sibling_no_byte_pos();

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0xAB, 0x00],
            json!({
                "test_service_pos_sid": sid,
                "sibling_val": 0xABu32,
                "dlf_items": [],
            }),
        )
        .await;
    }
}
