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

//! Database lookups for the UDS service Authentication (SID 0x29).

use cda_database::datatypes;
use cda_interfaces::{DiagServiceError, authentication::AuthenticationSubFunction, service_ids};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

/// Byte position of the first parameter following the response SID and sub-function.
const FIRST_DATA_BYTE: u32 = 2;

impl<S: SecurityPlugin> EcuManager<S> {
    /// Finds the SID 0x29 service whose request contains `sub_function` as coded
    /// constant. The short name is not evaluated.
    pub(in crate::diag_kernel) fn find_authentication_service(
        &self,
        sub_function: AuthenticationSubFunction,
    ) -> Result<datatypes::DiagService<'_>, DiagServiceError> {
        self.lookup_services_by_sid(service_ids::AUTHENTICATION)?
            .into_iter()
            .find(|service| {
                service
                    .request_sub_function_id()
                    .is_some_and(|(id, _)| id == u32::from(sub_function.id()))
            })
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "No Authentication service for sub-function '{sub_function}' found"
                ))
            })
    }

    /// See [`cda_interfaces::EcuSecurity::authentication_return_value`].
    pub(in crate::diag_kernel) fn decode_authentication_return_value(
        &self,
        sub_function: AuthenticationSubFunction,
        raw_response: &[u8],
    ) -> Result<Option<u64>, DiagServiceError> {
        let service = self.find_authentication_service(sub_function)?;

        let Some((param, byte_pos, offset)) = service
            .pos_responses()
            .into_iter()
            .flatten()
            .filter_map(|r| r.params())
            .filter_map(|params| {
                let params: Vec<_> = params.iter().map(datatypes::Parameter).collect();
                // The raw response starts at the first DATA parameter, see
                // `raw_payload_offset`.
                let offset = self.raw_payload_offset(&params);
                effective_byte_positions(&params)
                    .into_iter()
                    .filter_map(|(p, pos)| pos.map(|pos| (p, pos)))
                    .filter(|(p, pos)| {
                        *pos >= FIRST_DATA_BYTE
                            && *pos >= offset
                            && p.specific_data_as_value().is_some()
                    })
                    .min_by_key(|(_, pos)| *pos)
                    .map(|(p, pos)| (p, pos, offset))
            })
            .min_by_key(|(_, pos, _)| *pos)
        else {
            return Ok(None);
        };

        let dop = param
            .specific_data_as_value()
            .and_then(|v| v.dop())
            .and_then(|dop| dop.specific_data_as_normal_dop())
            .map(datatypes::NormalDop)
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "Authentication return parameter '{}' has no normal DOP",
                    param.short_name().unwrap_or_default()
                ))
            })?;
        let coded_type = dop.diag_coded_type()?;
        let (bytes, _) = coded_type.decode(
            raw_response,
            byte_pos.saturating_sub(offset) as usize,
            param.bit_position() as usize,
        )?;

        if bytes.len() > std::mem::size_of::<u64>() {
            return Err(DiagServiceError::InvalidDatabase(format!(
                "Authentication return parameter '{}' is longer than 8 bytes",
                param.short_name().unwrap_or_default()
            )));
        }
        // `decode` normalizes numeric types to most-significant byte first (it
        // reverses LOW-HIGH). Shift each byte in from the right to build the value.
        Ok(Some(
            bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)),
        ))
    }
}

/// Resolves the byte position of each param in database order. A param
/// without BYTE-POSITION follows its predecessor (ISO 22901-1 §7.4.8); its
/// position is only known if all preceding params up to the last positioned
/// one have a static length, otherwise it is `None`.
fn effective_byte_positions<'a>(
    params: &[datatypes::Parameter<'a>],
) -> Vec<(datatypes::Parameter<'a>, Option<u32>)> {
    let mut next = Some(0u32);
    params
        .iter()
        .map(|p| {
            let pos = if p.has_byte_position() {
                Some(p.byte_position())
            } else {
                next
            };
            next = pos.and_then(|pos| static_byte_length(p).and_then(|len| pos.checked_add(len)));
            (p.clone(), pos)
        })
        .collect()
}

/// Number of bytes a CODED-CONST or VALUE param with a standard length
/// occupies, `None` for variable or unsupported lengths.
fn static_byte_length(param: &datatypes::Parameter) -> Option<u32> {
    let coded_type: datatypes::DiagCodedType =
        if let Some(cc) = param.specific_data_as_coded_const() {
            cc.diag_coded_type()?.try_into().ok()?
        } else {
            param
                .specific_data_as_value()
                .and_then(|v| v.dop())
                .and_then(|dop| dop.specific_data_as_normal_dop())
                .map(datatypes::NormalDop)?
                .diag_coded_type()
                .ok()?
        };
    match coded_type.type_() {
        datatypes::DiagCodedTypeVariant::StandardLength(slt) => Some(
            param
                .bit_position()
                .checked_add(slt.bit_length)?
                .div_ceil(8),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{self, DataType, ResponseType, database_builder::EcuDataBuilder};
    use cda_interfaces::{
        DiagServiceError, EcuSecurity, PayloadDecoder, PayloadEncoder, Protocol, ServicePayload,
        authentication::AuthenticationSubFunction, diagservices::DiagServiceResponse, service_ids,
    };
    use cda_plugin_security::DefaultSecurityPluginData;

    use crate::diag_kernel::{
        ecumanager::EcuManager,
        test_utils::{
            db_builder::finish_db,
            ecu_manager_builder::new_ecu_manager,
            mdd_type_builder::{create_sid_param, new_diag_comm, new_diag_service},
        },
    };

    const VERIFY_NAME: &str = "Authentication_VerifyPOWN_Bidirectional";
    const DEAUTH_NAME: &str = "Authentication_DeAuthenticate";
    const POWN_NAME: &str = "Authentication_ProofOfOwnership";
    const CONFIG_NAME: &str = "Authentication_Config";

    /// Builds an ECU with Authentication services whose short names do not
    /// follow any convention:
    /// * sub-function 0x07, positive response `69 07 <returnParameter> <proofOfOwnershipServer>`
    /// * sub-function 0x00, positive response `69 00` without return parameter
    /// * sub-function 0x03, positive response `69 03 <returnParameter> <sessionKeyInfo>`
    ///   with DATA semantic, so the raw response starts at the return parameter
    /// * sub-function 0x08, positive response `69 08 <returnParameter>`, the
    ///   return parameter has no BYTE-POSITION
    fn ecu_manager() -> EcuManager<DefaultSecurityPluginData> {
        let default_protocol = Protocol::default();
        let mut b = EcuDataBuilder::new();
        let protocol = b.create_protocol(default_protocol.str(), None, None, None);
        let sid = service_ids::AUTHENTICATION;
        let pos_sid = sid | cda_interfaces::UDS_ID_RESPONSE_BITMASK;

        let u8_type = b.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_type = b.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let compu = b.create_compu_method(datatypes::CompuCategory::Identical, None, None);
        let compu2 = b.create_compu_method(datatypes::CompuCategory::Identical, None, None);
        let return_dop = b.create_regular_normal_dop("return_dop", u8_type, compu);
        let proof_dop = b.create_regular_normal_dop("proof_dop", u16_type, compu2);

        let mut services = Vec::new();
        for (name, sub_function, with_return) in [
            (VERIFY_NAME, 7u8, true),
            (DEAUTH_NAME, 0, false),
            (POWN_NAME, 3, true),
            (CONFIG_NAME, 8, true),
        ] {
            let req_sid = create_sid_param!(b, "sid", sid);
            let req_sf = b.create_coded_const_param(
                "sub_function",
                &sub_function.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let request = b.create_request(Some(vec![req_sid, req_sf]), None);

            let resp_sid = create_sid_param!(b, "sid_pr", pos_sid);
            let resp_sf = b.create_coded_const_param(
                "sub_function_pr",
                &sub_function.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let mut params = vec![resp_sid, resp_sf];
            if sub_function == 3 {
                // Default semantic of `DatabaseNamingConvention`
                let data = "DATA";
                params.push(b.create_value_param_with_semantic(
                    "authenticationReturnParameter",
                    data,
                    return_dop,
                    2,
                ));
                params.push(b.create_value_param_with_semantic(
                    "sessionKeyInfo",
                    data,
                    proof_dop,
                    3,
                ));
            } else if sub_function == 8 {
                // Without BYTE-POSITION, follows the sub-function at byte 2.
                params.push(
                    b.create_value_param_no_byte_pos("authenticationReturnParameter", return_dop),
                );
            } else if with_return {
                // Declared out of order to verify the lowest byte position is used.
                params.push(b.create_value_param("proofOfOwnershipServer", proof_dop, 3, 0));
                params.push(b.create_value_param(
                    "authenticationReturnParameter",
                    return_dop,
                    2,
                    0,
                ));
            }
            let response = b.create_response(ResponseType::Positive, Some(params), None);
            let diag_comm = new_diag_comm!(b, name, protocol);
            services.push(new_diag_service!(
                b,
                diag_comm,
                request,
                vec![response],
                vec![]
            ));
        }
        new_ecu_manager(finish_db!(b, protocol, services))
    }

    #[test]
    fn lookup_by_subfunction_ignores_name() {
        let ecu = ecu_manager();
        let dc = ecu
            .lookup_authentication_service(
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
            )
            .unwrap();
        assert_eq!(dc.lookup_name.as_deref(), Some(VERIFY_NAME));

        let dc = ecu
            .lookup_authentication_service(AuthenticationSubFunction::DeAuthenticate)
            .unwrap();
        assert_eq!(dc.lookup_name.as_deref(), Some(DEAUTH_NAME));
    }

    #[tokio::test]
    async fn looked_up_service_can_be_encoded() {
        let ecu = ecu_manager();
        let dc = ecu
            .lookup_authentication_service(AuthenticationSubFunction::DeAuthenticate)
            .unwrap();
        let plugin: cda_interfaces::DynamicPlugin = Box::new(());
        let payload = ecu
            .create_uds_payload(&dc, &plugin, None, None)
            .await
            .unwrap();
        assert_eq!(payload.data, vec![service_ids::AUTHENTICATION, 0x00]);
    }

    #[test]
    fn lookup_missing_subfunction_is_not_found() {
        let ecu = ecu_manager();
        assert!(matches!(
            ecu.lookup_authentication_service(AuthenticationSubFunction::TransmitCertificate),
            Err(DiagServiceError::NotFound(_))
        ));
    }

    #[test]
    fn return_value_is_read_from_description() {
        let ecu = ecu_manager();
        let value = ecu
            .authentication_return_value(
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                &[0x69, 0x07, 0x12, 0xAB, 0xCD],
            )
            .unwrap();
        assert_eq!(value, Some(0x12));
    }

    #[test]
    fn return_value_without_byte_position_follows_predecessor() {
        let ecu = ecu_manager();
        let value = ecu
            .authentication_return_value(
                AuthenticationSubFunction::AuthenticationConfiguration,
                &[0x69, 0x08, 0x12],
            )
            .unwrap();
        assert_eq!(value, Some(0x12));
    }

    #[test]
    fn return_value_missing_in_description_is_none() {
        let ecu = ecu_manager();
        let value = ecu
            .authentication_return_value(AuthenticationSubFunction::DeAuthenticate, &[0x69, 0x00])
            .unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn return_value_with_short_payload_is_error() {
        let ecu = ecu_manager();
        assert!(
            ecu.authentication_return_value(
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                &[0x69, 0x07],
            )
            .is_err()
        );
    }

    /// The raw response returned by the decoder starts at the first DATA
    /// parameter, the return parameter must be read relative to it.
    #[tokio::test]
    async fn return_value_is_read_from_decoded_raw_response() {
        let ecu = ecu_manager();
        let dc = ecu
            .lookup_authentication_service(AuthenticationSubFunction::ProofOfOwnership)
            .unwrap();
        let response = ecu
            .convert_from_uds(
                &dc,
                &ServicePayload {
                    data: vec![0x69, 0x03, 0x12, 0x00, 0x10],
                    source_address: 0,
                    target_address: 0,
                    new_session: None,
                    new_security: None,
                },
                true,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.get_raw(), &[0x12, 0x00, 0x10]);
        let value = ecu
            .authentication_return_value(
                AuthenticationSubFunction::ProofOfOwnership,
                response.get_raw(),
            )
            .unwrap();
        assert_eq!(value, Some(0x12));
    }
}
