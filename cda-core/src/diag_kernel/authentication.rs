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
const FIRST_DATA_BYTE: usize = 2;

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
        response_payload: &[u8],
    ) -> Result<Option<u64>, DiagServiceError> {
        let service = self.find_authentication_service(sub_function)?;

        // Positions are taken from the payload, so a parameter without
        // BYTE-POSITION behind a variable-length one is found as well.
        let mut found: Option<(datatypes::Parameter<'_>, usize)> = None;
        for params in service
            .pos_responses()
            .into_iter()
            .flatten()
            .filter_map(|r| r.params())
        {
            let params: Vec<_> = params.iter().map(datatypes::Parameter).collect();
            let positions = self.response_param_positions(&service, &params, response_payload)?;
            let candidate = params
                .into_iter()
                .zip(positions)
                .filter_map(|(p, pos)| pos.map(|pos| (p, pos)))
                .filter(|(p, pos)| *pos >= FIRST_DATA_BYTE && p.specific_data_as_value().is_some())
                .min_by_key(|(_, pos)| *pos);
            if let Some(candidate) = candidate
                && found.as_ref().is_none_or(|(_, pos)| candidate.1 < *pos)
            {
                found = Some(candidate);
            }
        }
        let Some((param, position)) = found else {
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
        let (bytes, _) =
            coded_type.decode(response_payload, position, param.bit_position() as usize)?;

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

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        self, DataType, DiagCodedTypeVariant, ResponseType,
        database_builder::{DataFormatDop, DataFormatParam, EcuDataBuilder},
    };
    use cda_interfaces::{
        DiagServiceError, EcuSecurity, PayloadDecoder, PayloadEncoder, Protocol, ServicePayload,
        authentication::AuthenticationSubFunction, diagservices::DiagServiceResponse, service_ids,
    };
    use cda_plugin_security::DefaultSecurityPluginData;
    use flatbuffers::WIPOffset;

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

    /// Response `69 07 ..`, built by `build` behind SID and sub-function.
    fn ecu_with_response(
        build: impl for<'a> FnOnce(
            &mut EcuDataBuilder<'a>,
            WIPOffset<DataFormatDop<'a>>,
            WIPOffset<DataFormatDop<'a>>,
        ) -> Vec<WIPOffset<DataFormatParam<'a>>>,
    ) -> EcuManager<DefaultSecurityPluginData> {
        let default_protocol = Protocol::default();
        let mut b = EcuDataBuilder::new();
        let protocol = b.create_protocol(default_protocol.str(), None, None, None);
        let sid = service_ids::AUTHENTICATION;
        let compu = b.create_compu_method(datatypes::CompuCategory::Identical, None, None);
        let u8_type = b.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let byte_dop = b.create_regular_normal_dop("byte", u8_type, compu);
        let variable_type = b.create_diag_coded_type(
            None,
            DataType::ByteField,
            true,
            DiagCodedTypeVariant::LeadingLengthInfo(8),
        );
        let variable_dop = b.create_regular_normal_dop("variable", variable_type, compu);
        let request_sid = create_sid_param!(b, "sid", sid);
        let sub_function =
            b.create_coded_const_param("sub_function", "7", 1, 0, 8, DataType::UInt32);
        let request = b.create_request(Some(vec![request_sid, sub_function]), None);
        let response_sid =
            create_sid_param!(b, "sid_pr", sid | cda_interfaces::UDS_ID_RESPONSE_BITMASK);
        let sub_function =
            b.create_coded_const_param("sub_function_pr", "7", 1, 0, 8, DataType::UInt32);
        let mut params = vec![response_sid, sub_function];
        params.extend(build(&mut b, byte_dop, variable_dop));
        let response = b.create_response(ResponseType::Positive, Some(params), None);
        let diag_comm = new_diag_comm!(b, VERIFY_NAME, protocol);
        let service = new_diag_service!(b, diag_comm, request, vec![response], vec![]);
        new_ecu_manager(finish_db!(b, protocol, vec![service]))
    }

    async fn return_value_of_decoded_response(
        ecu: &EcuManager<DefaultSecurityPluginData>,
        sub_function: AuthenticationSubFunction,
        data: Vec<u8>,
    ) -> Option<u64> {
        let dc = ecu.lookup_authentication_service(sub_function).unwrap();
        let payload = ServicePayload {
            data: data.clone(),
            source_address: 0,
            target_address: 0,
            new_session: None,
            new_security: None,
        };
        let response = ecu
            .convert_from_uds(&dc, &payload, true, None)
            .await
            .unwrap();
        assert_eq!(response.get_payload(), data);
        ecu.authentication_return_value(sub_function, response.get_payload())
            .unwrap()
    }

    #[tokio::test]
    async fn return_value_preceding_runtime_data_offset_is_read() {
        let ecu = ecu_with_response(|b, byte_dop, variable_dop| {
            vec![
                b.create_value_param("authenticationReturnParameter", byte_dop, 2, 0),
                b.create_value_param("variable", variable_dop, 3, 0),
                b.create_value_param_no_byte_pos_with_semantic("info", byte_dop, Some("DATA")),
            ]
        });
        let value = return_value_of_decoded_response(
            &ecu,
            AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
            vec![0x69, 0x07, 0x12, 0x01, 0xAA, 0xCC],
        )
        .await;
        assert_eq!(value, Some(0x12));
    }

    /// The return parameter has no BYTE-POSITION and follows a terminated
    /// constant, so its position is only known from the payload.
    #[tokio::test]
    async fn return_value_after_variable_length_param_is_read() {
        let ecu = ecu_with_response(|b, byte_dop, _| {
            let compu = b.create_compu_method(datatypes::CompuCategory::Identical, None, None);
            let terminated_type = b.create_diag_coded_type(
                None,
                DataType::AsciiString,
                true,
                DiagCodedTypeVariant::MinMaxLength(datatypes::MinMaxLengthType {
                    min_length: 0,
                    max_length: Some(8),
                    termination: datatypes::Termination::Zero,
                }),
            );
            let terminated_dop = b.create_regular_normal_dop("terminated", terminated_type, compu);
            vec![
                b.create_phys_const_param("constant", Some("AB"), terminated_dop, 2, 0),
                b.create_value_param_no_byte_pos("authenticationReturnParameter", byte_dop),
            ]
        });
        for (payload, expected) in [
            (vec![0x69, 0x07, 0x41, 0x42, 0x00, 0x12], 0x12),
            (vec![0x69, 0x07, 0x00, 0x34], 0x34),
        ] {
            let value = return_value_of_decoded_response(
                &ecu,
                AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional,
                payload,
            )
            .await;
            assert_eq!(value, Some(expected));
        }
    }

    #[tokio::test]
    async fn return_value_is_read_from_decoded_response() {
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
                response.get_payload(),
            )
            .unwrap();
        assert_eq!(value, Some(0x12));
    }
}
