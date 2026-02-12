/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

// The public re-exports are necessary for these types because they are used
// within a WipOffset<T> where we cannot provide a conversion for.
// This is only the case for types where we have to be able to name the type, i.e.
// for function parameters and return types.
pub use dataformat::{DefaultCase, SwitchKey};
use flatbuffers::UnionWIPOffset;
pub use flatbuffers::WIPOffset;

use crate::{
    dataformat_wrapper,
    datatypes::{
        CompuCategory, DataType, DiagCodedTypeVariant, IntervalType, Limit, ResponseType,
        Termination,
    },
    flatbuf::diagnostic_description::{
        dataformat,
        dataformat::{CompuInternalToPhys, CompuPhysToInternal},
    },
};

dataformat_wrapper!(DopType, dataformat::DOPType);
dataformat_wrapper!(SpecificDOPData, dataformat::SpecificDOPData);
dataformat_wrapper!(DiagClassType, dataformat::DiagClassType);
dataformat_wrapper!(Addressing, dataformat::Addressing);
dataformat_wrapper!(TransmissionMode, dataformat::TransmissionMode);

#[derive(Default)]
pub struct DiagLayerParams<'a> {
    pub short_name: &'a str,
    pub long_name: Option<&'a str>,
    pub funct_classes: Option<Vec<WIPOffset<dataformat::FunctClass<'a>>>>,
    pub com_param_refs: Option<Vec<WIPOffset<dataformat::ComParamRef<'a>>>>,
    pub diag_services: Option<Vec<WIPOffset<dataformat::DiagService<'a>>>>,
    pub single_ecu_jobs: Option<Vec<WIPOffset<dataformat::SingleEcuJob<'a>>>>,
    pub state_charts: Option<Vec<WIPOffset<dataformat::StateChart<'a>>>>,
    pub additional_audiences: Option<Vec<WIPOffset<dataformat::AdditionalAudience<'a>>>>,
    pub sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
}

#[derive(Default)]
pub struct DiagServiceParams<'a> {
    pub diag_comm: Option<WIPOffset<dataformat::DiagComm<'a>>>,
    pub request: Option<WIPOffset<dataformat::Request<'a>>>,
    pub pos_responses: Vec<WIPOffset<dataformat::Response<'a>>>,
    pub neg_responses: Vec<WIPOffset<dataformat::Response<'a>>>,
    pub is_cyclic: bool,
    pub is_multiple: bool,
    pub addressing: dataformat::Addressing,
    pub transmission_mode: dataformat::TransmissionMode,
    pub com_param_refs: Option<Vec<WIPOffset<dataformat::ComParamRef<'a>>>>,
}

pub struct DiagCommParams<'a> {
    pub short_name: &'a str,
    pub long_name: Option<&'a str>,
    pub semantic: Option<&'a str>,
    pub funct_class: Option<Vec<WIPOffset<dataformat::FunctClass<'a>>>>,
    pub sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
    pub diag_class_type: DiagClassType,
    pub pre_condition_state_refs: Option<Vec<WIPOffset<dataformat::PreConditionStateRef<'a>>>>,
    pub state_transition_refs: Option<Vec<WIPOffset<dataformat::StateTransitionRef<'a>>>>,
    pub protocols: Option<Vec<WIPOffset<dataformat::Protocol<'a>>>>,
    pub audience: Option<WIPOffset<dataformat::Audience<'a>>>,
    pub is_mandatory: bool,
    pub is_executable: bool,
    pub is_final: bool,
}

impl Default for DiagCommParams<'_> {
    fn default() -> Self {
        Self {
            short_name: "",
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: None,
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        }
    }
}

#[derive(Default)]
pub struct EcuDataParams<'a> {
    pub ecu_name: &'a str,
    pub revision: &'a str,
    pub version: &'a str,
    pub variants: Option<Vec<WIPOffset<dataformat::Variant<'a>>>>,
    pub metadata: Option<Vec<WIPOffset<dataformat::KeyValue<'a>>>>,
    pub feature_flags: Option<Vec<dataformat::FeatureFlag>>,
    pub functional_groups: Option<Vec<WIPOffset<dataformat::FunctionalGroup<'a>>>>,
    pub dtcs: Option<Vec<WIPOffset<dataformat::DTC<'a>>>>,
}

#[derive(Default)]
pub struct ParameterParams<'a> {
    pub param_type: dataformat::ParamType,
    pub short_name: Option<&'a str>,
    pub semantic: Option<&'a str>,
    pub sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
    pub physical_default_value: Option<&'a str>,
    pub byte_position: Option<u32>,
    pub bit_position: Option<u32>,
    pub specific_data_type: dataformat::ParamSpecificData,
    pub specific_data: Option<WIPOffset<dataformat::ParamSpecificDataUnionValue>>,
}

impl DopType {
    pub const REGULAR: Self = Self(dataformat::DOPType::REGULAR);
    pub const ENV_DATA_DESC: Self = Self(dataformat::DOPType::ENV_DATA_DESC);
    pub const MUX: Self = Self(dataformat::DOPType::MUX);
    pub const DYNAMIC_END_MARKER_FIELD: Self = Self(dataformat::DOPType::DYNAMIC_END_MARKER_FIELD);
    pub const DYNAMIC_LENGTH_FIELD: Self = Self(dataformat::DOPType::DYNAMIC_LENGTH_FIELD);
    pub const END_OF_PDU_FIELD: Self = Self(dataformat::DOPType::END_OF_PDU_FIELD);
    pub const STATIC_FIELD: Self = Self(dataformat::DOPType::STATIC_FIELD);
    pub const ENV_DATA: Self = Self(dataformat::DOPType::ENV_DATA);
    pub const STRUCTURE: Self = Self(dataformat::DOPType::STRUCTURE);
    pub const DTC: Self = Self(dataformat::DOPType::DTC);
}

#[allow(non_upper_case_globals)] // to comply with flatbuffers enum naming
impl SpecificDOPData {
    pub const NormalDOP: Self = Self(dataformat::SpecificDOPData::NormalDOP);
    pub const EndOfPduField: Self = Self(dataformat::SpecificDOPData::EndOfPduField);
    pub const StaticField: Self = Self(dataformat::SpecificDOPData::StaticField);
    pub const EnvDataDesc: Self = Self(dataformat::SpecificDOPData::EnvDataDesc);
    pub const EnvData: Self = Self(dataformat::SpecificDOPData::EnvData);
    pub const DTCDOP: Self = Self(dataformat::SpecificDOPData::DTCDOP);
    pub const Structure: Self = Self(dataformat::SpecificDOPData::Structure);
    pub const MUXDOP: Self = Self(dataformat::SpecificDOPData::MUXDOP);
    pub const DynamicLengthField: Self = Self(dataformat::SpecificDOPData::DynamicLengthField);
}

impl DiagClassType {
    pub const START_COMM: Self = Self(dataformat::DiagClassType::START_COMM);
    pub const STOP_COMM: Self = Self(dataformat::DiagClassType::STOP_COMM);
    pub const VARIANT_IDENTIFICATION: Self =
        Self(dataformat::DiagClassType::VARIANT_IDENTIFICATION);
    pub const READ_DYN_DEF_MESSAGE: Self = Self(dataformat::DiagClassType::READ_DYN_DEF_MESSAGE);
    pub const DYN_DEF_MESSAGE: Self = Self(dataformat::DiagClassType::DYN_DEF_MESSAGE);
    pub const CLEAR_DYN_DEF_MESSAGE: Self = Self(dataformat::DiagClassType::CLEAR_DYN_DEF_MESSAGE);
}

impl Addressing {
    pub const FUNCTIONAL: Self = Self(dataformat::Addressing::FUNCTIONAL);
    pub const PHYSICAL: Self = Self(dataformat::Addressing::PHYSICAL);
    pub const FUNCTIONAL_OR_PHYSICAL: Self = Self(dataformat::Addressing::FUNCTIONAL_OR_PHYSICAL);
}

impl TransmissionMode {
    pub const SEND_ONLY: Self = Self(dataformat::TransmissionMode::SEND_ONLY);
    pub const RECEIVE_ONLY: Self = Self(dataformat::TransmissionMode::RECEIVE_ONLY);
    pub const SEND_AND_RECEIVE: Self = Self(dataformat::TransmissionMode::SEND_AND_RECEIVE);
    pub const SEND_OR_RECEIVE: Self = Self(dataformat::TransmissionMode::SEND_OR_RECEIVE);
}

pub struct EcuDataBuilder<'a> {
    fbb: flatbuffers::FlatBufferBuilder<'a>,
    max_param_id: u32,
}

impl Default for EcuDataBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EcuDataBuilder<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fbb: flatbuffers::FlatBufferBuilder::new(),
            max_param_id: 0,
        }
    }

    fn create_long_name(
        &mut self,
        name: Option<&str>,
    ) -> Option<WIPOffset<dataformat::LongName<'a>>> {
        name.map(|name| {
            let name_offset = self.fbb.create_string(name);
            let args = dataformat::LongNameArgs {
                value: Some(name_offset),
                ti: None,
            };
            dataformat::LongName::create(&mut self.fbb, &args)
        })
    }

    /// Serialize the given [`EcuDataParams`] into a flatbuffer, wrap the result
    /// in a [`DiagnosticDatabase`] and return it.  Consumes the builder.
    ///
    /// [`DiagnosticDatabase`]: super::DiagnosticDatabase
    ///
    /// # Panics
    /// Panics if the database cannot be created from the built ECU data.
    ///
    /// Using panic here, because the database builder is not intended for production use
    /// and only is a helper to build databases for tests.
    #[must_use]
    pub fn finish(mut self, params: EcuDataParams<'a>) -> super::DiagnosticDatabase {
        let ecu_name_offset = self.fbb.create_string(params.ecu_name);
        let revision_offset = self.fbb.create_string(params.revision);
        let version_offset = self.fbb.create_string(params.version);

        let ecu_data_args = dataformat::EcuDataArgs {
            ecu_name: Some(ecu_name_offset),
            revision: Some(revision_offset),
            version: Some(version_offset),
            variants: params.variants.map(|v| self.fbb.create_vector(&v)),
            metadata: params.metadata.map(|v| self.fbb.create_vector(&v)),
            feature_flags: params
                .feature_flags
                .as_ref()
                .map(|flags| self.fbb.create_vector(flags)),
            functional_groups: params.functional_groups.map(|v| self.fbb.create_vector(&v)),
            dtcs: params.dtcs.map(|v| self.fbb.create_vector(&v)),
        };

        let ecu_data = dataformat::EcuData::create(&mut self.fbb, &ecu_data_args);
        self.fbb.finish(ecu_data, None);
        let blob = self.fbb.finished_data().to_vec();

        super::DiagnosticDatabase::new(
            String::default(),
            blob,
            cda_interfaces::datatypes::FlatbBufConfig::default(),
        )
        .expect("Failed to create DiagnosticDatabase from built ECU data")
    }

    /// Finishes the builder into a [`DiagnosticDatabase`]
    /// containing a single base variant with one `DiagLayer`.
    ///
    /// Creates all intermediate objects (com-param ref, diag layer, variant, ecu data)
    /// and returns a ready-to-use database.
    ///
    /// # Panics
    /// Panics if the database cannot be created from the built ECU data.
    ///
    /// [`DiagnosticDatabase`]: super::DiagnosticDatabase
    ///
    /// Using panic here, because the database builder is not intended for production use
    /// and only is a helper to build databases for tests.
    #[must_use]
    pub fn finish_with_single_variant(
        mut self,
        protocol: WIPOffset<dataformat::Protocol<'a>>,
        diag_services: Vec<WIPOffset<dataformat::DiagService<'a>>>,
        layer_name: &'a str,
        ecu_name: &'a str,
        revision: &'a str,
        version: &'a str,
    ) -> super::DiagnosticDatabase {
        let cp_ref = self.create_com_param_ref(None, None, None, Some(protocol), None);
        let diag_layer = self.create_diag_layer(DiagLayerParams {
            short_name: layer_name,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(diag_services),
            ..Default::default()
        });
        let variant = self.create_variant(diag_layer, true, None, None);
        self.finish(EcuDataParams {
            ecu_name,
            revision,
            version,
            variants: Some(vec![variant]),
            ..Default::default()
        })
    }

    pub fn create_diag_layer(
        &mut self,
        params: DiagLayerParams<'a>,
    ) -> WIPOffset<dataformat::DiagLayer<'a>> {
        let short_name_offset = self.fbb.create_string(params.short_name);
        let long_name_offset = self.create_long_name(params.long_name);
        let diag_layer_args = dataformat::DiagLayerArgs {
            short_name: Some(short_name_offset),
            long_name: long_name_offset,
            funct_classes: params.funct_classes.map(|v| self.fbb.create_vector(&v)),
            com_param_refs: params.com_param_refs.map(|v| self.fbb.create_vector(&v)),
            diag_services: params.diag_services.map(|v| self.fbb.create_vector(&v)),
            single_ecu_jobs: params.single_ecu_jobs.map(|v| self.fbb.create_vector(&v)),
            state_charts: params.state_charts.map(|v| self.fbb.create_vector(&v)),
            additional_audiences: params
                .additional_audiences
                .map(|v| self.fbb.create_vector(&v)),
            sdgs: params.sdgs,
        };

        dataformat::DiagLayer::create(&mut self.fbb, &diag_layer_args)
    }

    pub fn create_variant(
        &mut self,
        diag_layer: WIPOffset<dataformat::DiagLayer<'a>>,
        is_base_variant: bool,
        variant_pattern: Option<Vec<WIPOffset<dataformat::VariantPattern<'a>>>>,
        parent_refs: Option<Vec<WIPOffset<dataformat::ParentRef<'a>>>>,
    ) -> WIPOffset<dataformat::Variant<'a>> {
        let variant_args = dataformat::VariantArgs {
            diag_layer: Some(diag_layer),
            is_base_variant,
            variant_pattern: variant_pattern.map(|v| self.fbb.create_vector(&v)),
            parent_refs: parent_refs.map(|v| self.fbb.create_vector(&v)),
        };

        dataformat::Variant::create(&mut self.fbb, &variant_args)
    }

    pub fn create_protocol(
        &mut self,
        short_name: &'a str,
        com_param_spec: Option<WIPOffset<dataformat::ComParamSpec<'a>>>,
        prot_stack: Option<WIPOffset<dataformat::ProtStack<'a>>>,
        parent_refs: Option<Vec<WIPOffset<dataformat::Protocol<'a>>>>,
    ) -> WIPOffset<dataformat::Protocol<'a>> {
        let diag_layer = self.create_diag_layer(DiagLayerParams {
            short_name,
            long_name: None,
            funct_classes: None,
            com_param_refs: None,
            diag_services: None,
            single_ecu_jobs: None,
            state_charts: None,
            additional_audiences: None,
            sdgs: None,
        });
        let protocol_args = dataformat::ProtocolArgs {
            diag_layer: Some(diag_layer),
            com_param_spec,
            prot_stack,
            parent_refs: parent_refs.map(|v| self.fbb.create_vector(&v)),
        };
        dataformat::Protocol::create(&mut self.fbb, &protocol_args)
    }

    pub fn create_diag_comm(
        &mut self,
        params: DiagCommParams<'a>,
    ) -> WIPOffset<dataformat::DiagComm<'a>> {
        let short_name_offset = self.fbb.create_string(params.short_name);
        let long_name_offset = self.create_long_name(params.long_name);
        let semantic_offset = params.semantic.map(|s| self.fbb.create_string(s));
        let funct_class = params.funct_class.map(|v| self.fbb.create_vector(&v));
        let pre_condition_state_refs = params
            .pre_condition_state_refs
            .map(|v| self.fbb.create_vector(&v));
        let state_transition_refs = params
            .state_transition_refs
            .map(|v| self.fbb.create_vector(&v));
        let protocols = params.protocols.map(|v| self.fbb.create_vector(&v));

        let diagcomm_args = dataformat::DiagCommArgs {
            short_name: Some(short_name_offset),
            long_name: long_name_offset,
            semantic: semantic_offset,
            funct_class,
            sdgs: params.sdgs,
            diag_class_type: *params.diag_class_type,
            pre_condition_state_refs,
            state_transition_refs,
            protocols,
            audience: params.audience,
            is_mandatory: params.is_mandatory,
            is_executable: params.is_executable,
            is_final: params.is_final,
        };

        dataformat::DiagComm::create(&mut self.fbb, &diagcomm_args)
    }

    pub fn create_diag_service(
        &mut self,
        params: DiagServiceParams<'a>,
    ) -> WIPOffset<dataformat::DiagService<'a>> {
        let pos_responses_vector = (!params.pos_responses.is_empty())
            .then(|| self.fbb.create_vector(&params.pos_responses));

        let neg_responses_vector = (!params.neg_responses.is_empty())
            .then(|| self.fbb.create_vector(&params.neg_responses));

        let diag_service_args = dataformat::DiagServiceArgs {
            diag_comm: params.diag_comm,
            request: params.request,
            pos_responses: pos_responses_vector,
            neg_responses: neg_responses_vector,
            is_cyclic: params.is_cyclic,
            is_multiple: params.is_multiple,
            addressing: params.addressing,
            transmission_mode: params.transmission_mode,
            com_param_refs: params.com_param_refs.map(|v| self.fbb.create_vector(&v)),
        };

        dataformat::DiagService::create(&mut self.fbb, &diag_service_args)
    }

    pub fn create_request(
        &mut self,
        params: Option<Vec<WIPOffset<dataformat::Param<'a>>>>,
        sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
    ) -> WIPOffset<dataformat::Request<'a>> {
        let request_args = dataformat::RequestArgs {
            params: params.map(|v| self.fbb.create_vector(&v)),
            sdgs,
        };

        dataformat::Request::create(&mut self.fbb, &request_args)
    }

    pub fn create_response(
        &mut self,
        response_type: ResponseType,
        params: Option<Vec<WIPOffset<dataformat::Param<'a>>>>,
        sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
    ) -> WIPOffset<dataformat::Response<'a>> {
        let response_type = match response_type {
            ResponseType::Positive => dataformat::ResponseType::POS_RESPONSE,
            ResponseType::Negative => dataformat::ResponseType::NEG_RESPONSE,
            ResponseType::GlobalNegative => dataformat::ResponseType::GLOBAL_NEG_RESPONSE,
        };

        let response_args = dataformat::ResponseArgs {
            response_type,
            params: params.map(|v| self.fbb.create_vector(&v)),
            sdgs,
        };

        dataformat::Response::create(&mut self.fbb, &response_args)
    }

    pub fn create_funct_class(
        &mut self,
        short_name: &str,
    ) -> WIPOffset<dataformat::FunctClass<'a>> {
        let short_name_offset = self.fbb.create_string(short_name);
        let funct_class_args = dataformat::FunctClassArgs {
            short_name: Some(short_name_offset),
        };
        dataformat::FunctClass::create(&mut self.fbb, &funct_class_args)
    }

    pub fn create_com_param_ref(
        &mut self,
        simple_value: Option<WIPOffset<dataformat::SimpleValue<'a>>>,
        complex_value: Option<WIPOffset<dataformat::ComplexValue<'a>>>,
        com_param: Option<WIPOffset<dataformat::ComParam<'a>>>,
        protocol: Option<WIPOffset<dataformat::Protocol<'a>>>,
        prot_stack: Option<WIPOffset<dataformat::ProtStack<'a>>>,
    ) -> WIPOffset<dataformat::ComParamRef<'a>> {
        let com_param_ref_args = dataformat::ComParamRefArgs {
            simple_value,
            complex_value,
            com_param,
            protocol,
            prot_stack,
        };

        dataformat::ComParamRef::create(&mut self.fbb, &com_param_ref_args)
    }

    pub fn create_single_ecu_job(
        &mut self,
        diag_comm: Option<WIPOffset<dataformat::DiagComm<'a>>>,
        prog_codes: Option<Vec<WIPOffset<dataformat::ProgCode<'a>>>>,
        input_params: Option<Vec<WIPOffset<dataformat::JobParam<'a>>>>,
        output_params: Option<Vec<WIPOffset<dataformat::JobParam<'a>>>>,
        neg_output_params: Option<Vec<WIPOffset<dataformat::JobParam<'a>>>>,
    ) -> WIPOffset<dataformat::SingleEcuJob<'a>> {
        let single_ecu_job_args = dataformat::SingleEcuJobArgs {
            diag_comm,
            prog_codes: prog_codes.map(|v| self.fbb.create_vector(&v)),
            input_params: input_params.map(|v| self.fbb.create_vector(&v)),
            output_params: output_params.map(|v| self.fbb.create_vector(&v)),
            neg_output_params: neg_output_params.map(|v| self.fbb.create_vector(&v)),
        };

        dataformat::SingleEcuJob::create(&mut self.fbb, &single_ecu_job_args)
    }

    pub fn create_state_chart(
        &mut self,
        short_name: &str,
        semantic: Option<&str>,
        state_transitions: Option<Vec<WIPOffset<dataformat::StateTransition<'a>>>>,
        start_state_short_name_ref: Option<&str>,
        states: Option<Vec<WIPOffset<dataformat::State<'a>>>>,
    ) -> WIPOffset<dataformat::StateChart<'a>> {
        let short_name_offset = self.fbb.create_string(short_name);
        let semantic_offset = semantic.map(|s| self.fbb.create_string(s));
        let start_state_short_name_ref_offset =
            start_state_short_name_ref.map(|s| self.fbb.create_string(s));
        let states = states.map(|v| self.fbb.create_vector(&v));

        let state_chart_args = dataformat::StateChartArgs {
            short_name: Some(short_name_offset),
            semantic: semantic_offset,
            state_transitions: state_transitions.map(|v| self.fbb.create_vector(&v)),
            start_state_short_name_ref: start_state_short_name_ref_offset,
            states,
        };

        dataformat::StateChart::create(&mut self.fbb, &state_chart_args)
    }

    pub fn create_state(
        &mut self,
        short_name: &str,
        long_name: Option<&str>,
    ) -> WIPOffset<dataformat::State<'a>> {
        let short_name_offset = self.fbb.create_string(short_name);
        let long_name_offset = self.create_long_name(long_name);

        let state_args = dataformat::StateArgs {
            short_name: Some(short_name_offset),
            long_name: long_name_offset,
        };

        dataformat::State::create(&mut self.fbb, &state_args)
    }

    pub fn create_matching_parameter(
        &mut self,
        expected_value: &str,
        diag_service: WIPOffset<dataformat::DiagService<'a>>,
        out_param: WIPOffset<dataformat::Param<'a>>,
    ) -> WIPOffset<dataformat::MatchingParameter<'a>> {
        let expected_value_offset = self.fbb.create_string(expected_value);

        let matching_parameter_args = dataformat::MatchingParameterArgs {
            expected_value: Some(expected_value_offset),
            diag_service: Some(diag_service),
            out_param: Some(out_param),
            use_physical_addressing: None,
        };

        dataformat::MatchingParameter::create(&mut self.fbb, &matching_parameter_args)
    }

    pub fn create_variant_pattern(
        &mut self,
        matching_parameters: &Vec<WIPOffset<dataformat::MatchingParameter<'a>>>,
    ) -> WIPOffset<dataformat::VariantPattern<'a>> {
        let matching_parameters_vec = self.fbb.create_vector(matching_parameters);

        let variant_pattern_args = dataformat::VariantPatternArgs {
            matching_parameter: Some(matching_parameters_vec),
        };

        dataformat::VariantPattern::create(&mut self.fbb, &variant_pattern_args)
    }

    pub fn create_additional_audience(
        &mut self,
        short_name: &str,
        long_name: Option<&str>,
    ) -> WIPOffset<dataformat::AdditionalAudience<'a>> {
        let short_name_offset = self.fbb.create_string(short_name);
        let long_name_offset = self.create_long_name(long_name);

        let additional_audience_args = dataformat::AdditionalAudienceArgs {
            short_name: Some(short_name_offset),
            long_name: long_name_offset,
        };

        dataformat::AdditionalAudience::create(&mut self.fbb, &additional_audience_args)
    }

    pub fn create_param(
        &mut self,
        params: &ParameterParams<'a>,
    ) -> WIPOffset<dataformat::Param<'a>> {
        let short_name_offset = params.short_name.map(|s| self.fbb.create_string(s));
        let semantic_offset = params.semantic.map(|s| self.fbb.create_string(s));
        let physical_default_value_offset = params
            .physical_default_value
            .map(|v| self.fbb.create_string(v));
        self.max_param_id = self.max_param_id.saturating_add(1);

        let param_args = dataformat::ParamArgs {
            id: self.max_param_id,
            param_type: params.param_type,
            short_name: short_name_offset,
            semantic: semantic_offset,
            sdgs: params.sdgs,
            physical_default_value: physical_default_value_offset,
            byte_position: params.byte_position,
            bit_position: params.bit_position,
            specific_data_type: params.specific_data_type,
            specific_data: params.specific_data,
        };

        dataformat::Param::create(&mut self.fbb, &param_args)
    }

    pub fn create_coded_const_param(
        &mut self,
        name: &'a str,
        value: &str,
        byte_pos: u32,
        bit_pos: u32,
        bit_len: u32,
        coded_type: DataType,
    ) -> WIPOffset<dataformat::Param<'a>> {
        let coded_value = Some(self.fbb.create_string(value));
        let diag_coded_type =
            Some(self.create_diag_coded_type_standard_length(bit_len, coded_type));
        let specific_data = Some(
            dataformat::ParamSpecificData::tag_as_coded_const(dataformat::CodedConst::create(
                &mut self.fbb,
                &dataformat::CodedConstArgs {
                    coded_value,
                    diag_coded_type,
                },
            ))
            .value_offset(),
        );

        self.create_param(&ParameterParams {
            param_type: dataformat::ParamType::CODED_CONST,
            short_name: Some(name),
            semantic: None,
            sdgs: None,
            physical_default_value: None,
            byte_position: Some(byte_pos),
            bit_position: Some(bit_pos),
            specific_data_type: dataformat::ParamSpecificData::CodedConst,
            specific_data,
        })
    }

    pub fn create_value_param(
        &mut self,
        name: &'a str,
        dop: WIPOffset<dataformat::DOP>,
        byte_pos: u32,
        bit_pos: u32,
    ) -> WIPOffset<dataformat::Param<'a>> {
        let specific_data = Some(
            dataformat::ParamSpecificData::tag_as_value(dataformat::Value::create(
                &mut self.fbb,
                &dataformat::ValueArgs {
                    physical_default_value: None,
                    dop: Some(dop),
                },
            ))
            .value_offset(),
        );

        self.create_param(&ParameterParams {
            param_type: dataformat::ParamType::VALUE,
            short_name: Some(name),
            semantic: None,
            sdgs: None,
            physical_default_value: None,
            byte_position: Some(byte_pos),
            bit_position: Some(bit_pos),
            specific_data_type: dataformat::ParamSpecificData::Value,
            specific_data,
        })
    }
    pub fn create_phys_const_param(
        &mut self,
        name: &'a str,
        phys_constant_value: Option<&str>,
        dop: WIPOffset<dataformat::DOP<'a>>,
        byte_pos: u32,
        bit_pos: u32,
    ) -> WIPOffset<dataformat::Param<'a>> {
        let phys_value = phys_constant_value.map(|v| self.fbb.create_string(v));
        let specific_data = Some(
            dataformat::ParamSpecificData::tag_as_phys_const(dataformat::PhysConst::create(
                &mut self.fbb,
                &dataformat::PhysConstArgs {
                    phys_constant_value: phys_value,
                    dop: Some(dop),
                },
            ))
            .value_offset(),
        );

        self.create_param(&ParameterParams {
            param_type: dataformat::ParamType::PHYS_CONST,
            short_name: Some(name),
            semantic: None,
            sdgs: None,
            physical_default_value: None,
            byte_position: Some(byte_pos),
            bit_position: Some(bit_pos),
            specific_data_type: dataformat::ParamSpecificData::PhysConst,
            specific_data,
        })
    }

    pub fn create_structure(
        &mut self,
        params: Option<Vec<WIPOffset<dataformat::Param<'a>>>>,
        byte_size: Option<u32>,
        is_visible: bool,
    ) -> WIPOffset<dataformat::Structure<'a>> {
        let structure_args = dataformat::StructureArgs {
            params: params.map(|v| self.fbb.create_vector(&v)),
            byte_size,
            is_visible,
        };

        dataformat::Structure::create(&mut self.fbb, &structure_args)
    }

    pub fn create_structure_dop(
        &mut self,
        short_name: &str,
        structure: WIPOffset<dataformat::Structure>,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let short_name = Some(self.fbb.create_string(short_name));
        let specific_data =
            Some(dataformat::SpecificDOPData::tag_as_structure(structure).value_offset());

        dataformat::DOP::create(
            &mut self.fbb,
            &dataformat::DOPArgs {
                dop_type: *DopType::STRUCTURE,
                short_name,
                sdgs: None,
                specific_data_type: *SpecificDOPData::Structure,
                specific_data,
            },
        )
    }

    pub fn create_switch_key(
        &mut self,
        byte_position: u32,
        bit_position: Option<u32>,
        dop: Option<WIPOffset<dataformat::DOP<'a>>>,
    ) -> WIPOffset<SwitchKey<'a>> {
        let switch_key_args = dataformat::SwitchKeyArgs {
            byte_position,
            bit_position,
            dop,
        };

        SwitchKey::create(&mut self.fbb, &switch_key_args)
    }

    pub fn create_dop(
        &mut self,
        dop_type: dataformat::DOPType,
        short_name: Option<&str>,
        sdgs: Option<WIPOffset<dataformat::SDGS<'a>>>,
        specific_data_type: dataformat::SpecificDOPData,
        specific_data: Option<WIPOffset<dataformat::SpecificDOPDataUnionValue>>,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let short_name = short_name.map(|s| self.fbb.create_string(s));

        let dop_args = dataformat::DOPArgs {
            dop_type,
            short_name,
            sdgs,
            specific_data_type,
            specific_data,
        };

        dataformat::DOP::create(&mut self.fbb, &dop_args)
    }

    pub fn create_normal_specific_dop_data(
        &mut self,
        compu_method: Option<WIPOffset<dataformat::CompuMethod<'a>>>,
        diag_coded_type: Option<WIPOffset<dataformat::DiagCodedType<'a>>>,
        physical_type: Option<WIPOffset<dataformat::PhysicalType<'a>>>,
        internal_constr: Option<WIPOffset<dataformat::InternalConstr<'a>>>,
        unit_ref: Option<WIPOffset<dataformat::Unit<'a>>>,
        phys_constr: Option<WIPOffset<dataformat::InternalConstr<'a>>>,
    ) -> UnionWIPOffset<dataformat::SpecificDOPDataUnionValue> {
        let normal_dop_args = dataformat::NormalDOPArgs {
            compu_method,
            diag_coded_type,
            physical_type,
            internal_constr,
            unit_ref,
            phys_constr,
        };
        let normal_dop = dataformat::NormalDOP::create(&mut self.fbb, &normal_dop_args);
        dataformat::SpecificDOPData::tag_as_normal_dop(normal_dop)
    }

    /// Shorthand for creating a regular `NormalDOP` with only a compu method and diag coded type.
    ///
    /// Equivalent to calling [`create_normal_specific_dop_data`] (with all optional fields `None`)
    /// followed by [`create_dop`] with `DopType::REGULAR` and `SpecificDOPData::NormalDOP`.
    pub fn create_regular_normal_dop(
        &mut self,
        name: &str,
        diag_coded_type: WIPOffset<dataformat::DiagCodedType<'a>>,
        compu_method: WIPOffset<dataformat::CompuMethod<'a>>,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let specific_data = self
            .create_normal_specific_dop_data(
                Some(compu_method),
                Some(diag_coded_type),
                None,
                None,
                None,
                None,
            )
            .value_offset();
        self.create_dop(
            *DopType::REGULAR,
            Some(name),
            None,
            *SpecificDOPData::NormalDOP,
            Some(specific_data),
        )
    }

    pub fn create_dynamic_length_specific_dop_data(
        &mut self,
        offset: u32,
        number_of_items_byte_pos: u32,
        number_of_items_bit_pos: u32,
        number_of_items_dop: WIPOffset<dataformat::DOP>,
        repeated_struct: Option<WIPOffset<dataformat::Structure<'a>>>,
    ) -> UnionWIPOffset<dataformat::SpecificDOPDataUnionValue> {
        let repeated_struct = if let Some(repeated_struct) = repeated_struct {
            let structure_dop = self.create_dop(
                *DopType::STRUCTURE,
                None,
                None,
                *SpecificDOPData::Structure,
                Some(dataformat::SpecificDOPData::tag_as_structure(repeated_struct).value_offset()),
            );
            Some(structure_dop)
        } else {
            None
        };

        let field = dataformat::Field::create(
            &mut self.fbb,
            &dataformat::FieldArgs {
                basic_structure: repeated_struct,
                env_data_desc: None, // not supported yet.
                is_visible: true,
            },
        );

        let determine_number_of_items = dataformat::DetermineNumberOfItems::create(
            &mut self.fbb,
            &dataformat::DetermineNumberOfItemsArgs {
                byte_position: number_of_items_byte_pos,
                bit_position: number_of_items_bit_pos,
                dop: Some(number_of_items_dop),
            },
        );

        let dynamic_length_field_args = dataformat::DynamicLengthFieldArgs {
            offset,
            field: Some(field),
            determine_number_of_items: Some(determine_number_of_items),
        };

        let dynamic_length_field =
            dataformat::DynamicLengthField::create(&mut self.fbb, &dynamic_length_field_args);
        dataformat::SpecificDOPData::tag_as_dynamic_length_field(dynamic_length_field)
    }

    pub fn create_mux_dop(
        &mut self,
        name: &str,
        byte_position: u32,
        switch_key: Option<WIPOffset<dataformat::SwitchKey<'a>>>,
        default_case: Option<WIPOffset<dataformat::DefaultCase<'a>>>,
        cases: Option<Vec<WIPOffset<dataformat::Case<'a>>>>,
        is_visible: bool,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let mux_dop_args = dataformat::MUXDOPArgs {
            byte_position,
            switch_key,
            default_case,
            cases: cases.map(|v| self.fbb.create_vector(&v)),
            is_visible,
        };

        let mux = dataformat::MUXDOP::create(&mut self.fbb, &mux_dop_args);
        self.create_dop(
            *DopType::MUX,
            Some(name),
            None,
            *SpecificDOPData::MUXDOP,
            Some(dataformat::SpecificDOPData::tag_as_muxdop(mux).value_offset()),
        )
    }

    pub fn create_sdgs(
        &mut self,
        sdgs: Option<Vec<WIPOffset<dataformat::SDG<'a>>>>,
    ) -> WIPOffset<dataformat::SDGS<'a>> {
        let sdgs_args = dataformat::SDGSArgs {
            sdgs: sdgs.map(|v| self.fbb.create_vector(&v)),
        };

        dataformat::SDGS::create(&mut self.fbb, &sdgs_args)
    }

    pub fn create_diag_coded_type(
        &mut self,
        base_type_encoding: Option<&str>,
        base_data_type: DataType,
        is_high_low_byte_order: bool,
        specific_data_type: DiagCodedTypeVariant,
    ) -> WIPOffset<dataformat::DiagCodedType<'a>> {
        let base_type_encoding_offset =
            base_type_encoding.map(|encoding| self.fbb.create_string(encoding));

        let type_ = match specific_data_type {
            DiagCodedTypeVariant::LeadingLengthInfo(_) => {
                dataformat::DiagCodedTypeName::LEADING_LENGTH_INFO_TYPE
            }
            DiagCodedTypeVariant::MinMaxLength(_) => {
                dataformat::DiagCodedTypeName::MIN_MAX_LENGTH_TYPE
            }
            DiagCodedTypeVariant::StandardLength(_) => {
                dataformat::DiagCodedTypeName::STANDARD_LENGTH_TYPE
            }
        };

        let (specific_data_type, specific_data) = match specific_data_type {
            DiagCodedTypeVariant::LeadingLengthInfo(bit_length) => {
                let leading_length = dataformat::LeadingLengthInfoType::create(
                    &mut self.fbb,
                    &dataformat::LeadingLengthInfoTypeArgs { bit_length },
                );
                (
                    dataformat::SpecificDataType::LeadingLengthInfoType,
                    dataformat::SpecificDataType::tag_as_leading_length_info_type(leading_length),
                )
            }
            DiagCodedTypeVariant::MinMaxLength(min_max_length) => {
                let min_max_length = dataformat::MinMaxLengthType::create(
                    &mut self.fbb,
                    &dataformat::MinMaxLengthTypeArgs {
                        min_length: min_max_length.min_length,
                        max_length: min_max_length.max_length,
                        termination: match min_max_length.termination {
                            Termination::EndOfPdu => dataformat::Termination::END_OF_PDU,
                            Termination::Zero => dataformat::Termination::ZERO,
                            Termination::HexFF => dataformat::Termination::HEX_FF,
                        },
                    },
                );
                (
                    dataformat::SpecificDataType::MinMaxLengthType,
                    dataformat::SpecificDataType::tag_as_min_max_length_type(min_max_length),
                )
            }
            DiagCodedTypeVariant::StandardLength(standard_length) => {
                let bit_mask = standard_length
                    .bit_mask
                    .map(|mask| self.fbb.create_vector(&mask));
                let standard_length = dataformat::StandardLengthType::create(
                    &mut self.fbb,
                    &dataformat::StandardLengthTypeArgs {
                        bit_length: standard_length.bit_length,
                        bit_mask,
                        condensed: standard_length.condensed,
                    },
                );
                (
                    dataformat::SpecificDataType::StandardLengthType,
                    dataformat::SpecificDataType::tag_as_standard_length_type(standard_length),
                )
            }
        };

        let diag_coded_type_args = dataformat::DiagCodedTypeArgs {
            type_,
            base_type_encoding: base_type_encoding_offset,
            base_data_type: base_data_type.into(),
            is_high_low_byte_order,
            specific_data_type,
            specific_data: Some(specific_data.value_offset()),
        };

        dataformat::DiagCodedType::create(&mut self.fbb, &diag_coded_type_args)
    }

    pub fn create_diag_coded_type_standard_length(
        &mut self,
        bit_length: u32,
        data_type: DataType,
    ) -> WIPOffset<dataformat::DiagCodedType<'a>> {
        self.create_diag_coded_type(
            None,
            data_type,
            true,
            DiagCodedTypeVariant::StandardLength(crate::datatypes::StandardLengthType {
                bit_length,
                bit_mask: None,
                condensed: false,
            }),
        )
    }

    pub fn create_compu_method(
        &mut self,
        compu_category: CompuCategory,
        internal_to_phys: Option<WIPOffset<CompuInternalToPhys<'a>>>,
        phys_to_internal: Option<WIPOffset<CompuPhysToInternal<'a>>>,
    ) -> WIPOffset<dataformat::CompuMethod<'a>> {
        let compu_method_args = dataformat::CompuMethodArgs {
            category: compu_category.into(),
            internal_to_phys,
            phys_to_internal,
        };

        dataformat::CompuMethod::create(&mut self.fbb, &compu_method_args)
    }

    pub fn create_case(
        &mut self,
        short_name: &str,
        lower_limit: Option<Limit>,
        upper_limit: Option<Limit>,
        structure: Option<WIPOffset<dataformat::Structure<'a>>>,
    ) -> WIPOffset<dataformat::Case<'a>> {
        let short_name = Some(self.fbb.create_string(short_name));

        let structure_dop = structure.map(|s| {
            self.create_dop(
                *DopType::STRUCTURE,
                None,
                None,
                *SpecificDOPData::Structure,
                Some(dataformat::SpecificDOPData::tag_as_structure(s).value_offset()),
            )
        });

        let lower_limit = lower_limit.map(|limit| self.cda_limit_to_flatbuf_limit(&limit));
        let upper_limit = upper_limit.map(|limit| self.cda_limit_to_flatbuf_limit(&limit));

        let case_args = dataformat::CaseArgs {
            short_name,
            long_name: None,
            lower_limit,
            upper_limit,
            structure: structure_dop,
        };

        dataformat::Case::create(&mut self.fbb, &case_args)
    }

    fn cda_limit_to_flatbuf_limit(&mut self, limit: &Limit) -> WIPOffset<dataformat::Limit<'a>> {
        let val_str = self.fbb.create_string(&limit.value);
        dataformat::Limit::create(
            &mut self.fbb,
            &dataformat::LimitArgs {
                value: Some(val_str),
                interval_type: match limit.interval_type {
                    IntervalType::Open => dataformat::IntervalType::OPEN,
                    IntervalType::Closed => dataformat::IntervalType::CLOSED,
                    IntervalType::Infinite => dataformat::IntervalType::INFINITE,
                },
            },
        )
    }

    pub fn create_default_case(
        &mut self,
        short_name: &str,
        structure: Option<WIPOffset<dataformat::Structure<'a>>>,
    ) -> WIPOffset<dataformat::DefaultCase<'a>> {
        let short_name = Some(self.fbb.create_string(short_name));

        let structure_dop = structure.map(|s| {
            self.create_dop(
                *DopType::STRUCTURE,
                None,
                None,
                *SpecificDOPData::Structure,
                Some(dataformat::SpecificDOPData::tag_as_structure(s).value_offset()),
            )
        });

        let default_case_args = dataformat::DefaultCaseArgs {
            short_name,
            long_name: None,
            structure: structure_dop,
        };

        dataformat::DefaultCase::create(&mut self.fbb, &default_case_args)
    }

    pub fn create_end_of_pdu_field_dop(
        &mut self,
        min_items: u32,
        max_items: Option<u32>,
        structure: Option<WIPOffset<dataformat::Structure<'a>>>,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let field = if let Some(structure) = structure {
            let structure_dop = self.create_dop(
                *DopType::STRUCTURE,
                None,
                None,
                *SpecificDOPData::Structure,
                Some(dataformat::SpecificDOPData::tag_as_structure(structure).value_offset()),
            );

            Some(dataformat::Field::create(
                &mut self.fbb,
                &dataformat::FieldArgs {
                    basic_structure: Some(structure_dop),
                    env_data_desc: None,
                    is_visible: true,
                },
            ))
        } else {
            None
        };

        let end_of_pdu_field_specific_data = dataformat::EndOfPduField::create(
            &mut self.fbb,
            &dataformat::EndOfPduFieldArgs {
                min_number_of_items: Some(min_items),
                max_number_of_items: max_items,
                field,
            },
        );

        self.create_dop(
            *DopType::END_OF_PDU_FIELD,
            None,
            None,
            *SpecificDOPData::EndOfPduField,
            Some(
                dataformat::SpecificDOPData::tag_as_end_of_pdu_field(
                    end_of_pdu_field_specific_data,
                )
                .value_offset(),
            ),
        )
    }

    pub fn create_dtc(
        &mut self,
        trouble_code: u32,
        display_trouble_code: Option<&str>,
        text: Option<&str>,
        level: u32,
    ) -> WIPOffset<dataformat::DTC<'a>> {
        let display_trouble_code = display_trouble_code.map(|s| self.fbb.create_string(s));
        let text_offset = text.map(|s| {
            let text_str = self.fbb.create_string(s);
            dataformat::Text::create(
                &mut self.fbb,
                &dataformat::TextArgs {
                    ti: Some(text_str),
                    value: Some(text_str),
                },
            )
        });

        let dtc_args = dataformat::DTCArgs {
            short_name: None,
            sdgs: None,
            trouble_code,
            display_trouble_code,
            text: text_offset,
            level: Some(level),
            is_temporary: false,
        };

        dataformat::DTC::create(&mut self.fbb, &dtc_args)
    }

    pub fn create_dtc_dop(
        &mut self,
        diag_coded_type: WIPOffset<dataformat::DiagCodedType<'a>>,
        dtcs: Option<Vec<WIPOffset<dataformat::DTC<'a>>>>,
        compu_method: Option<WIPOffset<dataformat::CompuMethod<'a>>>,
    ) -> WIPOffset<dataformat::DOP<'a>> {
        let dtcs_vector = dtcs.map(|d| self.fbb.create_vector(&d));

        let dtc_dop_specific_data = dataformat::DTCDOP::create(
            &mut self.fbb,
            &dataformat::DTCDOPArgs {
                diag_coded_type: Some(diag_coded_type),
                physical_type: None,
                compu_method,
                dtcs: dtcs_vector,
                is_visible: true,
            },
        );

        self.create_dop(
            *DopType::DTC,
            None,
            None,
            *SpecificDOPData::DTCDOP,
            Some(dataformat::SpecificDOPData::tag_as_dtcdop(dtc_dop_specific_data).value_offset()),
        )
    }

    pub fn create_state_transition(
        &mut self,
        short_name: &str,
        source_short_name_ref: Option<&str>,
        target_short_name_ref: Option<&str>,
    ) -> WIPOffset<dataformat::StateTransition<'a>> {
        let short_name_offset = self.fbb.create_string(short_name);
        let source_offset = source_short_name_ref.map(|s| self.fbb.create_string(s));
        let target_offset = target_short_name_ref.map(|s| self.fbb.create_string(s));

        let args = dataformat::StateTransitionArgs {
            short_name: Some(short_name_offset),
            source_short_name_ref: source_offset,
            target_short_name_ref: target_offset,
        };

        dataformat::StateTransition::create(&mut self.fbb, &args)
    }

    pub fn create_state_transition_ref(
        &mut self,
        state_transition: WIPOffset<dataformat::StateTransition<'a>>,
    ) -> WIPOffset<dataformat::StateTransitionRef<'a>> {
        let args = dataformat::StateTransitionRefArgs {
            value: None,
            state_transition: Some(state_transition),
        };

        dataformat::StateTransitionRef::create(&mut self.fbb, &args)
    }

    pub fn create_pre_condition_state_ref(
        &mut self,
        state: WIPOffset<dataformat::State<'a>>,
    ) -> WIPOffset<dataformat::PreConditionStateRef<'a>> {
        let args = dataformat::PreConditionStateRefArgs {
            value: None,
            in_param_if_short_name: None,
            in_param_path_short_name: None,
            state: Some(state),
        };

        dataformat::PreConditionStateRef::create(&mut self.fbb, &args)
    }
}
