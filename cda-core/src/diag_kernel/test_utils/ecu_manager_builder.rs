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

//! Factory helpers for constructing [`EcuManager`] instances in tests.

use cda_interfaces::{
    Connectivity, EcuManagerType, Protocol, VariantState,
    datatypes::{ComParams, DatabaseNamingConvention},
    util::std_ext,
};
use cda_plugin_security::DefaultSecurityPluginData;

use crate::diag_kernel::ecumanager::{EcuManager, EcuManagerConfig};

pub(crate) const TEST_DIAG_LAYER: &str = "TestLayer";
pub(crate) const SID_PARM_NAME: &str = "sid";

/// Build a default [`EcuManager`] from the given database.
///
/// The manager is set up with [`TEST_DIAG_LAYER`] as the active variant and
/// `variant_index = Some(0)`.  It does **not** go through `set_variant` so no
/// state charts are built - this is intentional for unit tests.
pub(crate) fn new_ecu_manager(
    db: cda_database::datatypes::DiagnosticDatabase,
) -> EcuManager<DefaultSecurityPluginData> {
    let manager = EcuManager::new(
        db,
        Protocol::default(),
        &ComParams::default(),
        DatabaseNamingConvention::default(),
        EcuManagerConfig {
            type_: EcuManagerType::Ecu,
            fallback_to_base_variant: true,
            strict_parameter_validation: false,
        },
        &cda_interfaces::FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
        },
    )
    .expect("Failed to create EcuManager");

    // not using set_variant here, because that would require us to build state charts etc.
    {
        let mut es = std_ext::lock_write(&manager.runtime_state.ecu_state);
        es.connectivity = Connectivity::Online;
        es.variant_state = VariantState::Detected {
            name: TEST_DIAG_LAYER.to_owned(),
            is_base_variant: true,
            is_fallback: false,
        };
        es.variant_index = Some(0);
    }

    manager
}

/// Build a default [`EcuManager`] from the given database without the
/// base-variant / fallback behaviour.
pub(crate) fn new_ecu_manager_no_base_fallback(
    db: cda_database::datatypes::DiagnosticDatabase,
) -> EcuManager<DefaultSecurityPluginData> {
    EcuManager::new(
        db,
        Protocol::default(),
        &ComParams::default(),
        DatabaseNamingConvention::default(),
        EcuManagerConfig {
            type_: EcuManagerType::Ecu,
            fallback_to_base_variant: false,
            strict_parameter_validation: false,
        },
        &cda_interfaces::FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
        },
    )
    .unwrap()
}

use cda_database::{
    datatypes,
    datatypes::{
        CompuCategory, DataType, DiagCodedTypeVariant, Limit, ResponseType,
        database_builder::{
            DiagClassType, DiagCommParams, DiagLayerParams, DopType, EcuDataBuilder, EcuDataParams,
            SpecificDOPData,
        },
    },
};
use cda_interfaces::{
    DiagCommType, UDS_ID_RESPONSE_BITMASK, datatypes::semantics, service_ids, subfunction_ids,
};
use flatbuffers::WIPOffset;

use crate::diag_kernel::test_utils::{
    db_builder::{finish_db, finish_db_with_functional_groups},
    mdd_type_builder::{
        create_pos_response_with_param, create_sid_only_request, create_sid_param, new_diag_comm,
        new_diag_service,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndOfPduStructureType {
    FixedSize,
    LeadingLengthDop,
}

/// Whether the service's security `state_transition_ref` should use the
/// `Locked -> Extended` or `Extended -> Programming` transition.
#[derive(Copy, Clone)]
pub(crate) enum ServiceSecurityTransition {
    /// Service references `LockedSecurity -> ExtendedSecurity`.
    /// The default state (`LockedSecurity`) is also the transition source,
    /// so it is always implicitly allowed.
    LockedToExtended,
    /// Service references `ExtendedSecurity -> ProgrammingSecurity`.
    /// The default state (`LockedSecurity`) is NOT a transition source,
    /// which means it can be rejected.
    ExtendedToProgramming,
}

/// Creates an ECU manager whose database contains a functional group named `"MixedGroup"`
/// with one `ReadDataByIdentifier` service (`"ReadService"`) and one
/// `WriteDataByIdentifier` service (`"WriteService"`).
pub(crate) fn create_ecu_manager_with_mixed_functional_group()
-> crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData> {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

    // Create a READ_DATA_BY_IDENTIFIER service
    let read_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: "ReadService",
        long_name: Some("Read Service"),
        semantic: Some("DATA"),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let read_request = create_sid_only_request!(db_builder, service_ids::READ_DATA_BY_IDENTIFIER);
    let read_service = new_diag_service!(db_builder, read_diag_comm, read_request, vec![], vec![]);

    // Create a WRITE_DATA_BY_IDENTIFIER service
    let write_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: "WriteService",
        long_name: Some("Write Service"),
        semantic: Some("DATA"),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let write_request = create_sid_only_request!(db_builder, service_ids::WRITE_DATA_BY_IDENTIFIER);
    let write_service =
        new_diag_service!(db_builder, write_diag_comm, write_request, vec![], vec![]);

    let fg_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
        short_name: "MixedGroup",
        diag_services: Some(vec![read_service, write_service]),
        ..Default::default()
    });
    let fg = db_builder.create_functional_group(fg_diag_layer, None);

    let db = finish_db_with_functional_groups!(db_builder, protocol, vec![], vec![fg]);
    new_ecu_manager(db)
}

/// Creates an ECU manager with a diagnostic service containing a `DynamicLengthField` DOP.
///
/// # Database contents:
/// - **Service**: `TestDynamicLengthFieldService` (SID: 0x2E - `WriteDataByIdentifier`)
/// - **Request**: Contains a `num_items` parameter (u8) that specifies the count
/// - **Response**: Contains a `dynamic_length_field_dop`
///   that repeats a structure based on `num_items`
///   - Each repeated structure contains `item_param` (u16)
/// - **DOPs**: `NormalDOP` for `num_items`, `DynamicLengthField` DOP for response
// allowed because creation of test data should keep together
#[allow(clippy::too_many_lines)]
pub(crate) fn create_ecu_manager_with_dynamic_length_field_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create DOPs for structure parameters
    let num_items_dop =
        db_builder.create_regular_normal_dop("num_items_dop", u8_diag_type, compu_identical);

    // Create the structure for the repeated item
    let repeated_struct = {
        let item_param_dop =
            db_builder.create_regular_normal_dop("item_param_dop", u16_diag_type, compu_identical);

        // Create parameter for the repeated item
        let item_param = db_builder.create_value_param("item_param", item_param_dop, 0, 0);
        db_builder.create_structure(Some(vec![item_param]), Some(2), true)
    };

    let dynamic_length_field_dop = {
        // Create DynamicLengthField DoP
        let dynamic_length_field_dop_specific_data = db_builder
            .create_dynamic_length_specific_dop_data(1, 0, 0, num_items_dop, Some(repeated_struct))
            .value_offset();

        db_builder.create_dop(
            *DopType::REGULAR,
            Some("dynamic_length_field_dop"),
            None,
            *SpecificDOPData::DynamicLengthField,
            Some(dynamic_length_field_dop_specific_data),
        )
    };

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestDynamicLengthFieldService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let request_num_items_param =
            db_builder.create_value_param("num_items", num_items_dop, 1, 0);
        db_builder.create_request(Some(vec![sid_param, request_num_items_param]), None)
    };

    // Build response
    let pos_response = create_pos_response_with_param!(
        db_builder,
        sid,
        "pos_response_param",
        dynamic_length_field_dop,
        1
    );

    let neg_response = {
        let nack_param = db_builder.create_coded_const_param(
            "test_service_nack",
            &service_ids::NEGATIVE_RESPONSE.to_string(),
            0,
            0,
            8,
            DataType::UInt32,
        );
        let sid_param = db_builder.create_coded_const_param(
            "test_service_neg_sid",
            &sid.to_string(),
            1,
            0,
            8,
            DataType::UInt32,
        );
        db_builder.create_response(
            ResponseType::Negative,
            Some(vec![nack_param, sid_param]),
            None,
        )
    };

    let diag_service = new_diag_service!(
        db_builder,
        diag_comm,
        request,
        vec![pos_response],
        vec![neg_response]
    );

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
    )
}

/// Creates an ECU manager with a service
/// containing different parameter types for metadata testing.
///
/// # Database contents:
/// - **Service**: `RDBI_TestService` (SID: 0x22 - `ReadDataByIdentifier`)
/// - **Request**: Contains three parameter types:
///   - `sid`: CODED-CONST parameter (value: "34")
///   - `RDBI_DID`: CODED-CONST parameter (value: "0xF190" = 61840)
///   - `data`: VALUE parameter (u16)
/// - **Response**: Contains positive response SID
///
/// This helper is used to test parameter metadata extraction, including
/// distinguishing between CODED-CONST and VALUE parameter types.
pub(crate) fn create_ecu_manager_with_parameter_metadata()
-> crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData> {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);

    // Create a service with CODED-CONST parameters
    let sid = service_ids::READ_DATA_BY_IDENTIFIER;
    let dc_name = "RDBI_TestService";

    // Create DOP for VALUE parameter
    let value_dop =
        db_builder.create_regular_normal_dop("value_dop", u16_diag_type, compu_identical);

    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Create request with CODED-CONST and VALUE parameters
    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let did_param =
            db_builder.create_coded_const_param("RDBI_DID", "0xF190", 1, 0, 16, DataType::UInt32);
        let value_param = db_builder.create_value_param("data", value_dop, 3, 0);
        db_builder.create_request(Some(vec![sid_param, did_param, value_param]), None)
    };

    let pos_response = {
        let sid_param = create_sid_param!(db_builder, "pos_sid", (sid + UDS_ID_RESPONSE_BITMASK));
        db_builder.create_response(ResponseType::Positive, Some(vec![sid_param]), None)
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    new_ecu_manager(db)
}

/// Creates an ECU manager with a diagnostic service containing a Structure DOP.
///
/// # Database contents:
/// - **Service**: `TestStructService` (SID: 0x2E - `WriteDataByIdentifier`)
/// - **Request**: Contains a `main_param` that is a Structure DOP
///   - `param1`: u16
///   - `param2`: f32
///   - `param3`: ASCII string (32 bits)
/// - **Structure**: 10 bytes total (2 + 4 + 4)
/// - **DOPs**: `NormalDOPs` for each parameter, wrapped in a Structure DOP
///
/// # Parameters:
/// - `struct_byte_pos`: The byte position where the structure starts in the payload
// allowed because creation of test data should kept together
pub(crate) fn create_ecu_manager_with_struct_service(
    struct_byte_pos: u32,
) -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
    u32,
) {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create the structure with parameters
    let (structure_dop, structure_byte_len) = {
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let f32_diag_type =
            db_builder.create_diag_coded_type_standard_length(32, DataType::Float32);
        let ascii_diag_type =
            db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);

        // Create DOPs for structure parameters
        let param1_dop =
            db_builder.create_regular_normal_dop("param1_dop", u16_diag_type, compu_identical);
        let param2_dop =
            db_builder.create_regular_normal_dop("param2_dop", f32_diag_type, compu_identical);
        let param3_dop =
            db_builder.create_regular_normal_dop("param3_dop", ascii_diag_type, compu_identical);

        // Create parameters for the structure
        let struct_param1 = db_builder.create_value_param("param1", param1_dop, 0, 0);
        let struct_param2 = db_builder.create_value_param("param2", param2_dop, 2, 0);
        let struct_param3 = db_builder.create_value_param("param3", param3_dop, 6, 0);

        let struct_byte_len = 10; // 2 + 4 + 4 bytes
        let structure = db_builder.create_structure(
            Some(vec![struct_param1, struct_param2, struct_param3]),
            Some(struct_byte_len),
            true,
        );

        // Wrap the structure in a DOP
        (
            db_builder.create_structure_dop("test_structure_dop", structure),
            struct_byte_len,
        )
    };

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestStructService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let main_param =
            db_builder.create_value_param("main_param", structure_dop, struct_byte_pos, 0);
        db_builder.create_request(Some(vec![sid_param, main_param]), None)
    };

    let diag_service = new_diag_service!(db_builder, diag_comm, request, vec![], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
        structure_byte_len,
    )
}

/// Creates an ECU manager with a MUX service that includes a default case.
///
/// # Database contents:
/// - **Service**: `TestMuxService` (SID: `ReadDataByIdentifier` - 0x22)
/// - **MUX DOP**: Multiplexer with switch key and cases
///   - **Switch key**: u16 at byte position 0
///   - **Case 1** (range 1-10): Contains f32 and u8 parameters
///   - **Case 2** (range 11-600): Contains i16 and ASCII string parameters
///   - **Case 3** (string "test"): No structure
///   - **Default case**: Contains `default_structure_param_1` (u8)
/// - **Request and Response**: Both contain the MUX parameter
pub(crate) fn create_ecu_manager_with_mux_service_and_default_case() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create DOP for default structure parameter
    let default_structure_param_1 = {
        let default_structure_param_1_dop = db_builder.create_regular_normal_dop(
            "default_structure_param_1_dop",
            u8_diag_type,
            compu_identical,
        );
        db_builder.create_value_param(
            "default_structure_param_1",
            default_structure_param_1_dop,
            0,
            0,
        )
    };

    // Create default structure
    let default_structure =
        db_builder.create_structure(Some(vec![default_structure_param_1]), Some(1), true);
    let default_case = db_builder.create_default_case("default_case", Some(default_structure));

    create_ecu_manager_with_mux_service(Some(db_builder), None, Some(default_case))
}

/// Creates an ECU manager with a MUX (multiplexer) service.
///
/// # Database contents:
/// - **Service**: `TestMuxService` (SID: `ReadDataByIdentifier` - 0x22)
/// - **MUX DOP**: Multiplexer with configurable switch key and cases
///   - **Switch key**: Configurable via parameter, defaults to u16 at byte position 0
///   - **Case 1** (range 1-10):
///     - `mux_1_case_1_param_1`: f32 at byte 0
///     - `mux_1_case_1_param_2`: u8 at byte 4
///   - **Case 2** (range 11-600):
///     - `mux_1_case_2_param_1`: i16 at byte 1
///     - `mux_1_case_2_param_2`: ASCII string (32 bits) at byte 4
///   - **Case 3** (string "test"): No structure
///   - **Default case**: Optional, configurable via parameter
/// - **Request and Response**: Both contain the MUX parameter at byte position 2
///
/// # Parameters:
/// - `db_builder`: Optional pre-configured builder (creates new if None)
/// - `switch_key`: Optional custom switch key (creates default u16 if None)
/// - `default_case`: Optional default case for unmatched switch values
// allowed because creation of test data should kept together
pub(crate) fn create_ecu_manager_with_mux_service(
    db_builder: Option<EcuDataBuilder>,
    switch_key: Option<WIPOffset<datatypes::database_builder::SwitchKey>>,
    default_case: Option<WIPOffset<datatypes::database_builder::DefaultCase>>,
) -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = db_builder.unwrap_or_default();

    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let i16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::Int32);
    let f32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::Float32);
    let ascii_diag_type =
        db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create DOPs for case 1 parameters
    let mux_1_case_1_params_dop_1 = db_builder.create_regular_normal_dop(
        "mux_1_case_1_params_dop_1",
        f32_diag_type,
        compu_identical,
    );
    let mux_1_case_1_params_dop_2 = db_builder.create_regular_normal_dop(
        "mux_1_case_1_params_dop_2",
        u8_diag_type,
        compu_identical,
    );

    // Create DOPs for case 2 parameters
    let mux_1_case_2_params_dop_1 = db_builder.create_regular_normal_dop(
        "mux_1_case_2_params_dop_1",
        i16_diag_type,
        compu_identical,
    );
    let mux_1_case_2_params_dop_2 = db_builder.create_regular_normal_dop(
        "mux_1_case_2_params_dop_2",
        ascii_diag_type,
        compu_identical,
    );

    // Create parameters for case 1
    let mux_1_case_1_param_1 =
        db_builder.create_value_param("mux_1_case_1_param_1", mux_1_case_1_params_dop_1, 0, 0);
    let mux_1_case_1_param_2 =
        db_builder.create_value_param("mux_1_case_1_param_2", mux_1_case_1_params_dop_2, 4, 0);

    // Create parameters for case 2
    let mux_1_case_2_param_1 =
        db_builder.create_value_param("mux_1_case_2_param_1", mux_1_case_2_params_dop_1, 1, 0);
    let mux_1_case_2_param_2 =
        db_builder.create_value_param("mux_1_case_2_param_2", mux_1_case_2_params_dop_2, 4, 0);

    // Create structures
    let mux_1_case_1_structure = db_builder.create_structure(
        Some(vec![mux_1_case_1_param_1, mux_1_case_1_param_2]),
        Some(7),
        true,
    );

    let mux_1_case_2_structure = db_builder.create_structure(
        Some(vec![mux_1_case_2_param_1, mux_1_case_2_param_2]),
        Some(7),
        true,
    );

    // Create cases using the new helper method
    let mux_1_case_1 = db_builder.create_case(
        "mux_1_case_1",
        Some(Limit {
            value: 1.0.to_string(),
            interval_type: datatypes::IntervalType::Infinite,
        }),
        Some(Limit {
            value: 10.0.to_string(),
            interval_type: datatypes::IntervalType::Infinite,
        }),
        Some(mux_1_case_1_structure),
    );

    let mux_1_case_2 = db_builder.create_case(
        "mux_1_case_2",
        Some(Limit {
            value: 11.0.to_string(),
            interval_type: datatypes::IntervalType::Infinite,
        }),
        Some(Limit {
            value: 600.0.to_string(),
            interval_type: datatypes::IntervalType::Infinite,
        }),
        Some(mux_1_case_2_structure),
    );

    let mux_1_case_3 = db_builder.create_case(
        "mux_1_case_3",
        Some(Limit {
            value: "test".to_owned(),
            interval_type: datatypes::IntervalType::Infinite,
        }),
        None,
        None,
    );

    // Create switch key if not provided
    let mux_1_switch_key = switch_key.unwrap_or_else(|| {
        let switch_key_dop =
            db_builder.create_regular_normal_dop("switch_key_dop", u16_diag_type, compu_identical);
        db_builder.create_switch_key(0, Some(0), Some(switch_key_dop))
    });

    let cases = vec![mux_1_case_1, mux_1_case_2, mux_1_case_3];

    // Create mux DOP specific data
    let mux_dop = db_builder.create_mux_dop(
        "mux_dop",
        2,
        Some(mux_1_switch_key),
        default_case,
        Some(cases),
        true,
    );

    let sid = service_ids::READ_DATA_BY_IDENTIFIER;
    let dc_name = "TestMuxService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Create request with mux parameter
    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let mux_param = db_builder.create_value_param("mux_1_param", mux_dop, 2, 0);
        db_builder.create_request(Some(vec![sid_param, mux_param]), None)
    };

    // Create response with mux parameter
    let pos_response = create_pos_response_with_param!(db_builder, sid, "mux_1_param", mux_dop, 2);

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Data),
        sid,
    )
}

/// Creates an ECU manager with an `EndOfPdu` service for variable-length repeated structures.
///
/// # Database contents:
/// - **Service**: `TestEndOfPduService` (SID: `ReadDataByIdentifier` - 0x22)
/// - **Request**: Simple request with only SID
/// - **Response**: Contains an `end_pdu_param` with `EndOfPdu` DOP
///   - Repeats a structure until end of payload
///   - **Structure type** (configurable):
///     - **`FixedSize`**: Each item is 3 bytes
///       - `item_param1`: u8 at byte 0
///       - `item_param2`: u16 at byte 1
///     - **`LeadingLengthDop`**: Variable-size items with 8-bit length prefix
///       - `data`: `ByteField` with leading length info
///   - **Constraints**:
///   - `min_items`: Minimum number of items required
///   - `max_items`: Optional maximum number of items allowed
///
/// # Parameters:
/// - `min_items`: Minimum number of structures required
/// - `max_items`: Optional maximum number of structures
/// - `structure_type`: Whether structures are fixed-size or have leading length
// allowed because creation of test data should kept together
pub(crate) fn create_ecu_manager_with_end_pdu_service(
    min_items: u32,
    max_items: Option<u32>,
    structure_type: EndOfPduStructureType,
) -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create the structure that will be repeated in EndOfPdu
    let item_structure = match structure_type {
        EndOfPduStructureType::LeadingLengthDop => {
            // Create structure with leading length DOP
            // The DiagCodedType with LeadingLengthInfo handles the length prefix automatically
            let leading_length_diag_type = db_builder.create_diag_coded_type(
                None,
                DataType::ByteField,
                true,
                DiagCodedTypeVariant::LeadingLengthInfo(8),
            );

            let data_dop = db_builder.create_regular_normal_dop(
                "data_dop",
                leading_length_diag_type,
                compu_identical,
            );

            let data_param = db_builder.create_value_param("data", data_dop, 0, 0);

            // Create structure with just the data parameter
            db_builder.create_structure(Some(vec![data_param]), None, true)
        }
        EndOfPduStructureType::FixedSize => {
            // Create fixed-size structure
            let item_param1_dop = db_builder.create_regular_normal_dop(
                "item_param1_dop",
                u8_diag_type,
                compu_identical,
            );
            let item_param2_dop = db_builder.create_regular_normal_dop(
                "item_param2_dop",
                u16_diag_type,
                compu_identical,
            );

            // Create parameters for the repeating structure
            let item_param1 = db_builder.create_value_param("item_param1", item_param1_dop, 0, 0);
            let item_param2 = db_builder.create_value_param("item_param2", item_param2_dop, 1, 0);

            // Create the basic structure that will be repeated
            db_builder.create_structure(
                Some(vec![item_param1, item_param2]),
                Some(3), // byte_size: 1 byte + 2 bytes = 3 bytes per item
                true,
            )
        }
    };

    // Create EndOfPdu DOP using the new helper method
    let end_pdu_dop =
        db_builder.create_end_of_pdu_field_dop(min_items, max_items, Some(item_structure));

    let sid = service_ids::READ_DATA_BY_IDENTIFIER;
    let dc_name = "TestEndOfPduService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Create request
    let request = create_sid_only_request!(db_builder, sid);

    // Create response with EndOfPdu parameter
    let pos_response =
        create_pos_response_with_param!(db_builder, sid, "end_pdu_param", end_pdu_dop, 1);

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Data),
        sid,
    )
}

/// Creates an ECU manager with a DTC (Diagnostic Trouble Code) service.
///
/// # Database contents:
/// - **Service**: `TestDtcService` (SID: 0x19 - `ReadDTCInformation`)
/// - **Request**: Simple request with only SID
/// - **Response**: Contains a `dtc_param` (u32 DTC code)
/// - **DTC**: Single DTC definition
///   - **Code**: 0xDEADBEEF (32-bit)
///   - **Display code**: "P1234" (OBD-II format)
///   - **Fault name**: "`TestFault`"
///   - **Severity**: 2
/// - **DOP**: DTC DOP with 32-bit coded type
pub(crate) fn create_ecu_manager_with_dtc() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
    u32,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    let dtc_code = 0xDEAD_BEEF;
    let dtc = db_builder.create_dtc(dtc_code, Some("P1234"), Some("TestFault"), 2);

    let dtc_dop = db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc]), Some(compu_identical));

    let sid = service_ids::READ_DTC_INFORMATION;
    let dc_name = "TestDtcService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Create request
    let request = create_sid_only_request!(db_builder, sid);

    // Create response with DTC parameter
    let pos_response = create_pos_response_with_param!(db_builder, sid, "dtc_param", dtc_dop, 1);

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Faults),
        sid,
        dtc_code,
    )
}

/// Creates an ECU manager with a service that has a DTC param followed by an ENV-DATA-DESC
/// param. The ENV-DATA-DESC selects the right ENV-DATA based on the DTC code and decodes
/// a single `temperature` (u8) parameter from it.
pub(crate) fn create_ecu_manager_with_env_data_desc() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
    u32,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let default_protocol = Protocol::default();
    let protocol = db_builder.create_protocol(default_protocol.str(), None, None, None);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    let dtc_code: u32 = 0x0001_0002;
    let dtc = db_builder.create_dtc(dtc_code, Some("P0001"), Some("TestEnvFault"), 1);
    let dtc_dop = db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc]), Some(compu_identical));

    // ENV-DATA for dtc_code: contains a single u8 param "temperature"
    let compu_identical2 =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let temp_dop = db_builder.create_regular_normal_dop("temp_dop", u8_diag_type, compu_identical2);
    let temp_param = db_builder.create_value_param("temperature", temp_dop, 0, 0);
    let env_data_dop = db_builder.create_env_data_dop(&[dtc_code], &[temp_param]);

    // ENV-DATA-DESC: selector is "dtc_param"
    let env_data_desc_dop =
        db_builder.create_env_data_desc_dop("env_snapshot", "dtc_param", &[env_data_dop]);

    let sid = service_ids::READ_DTC_INFORMATION;
    let dc_name = "TestEnvDataDescService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = create_sid_only_request!(db_builder, sid);

    let sid_param = create_sid_param!(db_builder, "test_service_pos_sid", sid);
    let dtc_value_param = db_builder.create_value_param("dtc_param", dtc_dop, 1, 0);
    let env_data_value_param =
        db_builder.create_value_param("env_snapshot", env_data_desc_dop, 5, 0);
    let pos_response = db_builder.create_response(
        ResponseType::Positive,
        Some(vec![sid_param, dtc_value_param, env_data_value_param]),
        None,
    );

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Faults),
        sid,
        dtc_code,
    )
}

// StaticField DOP

pub(crate) fn create_ecu_manager_with_static_field_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let default_protocol = Protocol::default();
    let protocol = db_builder.create_protocol(default_protocol.str(), None, None, None);

    let item_dop = db_builder.create_regular_normal_dop("item_dop", u16_diag_type, compu_identical);
    let item_param = db_builder.create_value_param("item_val", item_dop, 0, 0);
    let item_structure = db_builder.create_structure(Some(vec![item_param]), Some(2), true);

    // 3 items, each 2 bytes wide
    let static_field_dop = db_builder.create_static_field_dop(3, 2, item_structure);

    let sid = service_ids::READ_DATA_BY_IDENTIFIER;
    let dc_name = "TestStaticFieldService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);
    let request = create_sid_only_request!(db_builder, sid);
    let pos_response =
        create_pos_response_with_param!(db_builder, sid, "items", static_field_dop, 1);
    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Data),
        sid,
    )
}

// EnvDataDesc wildcard fallback

pub(crate) fn create_ecu_manager_with_env_data_desc_wildcard() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
    u32, // specific_dtc
    u32, // other_dtc (triggers wildcard)
) {
    let mut db_builder = EcuDataBuilder::new();
    let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let compu_identical2 =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let compu_identical3 =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let default_protocol = Protocol::default();
    let protocol = db_builder.create_protocol(default_protocol.str(), None, None, None);

    let specific_dtc: u32 = 0x0001_0002;
    let other_dtc: u32 = 0x0003_0004;

    let dtc1 = db_builder.create_dtc(specific_dtc, Some("P0001"), Some("SpecificFault"), 1);
    let dtc2 = db_builder.create_dtc(other_dtc, Some("P0002"), Some("OtherFault"), 2);
    let dtc_dop =
        db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc1, dtc2]), Some(compu_identical));

    let temp_dop = db_builder.create_regular_normal_dop("temp_dop", u8_diag_type, compu_identical2);
    let humidity_dop =
        db_builder.create_regular_normal_dop("humidity_dop", u8_diag_type, compu_identical3);

    // Specific env_data matches only specific_dtc -> reports "temperature"
    let temp_param = db_builder.create_value_param("temperature", temp_dop, 0, 0);
    let specific_env_data_dop = db_builder.create_env_data_dop(&[specific_dtc], &[temp_param]);

    // Wildcard env_data (empty dtc_values) -> reports "humidity"
    let humidity_param = db_builder.create_value_param("humidity", humidity_dop, 0, 0);
    let wildcard_env_data_dop = db_builder.create_env_data_dop(&[], &[humidity_param]);

    let env_data_desc_dop = db_builder.create_env_data_desc_dop(
        "env_snapshot",
        "dtc_param",
        &[specific_env_data_dop, wildcard_env_data_dop],
    );

    let sid = service_ids::READ_DTC_INFORMATION;
    let dc_name = "TestEnvDataDescWildcardService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);
    let request = create_sid_only_request!(db_builder, sid);

    let sid_param = create_sid_param!(db_builder, "test_service_pos_sid", sid);
    let dtc_value_param = db_builder.create_value_param("dtc_param", dtc_dop, 1, 0);
    let env_data_value_param =
        db_builder.create_value_param("env_snapshot", env_data_desc_dop, 5, 0);
    let pos_response = db_builder.create_response(
        ResponseType::Positive,
        Some(vec![sid_param, dtc_value_param, env_data_value_param]),
        None,
    );

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Faults),
        sid,
        specific_dtc,
        other_dtc,
    )
}

pub(crate) fn create_ecu_manager_env_data_no_wildcard() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
    u32, // dtc_in_db (used in payload; no matching env_data)
) {
    let mut db_builder = EcuDataBuilder::new();
    let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let compu_id = db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let compu_id2 = db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let default_protocol = Protocol::default();
    let protocol = db_builder.create_protocol(default_protocol.str(), None, None, None);

    let dtc_in_db: u32 = 0x0001_AAAA;
    let dtc = db_builder.create_dtc(dtc_in_db, Some("P9999"), Some("SomeFault"), 1);
    let dtc_dop = db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc]), Some(compu_id));

    // env_data only matches a *different* DTC code; no wildcard
    let temp_dop = db_builder.create_regular_normal_dop("temp_dop", u8_diag_type, compu_id2);
    let temp_param = db_builder.create_value_param("temperature", temp_dop, 0, 0);
    let env_data_dop = db_builder.create_env_data_dop(&[0x0000_1111], &[temp_param]);
    let env_data_desc_dop =
        db_builder.create_env_data_desc_dop("env_snapshot", "dtc_param", &[env_data_dop]);

    let sid = service_ids::READ_DTC_INFORMATION;
    let dc_name = "TestEnvDataNoWildcard";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);
    let request = create_sid_only_request!(db_builder, sid);
    let sid_param = create_sid_param!(db_builder, "test_service_pos_sid", sid);
    let dtc_value_param = db_builder.create_value_param("dtc_param", dtc_dop, 1, 0);
    let env_data_value_param =
        db_builder.create_value_param("env_snapshot", env_data_desc_dop, 5, 0);
    let pos_response = db_builder.create_response(
        ResponseType::Positive,
        Some(vec![sid_param, dtc_value_param, env_data_value_param]),
        None,
    );
    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Faults),
        sid,
        dtc_in_db,
    )
}

// DynamicLengthField: sibling param before DLF with no byte_position

pub(crate) fn create_ecu_manager_dlf_sibling_no_byte_pos() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let compu_identical2 =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let compu_identical3 =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
    let default_protocol = Protocol::default();
    let protocol = db_builder.create_protocol(default_protocol.str(), None, None, None);

    let sibling_dop =
        db_builder.create_regular_normal_dop("sibling_dop", u8_diag_type, compu_identical);
    let num_items_dop =
        db_builder.create_regular_normal_dop("num_items_dop", u8_diag_type, compu_identical2);

    let item_dop =
        db_builder.create_regular_normal_dop("item_dop", u16_diag_type, compu_identical3);
    let item_param = db_builder.create_value_param("item_val", item_dop, 0, 0);
    let repeated_struct = db_builder.create_structure(Some(vec![item_param]), Some(2), true);

    // offset=3: items start at param_abs_byte_pos + 3 (= byte 0 + 3 = byte 3 absolute)
    // number_of_items_byte_pos=2:
    // count at param_abs_byte_pos + 2 (= byte 0 + 2 = byte 2 absolute)
    let dlf_specific = db_builder
        .create_dynamic_length_specific_dop_data(3, 2, 0, num_items_dop, Some(repeated_struct))
        .value_offset();
    let dlf_dop = db_builder.create_dop(
        *DopType::REGULAR,
        Some("dlf_dop"),
        None,
        *SpecificDOPData::DynamicLengthField,
        Some(dlf_specific),
    );

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestDlfSiblingNoBytePosService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);
    let request = create_sid_only_request!(db_builder, sid);

    let pos_response = {
        let sid_param = create_sid_param!(db_builder, "test_service_pos_sid", sid);
        // sibling at explicit byte_pos=1, advances last_read_byte_pos to 2 after decoding
        let sibling_param = db_builder.create_value_param("sibling_val", sibling_dop, 1, 0);
        // DLF with NO explicit byte_position - must use base_offset=0, not last_read_byte_pos
        let dlf_param = db_builder.create_value_param_no_byte_pos("dlf_items", dlf_dop);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![sid_param, sibling_param, dlf_param]),
            None,
        )
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
    )
}

/// Creates an ECU manager configured for variant detection testing.
///
/// # Database contents:
/// - **Service**: `ReadVariantData`
///   (SID: `ReadDataByIdentifier` - 0x22, `VARIANT_IDENTIFICATION` class)
/// - **Request**: Simple request with SID
/// - **Response**: Contains `variant_code` parameter (u8)
/// - **Variants**: Two variants with pattern matching
///   - **`BaseVariant`** (`is_base=true`):
///     - Pattern matches when `variant_code` = 0
///     - Contains variant detection service
///     - State charts: Session (`DefaultSession`), Security (Locked)
///   - **`SpecificVariant`** (`is_base=false`):
///     - Pattern matches when `variant_code` = 1
///     - Contains variant detection service
///     - State charts: Session (`DefaultSession`), Security (Locked)
/// - **ECU name**: "`VariantDetectionEcu`"
#[allow(clippy::too_many_lines)] // must be kept together
pub(crate) fn create_ecu_manager_variant_detection(
    fallback_to_base: bool,
) -> crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData> {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create a variant detection service
    let vd_service_sid = service_ids::READ_DATA_BY_IDENTIFIER;
    let vd_service_name = "ReadVariantData";

    // Create DOP for variant code response parameter
    let variant_code_dop =
        db_builder.create_regular_normal_dop("variant_code_dop", u8_diag_type, compu_identical);

    // Create the diagnostic communication
    let vd_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: vd_service_name,
        diag_class_type: DiagClassType::VARIANT_IDENTIFICATION,
        ..Default::default()
    });

    let vd_request = create_sid_only_request!(db_builder, "vd_service_sid", vd_service_sid);

    let vd_pos_response = {
        let sid_param = create_sid_param!(
            db_builder,
            "vd_service_pos_sid",
            (vd_service_sid + UDS_ID_RESPONSE_BITMASK)
        );
        let variant_param = db_builder.create_value_param("variant_code", variant_code_dop, 1, 0);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![sid_param, variant_param]),
            None,
        )
    };

    let vd_diag_service = new_diag_service!(
        db_builder,
        vd_diag_comm,
        vd_request,
        vec![vd_pos_response],
        vec![]
    );

    // Create state charts for session and security
    let session_state_chart = {
        let default_session_name = "DefaultSession";
        let default_session_state = db_builder.create_state(default_session_name, None);

        db_builder.create_state_chart(
            "Session",
            Some(semantics::SESSION),
            None,
            Some(default_session_name),
            Some(vec![default_session_state]),
        )
    };

    let security_state_chart = {
        let default_security_name = "Locked";
        let default_security_state = db_builder.create_state(default_security_name, None);

        db_builder.create_state_chart(
            "SecurityAccess",
            Some(semantics::SECURITY),
            None,
            Some(default_security_name),
            Some(vec![default_security_state]),
        )
    };

    let sid_param = create_sid_param!(
        db_builder,
        "vd_service_pos_sid_base",
        (vd_service_sid + UDS_ID_RESPONSE_BITMASK)
    );

    let variant_param = db_builder.create_value_param("variant_code", variant_code_dop, 1, 0);

    let pos_response_variant_code = {
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![sid_param, variant_param]),
            None,
        )
    };
    let diag_service = new_diag_service!(
        db_builder,
        vd_diag_comm,
        vd_request,
        vec![pos_response_variant_code],
        vec![]
    );

    // Create base variant with pattern matching variant_code = 0
    let base_variant = {
        let matching_param_base =
            db_builder.create_matching_parameter("0", diag_service, variant_param);
        let variant_pattern_base = db_builder.create_variant_pattern(&vec![matching_param_base]);
        let base_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "BaseVariant",
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![vd_diag_service]),
            state_charts: Some(vec![session_state_chart, security_state_chart]),
            ..Default::default()
        });
        db_builder.create_variant(
            base_diag_layer,
            true,
            Some(vec![variant_pattern_base]),
            None,
        )
    };

    // Create second variant with pattern matching variant_code = 1
    let specific_variant = {
        let matching_param_base =
            db_builder.create_matching_parameter("1", diag_service, variant_param);
        let variant_pattern_base = db_builder.create_variant_pattern(&vec![matching_param_base]);
        let base_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "SpecificVariant",
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![vd_diag_service]),
            state_charts: Some(vec![session_state_chart, security_state_chart]),
            ..Default::default()
        });
        db_builder.create_variant(
            base_diag_layer,
            false,
            Some(vec![variant_pattern_base]),
            None,
        )
    };

    // we need multiple variants, hence cannot use the finish_db! macro,
    // so we finish the db manually here.
    let db = db_builder.finish(EcuDataParams {
        ecu_name: "VariantDetectionEcu",
        revision: "revision_1",
        version: "1.0.0",
        variants: Some(vec![base_variant, specific_variant]),
        ..Default::default()
    });

    if fallback_to_base {
        new_ecu_manager(db)
    } else {
        new_ecu_manager_no_base_fallback(db)
    }
}

/// Creates an `EcuManager` with a service that uses a `PhysConst` parameter with a Normal DOP.
///
/// Service layout (response):
///   byte 0: SID (CODED-CONST)
///   byte 1-2: DID (PHYS-CONST, Normal DOP, u16)
///   byte 3: `data_param` (VALUE, u8)
#[allow(clippy::too_many_lines)]
pub(crate) fn create_ecu_manager_with_phys_const_normal_dop_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create Normal DOP for the PhysConst DID parameter
    let did_dop = {
        let did_dop_specific_data = db_builder
            .create_normal_specific_dop_data(
                Some(compu_identical),
                Some(u16_diag_type),
                None,
                None,
                None,
                None,
            )
            .value_offset();
        db_builder.create_dop(
            *DopType::REGULAR,
            Some("did_dop"),
            None,
            *SpecificDOPData::NormalDOP,
            Some(did_dop_specific_data),
        )
    };

    // Create Normal DOP for the VALUE data parameter
    let data_dop = {
        let data_dop_specific_data = db_builder
            .create_normal_specific_dop_data(
                Some(compu_identical),
                Some(u8_diag_type),
                None,
                None,
                None,
                None,
            )
            .value_offset();
        db_builder.create_dop(
            *DopType::REGULAR,
            Some("data_dop"),
            None,
            *SpecificDOPData::NormalDOP,
            Some(data_dop_specific_data),
        )
    };

    let sid = service_ids::READ_DATA_BY_IDENTIFIER + cda_interfaces::UDS_ID_RESPONSE_BITMASK;
    let dc_name = "TestPhysConstNormalService";
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Request: SID (coded const) + DID (phys const)
    let request = {
        let sid_param = create_sid_param!(db_builder, "sid", service_ids::READ_DATA_BY_IDENTIFIER);
        let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
        db_builder.create_request(Some(vec![sid_param, did_param]), None)
    };

    // Positive response: SID + DID (phys const) + data (value)
    let pos_response = {
        let sid_param = create_sid_param!(db_builder, "sid", sid);
        let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
        let data_param = db_builder.create_value_param("data_param", data_dop, 3, 0);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![sid_param, did_param, data_param]),
            None,
        )
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);

    let ecu_manager = new_ecu_manager(db);

    let dc = cda_interfaces::DiagComm {
        name: dc_name.to_owned(),
        type_: DiagCommType::Data,
        lookup_name: Some(dc_name.to_owned()),
        subfunction_id: None,
    };

    (ecu_manager, dc, sid)
}

/// Creates an `EcuManager` with a service that uses a `PhysConst` parameter
/// with a Structure DOP.
///
/// Service layout (request):
///   byte 0: SID (CODED-CONST)
///   byte 1-2: DID (PHYS-CONST, Normal DOP, u16)
///   byte 3+: DREC (PHYS-CONST, Structure DOP with sub-params)
///     sub-param1: u16 at byte 0
///     sub-param2: u8 at byte 2
#[allow(clippy::too_many_lines)]
pub(crate) fn create_ecu_manager_with_phys_const_structure_dop_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let compu_identical =
        db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

    // Create Normal DOP for the PhysConst DID parameter
    let did_dop = {
        let did_dop_specific_data = db_builder
            .create_normal_specific_dop_data(
                Some(compu_identical),
                Some(u16_diag_type),
                None,
                None,
                None,
                None,
            )
            .value_offset();
        db_builder.create_dop(
            *DopType::REGULAR,
            Some("did_dop"),
            None,
            *SpecificDOPData::NormalDOP,
            Some(did_dop_specific_data),
        )
    };

    // Create Structure DOP for the PhysConst DREC parameter
    let structure_dop = {
        // Sub-param DOPs
        let sub_param1_dop = {
            let specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u16_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("sub_param1_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(specific_data),
            )
        };

        let sub_param2_dop = {
            let specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u8_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("sub_param2_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(specific_data),
            )
        };

        // Create structure params
        let sub_param1 = db_builder.create_value_param("sub_param1", sub_param1_dop, 0, 0);
        let sub_param2 = db_builder.create_value_param("sub_param2", sub_param2_dop, 2, 0);

        let structure = db_builder.create_structure(
            Some(vec![sub_param1, sub_param2]),
            Some(3), // byte_size: 2 bytes (u16) + 1 byte (u8) = 3 bytes
            true,
        );

        db_builder.create_structure_dop("structure_dop", structure)
    };

    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let sid_request = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let sid_response =
        service_ids::WRITE_DATA_BY_IDENTIFIER + cda_interfaces::UDS_ID_RESPONSE_BITMASK;
    let dc_name = "TestPhysConstStructureService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    // Request: SID (coded const) + DID (phys const, normal) + DREC (phys const, structure)
    let request = {
        let sid_param = create_sid_param!(db_builder, "sid", sid_request);
        let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
        let drec_param = db_builder.create_phys_const_param("DREC", None, structure_dop, 3, 0);
        db_builder.create_request(Some(vec![sid_param, did_param, drec_param]), None)
    };

    // Positive response: SID + DID (phys const) + DREC (phys const, structure)
    let pos_response = {
        let sid_param = create_sid_param!(db_builder, "sid", sid_response);
        let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
        let drec_param = db_builder.create_phys_const_param("DREC", None, structure_dop, 3, 0);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![sid_param, did_param, drec_param]),
            None,
        )
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

    let db = finish_db!(db_builder, protocol, vec![diag_service]);

    let ecu_manager = new_ecu_manager(db);

    let dc = cda_interfaces::DiagComm {
        name: dc_name.to_owned(),
        type_: DiagCommType::Configurations,
        lookup_name: Some(dc_name.to_owned()),
        subfunction_id: None,
    };

    (ecu_manager, dc, sid_response)
}

/// Helper function to create an ECU manager with services that have state transition refs.
///
/// `security_transition` controls which security transition the service
/// references, which affects whether the default state ends up in the
/// allowed set.
pub(crate) fn create_ecu_manager_with_state_transitions(
    security_transition: ServiceSecurityTransition,
) -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
) {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

    // Create security states
    let locked_state = db_builder.create_state("LockedSecurity", None);
    let extended_state = db_builder.create_state("ExtendedSecurity", None);
    let programming_state = db_builder.create_state("ProgrammingSecurity", None);

    // Create session states
    let default_session_state = db_builder.create_state("DefaultSession", None);
    let extended_session_state = db_builder.create_state("ExtendedSession", None);
    let programming_session_state = db_builder.create_state("ProgrammingSession", None);

    // Create state transitions for session
    let default_to_extended_session = db_builder.create_state_transition(
        "DefaultToExtended",
        Some("DefaultSession"),
        Some("ExtendedSession"),
    );
    let extended_to_programming_session = db_builder.create_state_transition(
        "ExtendedToProgramming",
        Some("ExtendedSession"),
        Some("ProgrammingSession"),
    );

    // Create state transitions for security
    let locked_to_extended_transition = db_builder.create_state_transition(
        "LockedToExtended",
        Some("LockedSecurity"),
        Some("ExtendedSecurity"),
    );

    let extended_to_programming_transition = db_builder.create_state_transition(
        "ExtendedToProgramming",
        Some("ExtendedSecurity"),
        Some("ProgrammingSecurity"),
    );

    // Create state chart for security
    let security_state_chart = db_builder.create_state_chart(
        "SecurityAccess",
        Some(semantics::SECURITY),
        Some(vec![
            locked_to_extended_transition,
            extended_to_programming_transition,
        ]),
        Some("LockedSecurity"),
        Some(vec![locked_state, extended_state, programming_state]),
    );

    // Create state chart for session
    let session_state_chart = db_builder.create_state_chart(
        "Session",
        Some(semantics::SESSION),
        Some(vec![
            default_to_extended_session,
            extended_to_programming_session,
        ]),
        Some("DefaultSession"),
        Some(vec![
            default_session_state,
            extended_session_state,
            programming_session_state,
        ]),
    );

    // Choose which security transition the service references
    let service_security_transition = match security_transition {
        ServiceSecurityTransition::LockedToExtended => locked_to_extended_transition,
        ServiceSecurityTransition::ExtendedToProgramming => extended_to_programming_transition,
    };

    // Create state transition refs for the service
    let state_transition_ref = db_builder.create_state_transition_ref(service_security_transition);
    let session_transition_ref =
        db_builder.create_state_transition_ref(default_to_extended_session);

    // Create precondition state ref - service requires Programming
    let precondition_ref = db_builder.create_pre_condition_state_ref(programming_state);

    // Create a service with state transition refs
    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestServiceWithStateTransitions";

    let diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: dc_name,
        pre_condition_state_refs: Some(vec![precondition_ref]),
        state_transition_refs: Some(vec![session_transition_ref, state_transition_ref]),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });

    let request = create_sid_only_request!(db_builder, sid);
    let diag_service = new_diag_service!(db_builder, diag_comm, request, vec![], vec![]);

    let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
        short_name: "TestVariantDiagLayer",
        com_param_refs: Some(vec![cp_ref]),
        diag_services: Some(vec![diag_service]),
        state_charts: Some(vec![session_state_chart, security_state_chart]),
        ..Default::default()
    });

    let variant = db_builder.create_variant(diag_layer, true, None, None);
    let db = db_builder.finish(EcuDataParams {
        revision: "revision_1",
        version: "1.0.0",
        variants: Some(vec![variant]),
        ..Default::default()
    });

    let dc = cda_interfaces::DiagComm {
        name: dc_name.to_owned(),
        type_: DiagCommType::Configurations,
        lookup_name: Some(dc_name.to_owned()),
        subfunction_id: None,
    };
    (new_ecu_manager(db), dc)
}

/// Helper that builds an ECU manager whose variant has a service with a
/// `ProgrammingSecurity` precondition **and** a functional group containing
/// the same service. Returns `(ecu_manager, diag_comm, sid)`.
pub(crate) fn create_ecu_manager_with_preconditions_and_functional_group() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

    let locked_state = db_builder.create_state("LockedSecurity", None);
    let extended_state = db_builder.create_state("ExtendedSecurity", None);
    let programming_state = db_builder.create_state("ProgrammingSecurity", None);

    let default_session_state = db_builder.create_state("DefaultSession", None);
    let extended_session_state = db_builder.create_state("ExtendedSession", None);
    let programming_session_state = db_builder.create_state("ProgrammingSession", None);

    let locked_to_extended = db_builder.create_state_transition(
        "LockedToExtended",
        Some("LockedSecurity"),
        Some("ExtendedSecurity"),
    );
    let extended_to_programming = db_builder.create_state_transition(
        "ExtendedToProgramming",
        Some("ExtendedSecurity"),
        Some("ProgrammingSecurity"),
    );
    let default_to_extended_session = db_builder.create_state_transition(
        "DefaultToExtended",
        Some("DefaultSession"),
        Some("ExtendedSession"),
    );
    let extended_to_programming_session = db_builder.create_state_transition(
        "ExtendedToProgramming",
        Some("ExtendedSession"),
        Some("ProgrammingSession"),
    );

    let security_state_chart = db_builder.create_state_chart(
        "SecurityAccess",
        Some(semantics::SECURITY),
        Some(vec![locked_to_extended, extended_to_programming]),
        Some("LockedSecurity"),
        Some(vec![locked_state, extended_state, programming_state]),
    );
    let session_state_chart = db_builder.create_state_chart(
        "Session",
        Some(semantics::SESSION),
        Some(vec![
            default_to_extended_session,
            extended_to_programming_session,
        ]),
        Some("DefaultSession"),
        Some(vec![
            default_session_state,
            extended_session_state,
            programming_session_state,
        ]),
    );

    let precondition_ref = db_builder.create_pre_condition_state_ref(programming_state);
    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestFGService";

    // Service for the functional group diag layer
    let fg_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: dc_name,
        pre_condition_state_refs: Some(vec![precondition_ref]),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let fg_request = create_sid_only_request!(db_builder, sid);
    let fg_service = new_diag_service!(db_builder, fg_diag_comm, fg_request, vec![], vec![]);
    let fg_layer = db_builder.create_diag_layer(DiagLayerParams {
        short_name: "TestFunctionalGroup",
        diag_services: Some(vec![fg_service]),
        ..Default::default()
    });
    let functional_group = db_builder.create_functional_group(fg_layer, None);

    // Same service for the variant diag layer
    let variant_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: dc_name,
        pre_condition_state_refs: Some(vec![precondition_ref]),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let variant_request = create_sid_only_request!(db_builder, sid);
    let variant_service = new_diag_service!(
        db_builder,
        variant_diag_comm,
        variant_request,
        vec![],
        vec![]
    );
    let variant_layer = db_builder.create_diag_layer(DiagLayerParams {
        short_name: TEST_DIAG_LAYER,
        com_param_refs: Some(vec![cp_ref]),
        diag_services: Some(vec![variant_service]),
        state_charts: Some(vec![session_state_chart, security_state_chart]),
        ..Default::default()
    });
    let variant = db_builder.create_variant(variant_layer, true, None, None);

    let db = db_builder.finish(EcuDataParams {
        ecu_name: "TestEcu",
        revision: "1",
        version: "1.0.0",
        variants: Some(vec![variant]),
        functional_groups: Some(vec![functional_group]),
        ..Default::default()
    });

    let dc = cda_interfaces::DiagComm {
        name: dc_name.to_owned(),
        type_: DiagCommType::Configurations,
        lookup_name: Some(dc_name.to_owned()),
        subfunction_id: None,
    };
    (new_ecu_manager(db), dc, sid)
}

pub(crate) fn create_ecu_manager_with_length_key_request_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical = db_builder.create_compu_method(CompuCategory::Identical, None, None);

    let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);

    let length_key_dop =
        db_builder.create_regular_normal_dop("lk_dop", u8_diag_type, compu_identical);
    let value_dop = db_builder.create_regular_normal_dop("val_dop", u16_diag_type, compu_identical);

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestLengthKeyReqService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let lk_param = db_builder.create_length_key_param("length_indicator", length_key_dop, 1, 0);
        let val_param = db_builder.create_value_param("value_param", value_dop, 2, 0);
        db_builder.create_request(Some(vec![sid_param, lk_param, val_param]), None)
    };

    let pos_response = {
        let sid_param = create_sid_param!(
            db_builder,
            "pos_sid",
            sid.saturating_add(UDS_ID_RESPONSE_BITMASK)
        );
        db_builder.create_response(ResponseType::Positive, Some(vec![sid_param]), None)
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
    )
}

pub(crate) fn create_ecu_manager_with_param_length_info_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    const LEN_KEY: &str = "len_key";
    const VAR_DATA: &str = "var_data";

    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical = db_builder.create_compu_method(CompuCategory::Identical, None, None);

    let len_key_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let var_data_diag_type =
        db_builder.create_diag_coded_type_param_length_info(LEN_KEY, DataType::ByteField);

    let len_key_dop =
        db_builder.create_regular_normal_dop("len_key_dop", len_key_diag_type, compu_identical);
    let var_data_dop =
        db_builder.create_regular_normal_dop("var_data_dop", var_data_diag_type, compu_identical);

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestParamLengthInfoService";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let len_key_param = db_builder.create_length_key_param(LEN_KEY, len_key_dop, 1, 0);
        let var_data_param = db_builder.create_value_param(VAR_DATA, var_data_dop, 2, 0);
        db_builder.create_request(Some(vec![sid_param, len_key_param, var_data_param]), None)
    };

    let pos_response = {
        let pos_sid_param = create_sid_param!(
            db_builder,
            "pos_sid",
            sid.saturating_add(UDS_ID_RESPONSE_BITMASK)
        );
        let len_key_param = db_builder.create_length_key_param(LEN_KEY, len_key_dop, 1, 0);
        let var_data_param = db_builder.create_value_param(VAR_DATA, var_data_dop, 2, 0);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![pos_sid_param, len_key_param, var_data_param]),
            None,
        )
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
    )
}

// Models the pattern from ISO 22901-1 §7.4.8 (readMemoryByAddress):
// one parameter determines the length of the next, and the parameter
// that comes *after* the variable-length data has no BYTE-POSITION in
// the ODX because its position is unknown until runtime.
//
// Layout (request & positive response):
//   byte 0     : SID       (coded const, 8 bit)
//   byte 1     : len_key   (LENGTH-KEY param, u8)
//   byte 2     : var_data  (PARAM-LENGTH-INFO, `len_key` bytes)
//   byte 2 + N : suffix    (value param, u16 - BYTE-POSITION omitted)
pub(crate) fn create_ecu_manager_with_trailing_param_after_param_length_info_service() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    cda_interfaces::DiagComm,
    u8,
) {
    const LEN_KEY: &str = "len_key";
    const VAR_DATA: &str = "var_data";

    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let compu_identical = db_builder.create_compu_method(CompuCategory::Identical, None, None);

    // diag coded types
    let u8_dct = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
    let u16_dct = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
    let var_dct = db_builder.create_diag_coded_type_param_length_info(LEN_KEY, DataType::ByteField);

    // DOPs
    let len_key_dop = db_builder.create_regular_normal_dop("len_key_dop", u8_dct, compu_identical);
    let var_data_dop =
        db_builder.create_regular_normal_dop("var_data_dop", var_dct, compu_identical);
    let suffix_dop = db_builder.create_regular_normal_dop("suffix_dop", u16_dct, compu_identical);

    let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
    let dc_name = "TestTrailingParamAfterPLI";
    let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

    let request = {
        let sid_param = create_sid_param!(db_builder, sid);
        let lk_param = db_builder.create_length_key_param(LEN_KEY, len_key_dop, 1, 0);
        let var_param = db_builder.create_value_param(VAR_DATA, var_data_dop, 2, 0);
        // Per spec: BYTE-POSITION omitted - position depends on runtime length of var_data
        let suffix_param = db_builder.create_value_param_no_byte_pos("suffix", suffix_dop);
        db_builder.create_request(
            Some(vec![sid_param, lk_param, var_param, suffix_param]),
            None,
        )
    };
    let pos_response = {
        let pos_sid_param = create_sid_param!(
            db_builder,
            "pos_sid",
            sid.saturating_add(UDS_ID_RESPONSE_BITMASK)
        );
        let lk_param = db_builder.create_length_key_param(LEN_KEY, len_key_dop, 1, 0);
        let var_param = db_builder.create_value_param(VAR_DATA, var_data_dop, 2, 0);
        let suffix_param = db_builder.create_value_param_no_byte_pos("suffix", suffix_dop);
        db_builder.create_response(
            ResponseType::Positive,
            Some(vec![pos_sid_param, lk_param, var_param, suffix_param]),
            None,
        )
    };

    let diag_service =
        new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    (
        new_ecu_manager(db),
        cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
        sid,
    )
}

/// Creates an ECU manager whose database contains a routine control service with the
/// following request structure:
/// - SID: 0x31 (Routine Control)
/// - Sub-function: 0x03 (8-bit, at byte position 1)
/// - Routine ID: 0x0A5C (16-bit, at byte positions 2-3)
pub(crate) fn create_ecu_manager_with_routine_control_service()
-> crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData> {
    const SERVICE_ID: u8 = 0x31;
    const ROUTINE_ID: u16 = 0x0A5C;
    const SERVICE_NAME: &str = "Test";

    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

    // Create the SID parameter
    let sid_param = db_builder.create_coded_const_param(
        "SID_RQ",
        &SERVICE_ID.to_string(),
        0,
        0,
        8,
        DataType::UInt32,
    );

    // Create the subfunction parameter
    let subfunction_param = db_builder.create_coded_const_param(
        "RoutineControlType",
        &subfunction_ids::routine::REQUEST_RESULTS.to_string(),
        1,
        0,
        8,
        DataType::UInt32,
    );

    // Create the routine ID parameter
    let routine_id_param = db_builder.create_coded_const_param(
        "RoutineIdentifier",
        &ROUTINE_ID.to_string(),
        2,
        0,
        16,
        DataType::UInt32,
    );

    // Create the request with all three parameters
    let request = db_builder.create_request(
        Some(vec![sid_param, subfunction_param, routine_id_param]),
        None,
    );

    // Create the DiagComm
    let diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: SERVICE_NAME,
        diag_class_type: DiagClassType::START_COMM,
        protocols: Some(vec![protocol]),
        ..Default::default()
    });

    // Create the DiagService
    let diag_service = new_diag_service!(db_builder, diag_comm, request, vec![], vec![]);
    let db = finish_db!(db_builder, protocol, vec![diag_service]);
    new_ecu_manager(db)
}

/// Build an ECU manager with two SID 0x27 (`SecurityAccess`) `RequestSeed` services,
/// one `SendKey` service, and a SECURITY state chart.
///
/// Services:
/// - `RequestSeed_level_01`: sub-function 0x01, 2 params (SID + `sub_func`)
/// - `RequestSeed_level_12`: sub-function 0x12 (18 dec), 2 params
/// - `SendKey_level_01`: sub-function 0x02, 3 params, carries LockedSecurity->ExtendedSecurity ref
///
/// Returns `(ecu_manager, request_seed_name_01, request_seed_name_12, send_key_name)`.
#[allow(clippy::too_many_lines)] // Splitting the 'create' function up, makes it worse to read.
pub(crate) fn create_ecu_manager_with_security_access_services() -> (
    crate::diag_kernel::ecumanager::EcuManager<DefaultSecurityPluginData>,
    String,
    String,
    String,
) {
    let mut db_builder = EcuDataBuilder::new();
    let protocol_name = Protocol::default().to_string();
    let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
    let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

    let sid = service_ids::SECURITY_ACCESS;

    let request_seed_01_name = "RequestSeed_level_01";
    let request_seed_01_sid = db_builder.create_coded_const_param(
        SID_PARM_NAME,
        &sid.to_string(),
        0,
        0,
        8,
        DataType::UInt32,
    );
    let request_seed_01_sub_func =
        db_builder.create_coded_const_param("sub_func", "1", 1, 0, 8, DataType::UInt32);
    let request_seed_01_request = db_builder.create_request(
        Some(vec![request_seed_01_sid, request_seed_01_sub_func]),
        None,
    );
    let request_seed_01_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: request_seed_01_name,
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let request_seed_01_service = new_diag_service!(
        db_builder,
        request_seed_01_diag_comm,
        request_seed_01_request,
        vec![],
        vec![]
    );

    // Sub-function 0x12 (18 dec) - used to test the hex-string id fallback path.
    let request_seed_12_name = "RequestSeed_level_12";
    let request_seed_12_sid = db_builder.create_coded_const_param(
        SID_PARM_NAME,
        &sid.to_string(),
        0,
        0,
        8,
        DataType::UInt32,
    );
    let request_seed_12_sub_func =
        db_builder.create_coded_const_param("sub_func", "18", 1, 0, 8, DataType::UInt32);
    let request_seed_12_request = db_builder.create_request(
        Some(vec![request_seed_12_sid, request_seed_12_sub_func]),
        None,
    );
    let request_seed_12_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: request_seed_12_name,
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let request_seed_12_service = new_diag_service!(
        db_builder,
        request_seed_12_diag_comm,
        request_seed_12_request,
        vec![],
        vec![]
    );

    let locked_state = db_builder.create_state("LockedSecurity", None);
    let extended_state = db_builder.create_state("ExtendedSecurity", None);

    let locked_to_extended = db_builder.create_state_transition(
        "LockedToExtended",
        Some("LockedSecurity"),
        Some("ExtendedSecurity"),
    );

    let security_state_chart = db_builder.create_state_chart(
        "SecurityAccess",
        Some(semantics::SECURITY),
        Some(vec![locked_to_extended]),
        Some("LockedSecurity"),
        Some(vec![locked_state, extended_state]),
    );

    let default_session_state = db_builder.create_state("DefaultSession", None);
    let session_state_chart = db_builder.create_state_chart(
        "Session",
        Some(semantics::SESSION),
        None,
        Some("DefaultSession"),
        Some(vec![default_session_state]),
    );

    let send_key_01_name = "SendKey_level_01";
    let send_key_01_sid = db_builder.create_coded_const_param(
        SID_PARM_NAME,
        &sid.to_string(),
        0,
        0,
        8,
        DataType::UInt32,
    );
    let send_key_01_sub_func =
        db_builder.create_coded_const_param("sub_func", "2", 1, 0, 8, DataType::UInt32);
    let send_key_01_key =
        db_builder.create_coded_const_param("key", "0", 2, 0, 8, DataType::UInt32);
    let send_key_01_request = db_builder.create_request(
        Some(vec![send_key_01_sid, send_key_01_sub_func, send_key_01_key]),
        None,
    );
    let locked_to_extended_ref = db_builder.create_state_transition_ref(locked_to_extended);
    let send_key_01_diag_comm = db_builder.create_diag_comm(DiagCommParams {
        short_name: send_key_01_name,
        state_transition_refs: Some(vec![locked_to_extended_ref]),
        protocols: Some(vec![protocol]),
        ..Default::default()
    });
    let send_key_01_service = new_diag_service!(
        db_builder,
        send_key_01_diag_comm,
        send_key_01_request,
        vec![],
        vec![]
    );

    let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
        short_name: TEST_DIAG_LAYER,
        com_param_refs: Some(vec![cp_ref]),
        diag_services: Some(vec![
            request_seed_01_service,
            request_seed_12_service,
            send_key_01_service,
        ]),
        state_charts: Some(vec![session_state_chart, security_state_chart]),
        ..Default::default()
    });
    let variant = db_builder.create_variant(diag_layer, true, None, None);
    let db = db_builder.finish(EcuDataParams {
        revision: "1",
        version: "1.0.0",
        variants: Some(vec![variant]),
        ..Default::default()
    });

    (
        new_ecu_manager(db),
        request_seed_01_name.to_owned(),
        request_seed_12_name.to_owned(),
        send_key_01_name.to_owned(),
    )
}
