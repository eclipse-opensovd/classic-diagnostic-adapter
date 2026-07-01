# SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
from helper import (
    derived_id,
    find_dop_by_shortname,
    find_dtc_dop,
    functional_class_ref,
    matching_request_parameter_subfunction,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
    subfunction_rq,
    texttable_int_str_dop,
)
from odxtools.addressing import Addressing
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compumethod import CompuMethod
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagnostictroublecode import DiagnosticTroubleCode
from odxtools.diagservice import DiagService
from odxtools.dtcdop import DtcDop
from odxtools.dynamiclengthfield import DetermineNumberOfItems, DynamicLengthField
from odxtools.endofpdufield import EndOfPduField
from odxtools.multiplexer import Multiplexer
from odxtools.multiplexerdefaultcase import MultiplexerDefaultCase
from odxtools.multiplexerswitchkey import MultiplexerSwitchKey
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.structure import Structure
from odxtools.text import Text
from odxtools.transmode import TransMode


def add_dtc_setting_service(
    dlr: DiagLayerRaw,
    name: str,
    setting_type: int,
    description: str,
    is_functional: bool = False,
):
    """
    Add a DTC Setting service (0x85).

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "DTC_Setting_On")
        setting_type: The setting type subfunction value
        description: Description of the setting type
        is_functional: If the communication control service shall be added as a functional request
    """

    name_suffix = ""

    if is_functional:
        setting_type = setting_type | 0x80  # set suppress response bit
        name_suffix = "_Func"

    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}{name_suffix}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x85),
                subfunction_rq(setting_type, "SettingType"),
            ]
        ),
    )
    dlr.requests.append(request)

    pos_response_refs = []
    if not is_functional:
        response = Response(
            response_type=ResponseType.POSITIVE,
            odx_id=derived_id(dlr, f"PR.PR_{name}{name_suffix}"),
            short_name=f"PR_{name}",
            parameters=NamedItemList(
                [
                    sid_parameter_pr(0x85 + 0x40),
                    matching_request_parameter_subfunction("SettingType"),
                ]
            ),
        )
        dlr.positive_responses.append(response)
        pos_response_refs.append(ref(response))

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}{name_suffix}"),
            short_name=name + name_suffix,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "DtcSetting")],
            request_ref=ref(request),
            pos_response_refs=pos_response_refs,
            addressing_raw=None if not is_functional else Addressing.FUNCTIONAL,
            transmission_mode_raw=None if not is_functional else TransMode.SEND_ONLY,
        )
    )


def add_dtc_setting_services(
    dlr: DiagLayerRaw,
    is_functional: bool = False,
):
    """
    Add DTC Setting (0x85) services to the diagnostic layer.

    Implements the following setting types:
    - 0x01: on
    - 0x02: off
    - 0x42: TimeTravelDTCsOn (custom vendor-specific)
    """

    # 85 01 - DTC Setting Mode On
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_On",
        0x01,
        "DTC Setting On",
        is_functional,
    )

    # 85 02 - DTC Setting Mode Off
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_Off",
        0x02,
        "DTC Setting Off",
        is_functional,
    )

    # 85 42 -  DTC Setting Mode TimeTravelDTCsOn (custom vendor-specific)
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_TimeTravelDTCsOn",
        0x42,
        "DTC Setting Time Travel DTCs On",
        is_functional,
    )


def dtc_status_parameters(dlr: DiagLayerRaw, byte_position: int) -> NamedItemList:
    return NamedItemList(
        [
            ValueParameter(
                short_name="testFailed",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=0,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="testFailedThisOperationCycle",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=1,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="pendingDTC",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=2,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="confirmedDTC",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=3,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="testNotCompletedSinceLastClear",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=4,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="testFailedSinceLastClear",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=5,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="testNotCompletedThisOperationCycle",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=6,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
            ValueParameter(
                short_name="warningIndicatorRequested",
                semantic="DATA",
                byte_position=byte_position,
                bit_position=7,
                dop_ref=ref(find_dop_by_shortname(dlr, "TrueFalseDop")),
            ),
        ]
    )


def add_dtc_read_by_mask_service(
    dlr: DiagLayerRaw,
    name: str,
    subfunction: int,
    description: str,
    dtc_record_dop: OdxLinkRef,
):
    """
    Add a DTC Reading service (0x19).

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "reportDTCByStatusMask")
        subfunction: The subfunction value (e.g, 0x02)
        description: Description of the service
        dtc_record_dop: OdxLinkRef for the DTC structure,
    """
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x19),
                subfunction_rq(subfunction, "SubFunction"),
                *dtc_status_parameters(dlr, 2),
            ],
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x19 + 0x40),
                matching_request_parameter_subfunction("SubFunction"),
                *dtc_status_parameters(dlr, 2),
                ValueParameter(
                    short_name="DTCAndStatusRecord",
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=dtc_record_dop,
                ),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "FaultMem")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_dtc_read_snapshots_by_dtc_number_service(
    dlr: DiagLayerRaw,
    name: str,
    subfunction: int,
    description: str,
    dtc_record_dop: OdxLinkRef,
):
    """
    Adds the service for DTC Reading (0x19) with Snapshot Data.

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "reportDTCByStatusMask")
        subfunction: The subfunction value (e.g, 0x02)
        description: Description of the service
        dtc_record_dop: OdxLinkRef for the DTC record,
    """

    dtc_snapshot_record_dop = texttable_int_str_dop(
        dlr,
        "DtcSnapshotRecordDop",
        [
            (16, "First Occurence"),
            (32, "Last Occurence"),
            (255, "All Snapshot Records"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(dtc_snapshot_record_dop)

    # TEXTTABLE uint8 DOP for the snapshot record number field in the response
    # Maps all possible uint8 values (0-255) to their decimal string representation
    # Currently CDA expects a String type for this field
    dtc_snapshot_record_number_dop = texttable_int_str_dop(
        dlr,
        "DTCSnapshotRecordNumberDop",
        [(i, f"{i:02X}") for i in range(256)],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(dtc_snapshot_record_number_dop)

    # uint8 DOP for the number-of-identifiers field in the snapshot record
    dtc_snapshot_number_of_identifiers_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")

    # uint16 DOP for the 2-byte DID within a snapshot record
    dtc_snapshot_did_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_16")

    # uint32 DOP for the data bytes associated with the DID as example
    dtc_snapshot_did_data_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_32")

    # Structure DOP for a single Snapshot entry (DID + Data)
    dtc_snapshot_record_did_entry_structure = Structure(
        odx_id=derived_id(dlr, "STRUCT.DTCSnapshotRecordDidEntry"),
        short_name="DTCSnapshotRecordDidEntry",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="DTCSnapshotRecordDid",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_snapshot_did_dop),
                ),
                ValueParameter(
                    short_name="DTCSnapshotRecordDidData",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(dtc_snapshot_did_data_dop),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(dtc_snapshot_record_did_entry_structure)

    # Dynamic Field for actual data (Number of DIDs + Variable number of DIDs with their data)
    dtc_snapshot_record_entries = DynamicLengthField(
        odx_id=derived_id(dlr, "DYN_FIELD.DTCSnapshotRecordEntries"),
        short_name="DTCSnapshotRecordEntries",
        structure_ref=ref(dtc_snapshot_record_did_entry_structure.odx_id),
        offset=1,  # count byte is at offset 0, items start at offset 1
        determine_number_of_items=DetermineNumberOfItems(
            byte_position=0,  # count integer at byte 0 of the field
            dop_ref=ref(dtc_snapshot_number_of_identifiers_dop),
        ),
    )

    dlr.diag_data_dictionary_spec.dynamic_length_fields.append(dtc_snapshot_record_entries)

    # Structure DOP for a complete DTC Snapshot Record (Rec Number + Number of DIDs + Data Entries)
    # Layout: [RecordNumber(1)][NumberOfIdentifiers(1)][DID(2)][DID data(4)]...[DID[2]][DID data(4)]
    dtc_snapshot_record_structure = Structure(
        odx_id=derived_id(dlr, "STRUCT.DTCSnapshotRecord"),
        short_name="DTCSnapshotRecord",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="DTCSnapshotRecordNumber",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_snapshot_record_number_dop),
                ),
                ValueParameter(
                    short_name="DTCSnapshotRecordNumberOfIdentifiers",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(dtc_snapshot_number_of_identifiers_dop),
                ),
                ValueParameter(
                    short_name="DTCSnapshotRecordEntries",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(dtc_snapshot_record_entries),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(dtc_snapshot_record_structure)

    dtc_snapshot_end_of_pdu = EndOfPduField(
        odx_id=derived_id(dlr, "EndOfPdu.DTCSnapshotRecords"),
        short_name="DTCSnapshotRecords",
        structure_ref=ref(dtc_snapshot_record_structure.odx_id),
    )
    dlr.diag_data_dictionary_spec.end_of_pdu_fields.append(dtc_snapshot_end_of_pdu)

    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x19),
                subfunction_rq(subfunction, "SubFunction"),
                ValueParameter(
                    short_name="DtcCode",
                    semantic="DATA",
                    byte_position=2,
                    bit_position=0,
                    dop_ref=ref(find_dtc_dop(dlr, "RecordDataType")),
                ),
                ValueParameter(
                    short_name="DTCSnapshotRecordNr",
                    semantic="DATA",
                    byte_position=5,
                    dop_ref=ref(find_dop_by_shortname(dlr, "DtcSnapshotRecordDop")),
                ),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x19 + 0x40),
                matching_request_parameter_subfunction("SubFunction"),
                ValueParameter(
                    short_name="DTCAndStatusRecord",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=dtc_record_dop,
                ),
                ValueParameter(
                    short_name="DTCSnapshotRecords",
                    semantic="DATA",
                    byte_position=6,
                    dop_ref=ref(dtc_snapshot_end_of_pdu),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "FaultMem")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_dtc_read_ext_data_by_dtc_number_service(
    dlr: DiagLayerRaw,
    name: str,
    subfunction: int,
    description: str,
    dtc_record_dop: OdxLinkRef,
):
    """
    Adds the service for DTC Reading (0x19) with Extended Data.

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "reportDTCByStatusMask")
        subfunction: The subfunction value (e.g, 0x02)
        description: Description of the service
        dtc_record_dop: OdxLinkRef for the DTC record,
    """

    dtc_req_ext_data_record_number_dop = texttable_int_str_dop(
        dlr,
        "DtcReqExtDataRecordNrDop",
        [
            (16, "First Occurence"),
            (32, "Last Occurence"),
            (254, "All Ext Data Records"),
            (255, "All Ext Data Records"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(dtc_req_ext_data_record_number_dop)

    # TEXTTABLE uint8 DOP for the Extended data record number field in the response
    # Maps all possible uint8 values (0-255) to their decimal string representation
    # Currently CDA expects a String type for this field
    dtc_ext_data_record_number_dop = texttable_int_str_dop(
        dlr,
        "DTCExtDataRecordNumberDop",
        [(i, f"{i:02X}") for i in range(256)],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(dtc_ext_data_record_number_dop)

    # uint8 DOP for Record Number as part of Multiplexer, as Texttable DoP is not accepted
    dtc_ext_data_record_number_mux_sel_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")

    # uint32 DOP for the actual data bytes as example
    dtc_ext_data_record_data_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_32")

    # Structure for the default Mux case, holding the uint32 data field.
    dtc_ext_data_default_case_structure = Structure(
        odx_id=derived_id(dlr, "STRUCT.DTCExtDataRecordDataStruct"),
        short_name="DTCExtDataRecordDataStruct",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="DTCExtDataRecordData",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_ext_data_record_data_dop),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(dtc_ext_data_default_case_structure)

    # Multiplexer wrapping the data bytes.
    # Only the default case structure is defined to act as test example
    dtc_ext_data_mux = Multiplexer(
        odx_id=derived_id(dlr, "MUX.DTCExtDataRecordMux"),
        short_name="DTCExtDataRecordMux",
        byte_position=1,
        switch_key=MultiplexerSwitchKey(
            byte_position=0,
            dop_ref=ref(dtc_ext_data_record_number_mux_sel_dop),
        ),
        default_case=MultiplexerDefaultCase(
            short_name="DefaultTestExtDataStruct",
            structure_ref=ref(dtc_ext_data_default_case_structure),
        ),
    )
    dlr.diag_data_dictionary_spec.muxs.append(dtc_ext_data_mux)

    # Structure DOP for a single DTC Extended Data record
    # Layout: [RecordNumber(1)] [Data(4)]
    dtc_ext_data_record_structure = Structure(
        odx_id=derived_id(dlr, "STRUCT.DTCExtDataRecord"),
        short_name="DTCExtDataRecord",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="DTCExtDataRecordNumber",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_ext_data_record_number_dop),
                ),
                ValueParameter(
                    short_name="DTCExtDataRecordData",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_ext_data_mux),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(dtc_ext_data_record_structure)

    dtc_ext_data_end_of_pdu = EndOfPduField(
        odx_id=derived_id(dlr, "EndOfPdu.DTCExtDataRecord"),
        short_name="DTCExtDataRecord",
        structure_ref=ref(dtc_ext_data_record_structure.odx_id),
    )
    dlr.diag_data_dictionary_spec.end_of_pdu_fields.append(dtc_ext_data_end_of_pdu)

    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x19),
                subfunction_rq(subfunction, "SubFunction"),
                ValueParameter(
                    short_name="DtcCode",
                    semantic="DATA",
                    byte_position=2,
                    bit_position=0,
                    dop_ref=ref(find_dtc_dop(dlr, "RecordDataType")),
                ),
                ValueParameter(
                    short_name="DTCExtDataRecordNr",
                    semantic="DATA",
                    byte_position=5,
                    dop_ref=ref(find_dop_by_shortname(dlr, "DtcReqExtDataRecordNrDop")),
                ),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x19 + 0x40),
                matching_request_parameter_subfunction("SubFunction"),
                ValueParameter(
                    short_name="DTCAndStatusRecord",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=dtc_record_dop,
                ),
                ValueParameter(
                    short_name="DTCExtDataRecords",
                    semantic="DATA",
                    byte_position=6,
                    dop_ref=ref(dtc_ext_data_end_of_pdu),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "FaultMem")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_dtc_read_services(dlr: DiagLayerRaw):
    """
    Add DTC Read (0x19) services to the diagnostic layer.

    Implements the following subfunctions:
    - 0x02: ReportDTCByStatusMask
    - 0x06: ReportDTCByDtcNumber
    """

    true_false_dop = texttable_int_str_dop(
        dlr,
        "TrueFalseDop",
        [
            (0, "false"),
            (1, "true"),
        ],
        bit_length=1,
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(true_false_dop)

    # Create DTC DOP
    dtc_dop = DtcDop(
        odx_id=derived_id(dlr, "DOP.RecordDataType"),
        short_name="RecordDataType",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UINT32,
            internal_type=DataType.A_UINT32,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
        diag_coded_type=StandardLengthType(
            bit_length=24,
            base_data_type=DataType.A_UINT32,
        ),
        dtcs_raw=[
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code1"),
                short_name="Code1",
                trouble_code=0x01E240,  # 123456
                text=Text(
                    text="DTC Code 1",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code2"),
                short_name="Code2",
                trouble_code=0x039447,  # 234567
                text=Text(
                    text="DTC Code 2",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code3"),
                short_name="Code3",
                trouble_code=0x01E241,  # 123457
                text=Text(
                    text="DTC Code 3",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code4"),
                short_name="Code4",
                trouble_code=0x01E242,  # 123458
                text=Text(
                    text="DTC Code 4",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code5"),
                short_name="Code5",
                trouble_code=0x01E243,  # 123459
                text=Text(
                    text="DTC Code 5",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code6"),
                short_name="Code6",
                trouble_code=0x01E244,  # 123460
                text=Text(
                    text="DTC Code 6",
                ),
            ),
        ],
    )
    dlr.diag_data_dictionary_spec.dtc_dops.append(dtc_dop)

    # Create structure DOP for DTC records
    dtc_record_structure = Structure(
        odx_id=derived_id(dlr, "STRUCT.DTCRecord"),
        short_name="DTCRecord",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="DTCRecord",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(dtc_dop.odx_id),
                ),
                *dtc_status_parameters(dlr, 3),
            ],
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(dtc_record_structure)

    dtc_end_of_pdu = EndOfPduField(
        odx_id=derived_id(dlr, "EndOfPdu.DTCRecords"),
        short_name="DTCRecords",
        structure_ref=ref(dtc_record_structure.odx_id),
    )
    dlr.diag_data_dictionary_spec.end_of_pdu_fields.append(dtc_end_of_pdu)

    # 19 02 -  Report DTC By Status Mask
    add_dtc_read_by_mask_service(
        dlr,
        "FaultMem_ReportDTCByStatusMask",
        0x02,
        "Report DTC By Status Mask",
        ref(dtc_end_of_pdu.odx_id),
    )

    # 19 04 -  Report DTC By DTC Number
    add_dtc_read_snapshots_by_dtc_number_service(
        dlr,
        "FaultMem_ReportDTCSnapshotRecordByDtcNumber",
        0x04,
        "Report DTC Snapshot Record By DTC Number",
        ref(dtc_record_structure.odx_id),
    )

    # 19 06 -  Report DTC By DTC Number
    add_dtc_read_ext_data_by_dtc_number_service(
        dlr,
        "FaultMem_ReportDTCExtDataRecordByDtcNumber",
        0x06,
        "Report DTC Extended Data Record By DTC Number",
        ref(dtc_record_structure.odx_id),
    )


def add_dtc_clear_services(dlr: DiagLayerRaw):
    """
    Add DTC Clear (0x14) services to the diagnostic layer.

    Implements the following subfunctions:
    - 0x01: ClearDTCs
    """

    name = "FaultMem_ClearDTCs"
    description = "Clear DTCs"

    # 14 - Clear DTCs
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x14),
                ValueParameter(
                    short_name="Dtc",
                    semantic="DATA",
                    byte_position=1,
                    bit_position=0,
                    dop_ref=ref(find_dtc_dop(dlr, "RecordDataType")),
                ),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x14 + 0x40),
            ],
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "FaultMem")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_dtc_clear_user_memory_service(dlr: DiagLayerRaw):
    """
    Add a RoutineControl service (0x31) for clearing the user-defined DTC memory.

    This creates the "Clear_Diagnostic_User_Memory" service with request prefix
    [0x31, 0x01, 0x42, 0x00], which is looked up by CDA via
    ``lookup_diagcomms_by_request_prefix`` when a scoped fault deletion is requested.

    UDS structure:
    - Request:  31 01 42 00  (RoutineControl / startRoutine / routineId 0x4200)
    - Response: 71 01 42 00  (positive response)
    """
    from routines import add_routine

    add_routine(
        dlr,
        name="Clear_Diagnostic_User_Memory",
        routine_id=0x4200,
        routine_type="Start",
        functional_class="FaultMem",
        description="Clear User-Defined DTC Memory",
    )
