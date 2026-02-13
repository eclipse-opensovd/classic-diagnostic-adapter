# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compumethod import CompuMethod
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.dtcdop import DtcDop
from odxtools.diagnostictroublecode import DiagnosticTroubleCode
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.endofpdufield import EndOfPduField
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.structure import Structure
from odxtools.text import Text

from helper import (
    find_dop_by_shortname,
    find_dtc_dop,
    named_item_list_from_parts,
    sid_parameter_rq,
    sid_parameter_pr,
    derived_id,
    subfunction_rq,
    matching_request_parameter_subfunction,
    functional_class_ref,
    ref,
    texttable_int_str_dop,
)


def add_dtc_setting_service(
    dlr: DiagLayerRaw,
    name: str,
    setting_type: int,
    description: str,
):
    """
    Add a DTC Setting service (0x85).

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "DTC_Setting_On")
        setting_type: The setting type subfunction value
        description: Description of the setting type
    """
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x85),
                subfunction_rq(setting_type, "SettingType"),
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
                sid_parameter_pr(0x85 + 0x40),
                matching_request_parameter_subfunction("SettingType"),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, "DtcSetting")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_dtc_setting_services(dlr: DiagLayerRaw):
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
    )

    # 85 02 - DTC Setting Mode Off
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_Off",
        0x02,
        "DTC Setting Off",
    )

    # 85 42 -  DTC Setting Mode TimeTravelDTCsOn (custom vendor-specific)
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_TimeTravelDTCsOn",
        0x42,
        "DTC Setting Time Travel DTCs On",
    )


def dtc_status_parameters(dlr: DiagLayerRaw, byte_position: int) -> NamedItemList:
    return [
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
        parameters=named_item_list_from_parts(
            [
                [
                    sid_parameter_rq(0x19),
                    subfunction_rq(subfunction, "SubFunction"),
                ],
                dtc_status_parameters(dlr, 2),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=named_item_list_from_parts(
            [
                [
                    sid_parameter_pr(0x19 + 0x40),
                    matching_request_parameter_subfunction("SubFunction"),
                ],
                dtc_status_parameters(dlr, 2),
                [
                    ValueParameter(
                        short_name="DTCAndStatusRecord",
                        semantic="DATA",
                        byte_position=3,
                        dop_ref=dtc_record_dop,
                    )
                ],
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


def add_dtc_read_by_dtc_number_service(
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
        dtc_record_dop: OdxLinkRef for the DTC record,
    """
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
                # TODO:
                # Add DTC Snapshot Record Structure here (not relevant for now)
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
                trouble_code="123456",  # 0x01E240
                text=Text(
                    text="DTC Code 1",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code2"),
                short_name="Code2",
                trouble_code="234567",  # 0x039447
                text=Text(
                    text="DTC Code 2",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code3"),
                short_name="Code3",
                trouble_code="123457",  # 0x01E241
                text=Text(
                    text="DTC Code 3",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code4"),
                short_name="Code4",
                trouble_code="123458",  # 0x01E242
                text=Text(
                    text="DTC Code 4",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code5"),
                short_name="Code5",
                trouble_code="123459",  # 0x01E243
                text=Text(
                    text="DTC Code 5",
                ),
            ),
            DiagnosticTroubleCode(
                odx_id=derived_id(dlr, "DTC.Code6"),
                short_name="Code6",
                trouble_code="123460",  # 0x01E244
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
        parameters=named_item_list_from_parts(
            [
                [
                    ValueParameter(
                        short_name="DTCRecord",
                        semantic="DATA",
                        byte_position=0,
                        dop_ref=ref(dtc_dop.odx_id),
                    ),
                ],
                dtc_status_parameters(dlr, 3),
            ]
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
    add_dtc_read_by_dtc_number_service(
        dlr,
        "FaultMem_ReportDTCSnapshotRecordByDtcNumber",
        0x04,
        "Report DTC Snapshot Record By DTC Number",
        ref(dtc_end_of_pdu.odx_id),
    )

    # 19 06 -  Report DTC By DTC Number
    # TODO: (out of scope for now)
    # Change this to not reuse the snapshot record req & resp, but instead
    # create service that has an end of pdu field for DTCExtDataRecord
    # as last parameter
    add_dtc_read_by_dtc_number_service(
        dlr,
        "FaultMem_ReportDTCExtDataRecordByDtcNumber",
        0x06,
        "Report DTC Extended Data Record By DTC Number",
        ref(dtc_end_of_pdu.odx_id),
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
        parameters=named_item_list_from_parts(
            [
                [
                    sid_parameter_pr(0x14 + 0x40),
                ],
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
