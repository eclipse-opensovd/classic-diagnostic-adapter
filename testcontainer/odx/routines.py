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
    coded_const_int_parameter,
    derived_id,
    find_dop_by_shortname,
    functional_class_ref,
    matching_request_parameter,
    matching_request_parameter_subfunction,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
    subfunction_rq,
    texttable_int_str_dop,
)
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.identicalcompumethod import IdenticalCompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.encoding import Encoding
from odxtools.minmaxlengthtype import MinMaxLengthType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxtypes import DataType
from odxtools.parameters.parameter import Parameter
from odxtools.parameters.tablekeyparameter import TableKeyParameter
from odxtools.parameters.tablestructparameter import TableStructParameter
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.structure import Structure
from odxtools.table import Table
from odxtools.tablerow import TableRow
from odxtools.termination import Termination

_ROUTINE_TYPE_TO_SUBFUNCTION = {
    "Start": 0x01,
    "Stop": 0x02,
    "RequestResults": 0x03,
}


def add_routine(
    dlr: DiagLayerRaw,
    name: str,
    routine_id: int,
    routine_type: str,
    request_params: list[Parameter] | None = None,
    response_params: list[Parameter] | None = None,
    functional_class: str = "Identification",
    description: str | None = None,
    is_functional: bool = False,
    sdgs: list | None = None,
) -> None:
    """Add a RoutineControl (0x31) operation service to the diagnostic layer.

    Creates a complete UDS RoutineControl service with request, positive response,
    and DiagService, then appends them all to ``dlr``.

    Args:
        dlr: The diagnostic layer to add the service to.
        name: Base name for the service (e.g. ``"MyRoutine"``).
            The operation type is appended automatically, resulting in
            a service short name like ``"MyRoutine_Start"``.
        routine_id: The 16-bit routine identifier (bytes 2-3 of the request).
        routine_type: One of ``"Start"``, ``"Stop"``, or ``"RequestResults"``.
        request_params: Optional list of additional :class:`ValueParameter`
            objects appended after the RoutineId in the request.  Callers are
            responsible for setting correct ``byte_position`` values (starting
            at 4).
        response_params: Optional list of additional :class:`ValueParameter`
            objects appended after the echoed RoutineId in the positive
            response.  Callers are responsible for setting correct
            ``byte_position`` values (starting at 4).
        functional_class: Name of the functional class to reference.
            Defaults to ``"Identification"``.
        description: Optional long name / description for the service.
        is_functional: If the operation service shall be added as a functional request

    Raises:
        ValueError: If *operation_type* is not one of the supported values.
    """
    if routine_type not in _ROUTINE_TYPE_TO_SUBFUNCTION:
        raise ValueError(
            f"Unknown operation_type {routine_type!r}. "
            f"Must be one of {list(_ROUTINE_TYPE_TO_SUBFUNCTION.keys())}"
        )

    subfunction = _ROUTINE_TYPE_TO_SUBFUNCTION[routine_type]
    service_name_suffix = ""
    if is_functional:
        subfunction = subfunction | 0x80  # set suppress response bit
        service_name_suffix = "_Func"

    service_name = f"{name}_{routine_type}{service_name_suffix}"

    # Request
    request_parameters: list[Parameter] = [
        sid_parameter_rq(0x31),
        subfunction_rq(subfunction, "RoutineControlType"),
        coded_const_int_parameter(
            short_name="RoutineId",
            semantic="DATA",
            byte_position=2,
            coded_value_raw=str(routine_id),
            bit_length=16,
        ),
    ]
    if request_params:
        request_parameters.extend(request_params)

    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{service_name}"),
        short_name=f"RQ_{service_name}",
        parameters=NamedItemList(request_parameters),
    )
    dlr.requests.append(request)

    # Positive response
    response_parameters: list[Parameter] = [
        sid_parameter_pr(0x31 + 0x40),
        matching_request_parameter_subfunction("RoutineControlType"),
        matching_request_parameter(
            short_name="RoutineId",
            semantic="DATA",
            byte_length=2,
            byte_position=2,
            request_byte_position=2,
        ),
    ]
    if response_params:
        response_parameters.extend(response_params)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{service_name}"),
        short_name=f"PR_{service_name}",
        parameters=NamedItemList(response_parameters),
    )
    dlr.positive_responses.append(response)

    # DiagService
    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{service_name}"),
            short_name=service_name,
            long_name=description,
            functional_class_refs=[functional_class_ref(dlr, functional_class)],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
            sdgs=sdgs or [],
        )
    )


def add_safety_squints_routine(dlr: DiagLayerRaw) -> None:
    """Add the Engage_Safety_Squints routine with Start and Stop operations.

    Start includes a SquintSlitWidth parameter (float64, mm).
    Stop has no additional parameters.
    """
    routine_id = 0x0301
    functional_class = "Routines"

    # Start - with slit width parameter
    add_routine(
        dlr,
        name="Engage_Safety_Squints",
        routine_id=routine_id,
        routine_type="Start",
        request_params=[
            ValueParameter(
                short_name="SquintSlitWidth",
                semantic="DATA",
                byte_position=4,
                dop_ref=ref(find_dop_by_shortname(dlr, "SquintSlitWidth_mm")),
            ),
        ],
        functional_class=functional_class,
        description="Engage Safety Squints",
        is_functional=True,
    )

    # Stop - no additional parameters
    add_routine(
        dlr,
        name="Engage_Safety_Squints",
        routine_id=routine_id,
        routine_type="Stop",
        functional_class=functional_class,
        description="Disengage Safety Squints",
        is_functional=True,
    )


def add_time_circuits_routine(
    dlr: DiagLayerRaw, sdgs_by_service: dict[str, list] | None = None
) -> None:
    """Add the TimeCircuits routine (Start/RequestResults/Stop) using a
    TABLE-KEY/TABLE-STRUCT pair

    Start request layout (bytes after RoutineIdentifier):
        travelMethod     - uint8 TABLE-KEY, selects how the destination
                            time is specified via a table row key:
            "ManualEntry"        -> destinationYear (uint16),
                                     destinationMonth (uint8),
                                     destinationDay (uint8)
            "PresetDestination"  -> presetId (uint8, texttable of iconic
                                     movie dates)
            "PresentDay"         -> empty struct (no additional data,
                                     i.e. stay in the present)
        travelMethodData - TABLE-STRUCT, the row-dependent data selected by
                            travelMethod above.

    RequestResults response layout (bytes after the echoed RoutineIdentifier):
        percentComplete - uint8, 0-100
        step            - uint8 texttable enum (Idle, Accelerating,
                          TemporalDisplacement, Arrived)
        message         - optional, open-ended ASCII string (may be empty),
                          only populated once step == Arrived
    """
    sdgs_map = sdgs_by_service or {}
    routine_id = 0x1003
    functional_class = "Routines"

    uint8_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")
    uint16_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_16")

    # Structure for travelMethod case 0x01 - "ManualEntry"
    manual_entry_struct = Structure(
        odx_id=derived_id(dlr, "STRUCT.TimeCircuitsManualEntryStruct"),
        short_name="TimeCircuitsManualEntryStruct",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="destinationYear",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(uint16_dop),
                ),
                ValueParameter(
                    short_name="destinationMonth",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(uint8_dop),
                ),
                ValueParameter(
                    short_name="destinationDay",
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=ref(uint8_dop),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(manual_entry_struct)

    # Texttable DOP mapping preset IDs to iconic movie destinations
    preset_destination_dop = texttable_int_str_dop(
        dlr,
        "TimeCircuitsPresetDestinationDop",
        [
            (1, "1955-11-05_ClockTower"),
            (2, "1885-09-02_OldWest"),
            (3, "2015-10-21_HillValley"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(preset_destination_dop)

    # Structure for travelMethod case 0x02 - "PresetDestination"
    preset_destination_struct = Structure(
        odx_id=derived_id(dlr, "STRUCT.TimeCircuitsPresetDestinationStruct"),
        short_name="TimeCircuitsPresetDestinationStruct",
        parameters=NamedItemList(
            [
                ValueParameter(
                    short_name="presetId",
                    semantic="DATA",
                    byte_position=0,
                    dop_ref=ref(preset_destination_dop),
                ),
            ]
        ),
    )
    dlr.diag_data_dictionary_spec.structures.append(preset_destination_struct)

    # Default case - "PresentDay" - empty struct (no destination data needed)
    present_day_struct = Structure(
        odx_id=derived_id(dlr, "STRUCT.TimeCircuitsPresentDayStruct"),
        short_name="TimeCircuitsPresentDayStruct",
        parameters=NamedItemList([]),
    )
    dlr.diag_data_dictionary_spec.structures.append(present_day_struct)

    # Key DOP mapping travelMethod key bytes to their row's short name
    travel_method_key_dop = texttable_int_str_dop(
        dlr,
        "TimeCircuitsTravelMethodDop",
        [
            (0, "PresentDay"),
            (1, "ManualEntry"),
            (2, "PresetDestination"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(travel_method_key_dop)

    travel_method_table_id = derived_id(dlr, "TABLE.TimeCircuitsTravelMethodTable")
    travel_method_table = Table(
        odx_id=travel_method_table_id,
        short_name="TimeCircuitsTravelMethodTable",
        key_dop_ref=ref(travel_method_key_dop),
        table_rows_raw=[
            TableRow(
                odx_id=derived_id(dlr, "TABLEROW.TimeCircuitsTravelMethodTable.PresentDay"),
                short_name="PresentDay",
                table_ref=ref(travel_method_table_id),
                key_raw="PresentDay",
                structure_ref=None,
            ),
            TableRow(
                odx_id=derived_id(dlr, "TABLEROW.TimeCircuitsTravelMethodTable.ManualEntry"),
                short_name="ManualEntry",
                table_ref=ref(travel_method_table_id),
                key_raw="ManualEntry",
                structure_ref=ref(manual_entry_struct),
            ),
            TableRow(
                odx_id=derived_id(dlr, "TABLEROW.TimeCircuitsTravelMethodTable.PresetDestination"),
                short_name="PresetDestination",
                table_ref=ref(travel_method_table_id),
                key_raw="PresetDestination",
                structure_ref=ref(preset_destination_struct),
            ),
        ],
    )
    dlr.diag_data_dictionary_spec.tables.append(travel_method_table)

    travel_method_key_param = TableKeyParameter(
        odx_id=derived_id(dlr, "PARAM.TimeCircuitsTravelMethodKey"),
        short_name="travelMethod",
        semantic="DATA",
        byte_position=4,
        table_ref=ref(travel_method_table),
    )

    # 31 01 10 03 - TimeCircuits Start
    add_routine(
        dlr,
        name="TimeCircuits",
        routine_id=routine_id,
        routine_type="Start",
        request_params=[
            travel_method_key_param,
            TableStructParameter(
                short_name="travelMethodData",
                semantic="DATA",
                byte_position=5,
                table_key_ref=ref(travel_method_key_param.odx_id),
            ),
        ],
        functional_class=functional_class,
        description="Engage Time Circuits",
        sdgs=sdgs_map.get("TimeCircuits_Start"),
    )

    # 31 03 10 03 - TimeCircuits RequestResults
    step_dop = texttable_int_str_dop(
        dlr,
        "TimeCircuitsStepDop",
        [
            (0, "Idle"),
            (1, "Accelerating"),
            (2, "TemporalDisplacement"),
            (3, "Arrived"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(step_dop)

    # Optional, open-ended free-text message (e.g. populated once Arrived).
    # min_length=0 makes the trailing string genuinely optional, mirroring
    # the pattern used by transferdata.py's TransferRequestParameterRecord.
    message_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.TimeCircuitsMessageDop"),
        short_name="TimeCircuitsMessageDop",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UNICODE2STRING,
            internal_type=DataType.A_UNICODE2STRING,
        ),
        diag_coded_type=MinMaxLengthType(
            base_data_type=DataType.A_ASCIISTRING,
            base_type_encoding=Encoding.ISO_8859_1,
            termination=Termination.END_OF_PDU,
            min_length=0,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(message_dop)

    add_routine(
        dlr,
        name="TimeCircuits",
        routine_id=routine_id,
        routine_type="RequestResults",
        response_params=[
            ValueParameter(
                short_name="percentComplete",
                semantic="DATA",
                byte_position=4,
                dop_ref=ref(uint8_dop),
            ),
            ValueParameter(
                short_name="step",
                semantic="DATA",
                byte_position=5,
                dop_ref=ref(step_dop),
            ),
            ValueParameter(
                short_name="message",
                semantic="DATA",
                byte_position=6,
                dop_ref=ref(message_dop),
            ),
        ],
        functional_class=functional_class,
        description="Time Circuits Request Results",
        sdgs=sdgs_map.get("TimeCircuits_RequestResults"),
    )

    # 31 02 10 03 - TimeCircuits Stop
    add_routine(
        dlr,
        name="TimeCircuits",
        routine_id=routine_id,
        routine_type="Stop",
        functional_class=functional_class,
        description="Disengage Time Circuits",
        sdgs=sdgs_map.get("TimeCircuits_Stop"),
    )
