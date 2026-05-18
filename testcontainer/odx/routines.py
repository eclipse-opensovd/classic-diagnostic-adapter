# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.nameditemlist import NamedItemList
from odxtools.parameters.parameter import Parameter
from odxtools.request import Request
from odxtools.response import Response, ResponseType

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
)
from odxtools.parameters.valueparameter import ValueParameter

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
