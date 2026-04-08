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
from odxtools.request import Request
from odxtools.response import Response, ResponseType

from helper import (
    coded_const_int_parameter,
    derived_id,
    functional_class_ref,
    matching_request_parameter,
    matching_request_parameter_subfunction,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
    subfunction_rq,
)


def _routine_request(
    dlr: DiagLayerRaw, name: str, subfunction: int, routine_id: int
) -> Request:
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
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
        ),
    )
    dlr.requests.append(request)
    return request


def _routine_response(dlr: DiagLayerRaw, name: str) -> Response:
    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
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
        ),
    )
    dlr.positive_responses.append(response)
    return response


def _routine_service(
    dlr: DiagLayerRaw,
    name: str,
    long_name: str,
    request: Request,
    response: Response,
) -> DiagService:
    service = DiagService(
        odx_id=derived_id(dlr, f"DC.{name}"),
        short_name=name,
        long_name=long_name,
        functional_class_refs=[functional_class_ref(dlr, "Operations")],
        request_ref=ref(request),
        pos_response_refs=[ref(response)],
    )
    dlr.diag_comms_raw.append(service)
    return service


def add_routine_control_services(dlr: DiagLayerRaw):
    # 31 01 10 01 — SelfTest Start (synchronous, Start only)
    request = _routine_request(dlr, "SelfTest_Start", 0x01, 0x1001)
    response = _routine_response(dlr, "SelfTest_Start")
    _routine_service(dlr, "SelfTest_Start", "Self Test", request, response)

    # 31 01 10 02 — CalibrateSensors Start (asynchronous)
    request = _routine_request(dlr, "CalibrateSensors_Start", 0x01, 0x1002)
    response = _routine_response(dlr, "CalibrateSensors_Start")
    _routine_service(
        dlr, "CalibrateSensors_Start", "Calibrate Sensors", request, response
    )

    # 31 02 10 02 — CalibrateSensors Stop
    request = _routine_request(dlr, "CalibrateSensors_Stop", 0x02, 0x1002)
    response = _routine_response(dlr, "CalibrateSensors_Stop")
    _routine_service(
        dlr, "CalibrateSensors_Stop", "Calibrate Sensors Stop", request, response
    )

    # 31 03 10 02 — CalibrateSensors RequestResults
    request = _routine_request(dlr, "CalibrateSensors_RequestResults", 0x03, 0x1002)
    response = _routine_response(dlr, "CalibrateSensors_RequestResults")
    _routine_service(
        dlr,
        "CalibrateSensors_RequestResults",
        "Calibrate Sensors Request Results",
        request,
        response,
    )
