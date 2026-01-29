# Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.nameditemlist import NamedItemList
from odxtools.request import Request
from odxtools.response import Response, ResponseType

from helper import (
    sid_parameter_rq,
    sid_parameter_pr,
    derived_id,
    subfunction_rq,
    matching_request_parameter_subfunction,
    functional_class_ref,
    ref,
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

    # 85 01 - DTC Setting On
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_On",
        0x01,
        "DTC Setting On",
    )

    # 85 02 - DTC Setting Off
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_Off",
        0x02,
        "DTC Setting Off",
    )

    # 85 42 - TimeTravelDTCsOn (custom vendor-specific)
    add_dtc_setting_service(
        dlr,
        "DTC_Setting_Mode_TimeTravelDTCsOn",
        0x42,
        "DTC Setting Time Travel DTCs On",
    )
