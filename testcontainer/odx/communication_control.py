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
from odxtools.parameters.codedconstparameter import CodedConstParameter
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.odxtypes import DataType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.compumethods.identicalcompumethod import IdenticalCompuMethod
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.physicaltype import PhysicalType

from helper import (
    sid_parameter_rq,
    sid_parameter_pr,
    derived_id,
    subfunction_rq,
    matching_request_parameter_subfunction,
    functional_class_ref,
    ref,
)


def add_communication_control_service(
    dlr: DiagLayerRaw,
    name: str,
    control_type: int,
    description: str,
):
    """
    Add a CommunicationControl service (0x28).

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "EnableRxAndTx")
        control_type: The control type subfunction value
        description: Description of the control type
    """
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}_Control"),
        short_name=f"RQ_{name}_Control",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x28),
                subfunction_rq(control_type, "ControlType"),
                CodedConstParameter(
                    short_name="CommunicationType",
                    semantic="DATA",
                    byte_position=2,
                    coded_value_raw=str(0x01),  # normalCommunicationMessages
                    diag_coded_type=StandardLengthType(
                        base_data_type=DataType.A_UINT32, bit_length=8
                    ),
                ),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}_Control"),
        short_name=f"PR_{name}_Control",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x28 + 0x40),
                matching_request_parameter_subfunction("ControlType"),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}_Control"),
            short_name=f"{name}_Control",
            long_name=f"Communication Control - {description}",
            functional_class_refs=[functional_class_ref(dlr, "CommCtrl")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_communication_control_service_with_param(
    dlr: DiagLayerRaw,
    name: str,
    control_type: int,
    description: str,
    param_name: str,
    param_dop: DataObjectProperty,
):
    """
    Add a CommunicationControl service (0x28) with a custom parameter.

    Args:
        dlr: The diagnostic layer
        name: Service name (e.g., "TemporalSync")
        control_type: The control type subfunction value
        description: Description of the control type
        param_name: Name of the custom parameter
        param_dop: Data object property for the custom parameter
    """
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}_Control"),
        short_name=f"RQ_{name}_Control",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x28),
                subfunction_rq(control_type, "ControlType"),
                CodedConstParameter(
                    short_name="CommunicationType",
                    semantic="DATA",
                    byte_position=2,
                    coded_value_raw=str(0x01),  # normalCommunicationMessages
                    diag_coded_type=StandardLengthType(
                        base_data_type=DataType.A_UINT32, bit_length=8
                    ),
                ),
                ValueParameter(
                    short_name=param_name,
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=ref(param_dop),
                ),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{name}_Control"),
        short_name=f"PR_{name}_Control",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x28 + 0x40),
                matching_request_parameter_subfunction("ControlType"),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}_Control"),
            short_name=f"{name}_Control",
            long_name=f"Communication Control - {description}",
            functional_class_refs=[functional_class_ref(dlr, "CommCtrl")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_communication_control_services(dlr: DiagLayerRaw):
    """
    Add all CommunicationControl (0x28) services to the diagnostic layer.

    Implements the following control types:
    - 0x00: enableRxAndEnableTx
    - 0x01: enableRxAndDisableTx
    - 0x02: disableRxAndEnableTx
    - 0x03: disableRxAndDisableTx
    - 0x04: enableRxAndDisableTxWithEnhancedAddressInformation
    - 0x05: enableRxAndTxWithEnhancedAddressInformation
    - 0x88: TemporalSync (custom control type with temporalEraId parameter)
    """

    # Add temporalEraId data object property (32-bit signed integer)
    temporal_era_id_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.temporalEraId"),
        short_name="temporalEraId",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_INT32,
            internal_type=DataType.A_INT32,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_INT32),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_INT32, bit_length=32
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(temporal_era_id_dop)

    # 28 00 - Enable RX and Enable TX
    add_communication_control_service(
        dlr,
        "EnableRxAndEnableTx",
        0x00,
        "Enable Receive and Enable Transmit",
    )

    # 28 01 - Enable RX and Disable TX
    add_communication_control_service(
        dlr,
        "EnableRxAndDisableTx",
        0x01,
        "Enable Receive and Disable Transmit",
    )

    # 28 02 - Disable RX and Enable TX
    add_communication_control_service(
        dlr,
        "DisableRxAndEnableTx",
        0x02,
        "Disable Receive and Enable Transmit",
    )

    # 28 03 - Disable RX and Disable TX
    add_communication_control_service(
        dlr,
        "DisableRxAndDisableTx",
        0x03,
        "Disable Receive and Disable Transmit",
    )

    # 28 04 - Enable RX and Disable TX with Enhanced Address Information
    add_communication_control_service(
        dlr,
        "EnableRxAndDisableTxWithEnhancedAddressInformation",
        0x04,
        "Enable Receive and Disable Transmit with Enhanced Address Information",
    )

    # 28 05 - Enable RX and TX with Enhanced Address Information
    add_communication_control_service(
        dlr,
        "EnableRxAndTxWithEnhancedAddressInformation",
        0x05,
        "Enable Receive and Transmit with Enhanced Address Information",
    )

    # 28 88 - TemporalSync (custom control type with temporalEraId parameter)
    add_communication_control_service_with_param(
        dlr,
        "TemporalSync",
        0x88,
        "Temporal Synchronization",
        "temporalEraId",
        temporal_era_id_dop,
    )
