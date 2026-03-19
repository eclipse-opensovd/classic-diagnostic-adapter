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
from odxtools.compumethods.identicalcompumethod import IdenticalCompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.encoding import Encoding
from odxtools.minmaxlengthtype import MinMaxLengthType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxtypes import DataType
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.termination import Termination
from packaging.version import Version

from helper import (
    derived_id,
    sid_parameter_rq,
    sid_parameter_pr,
    ref,
    functional_class_ref,
    matching_request_parameter_did,
    did_parameter_rq,
    texttable_int_str_dop,
    find_dop_by_shortname,
)
from security_access import add_state_chart_security_access
from sessions import add_default_session_services, add_state_chart_session

ODX_VERSION = Version("2.2.0")


def add_state_charts(dlr: DiagLayerRaw):
    add_state_chart_session(dlr)
    add_state_chart_security_access(dlr)


def add_common_datatypes(dlr: DiagLayerRaw):
    compu_method_identical_uint32 = IdenticalCompuMethod(
        category=CompuCategory.IDENTICAL,
        physical_type=DataType.A_UINT32,
        internal_type=DataType.A_UINT32,
    )

    compu_method_identical_unicode2string = IdenticalCompuMethod(
        category=CompuCategory.IDENTICAL,
        physical_type=DataType.A_UNICODE2STRING,
        internal_type=DataType.A_UNICODE2STRING,
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=derived_id(dlr, "DOP.IDENTICAL_UINT_8"),
            short_name="IDENTICAL_UINT_8",
            compu_method=IdenticalCompuMethod(
                category=CompuCategory.IDENTICAL,
                physical_type=DataType.A_UINT32,
                internal_type=DataType.A_UINT32,
            ),
            physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
            diag_coded_type=StandardLengthType(
                base_data_type=DataType.A_UINT32, bit_length=8
            ),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=derived_id(dlr, "DOP.IDENTICAL_UINT_16"),
            short_name="IDENTICAL_UINT_16",
            compu_method=compu_method_identical_uint32,
            physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
            diag_coded_type=StandardLengthType(
                base_data_type=DataType.A_UINT32, bit_length=16
            ),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=derived_id(dlr, "DOP.IDENTICAL_UINT_32"),
            short_name="IDENTICAL_UINT_32",
            compu_method=compu_method_identical_uint32,
            physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
            diag_coded_type=StandardLengthType(
                base_data_type=DataType.A_UINT32, bit_length=32
            ),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=derived_id(dlr, "DOP.IDENTICAL_STR_END_OF_PDU"),
            short_name="IDENTICAL_STR_END_OF_PDU",
            compu_method=compu_method_identical_unicode2string,
            diag_coded_type=MinMaxLengthType(
                base_data_type=DataType.A_ASCIISTRING,
                base_type_encoding=Encoding.ISO_8859_1,
                termination=Termination.END_OF_PDU,
                min_length=1,
            ),
            physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        texttable_int_str_dop(
            dlr,
            "EcuSessionType",
            [
                (0x01, "Default"),
                (0x02, "Programming"),
                (0x03, "Extended"),
                (0x44, "Custom"),
            ],
        )
    )


def add_service_did(
    dlr: DiagLayerRaw,
    service_name: str,
    property_name: str,
    did: int,
    dop: DataObjectProperty,
    add_write: bool = False,
    funct_class: str = "Ident",
    long_name: str | None = None,
):
    if not dop:
        raise Exception("dop property is required")
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{service_name}_Read"),
        short_name=f"RQ_{service_name}_Read",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x22),
                did_parameter_rq(did),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{service_name}_Read"),
        short_name=f"PR_{service_name}_Read",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x22 + 0x40),
                matching_request_parameter_did("DID_PR"),
                ValueParameter(
                    short_name=property_name,
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=ref(dop),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{service_name}_Read"),
            short_name=f"{service_name}_Read",
            long_name=long_name,
            functional_class_refs=[functional_class_ref(dlr, funct_class)],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )

    if not add_write:
        return

    request_write = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{service_name}_Write"),
        short_name=f"RQ_{service_name}_Write",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x2E),
                did_parameter_rq(did),
                ValueParameter(
                    short_name=property_name,
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=ref(dop),
                ),
            ]
        ),
    )
    dlr.requests.append(request_write)

    response_write = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{service_name}_Write"),
        short_name=f"PR_{service_name}_Write",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x2E + 0x40),
                matching_request_parameter_did("DID_PR"),
            ]
        ),
    )
    dlr.positive_responses.append(response_write)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{service_name}"),
            short_name=f"{service_name}_Write",
            long_name=long_name,
            functional_class_refs=[functional_class_ref(dlr, funct_class)],
            request_ref=ref(request_write),
            pos_response_refs=[ref(response_write)],
        )
    )


def add_vin_service(dlr: DiagLayerRaw):
    vin_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.VIN_17Byte"),
        short_name="VIN_17Byte",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UNICODE2STRING,
            internal_type=DataType.A_UNICODE2STRING,
        ),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_ASCIISTRING,
            base_type_encoding=Encoding.ISO_8859_1,
            bit_length=136,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(vin_dop)
    add_service_did(
        dlr,
        "VINDataIdentifier",
        "VIN",
        0xF190,
        vin_dop,
        add_write=True,
        long_name="Vehicle Identification Number",
    )


def add_ident_service(dlr: DiagLayerRaw):
    uint24_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.IDENTICAL_UINT_24"),
        short_name="IDENTICAL_UINT_24",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UINT32,
            internal_type=DataType.A_UINT32,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_UINT32, bit_length=24
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(uint24_dop)
    add_service_did(
        dlr, "Identification", "Identification", 0xF100, uint24_dop, add_write=False
    )


def add_session_type_service(dlr: DiagLayerRaw):
    add_service_did(
        dlr,
        "ActiveDiagnosticSessionDataIdentifier",
        "EcuSessionType",
        0xF186,
        find_dop_by_shortname(dlr, "EcuSessionType"),
        add_write=False,
    )


def add_common_diag_comms(dlr: DiagLayerRaw):
    add_vin_service(dlr)
    add_session_type_service(dlr)
    add_ident_service(dlr)
    add_default_session_services(dlr)
