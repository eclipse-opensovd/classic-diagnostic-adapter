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

"""Authentication (SID 0x29) services according to ISO 14229-1:2020 clause 10.6.

Service and parameter names follow the ISO 14229-1 sub-function and parameter
names. Each `lengthOf<X>` + `<X>` pair of the standard is modelled as a single
parameter `<X>` with a 2 byte leading length DOP.
"""

from dataclasses import dataclass

from helper import (
    derived_id,
    find_dop_by_shortname,
    functional_class_ref,
    matching_request_parameter_subfunction,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
    subfunction_rq,
    texttable_int_str_dop,
)
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compumethod import CompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.leadinglengthinfotype import LeadingLengthInfoType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxtypes import DataType
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.radix import Radix
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType

SID = 0x29

DOP_RETURN_PARAMETER = "AuthenticationReturnParameter"
DOP_UINT_8 = "IDENTICAL_UINT_8"
DOP_UINT_16 = "IDENTICAL_UINT_16"
DOP_ALGORITHM_INDICATOR = "Authentication_AlgorithmIndicator"
DOP_LEADING_LENGTH_BYTES = "Authentication_LeadingLength2ByteField"


@dataclass(frozen=True)
class Param:
    short_name: str
    dop: str
    # byte size if fixed, None for variable length (leading length) parameters
    size: int | None


def _bytes(short_name: str) -> Param:
    """`lengthOf<short_name>` (2 bytes) followed by `<short_name>`."""
    return Param(short_name, DOP_LEADING_LENGTH_BYTES, None)


RETURN_PARAMETER = Param("authenticationReturnParameter", DOP_RETURN_PARAMETER, 1)
COMMUNICATION_CONFIGURATION = Param("communicationConfiguration", DOP_UINT_8, 1)
ALGORITHM_INDICATOR = Param("algorithmIndicator", DOP_ALGORITHM_INDICATOR, 16)


@dataclass(frozen=True)
class SubFunction:
    id: int
    name: str
    request: list[Param]
    response: list[Param]


SUB_FUNCTIONS = [
    SubFunction(0x00, "DeAuthenticate", [], [RETURN_PARAMETER]),
    SubFunction(
        0x01,
        "VerifyCertificateUnidirectional",
        [COMMUNICATION_CONFIGURATION, _bytes("certificateClient"), _bytes("challengeClient")],
        [RETURN_PARAMETER, _bytes("challengeServer"), _bytes("ephemeralPublicKeyServer")],
    ),
    SubFunction(
        0x02,
        "VerifyCertificateBidirectional",
        [COMMUNICATION_CONFIGURATION, _bytes("certificateClient"), _bytes("challengeClient")],
        [
            RETURN_PARAMETER,
            _bytes("challengeServer"),
            _bytes("certificateServer"),
            _bytes("proofOfOwnershipServer"),
            _bytes("ephemeralPublicKeyServer"),
        ],
    ),
    SubFunction(
        0x03,
        "ProofOfOwnership",
        [_bytes("proofOfOwnershipClient"), _bytes("ephemeralPublicKeyClient")],
        [RETURN_PARAMETER, _bytes("sessionKeyInfo")],
    ),
    SubFunction(
        0x04,
        "TransmitCertificate",
        [Param("certificateEvaluationId", DOP_UINT_16, 2), _bytes("certificateData")],
        [RETURN_PARAMETER],
    ),
    SubFunction(
        0x05,
        "RequestChallengeForAuthentication",
        [COMMUNICATION_CONFIGURATION, ALGORITHM_INDICATOR],
        [
            RETURN_PARAMETER,
            ALGORITHM_INDICATOR,
            _bytes("challengeServer"),
            _bytes("neededAdditionalParameter"),
        ],
    ),
    SubFunction(
        0x06,
        "VerifyProofOfOwnershipUnidirectional",
        [
            ALGORITHM_INDICATOR,
            _bytes("proofOfOwnershipClient"),
            _bytes("challengeClient"),
            _bytes("additionalParameter"),
        ],
        [RETURN_PARAMETER, ALGORITHM_INDICATOR, _bytes("sessionKeyInfo")],
    ),
    SubFunction(
        0x07,
        "VerifyProofOfOwnershipBidirectional",
        [
            ALGORITHM_INDICATOR,
            _bytes("proofOfOwnershipClient"),
            _bytes("challengeClient"),
            _bytes("additionalParameter"),
        ],
        [
            RETURN_PARAMETER,
            ALGORITHM_INDICATOR,
            _bytes("proofOfOwnershipServer"),
            _bytes("sessionKeyInfo"),
        ],
    ),
    SubFunction(0x08, "AuthenticationConfiguration", [], [RETURN_PARAMETER]),
]


def _value_parameters(dlr: DiagLayerRaw, params: list[Param]) -> list[ValueParameter]:
    """Creates the value parameters following SID and sub-function (byte 2 onward).

    Byte positions are only set while they are statically known, parameters
    after a variable length parameter are placed directly after their predecessor.
    """
    result = []
    byte_position: int | None = 2
    for param in params:
        result.append(
            ValueParameter(
                short_name=param.short_name,
                semantic="DATA",
                byte_position=byte_position,
                dop_ref=ref(find_dop_by_shortname(dlr, param.dop)),
            )
        )
        if byte_position is not None and param.size is not None:
            byte_position += param.size
        else:
            byte_position = None
    return result


def add_authentication_service(dlr: DiagLayerRaw, sub_function: SubFunction):
    name = f"Authentication_{sub_function.name}"

    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(SID),
                subfunction_rq(sub_function.id, short_name="authenticationTask"),
                *_value_parameters(dlr, sub_function.request),
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
                sid_parameter_pr(SID + 0x40),
                matching_request_parameter_subfunction("authenticationTask"),
                *_value_parameters(dlr, sub_function.response),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{name}"),
            short_name=name,
            functional_class_refs=[functional_class_ref(dlr, "Authentication")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def _byte_field_dop(dlr: DiagLayerRaw, short_name: str, diag_coded_type) -> DataObjectProperty:
    return DataObjectProperty(
        odx_id=derived_id(dlr, f"DOP.{short_name}"),
        short_name=short_name,
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        diag_coded_type=diag_coded_type,
        physical_type=PhysicalType(
            base_data_type=DataType.A_BYTEFIELD,
            display_radix=Radix.HEX,
        ),
    )


def add_authentication_services(dlr: DiagLayerRaw):
    dops = dlr.diag_data_dictionary_spec.data_object_props
    # ISO 14229-1:2020 Table 98 - authenticationReturnParameter
    dops.append(
        texttable_int_str_dop(
            dlr,
            DOP_RETURN_PARAMETER,
            [
                (0x00, "RequestAccepted"),
                (0x01, "GeneralReject"),
                (0x02, "AuthenticationConfiguration APCE"),
                (0x03, "AuthenticationConfiguration ACR with asymmetric cryptography"),
                (0x04, "AuthenticationConfiguration ACR with symmetric cryptography"),
                (0x10, "DeAuthentication successful"),
                (0x11, "CertificateVerified, OwnershipVerificationNecessary"),
                (0x12, "OwnershipVerified, AuthenticationComplete"),
                (0x13, "CertificateVerified"),
            ],
        )
    )
    dops.append(
        _byte_field_dop(
            dlr,
            DOP_ALGORITHM_INDICATOR,
            StandardLengthType(base_data_type=DataType.A_BYTEFIELD, bit_length=16 * 8),
        )
    )
    dops.append(
        _byte_field_dop(
            dlr,
            DOP_LEADING_LENGTH_BYTES,
            LeadingLengthInfoType(base_data_type=DataType.A_BYTEFIELD, bit_length=16),
        )
    )

    for sub_function in SUB_FUNCTIONS:
        add_authentication_service(dlr, sub_function)
