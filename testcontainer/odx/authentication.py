from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.nameditemlist import NamedItemList
from odxtools.parameters.valueparameter import ValueParameter
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
    texttable_int_str_dop,
    find_dop_by_shortname,
)


def add_deauthentication(dlr: DiagLayerRaw):
    request = Request(
        odx_id=derived_id(dlr.odx_id, "RQ.RQ_Authentication_Deauthenticate"),
        short_name=f"RQ_Authentication_Deauthenticate",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x29),
                subfunction_rq(0x00),
            ]
        ),
    )
    dlr.requests.append(request)
    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, "PR.PR_Authentication_Deauthenticate"),
        short_name=f"PR_Authentication_Deauthenticate",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x29 + 0x40),
                matching_request_parameter_subfunction("SUBFUNCTION"),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, "DC.Authentication_Deauthenticate"),
            short_name=f"Authentication_Deauthenticate",
            functional_class_refs=[functional_class_ref(dlr, "Authentication")],
            request_ref=ref(request.odx_id),
            pos_response_refs=[ref(response.odx_id)],
        )
    )


def add_configuration(dlr: DiagLayerRaw):
    request = Request(
        odx_id=derived_id(dlr.odx_id, "RQ.RQ_Authentication_Configuration"),
        short_name=f"RQ_Authentication_Configuration",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x29),
                subfunction_rq(0x08),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, "PR.PR_Authentication_Configuration"),
        short_name=f"PR_Authentication_Configuration",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x29 + 0x40),
                matching_request_parameter_subfunction("SUBFUNCTION"),
                ValueParameter(
                    short_name="AuthenticationReturnParameter",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(find_dop_by_shortname(dlr, "AuthReturnParam")),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, "DC.Authentication_Configuration"),
            short_name=f"Authentication_Configuration",
            functional_class_refs=[functional_class_ref(dlr, "Authentication")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
        )
    )


def add_authentication_services(dlr: DiagLayerRaw):
    auth_return_param_dop = texttable_int_str_dop(
        dlr,
        "AuthReturnParam",
        [
            (0x00, "Request Accepted"),
            (0x01, "General Reject"),
            (0x02, "AuthenticationConfiguration APCE"),
            (0x03, "AuthenticationConfiguration ACR with asymmetric cryptography"),
            (0x04, "AuthenticationConfiguration ACR with symmetric cryptography"),
            (0x10, "DeAuthentication successful"),
            (0x11, "CertificateVerified, OwnershipVerificationNecessary"),
            (0x12, "OwnershipVerified, AuthenticationComplete"),
            (0x13, "CertificateVerified"),
        ],
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(auth_return_param_dop)

    # 29 00
    add_deauthentication(dlr)
    # 29 08
    add_configuration(dlr)
    # APCE and ACR must be implemented once we support /modes/authentication
    # 29 01
    # 29 03
    # 29 04
    pass
