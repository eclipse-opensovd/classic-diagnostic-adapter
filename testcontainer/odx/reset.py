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
from odxtools.statetransitionref import StateTransitionRef

from helper import (
    derived_id,
    sid_parameter_pr,
    sid_parameter_rq,
    subfunction_rq,
    matching_request_parameter_subfunction,
    functional_class_ref,
    ref,
)


def add_reset_service(dlr: DiagLayerRaw, name: str, subfunction: int):
    request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{name}"),
        short_name=f"RQ_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x11),
                subfunction_rq(subfunction, "ResetType"),
            ]
        ),
    )
    dlr.requests.append(request)

    response = Response(
        odx_id=derived_id(dlr, f"PR.PR_{name}"),
        short_name=f"PR_{name}",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x11 + 0x40),
                matching_request_parameter_subfunction("ResetType"),
            ]
        ),
        response_type=ResponseType.POSITIVE,
    )
    dlr.positive_responses.append(response)

    state_transition_refs = []
    session_transitions = dlr.state_charts["Session"].state_transitions
    for state_transition in session_transitions:
        if state_transition.target_snref == "Default":
            state_transition_refs.append(
                StateTransitionRef(
                    ref_id=state_transition.odx_id.local_id,
                    ref_docs=state_transition.odx_id.doc_fragments,
                )
            )
    sa_transitions = dlr.state_charts["SecurityAccess"].state_transitions
    for state_transition in sa_transitions:
        if state_transition.target_snref == "Locked":
            state_transition_refs.append(
                StateTransitionRef(
                    ref_id=state_transition.odx_id.local_id,
                    ref_docs=state_transition.odx_id.doc_fragments,
                )
            )

    service = DiagService(
        odx_id=derived_id(dlr.odx_id, f"DC.{name}"),
        short_name=name,
        request_ref=ref(request),
        pos_response_refs=[ref(response)],
        state_transition_refs=state_transition_refs,
        functional_class_refs=[functional_class_ref(dlr, "EcuReset")],
    )

    dlr.diag_comms_raw.append(service)


def add_reset_services(dlr: DiagLayerRaw):
    # 11 01 HardReset
    add_reset_service(dlr, "HardReset", 1)
    # 11 03 SoftReset
    add_reset_service(dlr, "SoftReset", 3)
