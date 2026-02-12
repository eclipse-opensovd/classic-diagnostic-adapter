# Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
from odxtools.state import State
from odxtools.statechart import StateChart
from odxtools.statetransition import StateTransition
from odxtools.statetransitionref import StateTransitionRef

from helper import (
    sid_parameter_rq,
    sid_parameter_pr,
    subfunction_rq,
    matching_request_parameter_subfunction,
    derived_id,
    functional_class_ref,
    ref,
)


##
# adds state charts, states and session switching services (10 xx) for them
##


def add_session_service(
    dlr: DiagLayerRaw,
    target_state_session: str,
    session: int,
    from_state_transitions_session: list[str],
):
    request = Request(
        odx_id=derived_id(dlr, f"RQ..RQ_{target_state_session}_Start"),
        short_name=f"RQ_{target_state_session}_Start",
        parameters=NamedItemList(
            [sid_parameter_rq(0x10), subfunction_rq(session, "SessionType")]
        ),
    )
    dlr.requests.append(request)
    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{target_state_session}_Start"),
        short_name=f"PR_{target_state_session}_Start",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x10 + 0x40),
                matching_request_parameter_subfunction("SessionType"),
            ]
        ),
    )
    dlr.positive_responses.append(response)

    state_transition_refs_session = []
    session_transitions_session = NamedItemList(
        dlr.state_charts["Session"].state_transitions
    )
    for from_state in from_state_transitions_session:
        stt = session_transitions_session[f"{from_state}_{target_state_session}"]
        if not stt:
            raise Exception(f"no transition {from_state}_{target_state_session}")
        # TODO switch to StateTransitionRef.from_id(stt.odx_id) once it's implemented
        state_transition_refs_session.append(
            StateTransitionRef(
                ref_id=stt.odx_id.local_id, ref_docs=stt.odx_id.doc_fragments
            )
        )

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{target_state_session}_Start"),
            short_name=f"{target_state_session}_Start",
            functional_class_refs=[functional_class_ref(dlr, "Session")],
            request_ref=ref(request),
            pos_response_refs=[ref(response)],
            state_transition_refs=state_transition_refs_session,
        )
    )


def add_state_chart_session(dlr: DiagLayerRaw):
    # todo use doc_frags
    # doc_frags = dlr.odx_id.doc_fragments

    states = ["Default", "Programming", "Extended", "Custom"]

    state_transitions = [
        ("Default", "Default"),
        ("Default", "Programming"),
        ("Default", "Extended"),
        ("Default", "Custom"),
        ("Programming", "Default"),
        ("Programming", "Programming"),
        ("Programming", "Extended"),
        ("Extended", "Default"),
        ("Extended", "Programming"),
        ("Extended", "Extended"),
        ("Custom", "Default"),
        ("Custom", "Custom"),
    ]

    odx_id = derived_id(dlr, "SC.Session")
    dlr.state_charts.append(
        StateChart(
            odx_id=odx_id,
            short_name="Session",
            semantic="SESSION",
            start_state_snref="Default",
            states=NamedItemList(
                [
                    State(odx_id=derived_id(odx_id, f"ST.{name}"), short_name=name)
                    for name in states
                ]
            ),
            state_transitions=[
                StateTransition(
                    odx_id=derived_id(odx_id, f"STT.{transition[0]}_{transition[1]}"),
                    short_name=f"{transition[0]}_{transition[1]}",
                    source_snref=transition[0],
                    target_snref=transition[1],
                )
                for transition in state_transitions
            ],
        )
    )


def add_default_session_services(dlr: DiagLayerRaw):
    # session
    # 10 01 Default_Start
    add_session_service(
        dlr, "Default", 1, ["Default", "Programming", "Extended", "Custom"]
    )
    # 10 02 Programming_Start
    add_session_service(dlr, "Programming", 2, ["Default", "Programming", "Extended"])
    # 10 03 Extended_Start
    add_session_service(dlr, "Extended", 3, ["Default", "Programming", "Extended"])
    # 10 44 Custom_Start
    add_session_service(dlr, "Custom", 0x44, ["Default", "Custom"])
