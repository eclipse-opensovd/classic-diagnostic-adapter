from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkId, OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.parameters.codedconstparameter import CodedConstParameter
from odxtools.parameters.matchingrequestparameter import MatchingRequestParameter
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.state import State
from odxtools.statechart import StateChart
from odxtools.statetransition import StateTransition
from odxtools.statetransitionref import StateTransitionRef

##
# adds state charts, states and session switching services (10 xx) for them
##

def add_session_service(dlr: DiagLayerRaw, target_state_session: str, session: int, from_state_transitions_session: list[str]):
    request = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_{target_state_session}_Start", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_{target_state_session}_Start",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x10),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="SessionType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(session),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
        ]),
    )
    dlr.requests.append(request)
    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_{target_state_session}_Start", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_{target_state_session}_Start",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x10 + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
            MatchingRequestParameter(
                short_name="SessionType",
                semantic="SUBFUNCTION",
                byte_position=1,
                request_byte_position=1,
                byte_length=1,
            ),
        ]),
    )
    dlr.positive_responses.append(response)

    state_transition_refs_session = []
    session_transitions_session = NamedItemList(dlr.state_charts["Session"].state_transitions)
    for from_state in from_state_transitions_session:
        stt = session_transitions_session[f"{from_state}_{target_state_session}"]
        if not stt:
            raise Exception(f"no transition {from_state}_{target_state_session}")
        # TODO switch to StateTransitionRef.from_id(stt.odx_id) once it's implemented
        state_transition_refs_session.append(StateTransitionRef(ref_id=stt.odx_id.local_id, ref_docs=stt.odx_id.doc_fragments))

    funct_class = dlr.functional_classes.get("Session")
    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DC.{target_state_session}_Start", doc_fragments=dlr.odx_id.doc_fragments),
            short_name=f"{target_state_session}_Start",
            functional_class_refs=[OdxLinkRef.from_id(funct_class.odx_id)],
            request_ref=OdxLinkRef.from_id(request.odx_id),
            pos_response_refs=[OdxLinkRef.from_id(response.odx_id)],
            state_transition_refs=state_transition_refs_session,
        )
    )


def add_state_chart_session(dlr: DiagLayerRaw):
    doc_frags = dlr.odx_id.doc_fragments

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

    odx_id = OdxLinkId(f"{dlr.odx_id.local_id}.SC.Session", doc_fragments=doc_frags)
    dlr.state_charts.append(
        StateChart(
            odx_id=odx_id,
            short_name="Session",
            semantic="SESSION",
            start_state_snref="Default",
            states=NamedItemList(
                [State(odx_id=OdxLinkId(f"{odx_id.local_id}.ST.{name}", doc_frags), short_name=name) for name in
                 states]),
            state_transitions=[StateTransition(
                odx_id=OdxLinkId(f"{odx_id.local_id}.STT.{transition[0]}_{transition[1]}", doc_fragments=doc_frags),
                short_name=f"{transition[0]}_{transition[1]}",
                source_snref=transition[0],
                target_snref=transition[1],
            ) for transition in state_transitions]
        )
    )

def add_default_session_services(dlr: DiagLayerRaw):
    # session
    # 10 01 Default_Start
    add_session_service(dlr, "Default", 1, ["Default", "Programming", "Extended", "Custom"])
    # 10 02 Programming_Start
    add_session_service(dlr, "Programming", 2, ["Default", "Programming", "Extended"])
    # 10 03 Extended_Start
    add_session_service(dlr, "Extended", 3, ["Default", "Programming", "Extended"])
    # 10 04 Custom_Start
    add_session_service(dlr, "Custom", 0x45, ["Default", "Custom"])
