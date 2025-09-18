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
from odxtools.statetransitionref import StateTransitionRef

from helper import find_functional_class


def add_reset_service(dlr: DiagLayerRaw, name: str, subfunction: int):
    request = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_{name}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_{name}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x11),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="ResetType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(subfunction),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
        ]),
    )
    dlr.requests.append(request)

    response = Response(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_{name}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_{name}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x11 + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            MatchingRequestParameter(
                short_name="ResetType",
                semantic="SUBFUNCTION",
                byte_position=1,
                request_byte_position=1,
                byte_length=1
            ),
        ]),
        response_type=ResponseType.POSITIVE,
    )
    dlr.positive_responses.append(response)

    state_transition_refs = []
    session_transitions = dlr.state_charts["Session"].state_transitions
    for state_transition in session_transitions:
        if state_transition.target_snref == "Default":
            state_transition_refs.append(StateTransitionRef(ref_id=state_transition.odx_id.local_id,
                                                            ref_docs=state_transition.odx_id.doc_fragments))
    sa_transitions = dlr.state_charts["SecurityAccess"].state_transitions
    for state_transition in sa_transitions:
        if state_transition.target_snref == "Locked":
            state_transition_refs.append(StateTransitionRef(ref_id=state_transition.odx_id.local_id,
                                                            ref_docs=state_transition.odx_id.doc_fragments))

    reset_class = find_functional_class(dlr, "EcuReset")
    service=DiagService(
        odx_id=OdxLinkId(local_id=f"{dlr.odx_id.local_id}.DC.{name}", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=name,
        request_ref=OdxLinkRef.from_id(request.odx_id),
        pos_response_refs=[OdxLinkRef.from_id(response.odx_id)],
        state_transition_refs=state_transition_refs,
        functional_class_refs=[OdxLinkRef.from_id(reset_class.odx_id)],
    )

    dlr.diag_comms_raw.append(service)


def add_reset_services(dlr: DiagLayerRaw):
    # 11 01 HardReset
    add_reset_service(dlr, "HardReset", 1)
    # 11 03 SoftReset
    add_reset_service(dlr, "SoftReset", 3)
