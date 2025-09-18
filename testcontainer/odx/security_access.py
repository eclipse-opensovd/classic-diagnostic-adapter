from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compumethod import CompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.minmaxlengthtype import MinMaxLengthType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkId, OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.parameters.codedconstparameter import CodedConstParameter
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.radix import Radix
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.state import State
from odxtools.statechart import StateChart
from odxtools.statetransition import StateTransition
from odxtools.statetransitionref import StateTransitionRef
from odxtools.termination import Termination

from helper import find_state_transition


##
# adds state charts, states and session switching services (27 xx) for them
##

def add_state_chart_security_access(dlr: DiagLayerRaw):
    doc_frags = dlr.odx_id.doc_fragments

    states = ["Locked", "Level_3", "Level_5", "Level_7"]

    state_transitions = [
        ("Locked", "Locked"),
        ("Locked", "Level_3"),
        ("Locked", "Level_5"),
        ("Locked", "Level_7"),
        ("Level_3", "Locked"),
        ("Level_5", "Locked"),
        ("Level_7", "Locked"),
    ]

    odx_id = OdxLinkId(f"{dlr.odx_id.local_id}.SC.SecurityAccess", doc_fragments=doc_frags)

    dlr.state_charts.append(
        StateChart(
            odx_id=odx_id,
            short_name="SecurityAccess",
            semantic="SECURITY",
            start_state_snref="Locked",
            states=NamedItemList(
                [State(odx_id=OdxLinkId(f"{odx_id.local_id}.ST.{name}", doc_frags), short_name=name)
                 for name in states]),
            state_transitions=[StateTransition(
                odx_id=OdxLinkId(f"{odx_id.local_id}.STT.{transition[0]}_{transition[1]}", doc_fragments=doc_frags),
                short_name=f"{transition[0]}_{transition[1]}",
                source_snref=transition[0],
                target_snref=transition[1],
            ) for transition in state_transitions]
        )
    )


def add_request_seed_service(dlr: DiagLayerRaw, level: int, end_of_pdu_array_dop: DataObjectProperty):
    request = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_RequestSeed_Level_{level}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_RequestSeed_Level_{level}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x27),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="SecurityAccessType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(level),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
        ]),
    )
    dlr.requests.append(request)

    response = Response(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_RequestSeed_Level_{level}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_RequestSeed_Level_{level}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x27 + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="SecurityAccessType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(level),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
            ValueParameter(
                short_name="SecuritySeed",
                semantic="DATA",
                byte_position=2,
                dop_ref=OdxLinkRef.from_id(end_of_pdu_array_dop.odx_id),
            )
        ]),
        response_type=ResponseType.POSITIVE,
    )
    dlr.positive_responses.append(response)

    service=DiagService(
        odx_id=OdxLinkId(local_id=f"{dlr.odx_id.local_id}.DC.RequestSeed_Level_{level}", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RequestSeed_Level_{level}",
        request_ref=OdxLinkRef.from_id(request.odx_id),
        pos_response_refs=[OdxLinkRef.from_id(response.odx_id)]
    )

    dlr.diag_comms_raw.append(service)


def add_send_key_service(dlc: DiagLayerContainer, dlr: DiagLayerRaw, level: int, end_of_pdu_array_dop: DataObjectProperty):
    request = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_SendKey_Level_{level}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_SendKey_Level_{level}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x27),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="SecurityAccessType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(level + 1),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
            ValueParameter(
                short_name="SecurityKey",
                semantic="DATA",
                byte_position=2,
                dop_ref=OdxLinkRef.from_id(end_of_pdu_array_dop.odx_id),
            )
        ]),
    )
    dlr.requests.append(request)

    response = Response(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_RequestSeed_Level_{level}",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_RequestSeed_Level_{level}",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x27 + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="SecurityAccessType",
                semantic="SUBFUNCTION",
                byte_position=1,
                coded_value_raw=str(level + 1),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
        ]),
        response_type=ResponseType.POSITIVE,
    )
    dlr.positive_responses.append(response)

    stt = find_state_transition(dlc, f"Locked_Level_{level}")

    service=DiagService(
        odx_id=OdxLinkId(local_id=f"{dlr.odx_id.local_id}.DC.SendKey_Level_{level}", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"SendKey_Level_{level}",
        request_ref=OdxLinkRef.from_id(request.odx_id),
        pos_response_refs=[OdxLinkRef.from_id(response.odx_id)],
        state_transition_refs=[StateTransitionRef(ref_id=stt.odx_id.local_id,ref_docs=stt.odx_id.doc_fragments)],
    )

    dlr.diag_comms_raw.append(service)


def add_security_access_services(dlc: DiagLayerContainer, dlr: DiagLayerRaw):
    end_of_pdu_array_dop = DataObjectProperty(
        odx_id=OdxLinkId(local_id=f"{dlr.odx_id.local_id}.DOP.SecurityAccess_EndOfPduByteArray",
                         doc_fragments=dlr.odx_id.doc_fragments),
        short_name="SecurityAccess_EndOfPduByteArray",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        diag_coded_type=MinMaxLengthType(
            base_type_encoding=None,
            base_data_type=DataType.A_BYTEFIELD,
            min_length=1,
            max_length=255,
            termination=Termination.END_OF_PDU,
        ),
        physical_type=PhysicalType(
            base_data_type=DataType.A_BYTEFIELD,
            display_radix=Radix.HEX,
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(end_of_pdu_array_dop)

    # 27 03 RequestSeed_Level_3
    add_request_seed_service(dlr, 3, end_of_pdu_array_dop)
    # 27 04 SendKey_Level_3
    add_send_key_service(dlc, dlr, 3, end_of_pdu_array_dop)
    # 27 05 RequestSeed_Level_5
    add_request_seed_service(dlr, 5, end_of_pdu_array_dop)
    # 27 06 SendKey_Level_5
    add_send_key_service(dlc, dlr, 5, end_of_pdu_array_dop)
    # 27 07 RequestSeed_Level_7
    add_request_seed_service(dlr, 7, end_of_pdu_array_dop)
    # 27 08 SendKey_Level_7
    add_send_key_service(dlc, dlr, 7, end_of_pdu_array_dop)

