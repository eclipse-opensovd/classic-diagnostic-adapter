# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from collections.abc import Iterable
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compuconst import CompuConst
from odxtools.compumethods.compuinternaltophys import CompuInternalToPhys
from odxtools.compumethods.compuscale import CompuScale
from odxtools.compumethods.limit import Limit
from odxtools.compumethods.texttablecompumethod import TexttableCompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.element import IdentifiableElement
from odxtools.functionalclass import FunctionalClass
from odxtools.odxlink import OdxLinkId, OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.parameters.codedconstparameter import CodedConstParameter
from odxtools.parameters.matchingrequestparameter import MatchingRequestParameter
from odxtools.physicaltype import PhysicalType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.statetransition import StateTransition
from odxtools.response import Response, ResponseType
from odxtools.nameditemlist import NamedItemList
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.compumethods.compumethod import CompuMethod


def find_state_transition(
    container: DiagLayerRaw | DiagLayerContainer, name: str
) -> StateTransition:
    if isinstance(container, DiagLayerRaw):
        for state_chart in container.state_charts.values():
            for state_transition in state_chart.state_transitions:
                if state_transition.short_name == name:
                    return state_transition

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_state_transition(base_variant.base_variant_raw, name)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_state_transition(ecu_variant.ecu_variant_raw, name)
            if res is not None:
                return res

    raise Exception(f"No state transition found {name}")


def find_functional_class(
    container: DiagLayerRaw | DiagLayerContainer, name: str
) -> FunctionalClass:
    if isinstance(container, DiagLayerRaw):
        res = container.functional_classes[name]
        if res is not None:
            return res

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_functional_class(base_variant.base_variant_raw, name)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_functional_class(ecu_variant.ecu_variant_raw, name)
            if res is not None:
                return res

    raise Exception(f"No functional class found {name}")


def find_dop_by_shortname(
    container: DiagLayerRaw | DiagLayerContainer, shortname: str
) -> DataObjectProperty:
    if isinstance(container, DiagLayerRaw):
        for item in container.diag_data_dictionary_spec.data_object_props:
            if item.short_name == shortname:
                return item

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_dop_by_shortname(base_variant.base_variant_raw, shortname)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_dop_by_shortname(ecu_variant.ecu_variant_raw, shortname)
            if res is not None:
                return res

    raise ValueError(f"Could not find {shortname} in dops")


def find_dtc_dop(
    container: DiagLayerRaw | DiagLayerContainer, shortname: str
) -> DataObjectProperty:
    if isinstance(container, DiagLayerRaw):
        for item in container.diag_data_dictionary_spec.dtc_dops:
            if item.short_name == shortname:
                return item

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_dtc_dop(base_variant.base_variant_raw, shortname)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_dtc_dop(ecu_variant.ecu_variant_raw, shortname)
            if res is not None:
                return res

    raise ValueError(f"Could not find DTC {shortname} in dops")


def coded_const_int_parameter(
    short_name: str,
    semantic: str,
    byte_position: int,
    coded_value_raw: str,
    bit_length: int = 8,
    bit_position: int | None = None,
) -> CodedConstParameter:
    return CodedConstParameter(
        short_name=short_name,
        semantic=semantic,
        byte_position=byte_position,
        bit_position=bit_position,
        coded_value_raw=coded_value_raw,
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_UINT32, bit_length=bit_length
        ),
    )


def did_parameter_rq(did: int) -> CodedConstParameter:
    return coded_const_int_parameter(
        short_name="DID_RQ",
        semantic="DID",
        byte_position=1,
        bit_length=16,
        coded_value_raw=str(did),
    )


def sid_parameter_rq(sid: int) -> CodedConstParameter:
    return coded_const_int_parameter(
        short_name="SID_RQ",
        semantic="SERVICE-ID",
        byte_position=0,
        coded_value_raw=str(sid),
    )


def sid_parameter_pr(sid: int) -> CodedConstParameter:
    return coded_const_int_parameter(
        short_name="SID_PR",
        semantic="SERVICE-ID",
        byte_position=0,
        coded_value_raw=str(sid),
    )


def sid_parameter_nr() -> CodedConstParameter:
    return coded_const_int_parameter(
        short_name="SID_NR",
        semantic="SERVICE-ID",
        byte_position=0,
        coded_value_raw=str(0x7F),
    )


def sidrq_parameter_nr() -> MatchingRequestParameter:
    return matching_request_parameter(
        short_name="SIDRQ_NR",
        semantic="SERVICEIDRQ",
        byte_length=1,
        byte_position=1,
        request_byte_position=0,
    )


def subfunction_rq(
    subfunction: int,
    short_name: str = "SUBFUNCTION",
    semantic: str = "SUBFUNCTION",
    byte_position: int = 1,
    bit_length: int = 8,
) -> CodedConstParameter:
    return coded_const_int_parameter(
        short_name=short_name,
        semantic=semantic,
        byte_position=byte_position,
        coded_value_raw=str(subfunction),
        bit_length=bit_length,
    )


def matching_request_parameter(
    short_name: str,
    semantic: str,
    byte_length: int,
    byte_position: int = 1,
    request_byte_position: int = 1,
) -> MatchingRequestParameter:
    return MatchingRequestParameter(
        short_name=short_name,
        semantic=semantic,
        byte_position=byte_position,
        request_byte_position=request_byte_position,
        byte_length=byte_length,
    )


def matching_request_parameter_subfunction(
    short_name: str,
    semantic: str = "SEMANTIC",
    byte_length: int = 1,
    byte_position: int = 1,
    request_byte_position: int = 1,
) -> MatchingRequestParameter:
    return matching_request_parameter(
        short_name=short_name,
        semantic=semantic,
        byte_length=byte_length,
        byte_position=byte_position,
        request_byte_position=request_byte_position,
    )


def matching_request_parameter_did(
    short_name: str,
    semantic: str = "DID",
    byte_length: int = 2,
    byte_position: int = 1,
    request_byte_position: int = 1,
) -> MatchingRequestParameter:
    return matching_request_parameter(
        short_name=short_name,
        semantic=semantic,
        byte_length=byte_length,
        byte_position=byte_position,
        request_byte_position=request_byte_position,
    )


def functional_class_ref(
    dlr: DiagLayerRaw | DiagLayerContainer, func_class_name: str
) -> OdxLinkRef:
    functional_class = find_functional_class(dlr, func_class_name)
    return ref(functional_class)


def derived_id(parent: OdxLinkId | IdentifiableElement, name: str) -> OdxLinkId:
    if isinstance(parent, OdxLinkId):
        return OdxLinkId(
            local_id=f"{parent.local_id}.{name}", doc_fragments=parent.doc_fragments
        )
    elif isinstance(parent, IdentifiableElement):
        return derived_id(parent.odx_id, name)
    else:
        raise Exception(f"Invalid object {parent}")


def ref(element: OdxLinkId | IdentifiableElement) -> OdxLinkRef:
    if isinstance(element, OdxLinkId):
        return OdxLinkRef.from_id(element)
    elif isinstance(element, IdentifiableElement):
        return ref(element.odx_id)
    else:
        raise Exception(f"Invalid object {element}")


def compuscales_int_to_str_map(value: list[tuple[int, str]]) -> list[CompuScale]:
    compuscale_list = []
    for t in value:
        compuscale_list.append(
            CompuScale(
                lower_limit=Limit(value_raw=str(t[0]), value_type=DataType.A_UINT32),
                upper_limit=Limit(value_raw=str(t[0]), value_type=DataType.A_UINT32),
                compu_const=CompuConst(vt=t[1], data_type=DataType.A_UNICODE2STRING),
                domain_type=DataType.A_UINT32,
                range_type=DataType.A_UINT32,
            )
        )
    return compuscale_list


def texttable_int_str_dop(
    dlr: DiagLayerRaw,
    short_name: str,
    text_table: list[tuple[int, str]],
    bit_length: int = 8,
) -> DataObjectProperty:
    return DataObjectProperty(
        odx_id=derived_id(dlr, f"DOP.{short_name}"),
        short_name=short_name,
        compu_method=TexttableCompuMethod(
            category=CompuCategory.TEXTTABLE,
            compu_internal_to_phys=CompuInternalToPhys(
                compu_scales=compuscales_int_to_str_map(text_table),
            ),
            physical_type=DataType.A_UNICODE2STRING,
            internal_type=DataType.A_UINT32,
        ),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_UINT32, bit_length=bit_length
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
    )


def negative_response(
    dlr: DiagLayerRaw,
    short_name: str,
) -> Response:
    nrc_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.NRC_{short_name}"),
        short_name="NRC_{short_name}",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_BYTEFIELD),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_UINT32, bit_length=8
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(nrc_dop)

    return Response(
        odx_id=derived_id(dlr, f"NR.{short_name}"),
        short_name=short_name,
        parameters=NamedItemList(
            [
                sid_parameter_nr(),
                sidrq_parameter_nr(),
                ValueParameter(
                    short_name="NRC",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(nrc_dop),
                ),
            ]
        ),
        response_type=ResponseType.NEGATIVE,
    )


def named_item_list_from_parts(
    parts: Iterable[NamedItemList],
) -> NamedItemList:
    result = NamedItemList()
    for part in parts:
        result.extend(part)
    return result
