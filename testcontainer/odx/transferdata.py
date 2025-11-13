from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compumethod import CompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.minmaxlengthtype import MinMaxLengthType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxtypes import DataType
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.termination import Termination

from helper import (
    find_dop_by_shortname,
    sid_parameter_rq,
    sid_parameter_pr,
    derived_id,
    matching_request_parameter,
    functional_class_ref,
    ref,
)


def add_requestdownload_service(
    dlr: DiagLayerRaw, address_length: int, size_length: int
):
    # switch to limited dop for format and identifier?
    data_format_identifier_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")
    memory_address_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.MemoryAddressArray"),
        short_name="MemoryAddressArray",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_BYTEFIELD),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_BYTEFIELD,
            bit_length=address_length * 8,
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(memory_address_dop)
    memory_size_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.MemorySizeArray"),
        short_name="MemorySizeArray",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_BYTEFIELD),
        diag_coded_type=StandardLengthType(
            base_data_type=DataType.A_BYTEFIELD,
            bit_length=size_length * 8,
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(memory_size_dop)

    requestdownload_request = Request(
        odx_id=derived_id(dlr, "RQ.RQ_RequestDownload"),
        short_name="RQ_RequestDownload",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x34),
                ValueParameter(
                    short_name="DataFormatIdentifier",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(data_format_identifier_dop),
                ),
                ValueParameter(
                    short_name="AddressAndLengthFormatIdentifier",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(data_format_identifier_dop),
                ),
                ValueParameter(
                    short_name="MemoryAddress",
                    semantic="DATA",
                    byte_position=3,
                    dop_ref=ref(memory_address_dop),
                ),
                ValueParameter(
                    short_name="MemorySize",
                    semantic="DATA",
                    byte_position=3 + address_length,
                    dop_ref=ref(memory_size_dop),
                ),
            ]
        ),
    )
    dlr.requests.append(requestdownload_request)

    max_number_of_blocklength_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_32")
    requestdownload_response = Response(
        odx_id=derived_id(dlr, "PR.PR_RequestDownload"),
        short_name="PR_RequestDownload",
        response_type=ResponseType.POSITIVE,
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x34 + 0x40),
                ValueParameter(
                    short_name="LengthFormatIdentifier",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(data_format_identifier_dop),
                ),
                ValueParameter(
                    short_name="MaxNumberOfBlockLength",
                    semantic="DATA",
                    byte_position=2,
                    dop_ref=ref(max_number_of_blocklength_dop),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(requestdownload_response)

    requestdownload_service = DiagService(
        odx_id=derived_id(dlr, "DC.RequestDownload"),
        short_name="RequestDownload",
        semantic="DATA",
        functional_class_refs=[functional_class_ref(dlr, "StandardDataTransfer")],
        request_ref=ref(requestdownload_request),
        pos_response_refs=[ref(requestdownload_response)],
    )

    dlr.diag_comms_raw.append(requestdownload_service)


def add_transferdata_service(dlr: DiagLayerRaw):
    data_array_dop = DataObjectProperty(
        odx_id=derived_id(dlr, "DOP.TransferData_Data"),
        short_name="TransferData",
        compu_method=CompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_BYTEFIELD,
            internal_type=DataType.A_BYTEFIELD,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_BYTEFIELD),
        diag_coded_type=MinMaxLengthType(
            base_data_type=DataType.A_BYTEFIELD,
            min_length=0,
            max_length=4_000_000,
            termination=Termination.END_OF_PDU,
        ),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(data_array_dop)

    single_byte_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")

    transferdata_request = Request(
        odx_id=derived_id(dlr, "RQ.RQ_TransferData"),
        short_name="RQ_TransferData",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x36),
                ValueParameter(
                    short_name="BlockSequenceCounter",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(single_byte_dop),
                ),
                ValueParameter(
                    short_name="TransferRequestParameterRecord",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(data_array_dop),
                ),
            ]
        ),
    )
    dlr.requests.append(transferdata_request)

    transferdata_response = Response(
        odx_id=derived_id(dlr, "PR.PR_TransferData"),
        short_name="PR_TransferData",
        response_type=ResponseType.POSITIVE,
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x36 + 0x40),
                matching_request_parameter(
                    short_name="BlockSequenceCounter", semantic="DATA", byte_length=1
                ),
                ValueParameter(
                    short_name="TransferRequestParameterRecord",
                    semantic="DATA",
                    byte_position=1,
                    dop_ref=ref(data_array_dop),
                ),
            ]
        ),
    )
    dlr.positive_responses.append(transferdata_response)

    transferdata_service = DiagService(
        odx_id=derived_id(dlr, "DC.TransferData"),
        short_name="TransferData",
        functional_class_refs=[functional_class_ref(dlr, "StandardDataTransfer")],
        request_ref=ref(transferdata_request),
        pos_response_refs=[ref(transferdata_response)],
    )
    dlr.diag_comms_raw.append(transferdata_service)


def add_transferexit(dlr: DiagLayerRaw):
    transferexit_request = Request(
        odx_id=derived_id(dlr, "RQ.RQ_TransferExit"),
        short_name="RQ_TransferExit",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x37),
            ]
        ),
    )
    dlr.requests.append(transferexit_request)

    transferexit_response = Response(
        odx_id=derived_id(dlr, "PR.PR_TransferExit"),
        short_name="PR_TransferData",
        response_type=ResponseType.POSITIVE,
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x37 + 0x40),
            ]
        ),
    )
    dlr.positive_responses.append(transferexit_response)

    transferexit_service = DiagService(
        odx_id=derived_id(dlr, "DC.TransferExit"),
        short_name="TransferExit",
        functional_class_refs=[functional_class_ref(dlr, "StandardDataTransfer")],
        request_ref=ref(transferexit_request),
        pos_response_refs=[ref(transferexit_response)],
    )
    dlr.diag_comms_raw.append(transferexit_service)


def add_transfer_services(dlr: DiagLayerRaw):
    # 34 ...
    add_requestdownload_service(dlr, 4, 4)
    # 36 ...
    add_transferdata_service(dlr)
    # 37
    add_transferexit(dlr)
