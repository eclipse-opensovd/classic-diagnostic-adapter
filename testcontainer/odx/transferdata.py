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

from helper import (
    derived_id,
    find_dop_by_shortname,
    functional_class_ref,
    matching_request_parameter,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
)
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

FLASH_FUNCTIONAL_CLASS_DEFAULT = "flash_download_upload"
FLASH_FUNCTIONAL_CLASS_BOOTLOADER = "flash_download_upload_bootloader"


def add_requestdownload_service(
    dlr: DiagLayerRaw,
    address_length: int,
    size_length: int,
    functional_class: str = FLASH_FUNCTIONAL_CLASS_DEFAULT,
    suffix: str = "",
):
    # switch to limited dop for format and identifier?
    data_format_identifier_dop = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")
    memory_address_dop = DataObjectProperty(
        odx_id=derived_id(dlr, f"DOP.MemoryAddressArray{suffix}"),
        short_name=f"MemoryAddressArray{suffix}",
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
        odx_id=derived_id(dlr, f"DOP.MemorySizeArray{suffix}"),
        short_name=f"MemorySizeArray{suffix}",
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
        odx_id=derived_id(dlr, f"RQ.RQ_RequestDownload{suffix}"),
        short_name=f"RQ_RequestDownload{suffix}",
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
        odx_id=derived_id(dlr, f"PR.PR_RequestDownload{suffix}"),
        short_name=f"PR_RequestDownload{suffix}",
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
        odx_id=derived_id(dlr, f"DC.RequestDownload{suffix}"),
        short_name=f"RequestDownload{suffix}",
        semantic="DATA",
        functional_class_refs=[functional_class_ref(dlr, functional_class)],
        request_ref=ref(requestdownload_request),
        pos_response_refs=[ref(requestdownload_response)],
    )

    dlr.diag_comms_raw.append(requestdownload_service)


def add_transferdata_service(
    dlr: DiagLayerRaw,
    functional_class: str = FLASH_FUNCTIONAL_CLASS_DEFAULT,
    suffix: str = "",
):
    data_array_dop = DataObjectProperty(
        odx_id=derived_id(dlr, f"DOP.TransferData_Data{suffix}"),
        short_name=f"TransferData{suffix}",
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
        odx_id=derived_id(dlr, f"RQ.RQ_TransferData{suffix}"),
        short_name=f"RQ_TransferData{suffix}",
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
        odx_id=derived_id(dlr, f"PR.PR_TransferData{suffix}"),
        short_name=f"PR_TransferData{suffix}",
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
        odx_id=derived_id(dlr, f"DC.TransferData{suffix}"),
        short_name=f"TransferData{suffix}",
        functional_class_refs=[functional_class_ref(dlr, functional_class)],
        request_ref=ref(transferdata_request),
        pos_response_refs=[ref(transferdata_response)],
    )
    dlr.diag_comms_raw.append(transferdata_service)


def add_transferexit(
    dlr: DiagLayerRaw,
    functional_class: str = FLASH_FUNCTIONAL_CLASS_DEFAULT,
    suffix: str = "",
):
    transferexit_request = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_TransferExit{suffix}"),
        short_name=f"RQ_TransferExit{suffix}",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x37),
            ]
        ),
    )
    dlr.requests.append(transferexit_request)

    transferexit_response = Response(
        odx_id=derived_id(dlr, f"PR.PR_TransferExit{suffix}"),
        short_name=f"PR_TransferData{suffix}",
        response_type=ResponseType.POSITIVE,
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x37 + 0x40),
            ]
        ),
    )
    dlr.positive_responses.append(transferexit_response)

    transferexit_service = DiagService(
        odx_id=derived_id(dlr, f"DC.TransferExit{suffix}"),
        short_name=f"TransferExit{suffix}",
        functional_class_refs=[functional_class_ref(dlr, functional_class)],
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

    # Second set of flash services that only differ in the functional class
    # (and the RequestDownload address/size format), used to test the functional
    # class selection of the flash API.
    add_requestdownload_service(dlr, 2, 2, FLASH_FUNCTIONAL_CLASS_BOOTLOADER, "_Bootloader")
    add_transferdata_service(dlr, FLASH_FUNCTIONAL_CLASS_BOOTLOADER, "_Bootloader")
    add_transferexit(dlr, FLASH_FUNCTIONAL_CLASS_BOOTLOADER, "_Bootloader")
