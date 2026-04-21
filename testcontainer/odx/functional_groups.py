# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

import odxtools
from odxtools.addressing import Addressing
from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.identicalcompumethod import IdenticalCompuMethod
from odxtools.database import Database
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diagdatadictionaryspec import DiagDataDictionarySpec
from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diaglayers.ecushareddata import EcuSharedData
from odxtools.diaglayers.ecushareddataraw import EcuSharedDataRaw
from odxtools.diaglayers.functionalgroup import FunctionalGroup
from odxtools.diaglayers.functionalgroupraw import FunctionalGroupRaw
from odxtools.diaglayers.diaglayertype import DiagLayerType
from odxtools.functionalclass import FunctionalClass
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkId, OdxDocFragment, DocType
from odxtools.odxtypes import DataType
from odxtools.parentref import ParentRef
from odxtools.physicaltype import PhysicalType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.transmode import TransMode

from communication_control import add_communication_control_services
from dtc_services import add_dtc_setting_services
from helper import ref, derived_id, find_unit_by_shortname
from metadata import add_functional_classes
from routines import add_safety_squints_routine
from sessions import add_state_chart_session, add_session_service
from shared_units import add_common_units


def add_functional_data_types(dlr: DiagLayerRaw):
    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=derived_id(dlr, "DOP.SquintSlitWidth_mm"),
            short_name="SquintSlitWidth_mm",
            compu_method=IdenticalCompuMethod(
                category=CompuCategory.IDENTICAL,
                physical_type=DataType.A_FLOAT64,
                internal_type=DataType.A_FLOAT64,
            ),
            physical_type=PhysicalType(base_data_type=DataType.A_FLOAT64),
            diag_coded_type=StandardLengthType(
                base_data_type=DataType.A_FLOAT64, bit_length=64
            ),
            unit_ref=ref(find_unit_by_shortname(dlr, "MilliMeter")),
        )
    )


def generate_functional_groups(filename: str):
    print("Generating functional groups")
    database = Database()
    database.short_name = "FGL_UDS"

    for odx_filename in (
        "base/ISO_13400_2.odx-cs",
        "base/ISO_14229_5.odx-cs",
        "base/ISO_14229_5_on_ISO_13400_2.odx-c",
        "base/UDS_Ethernet_DoIP.odx-d",
        "base/UDS_Ethernet_DoIP_DOBT.odx-d",
    ):
        database.add_odx_file(odx_filename)

    database.refresh()

    # ECU Shared Data (ESD)
    esd_doc_frags = (OdxDocFragment("ESD_FGL_UDS", DocType.CONTAINER),)

    esd_dlc = DiagLayerContainer(
        odx_id=OdxLinkId("DLC.ESD_FGL_UDS", doc_fragments=esd_doc_frags),
        short_name="ESD_FGL_UDS",
        long_name="ESD FunctionalGroup UDS",
    )

    session_fc = FunctionalClass(
        odx_id=OdxLinkId("ESD.ESD_FGL_UDS.FNC.Session", doc_fragments=esd_doc_frags),
        short_name="Session",
        long_name="Session",
    )

    esd_raw = EcuSharedDataRaw(
        odx_id=OdxLinkId("ESD.ESD_FGL_UDS", doc_fragments=esd_doc_frags),
        short_name="ESD_FGL_UDS",
        long_name="ESD FunctionalGroup UDS",
        variant_type=DiagLayerType.ECU_SHARED_DATA,
        functional_classes=NamedItemList([session_fc]),
        diag_data_dictionary_spec=DiagDataDictionarySpec(),
    )

    # Add session state chart with states and transitions
    add_state_chart_session(esd_raw)
    # Add functional classes
    add_functional_classes(esd_raw)
    add_common_units(esd_raw)
    # Add functional data types
    add_functional_data_types(esd_raw)

    # 10 83 Extended_Start_Func (suppress positive response bit)
    add_session_service(
        dlr=esd_raw,
        target_state_session="Extended",
        session=3,
        from_state_transitions_session=["Default", "Programming", "Extended"],
        suppress_positive_response=True,
        transmission_mode=TransMode.SEND_ONLY,
        addressing=Addressing.FUNCTIONAL,
        suffix="_Func",
    )

    # communication control 28 xx
    add_communication_control_services(esd_raw, True)
    add_dtc_setting_services(esd_raw, True)

    esd_dlc.ecu_shared_datas.append(EcuSharedData(diag_layer_raw=esd_raw))
    database.diag_layer_containers.append(esd_dlc)

    # 31 8x 03 01 - Engage Safety Squints (Start/Stop, functional)
    add_safety_squints_routine(esd_raw)

    # Functional Group: FGL_UDS_Ethernet_DoIP
    fgl_doip_doc_frags = (OdxDocFragment("FGL_UDS_Ethernet_DoIP", DocType.CONTAINER),)

    fgl_doip_dlc = DiagLayerContainer(
        odx_id=OdxLinkId("DLC.FGL_UDS_Ethernet_DoIP", doc_fragments=fgl_doip_doc_frags),
        short_name="FGL_UDS_Ethernet_DoIP",
        long_name="FGL UDS Ethernet DoIP",
    )

    fgl_doip_raw = FunctionalGroupRaw(
        odx_id=OdxLinkId("FG.FGL_UDS_Ethernet_DoIP", doc_fragments=fgl_doip_doc_frags),
        short_name="FGL_UDS_Ethernet_DoIP",
        long_name="FGL UDS Ethernet DoIP",
        variant_type=DiagLayerType.FUNCTIONAL_GROUP,
        diag_data_dictionary_spec=DiagDataDictionarySpec(),
        parent_refs=[
            ParentRef(
                layer_ref=ref(
                    OdxLinkId(
                        local_id="PROTO.UDS_Ethernet_DoIP",
                        doc_fragments=(
                            OdxDocFragment(
                                doc_name="UDS_Ethernet_DoIP",
                                doc_type=DocType.CONTAINER,
                            ),
                        ),
                    )
                )
            ),
            ParentRef(
                layer_ref=ref(
                    OdxLinkId(
                        local_id="ESD.ESD_FGL_UDS",
                        doc_fragments=esd_doc_frags,
                    )
                )
            ),
        ],
    )

    fgl_doip_dlc.functional_groups.append(FunctionalGroup(diag_layer_raw=fgl_doip_raw))
    database.diag_layer_containers.append(fgl_doip_dlc)

    # Functional Group: FGL_UDS_Ethernet_DoIP_DOBT
    fgl_dobt_doc_frags = (
        OdxDocFragment("FGL_UDS_Ethernet_DoIP_DOBT", DocType.CONTAINER),
    )

    fgl_dobt_dlc = DiagLayerContainer(
        odx_id=OdxLinkId(
            "DLC.FGL_UDS_Ethernet_DoIP_DOBT", doc_fragments=fgl_dobt_doc_frags
        ),
        short_name="FGL_UDS_Ethernet_DoIP_DOBT",
        long_name="FGL UDS Ethernet DoIP (DOBT)",
    )

    fgl_dobt_raw = FunctionalGroupRaw(
        odx_id=OdxLinkId(
            "FG.FGL_UDS_Ethernet_DoIP_DOBT", doc_fragments=fgl_dobt_doc_frags
        ),
        short_name="FGL_UDS_Ethernet_DoIP_DOBT",
        long_name="FGL UDS Ethernet DoIP (DOBT)",
        variant_type=DiagLayerType.FUNCTIONAL_GROUP,
        diag_data_dictionary_spec=DiagDataDictionarySpec(),
        parent_refs=[
            ParentRef(
                layer_ref=ref(
                    OdxLinkId(
                        local_id="PROTO.UDS_Ethernet_DoIP_DOBT",
                        doc_fragments=(
                            OdxDocFragment(
                                doc_name="UDS_Ethernet_DoIP_DOBT",
                                doc_type=DocType.CONTAINER,
                            ),
                        ),
                    )
                )
            ),
            ParentRef(
                layer_ref=ref(
                    OdxLinkId(
                        local_id="ESD.ESD_FGL_UDS",
                        doc_fragments=esd_doc_frags,
                    )
                )
            ),
        ],
    )

    fgl_dobt_dlc.functional_groups.append(FunctionalGroup(diag_layer_raw=fgl_dobt_raw))
    database.diag_layer_containers.append(fgl_dobt_dlc)

    database.refresh()
    odxtools.write_pdx_file(filename, database)
