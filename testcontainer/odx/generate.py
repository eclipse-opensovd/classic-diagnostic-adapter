import odxtools
from odxtools.database import Database
from odxtools.diagdatadictionaryspec import DiagDataDictionarySpec
from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.basevariant import BaseVariant
from odxtools.diaglayers.basevariantraw import BaseVariantRaw
from odxtools.diaglayers.diaglayertype import DiagLayerType
from odxtools.diaglayers.ecuvariant import EcuVariant
from odxtools.diaglayers.ecuvariantraw import EcuVariantRaw
from odxtools.ecuvariantpattern import EcuVariantPattern
from odxtools.matchingparameter import MatchingParameter
from odxtools.odxlink import OdxLinkId, DocType, OdxDocFragment
from odxtools.parentref import ParentRef

from authentication import add_authentication_services
from comparams import generate_comparam_refs
from helper import ref
from metadata import (
    add_functional_classes,
    add_admin_data,
    add_company_datas,
    add_additional_audiences,
)
from reset import add_reset_services
from security_access import add_security_access_services
from shared import add_common_datatypes, add_state_charts, add_common_diag_comms
from transferdata import add_transfer_services
from typing import List, Tuple


def add_variant(dlc: DiagLayerContainer, name: str, identification_pattern: int):
    ecu_name = dlc.short_name
    doc_frags = dlc.odx_id.doc_fragments
    variant = EcuVariantRaw(
        odx_id=OdxLinkId(local_id=f"EV.{ecu_name}.{name}", doc_fragments=doc_frags),
        short_name=name,
        variant_type=DiagLayerType.ECU_VARIANT,
        ecu_variant_patterns=[
            EcuVariantPattern(
                matching_parameters=[
                    MatchingParameter(
                        expected_value=str(identification_pattern),
                        diag_comm_snref="Identification_Read",
                        out_param_if_snref="Identification",
                    )
                ]
            )
        ],
        parent_refs=[ParentRef(layer_ref=ref(dlc.base_variants[0].odx_id))],
        diag_data_dictionary_spec=DiagDataDictionarySpec(),
    )
    if "_Boot_" in name:
        add_security_access_services(dlc, variant)

    dlc.ecu_variants.append(EcuVariant(diag_layer_raw=variant))


def add_base_variant(
    dlc: DiagLayerContainer,
    logical_address: int,
    gateway_address: int,
    functional_address: int,
    database: Database,
):
    ecu_name = dlc.short_name
    doc_frags = dlc.odx_id.doc_fragments
    base_variant = BaseVariantRaw(
        odx_id=OdxLinkId(local_id=f"BV.{ecu_name}", doc_fragments=doc_frags),
        short_name=ecu_name,
        comparam_refs=generate_comparam_refs(
            ecu_name=ecu_name,
            logical_address=logical_address,
            functional_address=functional_address,
            gateway_address=gateway_address,
            database=database,
        ),
        variant_type=DiagLayerType.BASE_VARIANT,
        parent_refs=[
            ParentRef(
                layer_ref=ref(
                    OdxLinkId(
                        local_id="PROTO.UDS_Ethernet_DoIP",
                        doc_fragments=(
                            OdxDocFragment(
                                doc_name="UDS_Ethernet_DoIP", doc_type=DocType.CONTAINER
                            ),
                        ),
                    )
                )
            ),
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
        ],
        diag_data_dictionary_spec=DiagDataDictionarySpec(),
    )

    add_functional_classes(base_variant)
    add_common_datatypes(base_variant)
    add_state_charts(base_variant)

    # common services (session (10 xx), vin, ident)
    add_common_diag_comms(base_variant)
    # 11
    add_reset_services(base_variant)
    # 34, 36, 37
    add_transfer_services(base_variant)
    # 29
    add_authentication_services(base_variant)

    dlc.base_variants.append(BaseVariant(diag_layer_raw=base_variant))


def generate_for_ecu(
    ecu_name: str,
    logical_address: int,
    gateway_address: int,
    functional_address: int,
    variants: List[Tuple[str, int]],
):
    print(f"Generating for {ecu_name}")
    database = Database()
    database.short_name = ecu_name

    for odx_filename in (
        "base/ISO_13400_2.odx-cs",
        "base/ISO_14229_5.odx-cs",
        "base/ISO_14229_5_on_ISO_13400_2.odx-c",
        "base/UDS_Ethernet_DoIP.odx-d",
        "base/UDS_Ethernet_DoIP_DOBT.odx-d",
    ):
        database.add_odx_file(odx_filename)

    # checks consistency for existing files
    database.refresh()

    doc_frags = (OdxDocFragment(ecu_name, DocType.CONTAINER),)

    dlc = DiagLayerContainer(
        odx_id=OdxLinkId(f"DLC.{ecu_name}", doc_fragments=doc_frags),
        short_name=ecu_name,
    )
    add_admin_data(dlc)
    add_company_datas(dlc)
    add_additional_audiences(dlc)

    add_base_variant(
        dlc=dlc,
        logical_address=logical_address,
        gateway_address=gateway_address,
        functional_address=functional_address,
        database=database,
    )

    for variant_name, identification_pattern in variants:
        add_variant(
            dlc=dlc,
            name=f"{ecu_name}_{variant_name}",
            identification_pattern=identification_pattern,
        )

    database.diag_layer_containers.append(dlc)

    database.refresh()  # probably not necessary
    odxtools.write_pdx_file(f"{ecu_name}.pdx", database)


generate_for_ecu(
    ecu_name="FLXC1000",
    logical_address=0x1000,
    gateway_address=0x1000,
    functional_address=0xFFFF,
    variants=[("Boot_Variant", 0xFF0000), ("App_0101", 0x000101)],
)

# mirror a use-case, where for different markets different hardware revisions
# (for whatever reason) are used, but due to having the same function, the logical address would be the same.
# The CDA should be able to differentiate those variants based on the variant response.
# During variant detection on of the ECUs is selected, whereas the other is marked as duplicate.
generate_for_ecu(
    ecu_name="FLXCNG1000",
    logical_address=0x1000,
    gateway_address=0x1000,
    functional_address=0xFFFF,
    variants=[("App_1010", 0x001010)],
)
