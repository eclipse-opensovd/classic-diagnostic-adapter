import datetime

from odxtools.additionalaudience import AdditionalAudience
from odxtools.admindata import AdminData
from odxtools.companydata import CompanyData
from odxtools.description import Description
from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.docrevision import DocRevision
from odxtools.functionalclass import FunctionalClass
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkId
from odxtools.teammember import TeamMember

from helper import derived_id


def add_admin_data(dlc: DiagLayerContainer):
    dlc.admin_data = AdminData(
        doc_revisions=[
            DocRevision(
                revision_label="00.01.00", date=f"{datetime.datetime.now().isoformat()}"
            )
        ]
    )


def add_company_datas(dlc: DiagLayerContainer):
    doc_frags = dlc.odx_id.doc_fragments

    elb_brown = TeamMember(
        odx_id=OdxLinkId("TM.ELB_Enterprises.DocBrown", doc_fragments=doc_frags),
        short_name="Doc Brown",
        long_name="Dr. Emmett Lathrop Brown",
        roles=["founder", "chief scientist"],
    )
    elb_mcfly = TeamMember(
        odx_id=OdxLinkId("TM.ELB_Enterprises.MartyMcFly", doc_fragments=doc_frags),
        short_name="Marty McFly",
        long_name="Martin Seamus McFly",
        roles=["driver"],
    )

    elb_enterprises = CompanyData(
        odx_id=OdxLinkId("CD.EB_Enterprises", doc_fragments=doc_frags),
        short_name="ELB Enterprises",
        long_name="Dr. E. Brown Enterprises",
        description=Description.from_string("24hr Scientific Services"),
        team_members=NamedItemList(
            [
                elb_brown,
                elb_mcfly,
            ]
        ),
    )
    fusion_industries = CompanyData(
        odx_id=OdxLinkId("CD.Fusion_Industries", doc_fragments=doc_frags),
        short_name="Fusion Industries",
        long_name="Fusion Industries",
    )

    dlc.company_datas = NamedItemList([elb_enterprises, fusion_industries])


def add_functional_classes(dlr: DiagLayerRaw):
    funct_class_names = [
        "Session",
        "EcuReset",
        "CommCtrl",
        "Ident",
        "StandardDataTransfer",
        "SecurityAccess",
        "Authentication",
    ]
    dlr.functional_classes = NamedItemList(
        [
            FunctionalClass(
                odx_id=derived_id(dlr, f"FNC.{name}"),
                short_name=name,
            )
            for name in funct_class_names
        ]
    )


def add_additional_audiences(dlc: DiagLayerContainer):
    add_audiences_names = [
        "Anyone",
        "After_Sales",
        "Manufacturing",
        "After_Market",
        "Development",
        "Supplier",
        "Custom",
    ]
    dlc.additional_audiences = NamedItemList(
        [
            AdditionalAudience(
                odx_id=derived_id(dlc, f"AA.{name}"),
                short_name=name,
            )
            for name in add_audiences_names
        ]
    )
