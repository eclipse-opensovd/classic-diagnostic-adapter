from odxtools.compumethods.compucategory import CompuCategory
from odxtools.compumethods.compuconst import CompuConst
from odxtools.compumethods.compuinternaltophys import CompuInternalToPhys
from odxtools.compumethods.compuscale import CompuScale
from odxtools.compumethods.identicalcompumethod import IdenticalCompuMethod
from odxtools.compumethods.limit import Limit
from odxtools.compumethods.texttablecompumethod import TexttableCompuMethod
from odxtools.dataobjectproperty import DataObjectProperty
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.encoding import Encoding
from odxtools.minmaxlengthtype import MinMaxLengthType
from odxtools.nameditemlist import NamedItemList
from odxtools.odxlink import OdxLinkId, OdxLinkRef
from odxtools.odxtypes import DataType
from odxtools.parameters.codedconstparameter import CodedConstParameter
from odxtools.parameters.matchingrequestparameter import MatchingRequestParameter
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.physicaltype import PhysicalType
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.standardlengthtype import StandardLengthType
from odxtools.termination import Termination
from packaging.version import Version

from security_access import add_state_chart_security_access
from sessions import add_default_session_services, add_state_chart_session

ODX_VERSION = Version("2.2.0")


def add_state_charts(dlr: DiagLayerRaw):
    add_state_chart_session(dlr)
    add_state_chart_security_access(dlr)


def add_common_datatypes(dlr: DiagLayerRaw):
    compu_method_identical_uint32 = IdenticalCompuMethod(
        category=CompuCategory.IDENTICAL,
        physical_type=DataType.A_UINT32,
        internal_type=DataType.A_UINT32,
    )

    compu_method_identical_unicode2string = IdenticalCompuMethod(
        category=CompuCategory.IDENTICAL,
        physical_type=DataType.A_UNICODE2STRING,
        internal_type=DataType.A_UNICODE2STRING,
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.IDENTICAL_UINT_16", doc_fragments=dlr.odx_id.doc_fragments),
            short_name="IDENTICAL_UINT_16",
            compu_method=compu_method_identical_uint32,
            physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
            diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=16),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.IDENTICAL_UINT_32", doc_fragments=dlr.odx_id.doc_fragments),
            short_name="IDENTICAL_UINT_32",
            compu_method=compu_method_identical_uint32,
            physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
            diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=32),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.IDENTICAL_STR_END_OF_PDU",
                             doc_fragments=dlr.odx_id.doc_fragments),
            short_name="IDENTICAL_STR_END_OF_PDU",
            compu_method=compu_method_identical_unicode2string,
            diag_coded_type=MinMaxLengthType(base_data_type=DataType.A_ASCIISTRING,
                                             base_type_encoding=Encoding.ISO_8859_1,
                                             termination=Termination.END_OF_PDU,
                                             min_length=1),
            physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
        )
    )

    dlr.diag_data_dictionary_spec.data_object_props.append(
        DataObjectProperty(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.EcuSessionType", doc_fragments=dlr.odx_id.doc_fragments),
            short_name="EcuSessionType",
            compu_method=TexttableCompuMethod(
                category=CompuCategory.TEXTTABLE,
                compu_internal_to_phys=CompuInternalToPhys(
                    compu_scales=[
                        CompuScale(lower_limit=Limit(value_raw="1", value_type=DataType.A_UINT32),
                                   upper_limit=Limit(value_raw="1", value_type=DataType.A_UINT32),
                                   compu_const=CompuConst(vt="Default", data_type=DataType.A_UNICODE2STRING),
                                   domain_type=DataType.A_UINT32,
                                   range_type=DataType.A_UINT32),
                        CompuScale(lower_limit=Limit(value_raw="2", value_type=DataType.A_UINT32),
                                   upper_limit=Limit(value_raw="2", value_type=DataType.A_UINT32),
                                   compu_const=CompuConst(vt="Programming", data_type=DataType.A_UNICODE2STRING),
                                   domain_type=DataType.A_UINT32,
                                   range_type=DataType.A_UINT32),
                        CompuScale(lower_limit=Limit(value_raw="3", value_type=DataType.A_UINT32),
                                   upper_limit=Limit(value_raw="3", value_type=DataType.A_UINT32),
                                   compu_const=CompuConst(vt="Extended", data_type=DataType.A_UNICODE2STRING),
                                   domain_type=DataType.A_UINT32,
                                   range_type=DataType.A_UINT32),
                        CompuScale(lower_limit=Limit(value_raw="35", value_type=DataType.A_UINT32),
                                   upper_limit=Limit(value_raw="35", value_type=DataType.A_UINT32),
                                   compu_const=CompuConst(vt="Custom", data_type=DataType.A_UNICODE2STRING),
                                   domain_type=DataType.A_UINT32,
                                   range_type=DataType.A_UINT32),
                    ]
                ),
                physical_type=DataType.A_UNICODE2STRING,
                internal_type=DataType.A_UINT32,
            ),
            diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32,
                                               bit_length=8),
            physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
        )
    )


def add_service_did(dlr: DiagLayerRaw,
                    service_name: str,
                    property_name: str,
                    did: int,
                    dop: DataObjectProperty,
                    add_write: bool = False,
                    funct_class: str = "Ident"):
    if not dop:
        raise Exception("dop property is required")
    request = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_{service_name}_Read", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_{service_name}_Read",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x22),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="DID_RQ",
                semantic="DID",
                byte_position=1,
                coded_value_raw=str(did),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=16),
            ),
        ]),
    )
    dlr.requests.append(request)

    response = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_{service_name}_Read", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_{service_name}_Read",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x22 + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
            MatchingRequestParameter(
                short_name="DID_PR",
                semantic="DID",
                byte_position=1,
                request_byte_position=1,
                byte_length=2,
            ),
            ValueParameter(
                short_name=property_name,
                semantic="DATA",
                byte_position=3,
                dop_ref=OdxLinkRef.from_id(dop.odx_id),
            ),
        ]),
    )
    dlr.positive_responses.append(response)

    funct_class = dlr.functional_classes.get(funct_class)
    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DC.{service_name}_Read", doc_fragments=dlr.odx_id.doc_fragments),
            short_name=f"{service_name}_Read",
            functional_class_refs=[OdxLinkRef.from_id(funct_class.odx_id)],
            request_ref=OdxLinkRef.from_id(request.odx_id),
            pos_response_refs=[OdxLinkRef.from_id(response.odx_id)]
        )
    )

    if not add_write:
        return

    request_write = Request(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.RQ.RQ_{service_name}_Write", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"RQ_{service_name}_Write",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_RQ",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x2e),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8)
            ),
            CodedConstParameter(
                short_name="DID_RQ",
                semantic="DID",
                byte_position=1,
                coded_value_raw=str(did),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=16),
            ),
            ValueParameter(
                short_name=property_name,
                semantic="DATA",
                byte_position=3,
                dop_ref=OdxLinkRef.from_id(dop.odx_id),
            ),
        ]),
    )
    dlr.requests.append(request_write)

    response_write = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.PR.PR_{service_name}_Write", doc_fragments=dlr.odx_id.doc_fragments),
        short_name=f"PR_{service_name}_Write",
        parameters=NamedItemList([
            CodedConstParameter(
                short_name="SID_PR",
                semantic="SID",
                byte_position=0,
                coded_value_raw=str(0x2e + 0x40),
                diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
            ),
            MatchingRequestParameter(
                short_name="DID_PR",
                semantic="DID",
                byte_position=1,
                request_byte_position=1,
                byte_length=2,
            ),
        ]),
    )
    dlr.positive_responses.append(response_write)

    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DC.{service_name}_Write", doc_fragments=dlr.odx_id.doc_fragments),
            short_name=f"{service_name}_Write",
            functional_class_refs=[OdxLinkRef.from_id(funct_class.odx_id)],
            request_ref=OdxLinkRef.from_id(request_write.odx_id),
            pos_response_refs=[OdxLinkRef.from_id(response_write.odx_id)]
        )
    )


def find_dop_by_shortname(dlr: DiagLayerRaw, shortname: str) -> DataObjectProperty:
    for item in dlr.diag_data_dictionary_spec.data_object_props:
        if item.short_name == shortname:
            return item
    raise ValueError(f"Could not find {shortname} in dops")


def add_common_diag_comms(dlr: DiagLayerRaw):
    vin_dop = DataObjectProperty(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.VIN_17Byte", doc_fragments=dlr.odx_id.doc_fragments),
        short_name="VIN_17Byte",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UNICODE2STRING,
            internal_type=DataType.A_UNICODE2STRING,
        ),
        diag_coded_type=StandardLengthType(base_data_type=DataType.A_ASCIISTRING,
                                           base_type_encoding=Encoding.ISO_8859_1,
                                           bit_length=136),
        physical_type=PhysicalType(base_data_type=DataType.A_UNICODE2STRING),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(vin_dop)
    add_service_did(dlr, "VINDataIdentifier", "VIN", 0xf190, vin_dop, add_write=True)

    session_type_dop = DataObjectProperty(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.IDENTICAL_UINT_8", doc_fragments=dlr.odx_id.doc_fragments),
        short_name="IDENTICAL_UINT_8",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UINT32,
            internal_type=DataType.A_UINT32,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
        diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=8),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(session_type_dop)
    add_service_did(dlr, "ActiveDiagnosticSessionDataIdentifier", "EcuSessionType", 0xf186,
                    session_type_dop, add_write=False)

    uint24_dop = DataObjectProperty(
        odx_id=OdxLinkId(f"{dlr.odx_id.local_id}.DOP.IDENTICAL_UINT_24", doc_fragments=dlr.odx_id.doc_fragments),
        short_name="IDENTICAL_UINT_24",
        compu_method=IdenticalCompuMethod(
            category=CompuCategory.IDENTICAL,
            physical_type=DataType.A_UINT32,
            internal_type=DataType.A_UINT32,
        ),
        physical_type=PhysicalType(base_data_type=DataType.A_UINT32),
        diag_coded_type=StandardLengthType(base_data_type=DataType.A_UINT32, bit_length=24),
    )
    dlr.diag_data_dictionary_spec.data_object_props.append(uint24_dop)
    add_service_did(dlr, "Identification", "Identification", 0xf100, uint24_dop, add_write=False)

    add_default_session_services(dlr)

    # security access
    # authentication (29)
    pass
