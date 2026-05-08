# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from odxtools.comparaminstance import ComparamInstance
from odxtools.database import Database

from helper import ref


def generate_comparam_refs(
    ecu_name: str,
    logical_address: int,
    gateway_address: int,
    functional_address: int,
    database: Database,
) -> list[ComparamInstance]:
    refs = []

    gw_addr = database.comparam_subsets.get("ISO_13400_2").comparams[
        "CP_DoIPLogicalGatewayAddress"
    ]
    cp_gw = ComparamInstance(
        value=str(gateway_address),
        spec_ref=ref(gw_addr),
        protocol_snref="UDS_Ethernet_DoIP",
    )
    refs.append(cp_gw)

    funct_addr = database.comparam_subsets.get("ISO_13400_2").comparams[
        "CP_DoIPLogicalFunctionalAddress"
    ]
    cp_fa = ComparamInstance(
        value=str(functional_address),
        spec_ref=ref(funct_addr),
        protocol_snref="UDS_Ethernet_DoIP",
    )
    refs.append(cp_fa)

    resp_id = database.comparam_subsets.get("ISO_13400_2").complex_comparams[
        "CP_UniqueRespIdTable"
    ]
    cp_resp = ComparamInstance(
        value=[str(logical_address), str(0), ecu_name],
        spec_ref=ref(resp_id),
        protocol_snref="UDS_Ethernet_DoIP",
    )
    refs.append(cp_resp)

    gw_addr_dobt = database.comparam_subsets.get("ISO_13400_2").comparams[
        "CP_DoIPLogicalGatewayAddress"
    ]
    cp_gw_dobt = ComparamInstance(
        value=str(gateway_address),
        spec_ref=ref(gw_addr_dobt),
        protocol_snref="UDS_Ethernet_DoIP_DOBT",
    )
    refs.append(cp_gw_dobt)

    funct_addr_dobt = database.comparam_subsets.get("ISO_13400_2").comparams[
        "CP_DoIPLogicalFunctionalAddress"
    ]
    cp_fa_dobt = ComparamInstance(
        value=str(functional_address),
        spec_ref=ref(funct_addr_dobt),
        protocol_snref="UDS_Ethernet_DoIP_DOBT",
    )
    refs.append(cp_fa_dobt)

    resp_id_dobt = database.comparam_subsets.get("ISO_13400_2").complex_comparams[
        "CP_UniqueRespIdTable"
    ]
    cp_resp_dobt = ComparamInstance(
        value=[str(logical_address), str(0), ecu_name],
        spec_ref=ref(resp_id_dobt),
        protocol_snref="UDS_Ethernet_DoIP_DOBT",
    )
    refs.append(cp_resp_dobt)

    return refs


def generate_minimal_comparam_refs(
    ecu_name: str,
    logical_address: int,
    database: Database,
    protocol_snref: str = None,
) -> list[ComparamInstance]:
    """Generate comparam refs with a deliberately wrong gateway address.

    CP_UniqueRespIdTable is emitted so the CDA resolves the ECU logical address
    from the MDD.  CP_DoIPLogicalGatewayAddress is emitted with a *wrong* value
    (0xDEAD) so that integration tests can verify that the CDA's per-ECU config
    override with ``precedence = "Config"`` takes priority over the DB value.

    When *protocol_snref* is given, every ComparamInstance is tagged with that
    protocol short-name so the CDA can match them during normal (non-ignore)
    protocol lookup.
    """
    refs = []

    resp_id = database.comparam_subsets.get("ISO_13400_2").complex_comparams[
        "CP_UniqueRespIdTable"
    ]
    refs.append(
        ComparamInstance(
            value=[str(logical_address), str(0), ecu_name],
            spec_ref=ref(resp_id),
            protocol_snref=protocol_snref,
        )
    )

    gw_addr = database.comparam_subsets.get("ISO_13400_2").comparams[
        "CP_DoIPLogicalGatewayAddress"
    ]
    refs.append(
        ComparamInstance(
            value=str(0xDEAD),
            spec_ref=ref(gw_addr),
            protocol_snref=protocol_snref,
        )
    )

    return refs
