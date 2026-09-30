# SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""DID 0xF300 (FluxCapacitorTimeline) with chained DYNAMIC-LENGTH-FIELDs.

Exercises encoding (0x2E) and decoding (0x22) of DYNAMIC-LENGTH-FIELDs end to end:

* several fields in a row, where only the first one has a BYTE-POSITION and the
  following ones start at the byte edge after the previous one (ISO 22901-1 7.3.5.4),
* a DYNAMIC-LENGTH-FIELD nested inside the item structure of another one,
* an 8 bit and a 16 bit item count, and an OFFSET larger than the count.

Data record layout (starting at byte 3, after SID + DID):

    Destinations  [count u8][ {Year u16, Month u8} * count ]
    Waypoints     [count u8][ {WaypointId u8, Readings} * count ]
      Readings    [count u8][ {Reading u16} * count ]
    Passengers    [count u16][ {PassengerId u8} * count ]
"""

from helper import (
    derived_id,
    did_parameter_rq,
    find_dop_by_shortname,
    functional_class_ref,
    matching_request_parameter_did,
    ref,
    sid_parameter_pr,
    sid_parameter_rq,
)
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.diagservice import DiagService
from odxtools.dynamiclengthfield import DetermineNumberOfItems, DynamicLengthField
from odxtools.nameditemlist import NamedItemList
from odxtools.parameters.valueparameter import ValueParameter
from odxtools.request import Request
from odxtools.response import Response, ResponseType
from odxtools.structure import Structure

TIMELINE_DID = 0xF300
SERVICE_NAME = "FluxCapacitorTimeline"


def _value_param(short_name: str, dop, byte_position: int | None) -> ValueParameter:
    return ValueParameter(
        short_name=short_name,
        semantic="DATA",
        byte_position=byte_position,
        dop_ref=ref(dop),
    )


def _structure(dlr: DiagLayerRaw, short_name: str, params: list[ValueParameter]) -> Structure:
    structure = Structure(
        odx_id=derived_id(dlr, f"STRUCT.{short_name}"),
        short_name=short_name,
        parameters=NamedItemList(params),
    )
    dlr.diag_data_dictionary_spec.structures.append(structure)
    return structure


def _dynamic_length_field(
    dlr: DiagLayerRaw,
    short_name: str,
    item: Structure,
    count_dop,
    offset: int,
) -> DynamicLengthField:
    field = DynamicLengthField(
        odx_id=derived_id(dlr, f"DYN_FIELD.{short_name}"),
        short_name=short_name,
        structure_ref=ref(item.odx_id),
        offset=offset,
        determine_number_of_items=DetermineNumberOfItems(
            byte_position=0,
            dop_ref=ref(count_dop),
        ),
    )
    dlr.diag_data_dictionary_spec.dynamic_length_fields.append(field)
    return field


def _timeline_params(
    destinations: DynamicLengthField,
    waypoints: DynamicLengthField,
    passengers: DynamicLengthField,
) -> list[ValueParameter]:
    return [
        _value_param("Destinations", destinations, 3),
        # no BYTE-POSITION: chained behind the previous field
        _value_param("Waypoints", waypoints, None),
        _value_param("Passengers", passengers, None),
    ]


def add_timeline_service(dlr: DiagLayerRaw):
    u8 = find_dop_by_shortname(dlr, "IDENTICAL_UINT_8")
    u16 = find_dop_by_shortname(dlr, "IDENTICAL_UINT_16")

    destination = _structure(
        dlr,
        "TimelineDestination",
        [_value_param("Year", u16, 0), _value_param("Month", u8, 2)],
    )
    destinations = _dynamic_length_field(dlr, "TimelineDestinations", destination, u8, 1)

    reading = _structure(dlr, "TimelineReading", [_value_param("Reading", u16, 0)])
    readings = _dynamic_length_field(dlr, "TimelineReadings", reading, u8, 1)

    waypoint = _structure(
        dlr,
        "TimelineWaypoint",
        [_value_param("WaypointId", u8, 0), _value_param("Readings", readings, 1)],
    )
    waypoints = _dynamic_length_field(dlr, "TimelineWaypoints", waypoint, u8, 1)

    passenger = _structure(dlr, "TimelinePassenger", [_value_param("PassengerId", u8, 0)])
    # 16 bit item count, items start after it
    passengers = _dynamic_length_field(dlr, "TimelinePassengers", passenger, u16, 2)

    # Read (0x22)
    request_read = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{SERVICE_NAME}_Read"),
        short_name=f"RQ_{SERVICE_NAME}_Read",
        parameters=NamedItemList([sid_parameter_rq(0x22), did_parameter_rq(TIMELINE_DID)]),
    )
    dlr.requests.append(request_read)
    response_read = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{SERVICE_NAME}_Read"),
        short_name=f"PR_{SERVICE_NAME}_Read",
        parameters=NamedItemList(
            [
                sid_parameter_pr(0x22 + 0x40),
                matching_request_parameter_did("DID_PR"),
                *_timeline_params(destinations, waypoints, passengers),
            ]
        ),
    )
    dlr.positive_responses.append(response_read)
    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{SERVICE_NAME}_Read"),
            short_name=f"{SERVICE_NAME}_Read",
            long_name="Flux Capacitor Timeline",
            functional_class_refs=[functional_class_ref(dlr, "Ident")],
            request_ref=ref(request_read),
            pos_response_refs=[ref(response_read)],
            semantic="STOREDDATA",
        )
    )

    # Write (0x2E)
    request_write = Request(
        odx_id=derived_id(dlr, f"RQ.RQ_{SERVICE_NAME}_Write"),
        short_name=f"RQ_{SERVICE_NAME}_Write",
        parameters=NamedItemList(
            [
                sid_parameter_rq(0x2E),
                did_parameter_rq(TIMELINE_DID),
                *_timeline_params(destinations, waypoints, passengers),
            ]
        ),
    )
    dlr.requests.append(request_write)
    response_write = Response(
        response_type=ResponseType.POSITIVE,
        odx_id=derived_id(dlr, f"PR.PR_{SERVICE_NAME}_Write"),
        short_name=f"PR_{SERVICE_NAME}_Write",
        parameters=NamedItemList(
            [sid_parameter_pr(0x2E + 0x40), matching_request_parameter_did("DID_PR")]
        ),
    )
    dlr.positive_responses.append(response_write)
    dlr.diag_comms_raw.append(
        DiagService(
            odx_id=derived_id(dlr, f"DC.{SERVICE_NAME}_Write"),
            short_name=f"{SERVICE_NAME}_Write",
            long_name="Flux Capacitor Timeline",
            functional_class_refs=[functional_class_ref(dlr, "Ident")],
            request_ref=ref(request_write),
            pos_response_refs=[ref(response_write)],
            semantic="STOREDDATA",
        )
    )
