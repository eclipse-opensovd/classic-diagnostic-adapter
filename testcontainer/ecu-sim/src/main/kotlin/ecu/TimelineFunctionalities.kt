/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package ecu

import NrcException
import RequestsData
import SimEcu
import utils.messagePayload
import java.io.ByteArrayOutputStream
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer

/*
 * DID 0xF300 (FluxCapacitorTimeline), see testcontainer/odx/dynamic_length_fields.py.
 *
 * The data record consists of three chained DYNAMIC-LENGTH-FIELDs:
 *
 *   Destinations  [count u8][ {Year u16, Month u8} * count ]
 *   Waypoints     [count u8][ {WaypointId u8, Readings [count u8][ {Reading u16} * count ]} * count ]
 *   Passengers    [count u16][ {PassengerId u8} * count ]
 *
 * The simulator parses written data strictly (every byte must be consumed), so a
 * wrongly encoded request is rejected with NRC 0x13 instead of being echoed back.
 */

data class TimelineDestination(
    val year: Int,
    val month: Int,
)

data class TimelineWaypoint(
    val waypointId: Int,
    val readings: List<Int>,
)

data class Timeline(
    val destinations: List<TimelineDestination>,
    val waypoints: List<TimelineWaypoint>,
    val passengers: List<Int>,
) {
    fun toByteArray(): ByteArray {
        val out = ByteArrayOutputStream()

        fun u8(v: Int) = out.write(v and 0xFF)

        fun u16(v: Int) {
            u8(v shr 8)
            u8(v)
        }

        u8(destinations.size)
        destinations.forEach {
            u16(it.year)
            u8(it.month)
        }
        u8(waypoints.size)
        waypoints.forEach { waypoint ->
            u8(waypoint.waypointId)
            u8(waypoint.readings.size)
            waypoint.readings.forEach { u16(it) }
        }
        u16(passengers.size)
        passengers.forEach { u8(it) }
        return out.toByteArray()
    }

    companion object {
        val DEFAULT =
            Timeline(
                destinations = listOf(TimelineDestination(1955, 11), TimelineDestination(1985, 10)),
                waypoints = listOf(TimelineWaypoint(1, listOf(88, 121))),
                passengers = listOf(1, 2),
            )

        fun parse(buffer: ByteBuffer): Timeline {
            fun u8() = buffer.get().toInt() and 0xFF

            fun u16() = buffer.short.toInt() and 0xFFFF

            try {
                val destinations = List(u8()) { TimelineDestination(year = u16(), month = u8()) }
                val waypoints =
                    List(u8()) {
                        val id = u8()
                        TimelineWaypoint(waypointId = id, readings = List(u8()) { u16() })
                    }
                val passengers = List(u16()) { u8() }
                if (buffer.hasRemaining()) {
                    throw NrcException(NrcError.IncorrectMessageLengthOrInvalidFormat)
                }
                return Timeline(destinations, waypoints, passengers)
            } catch (_: BufferUnderflowException) {
                throw NrcException(NrcError.IncorrectMessageLengthOrInvalidFormat)
            }
        }
    }
}

class TimelineHolder(
    var timeline: Timeline = Timeline.DEFAULT,
)

fun SimEcu.timeline(): TimelineHolder {
    val holder by this.storedProperty { TimelineHolder() }
    return holder
}

fun RequestsData.addTimelineRequests() {
    request("22 F3 00", name = "FluxCapacitorTimeline_Read") {
        ack(ecu.timeline().timeline.toByteArray())
    }

    request("2E F3 00 []", name = "FluxCapacitorTimeline_Write") {
        ecu.timeline().timeline = Timeline.parse(messagePayload())
        ack()
    }
}
