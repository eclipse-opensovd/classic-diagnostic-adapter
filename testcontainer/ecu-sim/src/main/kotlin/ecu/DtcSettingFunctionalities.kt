/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

package ecu

import RequestsData

fun RequestsData.addDtcSettingRequests() {
    // 85 01 - DTC Setting Mode On
    request("85 01", name = "DTC_Setting_Mode_On") {
        val ecuState = ecu.ecuState()
        ecuState.dtcSettingType = DtcSettingType.ON
        ack()
    }

    // 85 02 - DTC Setting Mode Off
    request("85 02", name = "DTC_Setting_Mode_Off") {
        val ecuState = ecu.ecuState()
        ecuState.dtcSettingType = DtcSettingType.OFF
        ack()
    }

    // 85 42 - TimeTravelDTCsOn (custom vendor-specific)
    request("85 42", name = "DTC_Setting_Mode_TimeTravelDTCsOn") {
        val ecuState = ecu.ecuState()
        ecuState.dtcSettingType = DtcSettingType.TIME_TRAVEL_DTCS_ON
        ack()
    }
}
