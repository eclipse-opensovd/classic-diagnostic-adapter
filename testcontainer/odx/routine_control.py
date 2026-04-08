# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from odxtools.diaglayers.diaglayerraw import DiagLayerRaw

from routines import add_routine


def add_routine_control_services(dlr: DiagLayerRaw):
    # 31 01 10 01 - SelfTest Start (synchronous, Start only)
    add_routine(
        dlr,
        name="SelfTest",
        routine_id=0x1001,
        routine_type="Start",
        functional_class="Routines",
        description="Self Test",
    )

    # 31 01 10 02 - CalibrateSensors Start (asynchronous)
    add_routine(
        dlr,
        name="CalibrateSensors",
        routine_id=0x1002,
        routine_type="Start",
        functional_class="Routines",
        description="Calibrate Sensors",
    )

    # 31 02 10 02 - CalibrateSensors Stop
    add_routine(
        dlr,
        name="CalibrateSensors",
        routine_id=0x1002,
        routine_type="Stop",
        functional_class="Routines",
        description="Calibrate Sensors Stop",
    )

    # 31 03 10 02 - CalibrateSensors RequestResults
    add_routine(
        dlr,
        name="CalibrateSensors",
        routine_id=0x1002,
        routine_type="RequestResults",
        functional_class="Routines",
        description="Calibrate Sensors Request Results",
    )
