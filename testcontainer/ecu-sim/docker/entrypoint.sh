#!/bin/bash -ex
# Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0


# shellcheck disable=SC2145
ls -la /app

if [ "$USE_MULTIPLE_IPS" = "true" ]; then
  ./ipcli.sh add eth0 100 '{100..150}'
fi

export SIM_NETWORK_INTERFACE=${SIM_NETWORK_INTERFACE:-eth0}

java -Djava.net.preferIPv4Stack=true $JAVA_OPTS -jar "/app/ecu-sim-all.jar" "$@"
