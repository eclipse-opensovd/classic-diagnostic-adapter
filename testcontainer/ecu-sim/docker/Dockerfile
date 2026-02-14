# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

ARG JAVA_VERSION=21
FROM gradle:8-jdk${JAVA_VERSION} AS builder
WORKDIR /build
COPY . .
RUN gradle build --no-daemon

FROM eclipse-temurin:${JAVA_VERSION}-jre

RUN apt-get -y update && apt-get -y install tcpdump vim iproute2 jq curl

WORKDIR /app

COPY --chmod=755 docker/ipcli.sh /app/ipcli.sh
COPY --chmod=755 docker/entrypoint.sh /app/entrypoint.sh
COPY --from=builder /build/build/libs/ecu-sim-all.jar /app/ecu-sim-all.jar

ENTRYPOINT ["/app/entrypoint.sh"]
