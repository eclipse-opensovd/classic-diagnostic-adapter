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

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential meson ninja-build pkg-config \
        libconfig-dev libsocketcan-dev iproute2 \
    && git clone --depth 1 https://github.com/linux-can/socketcand.git /tmp/socketcand \
    && cd /tmp/socketcand \
    && meson setup -Dlibconfig=true --buildtype=release build \
    && meson compile -C build \
    && meson install -C build \
    && ldconfig \
    && rm -rf /tmp/socketcand /var/lib/apt/lists/*

# Create the vcan bus at start (needs the `vcan` kernel module loaded on the
# host plus NET_ADMIN), then serve it over rawmode TCP on the default port
# 29536. The bus name `vcan0` is what clients pass in `< open vcan0 >`.
# `-n` disables the UDP discovery beacon (clients connect by host:port).
#
# NOTE: socketcand's `-l` takes an *interface name* (default `eth0`), NOT an IP
# address - passing `-l 0.0.0.0` makes it look up a non-existent interface and
# die with "bind: Cannot assign requested address". `eth0` is the container's
# interface on the compose bridge network, so clients reach it by service name.
CMD ["/bin/sh", "-c", "ip link add dev vcan0 type vcan && ip link set up vcan0 && exec socketcand -n -i vcan0 -l eth0"]
