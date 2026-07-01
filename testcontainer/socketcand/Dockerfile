# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# socketcand daemon fronting a virtual CAN bus, used by the CAN integration
# tests so the CDA and the ECU simulator can share a (v)can bus over TCP
# without each container needing its own kernel CAN stack. socketcand is not
# packaged in Debian, so it is built from source with meson.

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
# address — passing `-l 0.0.0.0` makes it look up a non-existent interface and
# die with "bind: Cannot assign requested address". `eth0` is the container's
# interface on the compose bridge network, so clients reach it by service name.
CMD ["/bin/sh", "-c", "ip link add dev vcan0 type vcan && ip link set up vcan0 && exec socketcand -n -i vcan0 -l eth0"]
