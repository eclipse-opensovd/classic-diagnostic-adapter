#!/bin/sh -e
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


DOIP_TESTER_IP=$(ip -4 a show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo "Using arguments: $@"
echo "Using DoIpTesterIp: $DOIP_TESTER_IP"

find "." -maxdepth 1 -type f -print0 | xargs -0 sha1sum

/app/opensovd-cda --tester-address "$DOIP_TESTER_IP" $@
