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

FROM python:3.12-slim-trixie

RUN pip install odxtools==11.0.0

WORKDIR /data

ENTRYPOINT ["/usr/local/bin/python", "generate.py"]
