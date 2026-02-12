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

FROM sphinxdoc/sphinx:8.2.3

RUN apt update && apt-get install -y git curl openjdk-17-jre && apt-get autoremove -y && apt-get -y clean
ADD requirements.txt /tmp
RUN python3 -m pip install -r /tmp/requirements.txt
RUN curl -L -o /usr/local/bin/plantuml.jar https://github.com/plantuml/plantuml/releases/download/v1.2026.1/plantuml-1.2026.1.jar
RUN sha256sum /usr/local/bin/plantuml.jar | grep "89c116168a2a0f7cf5292e11617ba22abd743f891914f1fec5bc9c7d257b3092" > /dev/null
RUN useradd -ms /bin/bash dockeruser

USER dockeruser
WORKDIR /docs
