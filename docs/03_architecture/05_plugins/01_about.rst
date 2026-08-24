.. SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

Overview
--------

The plugin system in the Classic Diagnostic Adapter (CDA) provides extensibility for vendor-specific functionality that cannot be standardized across all implementations. Plugins enable customization of security mechanisms, authentication flows, and other domain-specific requirements while maintaining the core diagnostic functionality.

The plugin architecture is designed around trait-based interfaces that allow runtime polymorphism and flexible configuration. This approach ensures that the CDA can adapt to different deployment environments and vendor requirements without requiring modifications to the core codebase.

The security plugin, which is the primary plugin implementation within the CDA, is described in detail in :doc:`02_security`.
