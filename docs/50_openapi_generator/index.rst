.. SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
..
.. See the NOTICE file(s) distributed with this work for additional
.. information regarding copyright ownership.
..
.. This program and the accompanying materials are made available under the
.. terms of the Apache License Version 2.0 which is available at
.. https://www.apache.org/licenses/LICENSE-2.0
..
.. SPDX-License-Identifier: Apache-2.0

************
Requirements
************


General
=======

.. req:: Standalone OpenAPI Generator
    :id: req~sovd-api-standalone-openapi-generator
    :links: arch~openapi-gen-standalone-tool
    :status: valid

    A standalone OpenAPI generator must be provided, which allows the creation of a full OpenAPI document for a single ECU,
    with a set of ECU variants, and audiences.

.. req:: ECU Variant Selection
    :id: req~openapi-gen-variant-selection
    :links: arch~openapi-gen-standalone-tool
    :status: valid

    The generator must create the document(s) for one or more explicitly selected ECU variants, or for all
    variants contained in the MDD file, without communicating with the ECU. If no variant is selected, the
    base variant is used. One document must be created per variant. An unknown variant must be rejected,
    listing the available variants.

.. req:: Audience Filtering
    :id: req~openapi-gen-audience-filter
    :links: arch~openapi-gen-standalone-tool
    :status: valid

    The generator must allow restricting the services contained in the document to a set of ODX audiences
    (the standard audiences ``supplier``, ``development``, ``manufacturing``, ``aftersales``, ``aftermarket``
    and additional audiences by short name). Without a selected audience, all services are included.
    Services without an audience definition are always included.

.. req:: OEM Extensibility
    :id: req~openapi-gen-oem-extensibility
    :links: arch~openapi-gen-extension-points
    :status: valid

    OEMs must be able to extend the generator in their own binary, by:

    * replacing or extending the service filter,
    * adding additional paths to the document,
    * post-processing the final document.

.. req:: Functional Groups in the generated document
    :id: req~openapi-gen-functional-groups
    :status: draft

    The generated document should contain the functional group endpoints (``/functions/functionalgroups/...``).

    .. note::

       Not supported yet: functional groups are out of scope for the first version of the generator.


************
Architecture
************

.. arch:: Standalone OpenAPI Generator Tool
    :id: arch~openapi-gen-standalone-tool
    :links: dimpl~openapi-gen-cli, dimpl~openapi-gen-document, dimpl~openapi-gen-variant-selection, dimpl~openapi-gen-audience-filter, dimpl~openapi-gen-offline-ecu-access, dsgn~openapi-gen-no-security-plugin, testset~openapi-gen
    :status: draft

    The generator is provided by the crate ``cda-openapi-gen`` as library and as the binary
    ``opensovd-cda-openapi``:

    .. code-block:: text

       opensovd-cda-openapi --mdd <FILE> [--config <CDA_CONFIG>]
           [--variant <NAME>]... | [--all-variants]
           [--audience supplier|development|manufacturing|aftersales|aftermarket]...
           [--additional-audience <NAME>]...
           [--output-dir <DIR> | --output <FILE>] [--server-url <URL>] [--list-variants]

    The MDD file is loaded with the same settings as the CDA (optional CDA configuration file, e.g. for the
    database naming convention), but never modified. The variant is selected offline in the ``EcuManager``
    of ``cda-core``, no variant detection is performed.

    For each selected variant, the data, configuration and operation services visible after filtering are
    turned into concrete paths below ``/vehicle/v15/components/{ecu}``, using the same builders as the
    online capability description endpoints (``.../{service}/docs``) of the CDA, so both are consistent.
    The document is written as ``<ecu>_<variant>.openapi.json``.

    .. note::

       Not included in the first version: the generic ECU endpoints (e.g. locks, modes, faults, generic
       service, flashing), the collection endpoints and functional groups
       (see ``req~openapi-gen-functional-groups``).

.. arch:: OEM Extension Points
    :id: arch~openapi-gen-extension-points
    :links: dimpl~openapi-gen-extension-points, testset~openapi-gen
    :status: draft

    OEMs build their own binary on top of the library, configuring a ``Generator`` via
    ``Generator::builder()``:

    * ``ServiceFilter`` - ``with_service_filter`` replaces the default audience filter,
      ``add_service_filter`` adds filters, which all must include a service.
    * ``PathContributor`` - adds paths to the document, after the generated ones.
    * ``DocumentPostProcessor`` - transforms the final document, in registration order.

    ``Generator::run_from_cli`` provides the standard command line interface.

.. dsgn:: Security plugin is not used by the generator
    :id: dsgn~openapi-gen-no-security-plugin
    :status: draft

    The generator does not evaluate the security plugin (``SecurityApi::validate_service``); the
    visibility of services is decided by the service filters only. An adapter may be added later.


************
Verification
************

.. testset:: Standalone OpenAPI Generator
    :id: testset~openapi-gen
    :links: test~openapi-gen-all-variants, test~openapi-gen-unknown-variant, test~openapi-gen-extensions, test~openapi-gen-cli, test~openapi-gen-audience-no-selection, test~openapi-gen-audience-standard, test~openapi-gen-audience-additional, test~openapi-gen-offline-variant-selection, test~openapi-gen-offline-audience
    :status: draft

    Verifies variant selection, audience filtering, the OEM extension points and the command line
    interface of the standalone OpenAPI generator.
