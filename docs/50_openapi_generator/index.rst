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
    :links: dimpl~openapi-gen-cli, dimpl~openapi-gen-document, dimpl~openapi-gen-variant-selection, dimpl~openapi-gen-audience-filter, dimpl~openapi-gen-offline-ecu-access, dimpl~openapi-gen-route-skeleton, dimpl~openapi-gen-template-instantiation, dimpl~openapi-gen-shared-schemas, dimpl~openapi-gen-fault-environment-data, dsgn~openapi-gen-no-security-plugin, dsgn~openapi-gen-runtime-ids, testset~openapi-gen
    :status: draft

    The generator is provided by the crate ``cda-openapi-gen`` as library and as the binary
    ``cda-openapi-gen``:

    .. code-block:: text

       cda-openapi-gen --mdd <FILE> [--config <CDA_CONFIG>]
           [--variant <NAME>]... | [--all-variants]
           [--audience supplier|development|manufacturing|aftersales|aftermarket]...
           [--additional-audience <NAME>]...
           [--output-dir <DIR> | --output <FILE>] [--server-url <URL>] [--fault-schemas full|generic]
           [--pretty] [--list-variants]

    The MDD file is loaded with the same settings as the CDA (optional CDA configuration file, e.g. for the
    database naming convention), but never modified. The variant is selected offline in the ``EcuManager``
    of ``cda-core``, no variant detection is performed.

    The document consists of two parts:

    * Generic ECU routes (component, collections, locks, modes, faults, generic service, comparam
      executions, flashing, embedded files): the unmodified route setup of ``cda-sovd`` is run
      against a UDS layer with a transport that never communicates, and the OpenAPI description collected
      while registering the routes is used. All routes outside the ECU (vehicle locks, functions,
      apps) are removed.
    * Per-resource routes: every route of a resource defined by the MDD (``/data/{service}``,
      ``/configurations/{service}``, ``/operations/{service}``, ``/x-single-ecu-jobs/{job_name}``, each with
      all sub routes such as ``.../docs`` and ``.../executions``) is turned into concrete paths below
      ``/vehicle/v15/components/{ecu}`` for every visible resource. The resource ids are the same the CDA
      lists at runtime. The main data, configuration and operation paths are built with the same builders as
      the online capability description endpoints (``.../{service}/docs``) of the CDA, so both are
      consistent, including the request and response schemas. All other per-resource routes are
      instantiated from the route description of the CDA: the placeholder is replaced, its path parameter
      removed and operation ids are made unique.

    The fault details (``/faults/{id}``) describe the environment data with the data types of the MDD
    (``--fault-schemas full``, default): the values of ``environment_data.snapshots.data`` and
    ``environment_data.extended_data_records.data`` use the response schemas of the ``ReadDTCInformation``
    snapshot (``0x19 04``, ``0x19 18``) and extended data (``0x19 06``, ``0x19 19``) services of the
    variant, mapped the same way as the CDA maps the responses (``cda-sovd`` ``docs::faults``). Fault and
    user memory services with different schemas are combined with ``anyOf``. As the content depends on the
    DTC (environment data descriptions, multiplexers), every possible record content is listed as an
    alternative. ``--fault-schemas generic`` keeps the generic schema of the CDA, e.g. to reduce the
    document size.

    The document thereby contains every path below ``/vehicle/v15/components/{ecu}`` that exists in a
    running CDA for this ECU and variant (see ``dsgn~openapi-gen-runtime-ids`` for ids created at runtime).

    As last step, after all extensions, the schemas defined inline in the paths are moved into
    ``components/schemas`` and replaced by references (``$ref``). Nested schemas are moved first, so
    identical schemas, e.g. of a data and a configuration service or parameter structures used by many
    services, are stored once. Schemas shorter than 100 characters stay inline. Local definitions
    (``$defs``) of inline schemas are moved as well, as their references would otherwise resolve against
    the document root. Component names are derived from the first path using the schema, e.g.
    ``data.<id>.get.200`` and ``data.<id>.get.200.data``.

    The document is written as ``<ecu>_<variant>.openapi.json``, as compact JSON by default and indented
    with ``--pretty``.

    .. note::

       Functional groups are not included (see ``req~openapi-gen-functional-groups``).

.. arch:: OEM Extension Points
    :id: arch~openapi-gen-extension-points
    :links: dimpl~openapi-gen-extension-points, testset~openapi-gen
    :status: draft

    OEMs build their own binary on top of the library, configuring a ``Generator`` via
    ``Generator::builder()``:

    * ``ServiceFilter`` - ``with_service_filter`` replaces the default audience filter,
      ``add_service_filter`` adds filters, which all must include a service.
    * ``EndpointDecorator`` - modifies every path of a resource generated from the MDD (e.g. adds
      descriptions or vendor extensions to the data endpoints). It is called per path with the resource
      (``Endpoint``: data, configuration, operation or single ECU job), its id and the MDD objects it was
      generated from (``DiagService`` / ``SingleEcuJob`` of ``cda-database``), before the path contributors.
    * ``PathContributor`` - adds paths to the document, after the generated ones.
    * ``DocumentPostProcessor`` - transforms the final document, in registration order.

    Path contributors and post processors get read access to the complete ECU description of the variant
    (``GenContext::diag_layers``: the variant's diag layer followed by the ones of its parent refs), e.g. to
    describe the generic routes (modes, faults, flashing) based on the MDD. ``Endpoint`` is non-exhaustive,
    so further resource kinds can be added without breaking OEM code.

    The MDD objects are passed as the read-only data types of ``cda-database`` (re-exported as
    ``cda_openapi_gen::datatypes``) instead of a dedicated API, giving access to the complete ECU
    description. They follow the MDD file format, which changes rarely and mostly by extension.

    ``Generator::run_from_cli`` provides the standard command line interface.

.. dsgn:: Security plugin is not used by the generator
    :id: dsgn~openapi-gen-no-security-plugin
    :status: draft

    The generator does not evaluate the security plugin (``SecurityApi::validate_service``); the
    visibility of services is decided by the service filters only. An adapter may be added later.

.. dsgn:: Resources with runtime ids stay templated
    :id: dsgn~openapi-gen-runtime-ids
    :status: draft

    Routes whose ids are only created by the running CDA are kept with their placeholder, as in the
    description the CDA serves: locks (``/locks/{lock}``), executions
    (``.../executions/{execution-id}``, ``/operations/comparam/executions/{id}``), flash transfers
    (``/x-sovd2uds-download/flashtransfer/{id}``) and embedded files
    (``/x-sovd2uds-bulk-data/mdd-embedded-files/{id}``, a random id per load). Faults
    (``/faults/{id}``) are kept as well, as the id is the code of a DTC stored in the ECU at runtime.

************
Verification
************

.. testset:: Standalone OpenAPI Generator
    :id: testset~openapi-gen
    :links: test~openapi-gen-all-variants, test~openapi-gen-generic-routes, test~openapi-gen-unknown-variant, test~openapi-gen-extensions, test~openapi-gen-cli, test~openapi-gen-audience-no-selection, test~openapi-gen-audience-standard, test~openapi-gen-audience-additional, test~openapi-gen-offline-variant-selection, test~openapi-gen-offline-audience, test~openapi-gen-endpoint-decorator, test~openapi-gen-template-instantiation, test~openapi-gen-offline-endpoint-services, test~openapi-gen-shared-schemas, test~openapi-gen-cli-pretty, test~openapi-gen-unique-operation-ids, test~openapi-gen-fault-environment-data
    :status: draft

    Verifies variant selection, audience filtering, the OEM extension points and the command line
    interface of the standalone OpenAPI generator.
