.. _requirements-plugins:

Plugins
=======

API
---

The plugin system API must support the following use-cases.

* Plugins must be able to utilize all the APIs in the CDA.
* Plugins must be able to access and modify a SOVD-request-context, if applicable for the type/interception point of that plugin

.. _requirements-plugins-security:

Security
--------

A SOVD security plugin must be able to:

* Validate and verify the JWT token from incoming HTTP Requests
* Utilize additional headers from the request
* Reject the incoming request
* Enhance the SOVD-request-context with data, this context can then be used in other addons

Paths
-----

A SOVD plugin must be able to:

* Add paths to the SOVD-API, and handle them
* Restructure existing path structures
* Modify existing path structures to run different code

UDS
---

An UDS plugin must be able to:

* Intercept UDS requests before they are sent to the ECU
* Intercept UDS responses

DoIP
----

A DoIP plugin must be able to:

* Intercept DoIP requests before they are sent to the ECU
* Intercept DoIP responses
