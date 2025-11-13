# CDA ECU SIM

## Intro

This is an ecu simulation intended to be used for integration tests with the classic-diagnostic-adapter in the Eclipse OpenSOVD project

## Features

- Simulates a DoIP/UDS topology of ECUs for testing with the CDA
- Mock for token creation
  - Used to create and verify tokens in the default security plugin
- Offers endpoints to:
  - Retrieve and modify the ECU state
  - Retrieve data transfer data
  - Record incoming UDS messages

  This allows integration tests to verify that the request to the CDA are translated correctly for the target ECU.
