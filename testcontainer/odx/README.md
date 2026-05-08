<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0
-->

# ECU topology

- FLXC1000 (Gateway "Flux capacitor")
  - TMC1001 (CAN-ECU "Time Circuit")
- FSNR2000 (Gateway "Fusion reactor")
  - FRIN2001 (CAN-ECU "Fusion reactor intake")
  - FRCH2002 (CAN-ECU "Fusion reactor chamber")
  - FRPW2003 (CAN-ECU "Fusion reactor power coupling")
- TMCC3000 (Gateway "Time Machine Control Computer" — no protocols in DB, `ignore_protocol` enabled, com-params via config overrides)
- HOVR4000 (Gateway "Hover Conversion" — per-ECU protocol override test, uses DMC_DoIP)
- JGWT5000 (Gateway "Jigowatt Power Regulator" — one non-default protocol in DB with `ignore_protocol` enabled, exercises `into_db_protocol` fallback path)

## Minimal comparam ECUs

TMCC3000, HOVR4000 and JGWT5000 are generated with minimal communication parameters
(only `CP_UniqueRespIdTable` and `CP_DoIPLogicalGatewayAddress`). The gateway address
is deliberately set to an invalid value (`0xDEAD`) so that integration tests can
verify that the CDA's per-ECU config override with `precedence = "Config"` takes
priority over the database value. The correct gateway addresses are supplied via the
test configuration file (`cda-test-config.toml`).

### Required TOML configuration

These ECUs will not work without the following per-ECU configuration:

#### TMCC3000

```toml
[ecu.TMCC3000]
ignore_protocol = true

[ecu.TMCC3000.com_params.doip.logical_gateway_address]
value = 12288  # 0x3000
name = "logical_gateway_address"
precedence = "Config"
```

#### HOVR4000

```toml
[ecu.HOVR4000]
ignore_protocol = false
protocol = "DMC_DoIP"

[ecu.HOVR4000.com_params.doip.logical_gateway_address]
value = 16384  # 0x4000
name = "logical_gateway_address"
precedence = "Config"
```

#### JGWT5000

```toml
[ecu.JGWT5000]
ignore_protocol = true

[ecu.JGWT5000.com_params.doip.logical_gateway_address]
value = 20480  # 0x5000
name = "logical_gateway_address"
precedence = "Config"
```

The `precedence = "Config"` setting ensures the config value overrides the invalid
`0xDEAD` gateway address in the MDD. The remaining com-params (timeouts, retry
policies, tester-present settings, etc.) use `precedence = "Database"` and fall back
to their defaults when not found in the DB — see `cda-test-config.toml` for the full
configuration.
