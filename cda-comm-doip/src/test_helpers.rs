/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{sync::OnceLock, time::Duration};

use cda_interfaces::{DoipComParams, EcuAddresses, HashMap, HashMapExtensions};

/// Lightweight ECU fixture for `DoIP` unit tests.
#[derive(Clone, Debug)]
pub(crate) struct TestEcu {
    logical_address: u16,
    gateway_address: u16,
}

impl TestEcu {
    pub(crate) const fn new(logical_address: u16, gateway_address: u16) -> Self {
        Self {
            logical_address,
            gateway_address,
        }
    }
}

impl Default for TestEcu {
    fn default() -> Self {
        Self::new(0x0E80, 0x1234)
    }
}

impl EcuAddresses for TestEcu {
    fn tester_address(&self) -> u16 {
        0x0E80
    }

    fn logical_address(&self) -> u16 {
        self.logical_address
    }

    fn logical_gateway_address(&self) -> u16 {
        self.gateway_address
    }

    fn logical_functional_address(&self) -> u16 {
        0xE400
    }

    fn ecu_name(&self) -> String {
        "test".to_owned()
    }

    fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
        self.logical_address == other.logical_address()
    }
}

impl DoipComParams for TestEcu {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        static EMPTY: OnceLock<HashMap<u8, u32>> = OnceLock::new();
        EMPTY.get_or_init(HashMap::new)
    }

    fn diagnostic_ack_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    fn retry_period(&self) -> Duration {
        Duration::from_millis(100)
    }

    fn routing_activation_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn repeat_request_count_transmission(&self) -> u32 {
        3
    }

    fn connection_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn connection_retry_delay(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn connection_retry_attempts(&self) -> u32 {
        3
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cda_interfaces::{DoipComParams, EcuAddresses};

    use super::TestEcu;

    #[test]
    fn test_ecu_has_concrete_address_and_doip_comparam_values() {
        let ecu = TestEcu::new(0x110A, 0x110A);
        let other = TestEcu::new(0x110A, 0x1163);

        assert_eq!(ecu.tester_address(), 0x0E80);
        assert_eq!(ecu.logical_address(), 0x110A);
        assert_eq!(ecu.logical_gateway_address(), 0x110A);
        assert_eq!(ecu.logical_functional_address(), 0xE400);
        assert_eq!(ecu.ecu_name(), "test");
        assert!(ecu.logical_address_eq(&other));
        assert!(ecu.nack_number_of_retries().is_empty());
        assert_eq!(ecu.diagnostic_ack_timeout(), Duration::from_secs(2));
        assert_eq!(ecu.retry_period(), Duration::from_millis(100));
        assert_eq!(ecu.routing_activation_timeout(), Duration::from_secs(5));
        assert_eq!(ecu.repeat_request_count_transmission(), 3);
        assert_eq!(ecu.connection_timeout(), Duration::from_secs(5));
        assert_eq!(ecu.connection_retry_delay(), Duration::from_secs(1));
        assert_eq!(ecu.connection_retry_attempts(), 3);
    }
}
