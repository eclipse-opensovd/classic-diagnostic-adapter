/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/// Implements [`DoipComParams`](crate::DoipComParams) for `$ty` with the fixed
/// values used by the test ECUs.
#[macro_export]
macro_rules! impl_test_doip_com_params {
    ($ty:ty) => {
        impl $crate::DoipComParams for $ty {
            fn nack_number_of_retries(&self) -> &$crate::HashMap<u8, u32> {
                static EMPTY: ::std::sync::OnceLock<$crate::HashMap<u8, u32>> =
                    ::std::sync::OnceLock::new();
                EMPTY.get_or_init(<$crate::HashMap<u8, u32> as $crate::HashMapExtensions>::new)
            }

            fn diagnostic_ack_timeout(&self) -> ::std::time::Duration {
                ::std::time::Duration::from_secs(2)
            }

            fn retry_period(&self) -> ::std::time::Duration {
                ::std::time::Duration::from_millis(100)
            }

            fn routing_activation_timeout(&self) -> ::std::time::Duration {
                ::std::time::Duration::from_secs(5)
            }

            fn repeat_request_count_transmission(&self) -> u32 {
                3
            }

            fn connection_timeout(&self) -> ::std::time::Duration {
                ::std::time::Duration::from_secs(5)
            }

            fn connection_retry_delay(&self) -> ::std::time::Duration {
                ::std::time::Duration::from_secs(1)
            }

            fn connection_retry_attempts(&self) -> u32 {
                3
            }
        }
    };
}

/// Connectivity handler that records the ECUs reported as replied.
#[derive(Default)]
pub struct RecordingConnectivityHandler {
    replied: std::sync::Mutex<Vec<String>>,
}

impl RecordingConnectivityHandler {
    /// The ECU names reported through `on_ecu_replied`, in order.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn replied(&self) -> Vec<String> {
        // A poisoned lock means a test already panicked while recording,
        // so panicking here as well makes that failure visible instead of
        // silently continuing with possibly inconsistent results.
        self.replied.lock().expect("lock replied").clone()
    }
}

#[async_trait::async_trait]
impl crate::EcuConnectivityHandler for RecordingConnectivityHandler {
    async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

    async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {}

    async fn on_ecu_replied(&self, ecu_name: &str) {
        self.replied
            .lock()
            .expect("lock replied")
            .push(ecu_name.to_owned());
    }
}
