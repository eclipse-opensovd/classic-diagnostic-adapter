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

//! Communication parameter provider trait implementations for [`EcuManager`].
//!
//! This module contains the [`cda_interfaces::UdsComParamProvider`] and
//! [`cda_interfaces::DoipComParamProvider`] trait implementations.

use std::time::Duration;

use cda_interfaces::{
    HashMap,
    datatypes::{AddressingMode, RetryPolicy, TesterPresentSendType},
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;

impl<S: SecurityPlugin> cda_interfaces::UdsComParamProvider for EcuManager<S> {
    fn tester_present_retry_policy(&self) -> bool {
        self.tester_present_retry_policy
    }
    fn tester_present_addr_mode(self) -> AddressingMode {
        self.tester_present_addr_mode.clone()
    }
    fn tester_present_response_expected(self) -> bool {
        self.tester_present_response_expected
    }
    fn tester_present_send_type(self) -> TesterPresentSendType {
        self.tester_present_send_type.clone()
    }
    fn tester_present_message(self) -> Vec<u8> {
        self.tester_present_message.clone()
    }
    fn tester_present_exp_pos_resp(self) -> Vec<u8> {
        self.tester_present_exp_pos_resp.clone()
    }
    fn tester_present_exp_neg_resp(self) -> Vec<u8> {
        self.tester_present_exp_neg_resp.clone()
    }
    fn tester_present_time(&self) -> Duration {
        self.tester_present_time
    }
    fn repeat_req_count_app(&self) -> u32 {
        self.repeat_req_count_app
    }
    fn rc_21_retry_policy(&self) -> RetryPolicy {
        self.rc_21_retry_policy.clone()
    }
    fn rc_21_completion_timeout(&self) -> Duration {
        self.rc_21_completion_timeout
    }
    fn rc_21_repeat_request_time(&self) -> Duration {
        self.rc_21_repeat_request_time
    }
    fn rc_78_retry_policy(&self) -> RetryPolicy {
        self.rc_78_retry_policy.clone()
    }
    fn rc_78_completion_timeout(&self) -> Duration {
        self.rc_78_completion_timeout
    }
    fn rc_78_timeout(&self) -> Duration {
        self.rc_78_timeout
    }
    fn rc_94_retry_policy(&self) -> RetryPolicy {
        self.rc_94_retry_policy.clone()
    }
    fn rc_94_completion_timeout(&self) -> Duration {
        self.rc_94_completion_timeout
    }
    fn rc_94_repeat_request_time(&self) -> Duration {
        self.rc_94_repeat_request_time
    }
    fn timeout_default(&self) -> Duration {
        self.timeout_default
    }
}

impl<S: SecurityPlugin> cda_interfaces::DoipComParamProvider for EcuManager<S> {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        &self.nack_number_of_retries
    }
    fn diagnostic_ack_timeout(&self) -> Duration {
        self.diagnostic_ack_timeout
    }
    fn retry_period(&self) -> Duration {
        self.retry_period
    }
    fn routing_activation_timeout(&self) -> Duration {
        self.routing_activation_timeout
    }
    fn repeat_request_count_transmission(&self) -> u32 {
        self.repeat_request_count_transmission
    }
    fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
    fn connection_retry_delay(&self) -> Duration {
        self.connection_retry_delay
    }
    fn connection_retry_attempts(&self) -> u32 {
        self.connection_retry_attempts
    }
}
