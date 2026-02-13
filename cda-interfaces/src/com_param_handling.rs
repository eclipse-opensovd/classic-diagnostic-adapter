/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::time::Duration;

use crate::{
    HashMap,
    datatypes::{AddressingMode, RetryPolicy, TesterPresentSendType},
};

pub trait UdsComParamProvider: Send + Sync + 'static {
    #[must_use]
    fn tester_present_retry_policy(&self) -> bool;
    #[must_use]
    fn tester_present_addr_mode(self) -> AddressingMode;
    #[must_use]
    fn tester_present_response_expected(self) -> bool;
    #[must_use]
    fn tester_present_send_type(self) -> TesterPresentSendType;
    #[must_use]
    fn tester_present_message(self) -> Vec<u8>;
    #[must_use]
    fn tester_present_exp_pos_resp(self) -> Vec<u8>;
    #[must_use]
    fn tester_present_exp_neg_resp(self) -> Vec<u8>;
    #[must_use]
    fn tester_present_time(&self) -> Duration;
    #[must_use]
    fn repeat_req_count_app(&self) -> u32;
    #[must_use]
    fn rc_21_retry_policy(&self) -> RetryPolicy;
    #[must_use]
    fn rc_21_completion_timeout(&self) -> Duration;
    #[must_use]
    fn rc_21_repeat_request_time(&self) -> Duration;
    #[must_use]
    fn rc_78_retry_policy(&self) -> RetryPolicy;
    #[must_use]
    fn rc_78_completion_timeout(&self) -> Duration;
    #[must_use]
    fn rc_78_timeout(&self) -> Duration;
    #[must_use]
    fn rc_94_retry_policy(&self) -> RetryPolicy;
    #[must_use]
    fn rc_94_completion_timeout(&self) -> Duration;
    #[must_use]
    fn rc_94_repeat_request_time(&self) -> Duration;
    #[must_use]
    fn timeout_default(&self) -> Duration;
}

pub trait DoipComParamProvider: Send + Sync + 'static {
    #[must_use]
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32>;
    #[must_use]
    fn diagnostic_ack_timeout(&self) -> Duration;
    #[must_use]
    fn retry_period(&self) -> Duration;
    #[must_use]
    fn routing_activation_timeout(&self) -> Duration;
    #[must_use]
    fn repeat_request_count_transmission(&self) -> u32;
    #[must_use]
    fn connection_timeout(&self) -> Duration;
    #[must_use]
    fn connection_retry_delay(&self) -> Duration;
    #[must_use]
    fn connection_retry_attempts(&self) -> u32;
}
