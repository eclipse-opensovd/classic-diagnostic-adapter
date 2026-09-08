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

//! Default no-preemption policy for the reference CDA.
//!
//! The default implementation preserves normal lock conflict handling by allowing
//! acquisition evaluation without selecting locks for preemption. Vendors can replace it through
//! `opensovd_cda_lib::Setup::with_lock_priority_plugin`.

use async_trait::async_trait;
use cda_interfaces::lock_priority_api::{
    LockPriorityDecision, LockPriorityError, LockPriorityEvaluation, LockPriorityPolicy,
};

/// Policy that never requests lock preemption.
#[derive(Debug, Default)]
pub struct NoPreemptionPolicy;

#[async_trait]
impl LockPriorityPolicy for NoPreemptionPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use cda_interfaces::lock_priority_api::{
        LockPrincipal, LockPriorityOperation, LockRequest, LockScope,
    };

    use super::*;

    #[tokio::test]
    async fn allows_lock_acquisition() {
        let evaluation = LockPriorityEvaluation {
            evaluation_id: "evaluation".to_owned(),
            operation: LockPriorityOperation::Acquire,
            request: LockRequest {
                scope: LockScope::Vehicle,
                principal: LockPrincipal {
                    subject: "client".to_owned(),
                    claims: serde_json::Map::new(),
                },
                expires_at: SystemTime::now(),
                break_lock: true,
                exclusive: true,
                metadata: serde_json::Map::new(),
            },
            revision: 1,
            captured_at: SystemTime::now(),
            active_locks: Vec::new(),
            preemption_candidates: vec!["existing-lock".to_owned()],
        };

        let decision = NoPreemptionPolicy.evaluate(&evaluation).await;

        assert_eq!(decision, Ok(LockPriorityDecision::Allow));
    }
}
