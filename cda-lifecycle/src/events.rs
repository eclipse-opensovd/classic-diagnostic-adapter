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

//! The events dispatched over the CDA's components.

use std::{any::Any, sync::Arc, time::Duration};

use cda_interfaces::{
    HashMap,
    communication_control::{DEFAULT_DEFERRED_RETRY_AFTER, PostUpdateCommunicationMode},
    http_protection::registry::{
        HttpProtectionConfig, HttpProtectionReason, HttpRouteMatcher, HttpStatusCode,
    },
    lifecycle::{DispatchGuards, LifecycleEvent},
    runtime_update_api::ExecutionMode,
    util::std_ext,
};

use crate::{
    guards::{LeaseOutcome, LeasePolicy},
    stages::CdaStage,
};

/// Execution modes that reload databases.
///
/// [`ExecutionMode::Cleanup`] deletes files without touching a database, so it
/// is deliberately not representable here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadExecutionMode {
    /// Apply staged files as the new current version.
    Apply,
    /// Revert to the backup from the previous apply.
    Rollback,
}

impl From<ReloadExecutionMode> for ExecutionMode {
    fn from(mode: ReloadExecutionMode) -> Self {
        match mode {
            ReloadExecutionMode::Apply => ExecutionMode::Apply,
            ReloadExecutionMode::Rollback => ExecutionMode::Rollback,
        }
    }
}

/// Database revisions per ECU, filled in as a reload completes.
///
/// Shared, because components see the event by reference.
#[derive(Clone, Debug, Default)]
pub struct EcuRevisions(Arc<std::sync::RwLock<HashMap<String, String>>>);

impl EcuRevisions {
    /// Records the revision a single ECU ended up on.
    pub fn record(&self, ecu: impl Into<String>, revision: impl Into<String>) {
        std_ext::lock_write(&self.0).insert(ecu.into(), revision.into());
    }

    /// Everything recorded so far.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<String, String> {
        std_ext::lock_read(&self.0).clone()
    }
}

/// One value handed between the components of a single dispatch.
///
/// A component that builds something a later one installs, and a component that
/// displaces a value a revert has to put back, both need somewhere to leave it.
/// The event outlives every component and is dropped with the dispatch, so
/// parking the value here frees it exactly when the reload can no longer be
/// undone. Type-erased, because the data belongs to the application and this
/// crate must not name it.
#[derive(Clone, Default)]
pub struct ParkedValue(Arc<std::sync::Mutex<Option<Box<dyn Any + Send>>>>);

impl std::fmt::Debug for ParkedValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The parked value is opaque here, so there is nothing to render.
        formatter.write_str("ParkedValue")
    }
}

impl ParkedValue {
    /// Parks `value` until [`take`](Self::take) claims it or the dispatch ends.
    pub fn retain<T: Send + 'static>(&self, value: T) {
        *std_ext::lock_mutex(&self.0) = Some(Box::new(value));
    }

    /// Claims the parked value, or `None` when nothing of type `T` is parked.
    #[must_use]
    pub fn take<T: Send + 'static>(&self) -> Option<T> {
        let mut parked = std_ext::lock_mutex(&self.0);
        let value = parked.take()?;
        match value.downcast::<T>() {
            Ok(value) => Some(*value),
            Err(other) => {
                *parked = Some(other);
                None
            }
        }
    }
}

/// The HTTP protection an update-style dispatch installs while it runs.
#[derive(Clone, Debug)]
pub struct UpdateHttpProtection {
    /// Routes that keep answering while the dispatch runs. Injected, because
    /// they are a SOVD fact and this crate must not depend on `cda-sovd`.
    pub exempt_routes: Vec<HttpRouteMatcher>,
    /// `Retry-After` hint returned to refused callers.
    pub retry_after: Duration,
}

impl Default for UpdateHttpProtection {
    fn default() -> Self {
        Self {
            exempt_routes: Vec::new(),
            retry_after: DEFAULT_DEFERRED_RETRY_AFTER,
        }
    }
}

impl UpdateHttpProtection {
    fn config(&self) -> HttpProtectionConfig {
        HttpProtectionConfig::new(
            HttpProtectionReason::UpdateInProgress,
            HttpStatusCode::CONFLICT,
            "A runtime update is in progress",
        )
        .with_exempt_routes(self.exempt_routes.clone())
        .with_retry_after(self.retry_after)
    }
}

/// A reload of the ECU databases into the running runtime.
#[derive(Clone, Debug)]
pub struct EcuDataReload {
    /// Which file transaction the reload runs.
    pub mode: ReloadExecutionMode,
    /// What the transport should look like once the reload finishes.
    pub communication_target: PostUpdateCommunicationMode,
    /// HTTP protection held for the duration of the reload.
    pub protection: UpdateHttpProtection,
    /// Filled in by the components that know the revisions they loaded.
    pub revisions: EcuRevisions,
    /// Where the component that builds the new data leaves it for the component
    /// that makes it live, so the two never share a slot outside the dispatch.
    pub prepared: ParkedValue,
    /// Where the committing component parks what it displaced, so its
    /// [`revert`](cda_interfaces::lifecycle::LifecycleComponent::revert) can put
    /// the previous value back.
    pub outgoing: ParkedValue,
}

impl EcuDataReload {
    /// Creates a reload for `mode`, targeting `communication_target`.
    #[must_use]
    pub fn new(
        mode: ReloadExecutionMode,
        communication_target: PostUpdateCommunicationMode,
        protection: UpdateHttpProtection,
    ) -> Self {
        Self {
            mode,
            communication_target,
            protection,
            revisions: EcuRevisions::default(),
            prepared: ParkedValue::default(),
            outgoing: ParkedValue::default(),
        }
    }
}

/// The transitions the CDA runtime dispatches while it is running.
///
/// Bringing the runtime up and taking it down are not here: they are the
/// construct / start and stop phases of
/// [`LifecycleRuntime`](crate::LifecycleRuntime), which the stage graph orders
/// rather than a dispatch.
///
/// Every variant names the stages it visits, in the table below. A component of
/// a visited stage may still match on the event and return without doing
/// anything, so the table decides what a transition reaches and the components
/// decide what they make of it.
#[non_exhaustive]
#[derive(strum_macros::AsRefStr, strum_macros::IntoStaticStr)]
#[strum(serialize_all = "kebab-case")]
pub enum CdaEvent {
    /// Replaces the ECU databases in the running runtime.
    ReloadEcuData(EcuDataReload),
    /// Deletes staged and backup files. Touches no database, so only the file
    /// transaction acts on it, but it takes the same guards and so still
    /// serializes against a concurrent execution.
    CleanupFiles(UpdateHttpProtection),
    /// Bare signal: components owning static data re-read their own source.
    ReloadStaticData,
}

/// A reload moves the database files, reads the databases they left behind,
/// makes what it read live, settles the staged set and republishes the version,
/// and ends by bringing communication back up.
const RELOAD_STAGES: [CdaStage; 6] = [
    CdaStage::DatabaseFiles,
    CdaStage::EcuData,
    CdaStage::Diagnostics,
    CdaStage::StagedFiles,
    CdaStage::Version,
    CdaStage::Activation,
];

/// A cleanup deletes files and touches no database.
const CLEANUP_STAGES: [CdaStage; 1] = [CdaStage::DatabaseFiles];

/// The version payload is the only static data the runtime owns.
const STATIC_DATA_STAGES: [CdaStage; 1] = [CdaStage::Version];

impl LifecycleEvent for CdaEvent {
    type Stage = CdaStage;

    fn name(&self) -> &'static str {
        self.into()
    }

    fn stages(&self) -> &'static [Self::Stage] {
        match self {
            CdaEvent::ReloadEcuData(_) => &RELOAD_STAGES,
            CdaEvent::CleanupFiles(_) => &CLEANUP_STAGES,
            CdaEvent::ReloadStaticData => &STATIC_DATA_STAGES,
        }
    }

    fn guards(&self) -> DispatchGuards {
        match self {
            CdaEvent::ReloadStaticData => DispatchGuards::default(),
            CdaEvent::ReloadEcuData(reload) => DispatchGuards {
                http_protection: Some(reload.protection.config()),
                communication_lease: true,
            },
            CdaEvent::CleanupFiles(protection) => DispatchGuards {
                http_protection: Some(protection.config()),
                communication_lease: true,
            },
        }
    }
}

/// Maps the event's communication target onto the lease outcome.
///
/// `DisableGuard::release` restores what the lease displaced, so releasing on a
/// deferred target would bring the transport up only for the activation to take
/// it back down.
pub struct CdaLeasePolicy;

impl LeasePolicy<CdaEvent> for CdaLeasePolicy {
    fn outcome(&self, event: &CdaEvent) -> LeaseOutcome {
        match event {
            CdaEvent::ReloadEcuData(reload)
                if reload.communication_target == PostUpdateCommunicationMode::Deferred =>
            {
                LeaseOutcome::Drop
            }
            _ => LeaseOutcome::Release,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered names travel in logs and in error messages, so a rename
    /// that changed them would silently change what an operator greps for.
    #[test]
    fn event_names_render_in_kebab_case() {
        let reload = CdaEvent::ReloadEcuData(EcuDataReload::new(
            ReloadExecutionMode::Apply,
            PostUpdateCommunicationMode::Enabled,
            UpdateHttpProtection::default(),
        ));
        assert_eq!(reload.name(), "reload-ecu-data");
        assert_eq!(
            CdaEvent::CleanupFiles(UpdateHttpProtection::default()).name(),
            "cleanup-files"
        );
        assert_eq!(CdaEvent::ReloadStaticData.name(), "reload-static-data");
    }

    #[test]
    fn only_update_events_take_guards() {
        assert!(
            CdaEvent::ReloadStaticData
                .guards()
                .http_protection
                .is_none()
        );
        assert!(!CdaEvent::ReloadStaticData.guards().communication_lease);

        let cleanup = CdaEvent::CleanupFiles(UpdateHttpProtection::default());
        assert!(cleanup.guards().http_protection.is_some());
        assert!(cleanup.guards().communication_lease);
    }

    #[test]
    fn deferred_target_drops_the_lease_instead_of_releasing_it() {
        let deferred = CdaEvent::ReloadEcuData(EcuDataReload::new(
            ReloadExecutionMode::Apply,
            PostUpdateCommunicationMode::Deferred,
            UpdateHttpProtection::default(),
        ));
        assert_eq!(CdaLeasePolicy.outcome(&deferred), LeaseOutcome::Drop);

        let enabled = CdaEvent::ReloadEcuData(EcuDataReload::new(
            ReloadExecutionMode::Rollback,
            PostUpdateCommunicationMode::Enabled,
            UpdateHttpProtection::default(),
        ));
        assert_eq!(CdaLeasePolicy.outcome(&enabled), LeaseOutcome::Release);
    }

    /// The table is the readable half of a reload: it says in one place that
    /// the files move before the databases are read, that what was read is made
    /// live before anything reports on it, and that communication comes back
    /// last.
    #[test]
    fn a_reload_visits_the_stages_a_reload_needs_in_that_order() {
        let reload = CdaEvent::ReloadEcuData(EcuDataReload::new(
            ReloadExecutionMode::Apply,
            PostUpdateCommunicationMode::Enabled,
            UpdateHttpProtection::default(),
        ));

        assert_eq!(
            reload.stages(),
            [
                CdaStage::DatabaseFiles,
                CdaStage::EcuData,
                CdaStage::Diagnostics,
                CdaStage::StagedFiles,
                CdaStage::Version,
                CdaStage::Activation,
            ]
        );
    }

    /// A cleanup deletes files, so it must not reach anything that would read a
    /// database or republish what is live.
    #[test]
    fn a_cleanup_visits_only_the_file_stage() {
        assert_eq!(
            CdaEvent::CleanupFiles(UpdateHttpProtection::default()).stages(),
            [CdaStage::DatabaseFiles]
        );
        assert_eq!(CdaEvent::ReloadStaticData.stages(), [CdaStage::Version]);
    }

    #[test]
    fn revisions_are_shared_across_clones() {
        let reload = EcuDataReload::new(
            ReloadExecutionMode::Apply,
            PostUpdateCommunicationMode::Enabled,
            UpdateHttpProtection::default(),
        );
        reload.revisions.record("ecu-a", "1.2.3");

        assert_eq!(
            reload.revisions.clone().snapshot().get("ecu-a").cloned(),
            Some("1.2.3".to_owned())
        );
    }
}
