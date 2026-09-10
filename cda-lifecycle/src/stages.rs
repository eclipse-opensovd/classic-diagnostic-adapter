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

//! The order the CDA runs in, written down once.
//!
//! Every component belongs to one of these stages, every event names the
//! stages it visits, and everything else about the runtime's order follows from
//! the edges below. Nothing here is derived from the types components exchange:
//! those deliver values and order nothing, which is why every step of a chain
//! is a stage of its own.

use cda_interfaces::lifecycle::Stage;

/// One coarse step of the CDA's order.
///
/// The edges below are the only thing that orders these; where a variant is
/// declared orders nothing.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, strum_macros::AsRefStr, strum_macros::IntoStaticStr,
)]
#[strum(serialize_all = "kebab-case")]
pub enum CdaStage {
    /// The two transports nothing else has to exist for: the HTTP router the
    /// routes are mounted on, and the diagnostic gateway to the vehicle.
    /// Neither reads anything the other publishes, which is what lets them
    /// share a stage.
    Transports,
    /// The communication runtime, built over the router and the gateway.
    CommunicationRuntime,
    /// The lifecycle manager, built over the runtime's disable authority. It is
    /// what every later dispatch goes through.
    LifecycleManager,
    /// The update storage and the transaction the file stages are run over,
    /// opened through the manager.
    Storage,
    /// The HTTP that answers without any ECU data: health, version, `OpenAPI`
    /// and the runtime-update endpoints.
    StaticApi,
    /// The port is open and the mounted routes answer.
    Serving,
    /// The database files an execution moves.
    ///
    /// It has to follow [`CdaStage::Storage`], because the transaction it is
    /// built over is published there. It is declared after
    /// [`CdaStage::Serving`] instead, which is a legibility choice and not a
    /// correctness constraint: nothing here starts or stops, a reload runs long
    /// after the port opened, and the single edge only buys a reload spine that
    /// reads as one line. Moving it back to `Storage` would change no
    /// behaviour.
    DatabaseFiles,
    /// Reading the diagnostic databases from whatever the files left behind.
    /// The slowest part of a start, which is why it runs against a runtime that
    /// already answers.
    EcuData,
    /// The UDS manager, and the point a prepared reload is made live at.
    Diagnostics,
    /// The SOVD component and functional-group routes, which are mounted over
    /// the UDS manager.
    VehicleApi,
    /// Discarding the staged set a committed rollback replaced.
    StagedFiles,
    /// `/version` naming the databases that are live.
    Version,
    /// Communication brought up as the configured init mode asks for. What the
    /// transport ends up as is decided here, so a dispatch hands its
    /// communication lease back before this stage rather than after it.
    Activation,
    /// The instance reporting itself ready.
    Readiness,
}

/// Every stage the graph contains.
///
/// A variant missing from here is not in the graph at all: a component that
/// declares it is refused at registration, naming it. The position of a variant
/// in this list decides nothing; stages that no chain of edges separates are
/// shuffled apart in debug and test builds.
const ALL: [CdaStage; 14] = [
    CdaStage::Transports,
    CdaStage::CommunicationRuntime,
    CdaStage::LifecycleManager,
    CdaStage::Storage,
    CdaStage::StaticApi,
    CdaStage::Serving,
    CdaStage::DatabaseFiles,
    CdaStage::EcuData,
    CdaStage::Diagnostics,
    CdaStage::VehicleApi,
    CdaStage::StagedFiles,
    CdaStage::Version,
    CdaStage::Activation,
    CdaStage::Readiness,
];

impl Stage for CdaStage {
    fn all() -> &'static [Self] {
        &ALL
    }

    fn follows(&self) -> &'static [Self] {
        match self {
            CdaStage::Transports => &[],
            CdaStage::CommunicationRuntime => &[CdaStage::Transports],
            CdaStage::LifecycleManager => &[CdaStage::CommunicationRuntime],
            CdaStage::Storage => &[CdaStage::LifecycleManager],
            CdaStage::StaticApi => &[CdaStage::Storage],
            CdaStage::Serving => &[CdaStage::StaticApi],
            CdaStage::DatabaseFiles => &[CdaStage::Serving],
            CdaStage::EcuData => &[CdaStage::DatabaseFiles],
            CdaStage::Diagnostics => &[CdaStage::EcuData],
            CdaStage::VehicleApi | CdaStage::StagedFiles | CdaStage::Version => {
                &[CdaStage::Diagnostics]
            }
            // VehicleApi is in here because otherwise nothing follows it, and
            // a stage nothing follows is free to be placed anywhere after the
            // one it follows, past Readiness included. Reporting the instance
            // ready has to be last by declaration rather than because the
            // vehicle routes happen to have no start of their own today.
            CdaStage::Activation => &[
                CdaStage::VehicleApi,
                CdaStage::StagedFiles,
                CdaStage::Version,
            ],
            CdaStage::Readiness => &[CdaStage::Activation],
        }
    }

    fn name(&self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stage the graph does not contain places nothing, so the list has to
    /// hold every variant `follows` can name.
    #[test]
    fn every_stage_an_edge_names_is_in_the_graph() {
        for stage in CdaStage::all() {
            for predecessor in stage.follows() {
                assert!(
                    ALL.contains(predecessor),
                    "{} follows {}, which is not listed",
                    stage.name(),
                    predecessor.name()
                );
            }
        }
    }

    /// What is forced is only that this stage follows Storage, which publishes
    /// the transaction it reads. Declaring it against Serving is the
    /// deliberate part, so it is pinned rather than left to a doc comment.
    #[test]
    fn the_database_files_stage_follows_serving() {
        assert_eq!(CdaStage::DatabaseFiles.follows(), [CdaStage::Serving]);
    }

    /// Nothing orders these three against each other, and the resolver shuffles
    /// what nothing orders. An edge added between any two of them would make
    /// this fail, which is where the reason for it would have to be written.
    #[test]
    fn the_stages_after_diagnostics_are_interchangeable() {
        let tied = [
            CdaStage::VehicleApi,
            CdaStage::StagedFiles,
            CdaStage::Version,
        ];

        for stage in tied {
            assert_eq!(stage.follows(), [CdaStage::Diagnostics], "{}", stage.name());
        }
        for stage in CdaStage::all() {
            for predecessor in stage.follows() {
                assert!(
                    !tied.contains(predecessor) || *stage == CdaStage::Activation,
                    "{} follows {}",
                    stage.name(),
                    predecessor.name()
                );
            }
        }
    }

    /// Every stage reaches readiness, so readiness is last whatever the
    /// tie-break does. A stage nothing follows would be free to overtake it.
    #[test]
    fn every_other_stage_is_a_predecessor_of_readiness() {
        let mut reached = vec![CdaStage::Readiness];
        let mut before = 0usize;
        while before < reached.len() {
            before = reached.len();
            for stage in CdaStage::all() {
                if !reached.contains(stage) {
                    continue;
                }
                for predecessor in stage.follows() {
                    if !reached.contains(predecessor) {
                        reached.push(*predecessor);
                    }
                }
            }
        }

        for stage in CdaStage::all() {
            assert!(reached.contains(stage), "{}", stage.name());
        }
    }

    /// The names travel in the resolved-order dump and in registration errors,
    /// so a rename that changed them would change what an operator greps for.
    #[test]
    fn stage_names_render_in_kebab_case() {
        assert_eq!(CdaStage::Transports.name(), "transports");
        assert_eq!(
            CdaStage::CommunicationRuntime.name(),
            "communication-runtime"
        );
        assert_eq!(CdaStage::StaticApi.name(), "static-api");
        assert_eq!(CdaStage::DatabaseFiles.name(), "database-files");
        assert_eq!(CdaStage::EcuData.name(), "ecu-data");
    }
}
