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

use cda_health::HealthState;
use cda_interfaces::spawn_named;
use tokio::task::JoinHandle;

/// Creates a background task that integrates with the systemd watchdog.
///
/// If the process was booted via systemd and the watchdog is enabled,
/// this function spawns a task that periodically checks the health state
/// and sends the appropriate `sd_notify` notification:
///
/// - `Ready` when transitioning from `Starting` to `Up`
/// - `Watchdog` while healthy (`Up` -> `Up`)
/// - `WatchdogTrigger` when health degrades (`Up` -> `Failed`)
///
/// The notification interval is the systemd-configured watchdog timeout
/// minus 5 seconds (to avoid timing issues).
///
/// If systemd is not detected or the watchdog is not enabled, returns `None`
/// and the CDA runs without `sd_notify` behavior.
pub fn create_sd_notify_task<F>(
    health_state: Option<HealthState>,
    shutdown_signal: F,
) -> Option<JoinHandle<()>>
where
    F: Future<Output = ()> + Clone + Send + 'static,
{
    if let Ok(true) = sd_notify::booted()
        && let Some(interval) = determine_interval()
    {
        // init sd notify task
        let watchdog_future = async move {
            let mut interval_timer = tokio::time::interval(interval);
            let mut state = cda_health::Status::Starting;
            loop {
                interval_timer.tick().await;
                state = trigger_watchdog(health_state.as_ref(), state).await;
            }
        };
        let sd_notify_future = spawn_named!("sd_notify", async move {
            tokio::select! {
                _ = watchdog_future => {},
                () = shutdown_signal => {},
            }
        });
        tracing::info!(
            "Systemd detected and watchdog enabled, initialized sd_notify task with interval of \
             {:?} seconds",
            interval.as_secs()
        );
        Some(sd_notify_future)
    } else {
        tracing::info!(
            "Systemd not detected or watchdog not enabled, skipping sd_notify initialization"
        );
        None
    }
}

fn determine_interval() -> Option<Duration> {
    if let Some(duration) = sd_notify::watchdog_enabled() {
        // ensure we are sending a bit more often than the watchdog expects,
        // to avoid any timing issues
        let interval = if let Some(interval) = duration.checked_sub(Duration::from_secs(5)) {
            interval
        } else {
            duration
        };
        Some(interval)
    } else {
        None
    }
}

async fn trigger_watchdog(
    health_state: Option<&HealthState>,
    prev_state: cda_health::Status,
) -> cda_health::Status {
    let new_status = fold_health_state(health_state).await;
    let notify = match (prev_state, new_status) {
        (cda_health::Status::Starting, cda_health::Status::Up) => sd_notify::NotifyState::Ready,
        (cda_health::Status::Up, cda_health::Status::Failed) => {
            sd_notify::NotifyState::WatchdogTrigger
        }
        (cda_health::Status::Up, cda_health::Status::Up) => sd_notify::NotifyState::Watchdog,
        // this would be Failure -> Starting or Up -> Starting. so makes no sense
        _ => {
            tracing::warn!(
                "Unexpected health status transition from {prev_state:?} to {new_status:?} when \
                 triggering sd_notify watchdog"
            );
            sd_notify::NotifyState::Watchdog
        }
    };
    tracing::debug!("Triggering sd_notify watchdog with status {notify:?}");
    if let Err(e) = sd_notify::notify(&[notify]) {
        tracing::warn!(error = %e, "Failed to send sd_notify watchdog notification");
    }
    new_status
}

fn fold_status(acc: cda_health::Status, status: cda_health::Status) -> cda_health::Status {
    match (acc, status) {
        (
            cda_health::Status::Up | cda_health::Status::Starting | cda_health::Status::Pending,
            cda_health::Status::Failed,
        )
        | (cda_health::Status::Failed, _) => cda_health::Status::Failed,
        (
            cda_health::Status::Starting | cda_health::Status::Pending,
            cda_health::Status::Pending,
        ) => cda_health::Status::Starting,
        (cda_health::Status::Starting | cda_health::Status::Pending, cda_health::Status::Up) => {
            cda_health::Status::Up
        }
        (_, status) => status,
    }
}

async fn fold_health_state(health_state: Option<&HealthState>) -> cda_health::Status {
    if let Some(health_state) = health_state {
        health_state
            .query_all_providers()
            .await
            .into_values()
            .fold(cda_health::Status::Starting, fold_status)
    } else {
        cda_health::Status::Up
    }
}

#[cfg(test)]
mod tests {
    use cda_health::Status;

    use super::fold_status;

    #[test]
    fn fold_up_then_failed_yields_failed() {
        assert_eq!(fold_status(Status::Up, Status::Failed), Status::Failed);
    }

    #[test]
    fn fold_starting_then_failed_yields_failed() {
        assert_eq!(
            fold_status(Status::Starting, Status::Failed),
            Status::Failed
        );
    }

    #[test]
    fn fold_pending_then_failed_yields_failed() {
        assert_eq!(fold_status(Status::Pending, Status::Failed), Status::Failed);
    }

    #[test]
    fn fold_failed_then_up_yields_failed() {
        assert_eq!(fold_status(Status::Failed, Status::Up), Status::Failed);
    }

    #[test]
    fn fold_failed_then_starting_yields_failed() {
        assert_eq!(
            fold_status(Status::Failed, Status::Starting),
            Status::Failed
        );
    }

    #[test]
    fn fold_failed_then_pending_yields_failed() {
        assert_eq!(fold_status(Status::Failed, Status::Pending), Status::Failed);
    }

    #[test]
    fn fold_failed_then_failed_yields_failed() {
        assert_eq!(fold_status(Status::Failed, Status::Failed), Status::Failed);
    }

    #[test]
    fn fold_starting_then_pending_yields_starting() {
        assert_eq!(
            fold_status(Status::Starting, Status::Pending),
            Status::Starting
        );
    }

    #[test]
    fn fold_pending_then_pending_yields_starting() {
        assert_eq!(
            fold_status(Status::Pending, Status::Pending),
            Status::Starting
        );
    }

    #[test]
    fn fold_starting_then_up_yields_up() {
        assert_eq!(fold_status(Status::Starting, Status::Up), Status::Up);
    }

    #[test]
    fn fold_pending_then_up_yields_up() {
        assert_eq!(fold_status(Status::Pending, Status::Up), Status::Up);
    }

    #[test]
    fn fold_up_then_up_yields_up() {
        assert_eq!(fold_status(Status::Up, Status::Up), Status::Up);
    }

    #[test]
    fn fold_up_then_starting_yields_starting() {
        assert_eq!(fold_status(Status::Up, Status::Starting), Status::Starting);
    }

    #[test]
    fn fold_up_then_pending_yields_pending() {
        assert_eq!(fold_status(Status::Up, Status::Pending), Status::Pending);
    }

    #[test]
    fn fold_sequence_all_up_from_starting() {
        // initial acc = Starting (as fold_health_state does), all providers Up
        let result = [Status::Up, Status::Up, Status::Up]
            .into_iter()
            .fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Up);
    }

    #[test]
    fn fold_sequence_any_failed_dominates() {
        let result = [Status::Up, Status::Failed, Status::Up]
            .into_iter()
            .fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Failed);
    }

    #[test]
    fn fold_sequence_failed_at_start_stays_failed() {
        let result = [Status::Failed, Status::Up, Status::Up]
            .into_iter()
            .fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Failed);
    }

    #[test]
    fn fold_sequence_all_starting_stays_starting() {
        let result = [Status::Starting, Status::Starting]
            .into_iter()
            .fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Starting);
    }

    #[test]
    fn fold_sequence_mix_starting_pending_yields_starting() {
        let result = [Status::Pending, Status::Starting, Status::Pending]
            .into_iter()
            .fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Starting);
    }

    #[test]
    fn fold_sequence_empty_providers_yields_starting() {
        // no providers → fold over empty iterator → initial accumulator = Starting
        let result = std::iter::empty::<Status>().fold(Status::Starting, fold_status);
        assert_eq!(result, Status::Starting);
    }

    #[tokio::test]
    async fn fold_health_state_none_yields_up() {
        let result = super::fold_health_state(None).await;
        assert_eq!(result, Status::Up);
    }
}
