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

//! Reconnecting to persisted gateways without a full broadcast discovery.

use std::sync::Arc;

use cda_interfaces::{DiagServiceError, EcuAddresses, HashMap, HashSet, topology::KnownGateway};
use doip_definitions::header::ProtocolVersion;
use tokio::sync::RwLock;

use crate::{DiscoveredGateway, create_udp_vir_socket, vir_vam};

/// Gateways to connect to directly, and gateways that need a broadcast.
#[derive(Debug, Default)]
pub(crate) struct ReconnectPlan {
    /// Persisted gateways with a usable network address.
    pub(crate) unicast: Vec<DiscoveredGateway>,
    /// Logical addresses of database gateways that must be searched by a
    /// broadcast: not persisted, or persisted with an unusable address.
    pub(crate) broadcast_for: HashSet<u16>,
}

/// Returns `true` if `ip` is inside the tester subnet. `netmask` is the network
/// address of the tester subnet, see `create_netmask`.
pub(crate) fn in_tester_subnet(ip: std::net::Ipv4Addr, netmask: u32) -> bool {
    ip.to_bits() & netmask == netmask
}

/// Splits the persisted gateways into direct reconnects and broadcast fallbacks.
///
/// `db_gateways` maps the logical address of every gateway in the databases to
/// its names (several for duplicate ECUs sharing a logical address). A persisted gateway without network address was not found by the
/// last full broadcast and is skipped (a later announcement still connects it).
/// `search` lists database gateways that are not persisted at all; they are
/// searched by a broadcast.
pub(crate) fn plan_reconnect(
    known: &[KnownGateway],
    search: &[u16],
    db_gateways: &HashMap<u16, Vec<String>>,
    netmask: u32,
) -> ReconnectPlan {
    let mut plan = ReconnectPlan::default();
    for gateway in known {
        let Some(db_names) = db_gateways.get(&gateway.logical_address) else {
            tracing::debug!(
                gateway = %gateway.name,
                "Persisted gateway is not in the databases, ignoring it"
            );
            continue;
        };
        let Some(address) = gateway.network_address.as_deref() else {
            tracing::debug!(
                gateway = %gateway.name,
                "Persisted gateway was not found by the last broadcast, skipping it"
            );
            continue;
        };
        let usable_address = address
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .filter(|ip| in_tester_subnet(*ip, netmask));
        let protocol_version = gateway
            .doip_protocol_version
            .and_then(|version| ProtocolVersion::try_from(&version).ok());
        let db_name = db_names
            .iter()
            .find(|name| name.eq_ignore_ascii_case(&gateway.name));
        if let (Some(ip), Some(doip_protocol_version), Some(db_name)) =
            (usable_address, protocol_version, db_name)
        {
            plan.unicast.push(DiscoveredGateway {
                ip: ip.to_string(),
                ecu_name: db_name.clone(),
                logical_address: gateway.logical_address,
                doip_protocol_version,
            });
        } else {
            tracing::info!(
                gateway = %gateway.name,
                address,
                "Persisted gateway entry is not usable, falling back to a broadcast"
            );
            plan.broadcast_for.insert(gateway.logical_address);
        }
    }
    plan.broadcast_for.extend(search.iter().copied());
    plan
}

/// Broadcasts a VIR from a new, ephemeral socket and returns the announced
/// gateways whose logical address is in `wanted`.
///
/// A separate socket is used because the VAM listener owns the socket bound to the
/// `DoIP` port; vehicle announcements answering a VIR are sent to its source port.
pub(crate) async fn fallback_identification<T, F>(
    tester_ip: &str,
    gateway_port: u16,
    netmask: u32,
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    wanted: &HashSet<u16>,
    shutdown: futures::future::Shared<F>,
) -> Result<Vec<DiscoveredGateway>, DiagServiceError>
where
    T: EcuAddresses,
    F: Future<Output = ()> + Send + 'static,
{
    let mut socket = create_udp_vir_socket(tester_ip, 0)
        .map_err(|error| DiagServiceError::SendFailed(error.to_string()))?;
    let gateways =
        vir_vam::get_vehicle_identification(&mut socket, netmask, gateway_port, ecus, shutdown)
            .await?;
    Ok(gateways
        .into_iter()
        .filter(|gateway| wanted.contains(&gateway.logical_address))
        .collect())
}

#[cfg(test)]
mod tests {
    use cda_interfaces::HashMapExtensions as _;

    use super::*;

    // Network address of 10.2.0.0/16.
    const NETMASK: u32 = 0x0A02_0000;

    fn known(logical_address: u16, address: Option<&str>, version: Option<u8>) -> KnownGateway {
        KnownGateway {
            name: format!("GW{logical_address:X}"),
            logical_address,
            network_address: address.map(str::to_owned),
            doip_protocol_version: version,
        }
    }

    fn db_gateways(addresses: &[u16]) -> HashMap<u16, Vec<String>> {
        let mut map = HashMap::new();
        for address in addresses {
            map.insert(*address, vec![format!("GW{address:X}")]);
        }
        map
    }

    /// [[ test~doip-plan-reconnect, Persisted gateways are reconnected directly or searched by broadcast, test ]]
    #[test]
    fn plan_reconnect_selects_unicast_and_broadcast_gateways() {
        let plan = plan_reconnect(
            &[
                known(0x1000, Some("10.2.1.10"), Some(3)),
                // Outside the tester subnet.
                known(0x2000, Some("192.168.1.1"), Some(3)),
                // Unknown protocol version.
                known(0x3000, Some("10.2.1.30"), Some(0x42)),
                // Not found by the last broadcast.
                known(0x4000, None, None),
                // No longer in the databases.
                known(0x9000, Some("10.2.1.90"), Some(3)),
            ],
            &[0x5000],
            &db_gateways(&[0x1000, 0x2000, 0x3000, 0x4000, 0x5000]),
            NETMASK,
        );

        let unicast: Vec<_> = plan
            .unicast
            .iter()
            .map(|g| (g.logical_address, g.ip.as_str()))
            .collect();
        assert_eq!(unicast, vec![(0x1000, "10.2.1.10")]);

        let mut broadcast: Vec<_> = plan.broadcast_for.into_iter().collect();
        broadcast.sort_unstable();
        // 0x5000 was never persisted.
        assert_eq!(broadcast, vec![0x2000, 0x3000, 0x5000]);
    }

    /// Duplicate ECUs share a gateway address; the persisted one is any of them.
    #[test]
    fn plan_reconnect_accepts_any_duplicate_name() {
        let mut gateway = known(0x1000, Some("10.2.1.10"), Some(3));
        gateway.name = "flxcng1000".to_owned();
        let mut db = HashMap::new();
        db.insert(0x1000, vec!["flxc1000".to_owned(), "flxcng1000".to_owned()]);
        let plan = plan_reconnect(&[gateway], &[], &db, NETMASK);
        assert_eq!(
            plan.unicast.first().map(|g| g.ecu_name.as_str()),
            Some("flxcng1000")
        );
        assert!(plan.broadcast_for.is_empty());
    }

    #[test]
    fn plan_reconnect_rejects_renamed_gateway() {
        let mut gateway = known(0x1000, Some("10.2.1.10"), Some(3));
        gateway.name = "OTHER".to_owned();
        let plan = plan_reconnect(&[gateway], &[], &db_gateways(&[0x1000]), NETMASK);
        assert!(plan.unicast.is_empty());
        assert!(plan.broadcast_for.contains(&0x1000));
    }

    /// [[ test~doip-lazy-gateway-connect, Announcements of pending gateways only refresh their address, test ]]
    #[tokio::test]
    async fn pending_gateway_address_is_refreshed_by_announcements() {
        let lazy = crate::LazyGateways::default();
        let gateway = DiscoveredGateway {
            ip: "10.2.1.99".to_owned(),
            ecu_name: "GW1000".to_owned(),
            logical_address: 0x1000,
            doip_protocol_version: ProtocolVersion::Iso13400_2012,
        };
        assert!(!lazy.update_pending(&gateway).await, "not pending");
        lazy.pending.lock().await.insert(0x1000, None);
        assert!(lazy.update_pending(&gateway).await);
        assert_eq!(
            lazy.pending
                .lock()
                .await
                .get(&0x1000)
                .and_then(|g| g.as_ref())
                .map(|g| g.ip.as_str()),
            Some("10.2.1.99")
        );
    }

    #[test]
    fn subnet_check_matches_vam_filter() {
        assert!(in_tester_subnet("10.2.1.10".parse().unwrap(), NETMASK));
        assert!(!in_tester_subnet("192.168.1.1".parse().unwrap(), NETMASK));
    }
}
