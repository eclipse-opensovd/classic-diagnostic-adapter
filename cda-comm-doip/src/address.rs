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

use std::net::{IpAddr, Ipv6Addr};

use cda_interfaces::config::ConfigSanityError;

pub(crate) fn socket_address(ip: IpAddr, port: u16, interface_index: u32) -> std::net::SocketAddr {
    match ip {
        IpAddr::V4(ip) => std::net::SocketAddr::from((ip, port)),
        IpAddr::V6(ip) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            ip,
            port,
            0,
            if ip.is_unicast_link_local() {
                interface_index
            } else {
                0
            },
        )),
    }
}

pub(crate) fn validate_ipv6_endpoint(ip: Ipv6Addr, field: &str) -> Result<(), ConfigSanityError> {
    if ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some() {
        return Err(ConfigSanityError::InvalidValue {
            field: field.to_owned(),
            reason: format!("{ip} must be a native IPv6 unicast address assigned to an endpoint"),
        });
    }
    Ok(())
}

pub(crate) fn resolve_interface(ip: IpAddr) -> Result<Option<u32>, ConfigSanityError> {
    if ip.is_ipv4() {
        return Ok(None);
    }
    let interfaces = if_addrs::get_if_addrs().map_err(|error| ConfigSanityError::InvalidValue {
        field: "tester_address".to_owned(),
        reason: format!("Failed to enumerate local interfaces: {error}"),
    })?;
    select_interface(
        ip,
        interfaces
            .iter()
            .filter(|interface| interface.ip() == ip)
            .map(|interface| interface.index),
    )
    .map(Some)
}

fn select_interface(
    ip: IpAddr,
    indices: impl Iterator<Item = Option<u32>>,
) -> Result<u32, ConfigSanityError> {
    let mut selected = None;
    for index in indices {
        match (selected, index) {
            (_, None | Some(0)) => {
                return Err(interface_error(ip, "its interface index is unavailable"));
            }
            (Some(previous), Some(index)) if previous != index => {
                return Err(interface_error(ip, "it is assigned to multiple interfaces"));
            }
            (_, Some(index)) => selected = Some(index),
        }
    }
    selected.ok_or_else(|| interface_error(ip, "it is not assigned to a local interface"))
}

fn interface_error(ip: IpAddr, reason: &str) -> ConfigSanityError {
    ConfigSanityError::InvalidValue {
        field: "tester_address".to_owned(),
        reason: format!(
            "Cannot select the IPv6 interface for {ip}: {reason}. Set doip.tester_address to an \
             address unique to the intended local interface"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_selection_requires_one_distinct_nonzero_index() {
        let ip = "fe80::1".parse().expect("IPv6 address");
        for indices in [vec![], vec![None], vec![Some(0)], vec![Some(2), Some(3)]] {
            assert!(select_interface(ip, indices.into_iter()).is_err());
        }
        assert_eq!(
            select_interface(ip, [Some(2), Some(2)].into_iter()).expect("one interface"),
            2
        );
    }

    #[test]
    fn ipv6_endpoint_types() {
        for ip in ["fe80::1", "fd00::1", "2001:db8::1", "::1"] {
            assert!(
                validate_ipv6_endpoint(ip.parse().expect("IPv6 address"), "tester_address").is_ok()
            );
        }
        for ip in ["::", "ff02::1", "::ffff:192.0.2.1"] {
            assert!(
                validate_ipv6_endpoint(ip.parse().expect("IPv6 address"), "tester_address")
                    .is_err()
            );
        }
    }

    #[test]
    fn resolves_local_ipv6_loopback() {
        assert!(
            resolve_interface(IpAddr::V6(Ipv6Addr::LOCALHOST))
                .expect("local loopback")
                .is_some()
        );
        assert_eq!(
            resolve_interface("127.0.0.1".parse().expect("IPv4")).expect("no IPv4 lookup"),
            None
        );
    }
}
