#!/bin/bash -e
# Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0


COMMAND=$1
IFNAME=$2

if [ -z "$IFNAME" ] || [[ "$COMMAND" != "add" && "$COMMAND" != "del" ]] || [ -z "$3" ] || [ -z "$4" ]; then
  echo "Usage: $0 <add/del> <ifname> <ip-range B> <ip-range C>"
  echo "ip ranges shall be in bash syntax for expansion, but will be expanded by the script"
  echo "Example:"
  echo "$0 add eth0 55 '{100..200}'"
  echo "If eth0 were 10.2.1.240, it would add the IP-range 10.2.55.100-10.2.55.200 to the interface"
  exit 1
fi

IP_OUTPUT=$(ip --json address)

IP=$(printf '%s' "$IP_OUTPUT" | jq --arg ifname "$IFNAME" -r '.[] | select(.ifname == $ifname) | .addr_info[0] | select(.family == "inet") | .local')
PREFIXLEN=$(printf '%s' "$IP_OUTPUT" | jq --arg ifname "$IFNAME" -r '.[] | select(.ifname == $ifname) | .addr_info[0] | select(.family == "inet") | .prefixlen')

if [ -z "$IP" ] && [ -z "$PREFIXLEN" ]; then
 # try via ip
  IP=$(printf '%s' "$IP_OUTPUT" | jq --arg ifname "$IFNAME" -r '.[] | select(.addr_info[] | (.local == $ifname and .family == "inet")) | .addr_info[0] | select(.family == "inet") | .local')
  PREFIXLEN=$(printf '%s' "$IP_OUTPUT" | jq --arg ifname "$IFNAME" -r '.[] | select(.addr_info[] | (.local == $ifname and .family == "inet")) | .addr_info[0] | select(.family == "inet") | .prefixlen')
fi

if [ -z "$IP" ] || [ -z "$PREFIXLEN" ]; then
  echo "IP/Prefixlen for '$IFNAME' couldn't be determined. Aborting"
  exit 1
fi

if [[ "$PREFIXLEN" -gt 16 ]]; then
  echo "The networks prefixlen is $PREFIXLEN, this script only works on networks with a prefixlen of 16 or lower"
  exit 1
fi

read -r -a SPLIT_IP <<< "${IP//./ }"

if [ "$3" != "-" ]; then
  SPLIT_IP[2]="$3"
fi

SPLIT_IP[3]="$4"

STR="${SPLIT_IP[*]}"
IP_RANGE_STR=${STR// /.}

IP_ARR=$(eval echo "$IP_RANGE_STR")
for ip in $IP_ARR; do
  echo "$COMMAND IP $ip on $IFNAME"
  ip address "$COMMAND" "$ip/32" dev "$IFNAME"
done
