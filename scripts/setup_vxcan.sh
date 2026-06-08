#!/bin/bash
# Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

# Setup virtual CAN pair for testing
# vxcan0 <-> vxcan1 are linked together
#
# Usage: ./scripts/setup_vxcan.sh

set -e

echo "============================================================"
echo "Setting up Virtual CAN Interfaces for CDA Testing"
echo "============================================================"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges."
    echo "Please run with sudo: sudo ./scripts/setup_vxcan.sh"
    exit 1
fi

# Load vcan kernel module
echo "Loading vcan kernel module..."
if ! modprobe vcan; then
    echo "ERROR: Failed to load vcan module"
    echo "Make sure your kernel has CAN support enabled"
    exit 1
fi

# Remove existing interfaces if present
echo "Cleaning up any existing vxcan interfaces..."
ip link delete vxcan0 2>/dev/null || true
ip link delete vxcan1 2>/dev/null || true

# Create linked vxcan pair
echo "Creating linked vxcan pair..."
if ! ip link add dev vxcan0 type vxcan peer name vxcan1; then
    echo "ERROR: Failed to create vxcan interfaces"
    exit 1
fi

# Bring up both interfaces
echo "Bringing up interfaces..."
ip link set up vxcan0
ip link set up vxcan1

echo ""
echo "✓ Virtual CAN pair created successfully!"
echo ""
echo "Interfaces:"
echo "  vxcan0 - for classic-diagnostic-adapter"
echo "  vxcan1 - for BMS simulator"
echo ""
echo "Verification:"
ip link show vxcan0
ip link show vxcan1
echo ""
echo "Next steps:"
echo "1. Start BMS simulator"
echo "2. Start CDA: cargo run --release -- --config opensovd-cda-can.toml"
echo "3. Test with: curl http://localhost:20002/diagnostics"
echo ""
