/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

pub const fn get_nrc_code(val: u8) -> &'static str {
    match val {
        0x00 => "Positive Response",
        0x10 => "General Reject",
        0x11 => "Service Not Supported",
        0x12 => "Sub-function Not Supported",
        0x13 => "Incorrect Message Length Or Invalid Format",
        0x14 => "Response Too Long",
        0x21 => "Busy Repeat Request",
        0x22 => "Conditions Not Correct",
        0x24 => "Request Sequence Error",
        0x25 => "No Response From Subnet Component",
        0x26 => "Failure Prevents Execution Of Requested Action",
        0x31 => "Request Out Of Range",
        0x33 => "Security Access Denied",
        0x34 => "Authentication Required",
        0x35 => "Invalid Key",
        0x36 => "Exceed Number Of Attempts",
        0x37 => "Required Time Delay Not Expired",
        0x38 => "Secure Data Transmission Required",
        0x39 => "Secure Data Transmission Not Allowed",
        0x3A => "Secure Data Verification Failed",
        0x50 => "Certificate verification failed - Invalid Time Period",
        0x51 => "Certificate verification failed - Invalid Signature",
        0x52 => "Certificate verification failed - Invalid Chain of Trust",
        0x53 => "Certificate verification failed - Invalid Type",
        0x54 => "Certificate verification failed - Invalid Format",
        0x55 => "Certificate verification failed - Invalid Content",
        0x56 => "Certificate verification failed - Invalid Scope",
        0x57 => "Certificate verification failed - Invalid Certificate (revoked)",
        0x58 => "Ownership verification failed",
        0x59 => "Challenge calculation failed",
        0x5A => "Setting Access Rights failed",
        0x5B => "Session key creation/derivation failed",
        0x5C => "Configuration data usage failed",
        0x5D => "DeAuthentication failed",
        0x70 => "uploadDownloadNotAccepted",
        0x71 => "transferDataSuspended",
        0x72 => "generalProgrammingFailure",
        0x73 => "wrongBlockSequenceCounter",
        0x78 => "Request Correctly Received-Response Pending",
        0x7E => "Sub-function Not Supported In Active Session",
        0x7F => "Service Not Supported In Active Session",
        0x81 => "Rpm Too High",
        0x82 => "Rpm Too Low",
        0x83 => "Engine Is Running",
        0x84 => "Engine Is Not Running",
        0x85 => "Engine Run Time Too Low",
        0x86 => "Temperature Too High",
        0x87 => "Temperature Too Low",
        0x88 => "Vehicle Speed Too High",
        0x89 => "Vehicle Speed Too Low",
        0x8A => "Throttle/Pedal Position Too High",
        0x8B => "Throttle/Pedal Position Too Low",
        0x8C => "Transmission Range Not In Neutral",
        0x8D => "Transmission Range Not In Gear",
        0x8F => "Brake Switch(es) Not Closed (Brake Pedal not pressed or not applied)",
        0x90 => "Shifter Lever Not In Park",
        0x91 => "Torque Converter Clutch Locked",
        0x92 => "Voltage Too High",
        0x93 => "Voltage Too Low",
        0x94 => "Resource Temporarily Not Available",
        0x01..=0x0F
        | 0x15..=0x20
        | 0x23
        | 0x27..=0x30
        | 0x32
        | 0x3B..=0x4F
        | 0x95..=0xEF
        | 0xF0..=0xFE
        | 0x5E..=0x6F
        | 0x74..=0x77
        | 0x79..=0x7D
        | 0x80
        | 0x8E
        | 0xFF => "ISO SAE Reserved",
    }
}
