#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Measures the tester turnaround during a flash download from a DoIP capture.

For every TransferData positive response (0x76) sent by the ECU, the gap is the time until
the first TCP segment with payload from the CDA that starts the next 0x36 request.
Prints one CSV line: count,mean_ms,median_ms,p95_ms,max_ms,min_ms
(with --header the column names first).
"""

import argparse
import statistics
import subprocess
import sys

DOIP_PORT = "13400"


def frames(pcap: str):
    out = subprocess.run(
        [
            "tshark",
            "-r",
            pcap,
            "-n",
            "-Y",
            "tcp.len > 0",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
            "-e",
            "frame.time_epoch",
            "-e",
            "tcp.srcport",
            "-e",
            "uds.sid",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in out.splitlines():
        ts, sport, sids = [*line.split("\t"), "", "", ""][:3]
        yield float(ts), sport == DOIP_PORT, {s.lower() for s in sids.split(",") if s}


def gaps(pcap: str) -> list[float]:
    result, pending_ack = [], None
    for ts, from_ecu, sids in frames(pcap):
        if from_ecu:
            # tshark reports the request SID (0x36) for the positive response 0x76 as well
            if "0x36" in sids:
                pending_ack = ts
        elif pending_ack is not None:
            # Segments without a decoded SID are the start of a TCP-segmented 0x36 request
            # (tshark decodes UDS only in the last segment). Anything else (0x37, tester
            # present) is not part of the block loop and is ignored.
            if not sids or sids == {"0x36"}:
                result.append((ts - pending_ack) * 1000.0)
            pending_ack = None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap")
    parser.add_argument("--header", action="store_true")
    args = parser.parse_args()
    if args.header:
        print("gap_count,gap_mean_ms,gap_median_ms,gap_p95_ms,gap_max_ms,gap_min_ms")
    g = gaps(args.pcap)
    if not g:
        print("0,,,,,")
        return 1
    g_sorted = sorted(g)
    p95 = g_sorted[min(len(g_sorted) - 1, int(0.95 * len(g_sorted)))]
    print(
        f"{len(g)},{statistics.fmean(g):.3f},{statistics.median(g):.3f},{p95:.3f},"
        f"{g_sorted[-1]:.3f},{g_sorted[0]:.3f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
