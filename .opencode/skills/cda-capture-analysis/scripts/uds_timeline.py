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
"""Extract UDS transactions and timings from a DoIP or CAN/ISO-TP capture via tshark."""

import argparse
import csv
import json
import shlex
import subprocess
import sys

FIELDS = [
    "frame.number",
    "frame.time_relative",
    "doip.payload_type",
    "doip.source_address",
    "doip.target_address",
    "doip.ack_code",
    "doip.nack_code",
    "doip.rsp_code",
    "can.id",
    "uds.sid",
    "uds",
]

NRC_NAMES = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x14: "responseTooLong",
    0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent", 0x26: "failurePreventsExecution",
    0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession", 0x94: "temporarilyNotAvailable",
}

# SIDs whose first data byte is a subfunction (suppressPosRsp in bit 7)
SUBFUNC_SIDS = {0x10, 0x11, 0x19, 0x27, 0x28, 0x29, 0x31, 0x3E, 0x83, 0x84, 0x85, 0x86, 0x87}


def first(value):
    return value.split(",")[0] if value else ""


def to_int(value):
    value = first(value)
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return int(value, 16)


def run_tshark(args):
    extra = shlex.split(args.tshark_arg) if args.tshark_arg else []
    cmd = ["tshark", *extra, "-r", args.file, "-Y", "uds || doip", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit("tshark not found - install Wireshark CLI (tshark)")
    except subprocess.CalledProcessError as e:
        sys.exit(f"tshark failed: {e.stderr}")
    payloads = uds_payloads(args, extra)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) + 1 - len(parts))
        rec = dict(zip(FIELDS, parts))
        frame = int(rec["frame.number"])
        rows.append({
            "frame": frame,
            "t": float(rec["frame.time_relative"]),
            "doip_type": to_int(rec["doip.payload_type"]),
            "src": to_int(rec["doip.source_address"]),
            "dst": to_int(rec["doip.target_address"]),
            "doip_ack": to_int(rec["doip.ack_code"]),
            "doip_nack": to_int(rec["doip.nack_code"]),
            "doip_rsp": to_int(rec["doip.rsp_code"]),
            "can_id": to_int(rec["can.id"]),
            "uds": payloads.get(frame, ""),
        })
    return rows


def uds_payloads(args, extra):
    """Raw UDS bytes per frame, taken from the hex dump of the uds protocol layer."""
    cmd = ["tshark", *extra, "-r", args.file, "-Y", "uds", "-T", "json", "-x",
           "-j", "frame uds"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    result = {}
    for pkt in json.loads(out or "[]"):
        layers = pkt["_source"]["layers"]
        raw = layers.get("uds_raw")
        while isinstance(raw, list):  # ["hex", offset, len, ...] or list of those
            raw = raw[0]
        if raw:
            result[int(layers["frame"]["frame.number"])] = raw
    return result


def describe(b):
    if not b:
        return ""
    if b[0] == 0x7F and len(b) >= 3:
        return f"NRC 0x{b[2]:02X} {NRC_NAMES.get(b[2], '')} (SID 0x{b[1]:02X})"
    if is_response(b):
        return f"+RSP 0x{b[0]:02X}"
    return f"REQ 0x{b[0]:02X}"


def is_response(b):
    return bool(b) and (b[0] == 0x7F or 0x50 <= b[0] <= 0x7E or b[0] in (0xC3, 0xC4, 0xC5, 0xC6, 0xC7))


def build(rows, ecu):
    msgs, doip, transactions, open_req = [], [], [], {}
    for r in rows:
        if ecu is not None and ecu not in (r["src"], r["dst"], r["can_id"]):
            if r["doip_type"] not in (0x0005, 0x0006):
                continue
        if r["doip_type"] is not None and r["doip_type"] != 0x8001:
            doip.append(r)
            if r["doip_type"] in (0x8002, 0x8003):
                key = (r["dst"], r["src"])
                if key in open_req and open_req[key].get("ack_t") is None:
                    open_req[key]["ack_t"] = r["t"]
                    open_req[key]["ack"] = "ACK" if r["doip_type"] == 0x8002 else \
                        f"NACK 0x{(r['doip_nack'] or 0):02X}"
            continue
        if not r["uds"]:
            continue
        b = bytes.fromhex(r["uds"])
        msgs.append({**r, "desc": describe(b)})
        if not is_response(b):
            key = (r["src"], r["dst"]) if r["src"] is not None else ("can", r["can_id"])
            spr = b[0] in SUBFUNC_SIDS and len(b) > 1 and bool(b[1] & 0x80)
            tr = {"req_frame": r["frame"], "t": r["t"], "sid": b[0], "req": b.hex(),
                  "src": r["src"], "dst": r["dst"], "can_id": r["can_id"],
                  "suppress_pos_rsp": spr, "ack_t": None, "ack": None, "pending": [],
                  "final_frame": None, "final_t": None, "result": None}
            transactions.append(tr)
            open_req[key] = tr
            continue
        key = (r["dst"], r["src"]) if r["src"] is not None else None
        tr = open_req.get(key) if key else None
        if tr is None:  # CAN: match last open request with same SID
            sid = b[1] if b[0] == 0x7F else b[0] - 0x40
            tr = next((t for t in reversed(transactions)
                       if t["sid"] == sid and t["final_t"] is None), None)
        if tr is None:
            continue
        if b[0] == 0x7F and len(b) >= 3 and b[2] == 0x78:
            tr["pending"].append(r["t"])
            continue
        tr["final_frame"], tr["final_t"] = r["frame"], r["t"]
        tr["result"] = describe(b)
        tr["rsp"] = b.hex()
    for tr in transactions:
        ms = lambda a, b: None if a is None or b is None else round((a - b) * 1000, 3)
        tr["ack_delay_ms"] = ms(tr["ack_t"], tr["t"])
        points = [tr["t"], *tr["pending"]] + ([tr["final_t"]] if tr["final_t"] else [])
        tr["gaps_ms"] = [ms(points[i + 1], points[i]) for i in range(len(points) - 1)]
        tr["first_rsp_ms"] = tr["gaps_ms"][0] if tr["gaps_ms"] else None
        tr["total_ms"] = ms(tr["final_t"], tr["t"])
        tr["nrc78_count"] = len(tr["pending"])
    return msgs, doip, transactions


def periodic(transactions, sid):
    ts = [t["t"] for t in transactions if t["sid"] == sid]
    return [round((b - a) * 1000, 1) for a, b in zip(ts, ts[1:])]


def fmt_addr(v):
    return "" if v is None else f"0x{v:04X}"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file")
    p.add_argument("--ecu", type=lambda s: int(s, 0), help="ECU logical address or CAN ID filter")
    p.add_argument("--tshark-arg", help="extra tshark args, e.g. '-d tcp.port==13401,doip'")
    p.add_argument("--csv", help="write transactions as CSV")
    p.add_argument("--json", help="write all extracted data as JSON")
    args = p.parse_args()

    rows = run_tshark(args)
    msgs, doip, trs = build(rows, args.ecu)

    print("== DoIP control messages ==")
    names = {0x0000: "GenericNACK", 0x0005: "RoutingActReq", 0x0006: "RoutingActRsp",
             0x0007: "AliveCheckReq", 0x0008: "AliveCheckRsp", 0x8002: "DiagACK",
             0x8003: "DiagNACK", 0x0004: "VehicleAnnounce", 0x0001: "VehicleIdReq"}
    last_ra = None
    for d in doip:
        extra = ""
        if d["doip_type"] == 0x0005:
            last_ra = d["t"]
        if d["doip_type"] == 0x0006 and last_ra is not None:
            extra = f" code=0x{(d['doip_rsp'] or 0):02X} delay={round((d['t'] - last_ra) * 1000, 3)}ms"
        if d["doip_type"] in (0x8002, 0x8003):
            continue
        print(f"#{d['frame']:>6} {d['t']:>12.6f} {names.get(d['doip_type'], hex(d['doip_type'] or 0))}"
              f" {fmt_addr(d['src'])}->{fmt_addr(d['dst'])}{extra}")

    print("\n== UDS transactions ==")
    print(f"{'req#':>6} {'t[s]':>12} {'addr':>13} {'request':<24} {'ack[ms]':>8} "
          f"{'1st[ms]':>9} {'#78':>4} {'total[ms]':>10} result")
    for t in trs:
        addr = f"{fmt_addr(t['src'])}->{fmt_addr(t['dst'])}" if t["src"] is not None \
            else f"can 0x{(t['can_id'] or 0):X}"
        req = t["req"][:22] + (".." if len(t["req"]) > 22 else "")
        res = t["result"] or ("(suppressed)" if t["suppress_pos_rsp"] else "NO RESPONSE")
        print(f"{t['req_frame']:>6} {t['t']:>12.6f} {addr:>13} {req:<24} "
              f"{t['ack_delay_ms'] if t['ack_delay_ms'] is not None else '':>8} "
              f"{t['first_rsp_ms'] if t['first_rsp_ms'] is not None else '':>9} "
              f"{t['nrc78_count']:>4} {t['total_ms'] if t['total_ms'] is not None else '':>10} {res}")
        if t["nrc78_count"]:
            print(f"{'':>8}gaps request->0x78..->final [ms]: {t['gaps_ms']}")

    tp = periodic(trs, 0x3E)
    if tp:
        print(f"\n== TesterPresent intervals [ms] == min={min(tp)} max={max(tp)} n={len(tp)}")
        print(f"   {tp[:50]}{' ...' if len(tp) > 50 else ''}")
    for t in trs:
        if t["sid"] == 0x10 and t.get("rsp", "").startswith("50") and len(t["rsp"]) >= 12:
            r = bytes.fromhex(t["rsp"])
            p2 = int.from_bytes(r[2:4], "big")
            p2s = int.from_bytes(r[4:6], "big") * 10
            print(f"\nSession 0x{r[1]:02X} @#{t['final_frame']}: P2server={p2}ms P2*server={p2s}ms")

    if args.csv:
        keys = ["req_frame", "t", "src", "dst", "can_id", "sid", "req", "suppress_pos_rsp",
                "ack", "ack_delay_ms", "first_rsp_ms", "nrc78_count", "gaps_ms", "total_ms",
                "final_frame", "result"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(trs)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"messages": msgs, "doip": doip, "transactions": trs,
                       "tester_present_intervals_ms": tp}, f, indent=2)


if __name__ == "__main__":
    main()
