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
import itertools
import json
import shlex
import subprocess
import sys

# Field names differ between Wireshark versions; all candidates are tried in order.
DOIP_FIELDS = {
    "type": ["doip.payload_type", "doip.type"],
    "src": ["doip.source_address"],
    "dst": ["doip.target_address"],
    "ack": ["doip.ack_code", "doip.diag_ack_code"],
    "nack": ["doip.diag_nack_code", "doip.nack_code"],
    "rsp": ["doip.rsp_code", "doip.response_code"],
    "tester": ["doip.tester_logical_address"],
}

# protocol layers requested from tshark (-J)
LAYERS = "frame ip ipv6 tcp udp can doip uds"


NRC_NAMES = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecution",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x34: "authenticationRequired",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x38: "secureDataTransmissionRequired",
    0x39: "secureDataTransmissionNotAllowed",
    0x3A: "secureDataVerificationFailed",
    0x50: "certificateVerificationFailedInvalidTimePeriod",
    0x51: "certificateVerificationFailedInvalidSignature",
    0x52: "certificateVerificationFailedInvalidChainOfTrust",
    0x53: "certificateVerificationFailedInvalidType",
    0x54: "certificateVerificationFailedInvalidFormat",
    0x55: "certificateVerificationFailedInvalidContent",
    0x56: "certificateVerificationFailedInvalidScope",
    0x57: "certificateVerificationFailedInvalidCertificate",
    0x58: "ownershipVerificationFailed",
    0x59: "challengeCalculationFailed",
    0x5A: "settingAccessRightsFailed",
    0x5B: "sessionKeyCreationDerivationFailed",
    0x5C: "configurationDataUsageFailed",
    0x5D: "deAuthenticationFailed",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceived-ResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
    0x81: "rpmTooHigh",
    0x82: "rpmTooLow",
    0x83: "engineIsRunning",
    0x84: "engineIsNotRunning",
    0x85: "engineRunTimeTooLow",
    0x86: "temperatureTooHigh",
    0x87: "temperatureTooLow",
    0x88: "vehicleSpeedTooHigh",
    0x89: "vehicleSpeedTooLow",
    0x8A: "throttlePedalTooHigh",
    0x8B: "throttlePedalTooLow",
    0x8C: "transmissionRangeNotInNeutral",
    0x8D: "transmissionRangeNotInGear",
    0x8F: "brakeSwitchesNotClosed",
    0x90: "shifterLeverNotInPark",
    0x91: "torqueConverterClutchLocked",
    0x92: "voltageTooHigh",
    0x93: "voltageTooLow",
    0x94: "temporarilyNotAvailable",
}

# SIDs whose first data byte is a subfunction (suppressPosRsp in bit 7)
SUBFUNC_SIDS = {0x10, 0x11, 0x19, 0x27, 0x28, 0x29, 0x31, 0x3E, 0x83, 0x84, 0x85, 0x86, 0x87}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def find(obj, names):
    """First scalar value of any of `names`, searched recursively (DoIP nests a Header tree)."""
    if isinstance(obj, list):
        for o in obj:
            v = find(o, names)
            if v is not None:
                return v
        return None
    if not isinstance(obj, dict):
        return None
    for n in names:
        if n in obj:
            v = obj[n]
            while isinstance(v, list):
                v = v[0] if v else None
            if v is not None:
                return v
    for k, v in obj.items():
        if not k.endswith("_raw") and isinstance(v, (dict, list)):
            r = find(v, names)
            if r is not None:
                return r
    return None


def to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        return int(value, 16)


def raw_hex(raw):
    """tshark -x raw entry is ["hex", offset, len, bitmask, type]."""
    return raw[0] if isinstance(raw, list) and raw else (raw or "")


NO_DOIP = dict.fromkeys(["doip_type", "src", "dst", "doip_ack", "doip_nack", "doip_rsp", "tester"])


def run_tshark(args):
    """One row per DoIP message / UDS message; frames may carry several DoIP messages."""
    extra = shlex.split(args.tshark_arg) if args.tshark_arg else []
    cmd = [
        "tshark",
        *extra,
        "-r",
        args.file,
        "-Y",
        "uds || doip",
        "-T",
        "json",
        "-x",
        "--no-duplicate-keys",  # repeated layers/fields become lists instead of lost keys
        "-J",
        LAYERS,
    ]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit("tshark not found - install Wireshark CLI (tshark)")
    except subprocess.CalledProcessError as e:
        sys.exit(f"tshark failed: {e.stderr}")
    rows = []
    for pkt in json.loads(out or "[]"):
        layers = pkt["_source"]["layers"]
        frame = layers["frame"]
        base = {
            "frame": int(find(frame, ["frame.number"])),
            "t": float(find(frame, ["frame.time_relative"])),
            "stream": to_int(find(layers.get("tcp"), ["tcp.stream"])),
            "ip_src": find(layers.get("ip"), ["ip.src"]) or find(layers.get("ipv6"), ["ipv6.src"]),
            "ip_dst": find(layers.get("ip"), ["ip.dst"]) or find(layers.get("ipv6"), ["ipv6.dst"]),
            "can_id": to_int(find(layers.get("can"), ["can.id"])),
        }
        raw = layers.get("uds_raw")
        # one uds layer: ["hex", off, len, ...]; several: list of those
        entries = raw if raw and isinstance(raw[0], list) else ([raw] if raw else [])
        uds_raws = [raw_hex(r) for r in entries]
        doips = as_list(layers.get("doip"))
        if not doips:  # CAN / ISO-TP: one row per UDS message
            for u in uds_raws:
                rows.append({**base, **NO_DOIP, "uds": u})
            continue
        uds_iter = iter(uds_raws)
        for d in doips:
            vals = {k: to_int(find(d, names)) for k, names in DOIP_FIELDS.items()}
            uds = next(uds_iter, "") if vals["type"] == 0x8001 else ""
            rows.append(
                {
                    **base,
                    "doip_type": vals["type"],
                    "src": vals["src"],
                    "dst": vals["dst"],
                    "doip_ack": vals["ack"],
                    "doip_nack": vals["nack"],
                    "doip_rsp": vals["rsp"],
                    "tester": vals["tester"],
                    "uds": uds,
                }
            )
    return rows


def describe(b):
    if not b:
        return ""
    if b[0] == 0x7F and len(b) >= 3:
        return f"NRC 0x{b[2]:02X} {NRC_NAMES.get(b[2], '')} (SID 0x{b[1]:02X})"
    if is_response(b):
        return f"+RSP 0x{b[0]:02X}"
    return f"REQ 0x{b[0]:02X}"


def is_response(b):
    return bool(b) and (
        b[0] == 0x7F or 0x50 <= b[0] <= 0x7E or b[0] in (0xC3, 0xC4, 0xC5, 0xC6, 0xC7)
    )


def build(rows, ecu):
    msgs, doip, transactions, open_req, unmatched = [], [], [], {}, []
    last_on_conn = {}  # (tester addr, tester IP, entity IP) -> last request
    for r in rows:
        if (
            ecu is not None
            and ecu not in (r["src"], r["dst"], r["can_id"])
            and r["doip_type"] not in (0x0005, 0x0006)
        ):
            continue
        if r["doip_type"] is not None and r["doip_type"] != 0x8001:
            doip.append(r)
            if r["doip_type"] in (0x8002, 0x8003):
                key = (r["dst"], r["src"], r["ip_dst"], r["ip_src"])
                if key in open_req and open_req[key].get("ack_t") is None:
                    open_req[key]["ack_t"] = r["t"]
                    open_req[key]["ack"] = (
                        "ACK" if r["doip_type"] == 0x8002 else f"NACK 0x{(r['doip_nack'] or 0):02X}"
                    )
            continue
        if not r["uds"]:
            continue
        b = bytes.fromhex(r["uds"])
        msgs.append({**r, "desc": describe(b)})
        if not is_response(b):
            key = (
                (r["src"], r["dst"], r["ip_src"], r["ip_dst"])
                if r["src"] is not None
                else ("can", r["can_id"])
            )
            spr = b[0] in SUBFUNC_SIDS and len(b) > 1 and bool(b[1] & 0x80)
            tr = {
                "req_frame": r["frame"],
                "t": r["t"],
                "sid": b[0],
                "req": b.hex(),
                "src": r["src"],
                "dst": r["dst"],
                "can_id": r["can_id"],
                "ip_src": r["ip_src"],
                "ip_dst": r["ip_dst"],
                "suppress_pos_rsp": spr,
                "ack_t": None,
                "ack": None,
                "pending": [],
                "final_frame": None,
                "final_t": None,
                "result": None,
                "functional": {},
            }
            transactions.append(tr)
            open_req[key] = tr
            if r["src"] is not None:
                last_on_conn[(r["src"], r["ip_src"], r["ip_dst"])] = tr
            continue
        key = (r["dst"], r["src"], r["ip_dst"], r["ip_src"]) if r["src"] is not None else None
        tr = open_req.get(key) if key else None
        rsp_sid = b[1] if b[0] == 0x7F else b[0] - 0x40
        if tr is not None and (tr["sid"] != rsp_sid or tr["final_t"] is not None):
            tr = None  # response belongs to another (unseen or already answered) request
        if tr is None and key is not None:
            # functional request: tester sent to a functional address, ECUs answer individually
            cand = last_on_conn.get((r["dst"], r["ip_dst"], r["ip_src"]))
            if (
                cand is not None
                and cand["sid"] == rsp_sid
                and is_functional(cand["dst"])
                and cand["dst"] != r["src"]
            ):
                f = cand["functional"].setdefault(
                    r["src"], {"pending": [], "final_frame": None, "final_t": None, "result": None}
                )
                if b[0] == 0x7F and len(b) >= 3 and b[2] == 0x78:
                    f["pending"].append(r["t"])
                elif f["final_t"] is None:
                    f["final_frame"], f["final_t"], f["result"] = r["frame"], r["t"], describe(b)
                continue
        if tr is None and key is None:  # CAN: match last open request with same SID
            tr = next(
                (t for t in reversed(transactions) if t["sid"] == rsp_sid and t["final_t"] is None),
                None,
            )
        if tr is None:
            unmatched.append({**r, "desc": describe(b)})
            continue
        if b[0] == 0x7F and len(b) >= 3 and b[2] == 0x78:
            tr["pending"].append(r["t"])
            continue
        tr["final_frame"], tr["final_t"] = r["frame"], r["t"]
        tr["result"] = describe(b)
        tr["rsp"] = b.hex()
    for tr in transactions:
        func = tr.pop("functional")
        if func:
            # one entry per responding ECU, with its own timings
            tr["functional_responses"] = [
                {
                    "ecu": fmt_addr(ecu),
                    "final_frame": f["final_frame"],
                    "nrc78_count": len(f["pending"]),
                    "first_rsp_ms": ms((f["pending"] or [f["final_t"]])[0], tr["t"]),
                    "total_ms": ms(f["final_t"], tr["t"]),
                    "result": f["result"] or "NO FINAL RESPONSE",
                }
                for ecu, f in func.items()
            ]
            if tr["result"] is None:
                tr["result"] = "functional: " + ", ".join(
                    f"{x['ecu']} {x['result']}" for x in tr["functional_responses"]
                )
        if tr["result"] is None:
            tr["result"] = "(suppressed)" if tr["suppress_pos_rsp"] else "NO RESPONSE"
        tr["ack_delay_ms"] = ms(tr["ack_t"], tr["t"])
        points = [tr["t"], *tr["pending"]] + ([tr["final_t"]] if tr["final_t"] else [])
        tr["gaps_ms"] = [ms(points[i + 1], points[i]) for i in range(len(points) - 1)]
        tr["first_rsp_ms"] = tr["gaps_ms"][0] if tr["gaps_ms"] else None
        tr["total_ms"] = ms(tr["final_t"], tr["t"])
        tr["nrc78_count"] = len(tr["pending"])
    return msgs, doip, transactions, unmatched


def ms(a, b):
    return None if a is None or b is None else round((a - b) * 1000, 3)


def is_functional(addr):
    """ISO 13400-2 functional logical address range (0xE400..0xEFFF)."""
    return addr is not None and 0xE400 <= addr <= 0xEFFF


def periodic(transactions, sid):
    """Request intervals per (IP src, IP dst, source, target / CAN ID).

    The IP pair shows which DoIP entity (e.g. gateway) the request was sent to, and
    separates identical functional requests sent on several connections.
    """
    groups = {}
    for t in transactions:
        if t["sid"] == sid:
            if t["src"] is not None:
                key = (t.get("ip_src"), t.get("ip_dst"), t["src"], t["dst"])
            else:
                key = (None, None, "can", t["can_id"])
            groups.setdefault(key, []).append(t["t"])
    return {
        key: [round((b - a) * 1000, 1) for a, b in itertools.pairwise(ts)]
        for key, ts in groups.items()
    }


def fmt_ip(ip_src, ip_dst):
    return f"{ip_src or '?'}->{ip_dst or '?'} " if ip_src or ip_dst else ""


def fmt_key(key):
    ip_src, ip_dst, a, b = key
    if a == "can":
        return f"can 0x{(b or 0):X}"
    return f"{fmt_ip(ip_src, ip_dst)}{fmt_addr(a)}->{fmt_addr(b)}"


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
    msgs, doip, trs, unmatched = build(rows, args.ecu)

    print("== DoIP control messages ==")
    names = {
        0x0000: "GenericNACK",
        0x0005: "RoutingActReq",
        0x0006: "RoutingActRsp",
        0x0007: "AliveCheckReq",
        0x0008: "AliveCheckRsp",
        0x8002: "DiagACK",
        0x8003: "DiagNACK",
        0x0004: "VehicleAnnounce",
        0x0001: "VehicleIdReq",
    }
    last_ra = {}  # tcp stream -> time of last routing activation request
    for d in doip:
        extra = ""
        src, dst = d["src"], d["dst"]
        if d["doip_type"] == 0x0005:
            last_ra[d["stream"]] = d["t"]
        if d["doip_type"] == 0x0006:
            # RA response carries the tester address in its own field
            src, dst = d["src"], d["tester"]
            extra = f" code=0x{(d['doip_rsp'] or 0):02X}"
            req_t = last_ra.pop(d["stream"], None)
            if req_t is not None:
                extra += f" delay={round((d['t'] - req_t) * 1000, 3)}ms"
        if d["doip_type"] in (0x8002, 0x8003):
            continue
        name = names.get(d["doip_type"], hex(d["doip_type"] or 0))
        stream = "" if d["stream"] is None else f" [tcp {d['stream']}]"
        print(
            f"#{d['frame']:>6} {d['t']:>12.6f} {name} {fmt_ip(d['ip_src'], d['ip_dst'])}"
            f"{fmt_addr(src)}->{fmt_addr(dst)}{extra}{stream}"
        )

    print("\n== UDS transactions ==")
    print(
        f"{'req#':>6} {'t[s]':>12} {'addr':>13} {'request':<24} {'ack[ms]':>8} "
        f"{'1st[ms]':>9} {'#78':>4} {'total[ms]':>10} result"
    )
    for t in trs:
        addr = (
            f"{fmt_addr(t['src'])}->{fmt_addr(t['dst'])}"
            if t["src"] is not None
            else f"can 0x{(t['can_id'] or 0):X}"
        )
        req = t["req"][:22] + (".." if len(t["req"]) > 22 else "")
        res = t["result"]
        print(
            f"{t['req_frame']:>6} {t['t']:>12.6f} {addr:>13} {req:<24} "
            f"{t['ack_delay_ms'] if t['ack_delay_ms'] is not None else '':>8} "
            f"{t['first_rsp_ms'] if t['first_rsp_ms'] is not None else '':>9} "
            f"{t['nrc78_count']:>4} {t['total_ms'] if t['total_ms'] is not None else '':>10} {res}"
        )
        if t["nrc78_count"]:
            print(f"{'':>8}gaps request->0x78..->final [ms]: {t['gaps_ms']}")

    tp = periodic(trs, 0x3E)
    if unmatched:
        print(f"\n== Responses without matching request: {len(unmatched)} ==")
        for u in unmatched[:20]:
            print(
                f"#{u['frame']:>6} {u['t']:>12.6f} {fmt_ip(u['ip_src'], u['ip_dst'])}"
                f"{fmt_addr(u['src'])}->{fmt_addr(u['dst'])} {u['desc']}"
            )
        if len(unmatched) > 20:
            print("   ...")
    for key, iv in tp.items():
        if not iv:
            continue
        med = sorted(iv)[len(iv) // 2]
        print(
            f"\n== TesterPresent intervals [ms] {fmt_key(key)} == "
            f"min={min(iv)} median={med} max={max(iv)} n={len(iv)}"
        )
        print(f"   {iv[:50]}{' ...' if len(iv) > 50 else ''}")
    for t in trs:
        if t["sid"] == 0x10 and t.get("rsp", "").startswith("50") and len(t["rsp"]) >= 12:
            r = bytes.fromhex(t["rsp"])
            p2 = int.from_bytes(r[2:4], "big")
            p2s = int.from_bytes(r[4:6], "big") * 10
            ecu = f"{t['ip_dst']} " if t["ip_dst"] else ""
            ecu += fmt_addr(t["dst"]) if t["dst"] is not None else f"can 0x{(t['can_id'] or 0):X}"
            print(
                f"Session 0x{r[1]:02X} @#{t['final_frame']} {ecu}: "
                f"P2server={p2}ms P2*server={p2s}ms"
            )

    if args.csv:
        keys = [
            "req_frame",
            "t",
            "src",
            "dst",
            "can_id",
            "sid",
            "req",
            "suppress_pos_rsp",
            "ack",
            "ack_delay_ms",
            "first_rsp_ms",
            "nrc78_count",
            "gaps_ms",
            "total_ms",
            "final_frame",
            "result",
        ]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(trs)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "messages": msgs,
                    "unmatched_responses": unmatched,
                    "doip": doip,
                    "transactions": trs,
                    "tester_present_intervals_ms": {fmt_key(k): v for k, v in tp.items()},
                },
                f,
                indent=2,
            )


if __name__ == "__main__":
    main()
