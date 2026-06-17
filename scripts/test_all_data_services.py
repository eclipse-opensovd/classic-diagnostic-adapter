#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
"""
Test all CDA data services for a component.

This script:
1. Authenticates with CDA to get a JWT token
2. Lists all available data services
3. Calls each service and reports failures (non-200 responses)
"""

import argparse
import contextlib
import json
import sys
import time
from urllib.parse import urljoin

import requests

# Default configuration
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 20002
DEFAULT_COMPONENT = "flxc1000"
DEFAULT_CLIENT_ID = "test_client"
DEFAULT_CLIENT_SECRET = "test_secret"

# Known services that fail due to MDD / simulator limitations
# (semantic aliases not supported). Empty by default; populate via
# --known-failure for ECUs that need it.
KNOWN_FAILURES: set[str] = set()


def authenticate(base_url: str, client_id: str, client_secret: str) -> str:
    """Authenticate and return JWT token."""
    auth_url = urljoin(base_url, "authorize")
    response = requests.post(
        auth_url,
        json={"client_id": client_id, "client_secret": client_secret},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def get_data_services(base_url: str, component: str, token: str) -> list[dict]:
    """Get list of all data services for a component."""
    url = urljoin(base_url, f"components/{component}/data/")
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    # The response contains a list of data items with 'id' and 'self' fields
    return data.get("items", data) if isinstance(data, dict) else data


def check_data_service(
    base_url: str, component: str, service_id: str, token: str, max_retries: int = 3
) -> tuple[int, dict | None, str, int]:
    """Test a single data service. Returns (status_code, error_response or None, url, attempts)."""
    url = urljoin(base_url, f"components/{component}/data/{service_id}")

    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,  # Some services may take longer
            )
            if response.status_code == 200:
                try:
                    result = response.json()
                except json.JSONDecodeError:
                    result = None
                return 200, result, url, attempt + 1
            else:
                # Check if it's a retryable error from CDA
                try:
                    error_json = response.json()
                    is_timeout = error_json.get("message", "").lower() == "timeout"
                    is_busy = "busy" in error_json.get("message", "").lower()
                except json.JSONDecodeError:
                    is_timeout = False
                    is_busy = False

                if (is_timeout or is_busy) and attempt < max_retries - 1:
                    wait = 4 * 2**attempt  # exponential backoff: 4, 8, 16...
                    label = "busy" if is_busy else "timeout"
                    print(f"      ({label}, retrying {attempt + 2}/{max_retries} after {wait}s...)")
                    time.sleep(wait)
                    continue

                # Capture full response for debugging
                error_info = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:2000] if response.text else "(empty)",
                }
                with contextlib.suppress(json.JSONDecodeError):
                    error_info["json"] = response.json()
                return response.status_code, error_info, url, attempt + 1

        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                print(f"      (HTTP timeout, retrying {attempt + 2}/{max_retries}...)")
                time.sleep(2)
                continue
            return 0, {"error": "Request timed out after retries"}, url, attempt + 1
        except requests.exceptions.RequestException as e:
            return 0, {"error": str(e)}, url, attempt + 1

    return 0, {"error": "Max retries exceeded"}, url, max_retries


def main():
    parser = argparse.ArgumentParser(description="Test all CDA data services")
    parser.add_argument(
        "component",
        nargs="?",
        default=DEFAULT_COMPONENT,
        help=f"Component/ECU name, e.g. flxc1000 (default: {DEFAULT_COMPONENT})",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"CDA host (default: {DEFAULT_HOST})")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"CDA port (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--client-id", default=DEFAULT_CLIENT_ID, help=f"Client ID (default: {DEFAULT_CLIENT_ID})"
    )
    parser.add_argument(
        "--client-secret",
        default=DEFAULT_CLIENT_SECRET,
        help=f"Client secret (default: {DEFAULT_CLIENT_SECRET})",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show all results, not just failures"
    )
    parser.add_argument(
        "--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--retries", type=int, default=3, help="Max retries on timeout (default: 3)"
    )
    parser.add_argument(
        "--known-failure",
        action="append",
        default=[],
        metavar="SERVICE_ID",
        help="Add a service id to the known-failure set. Repeatable.",
    )
    parser.add_argument(
        "--skip-known",
        action="store_true",
        help="Skip known failing services (default built-in set + --known-failure)",
    )
    args = parser.parse_args()

    base_url = f"http://{args.host}:{args.port}/vehicle/v15/"
    component = args.component

    print("=" * 60)
    print(f"CDA Data Services Test - {component}")
    print("=" * 60)
    print(f"Server: {base_url}")
    print(f"Component: {component}")
    print()

    # Step 1: Authenticate
    print("[1/3] Authenticating...")
    try:
        token = authenticate(base_url, args.client_id, args.client_secret)
        print(f"[OK] Authentication successful (token: {token[:30]}...)")
    except Exception as e:
        print(f"[FAIL] Authentication failed: {e}")
        sys.exit(1)
    print()

    # Step 2: Get all data services
    print("[2/3] Fetching data service list...")
    try:
        services = get_data_services(base_url, component, token)
        service_ids = []
        for svc in services:
            if isinstance(svc, dict):
                service_ids.append(svc.get("id", svc.get("name", str(svc))))
            else:
                service_ids.append(str(svc))
        print(f"[OK] Found {len(service_ids)} data services")
    except Exception as e:
        print(f"[FAIL] Failed to get services: {e}")
        sys.exit(1)
    print()

    # Step 3: Test each service
    skip_count = 0
    if args.skip_known:
        skip_set = KNOWN_FAILURES | set(args.known_failure)
        skip_count = sum(1 for s in service_ids if s in skip_set)
        service_ids = [s for s in service_ids if s not in skip_set]
        if skip_count > 0:
            print(f"Skipping {skip_count} known failing services: {', '.join(sorted(skip_set))}")
            print()

    print(f"[3/3] Testing {len(service_ids)} data services...")
    print("-" * 60)

    success_count = 0
    failure_count = 0
    failures = []

    for i, service_id in enumerate(service_ids, 1):
        status, result, url, attempts = check_data_service(
            base_url, component, service_id, token, max_retries=args.retries
        )

        if status == 200:
            success_count += 1
            if args.verbose:
                retry_note = f" (after {attempts} attempts)" if attempts > 1 else ""
                print(f"  [{i}/{len(service_ids)}] [OK] {service_id}{retry_note}")
                if result:
                    print(f"      {json.dumps(result, indent=2)}")
        else:
            failure_count += 1
            failures.append((service_id, status, result, url))
            print(f"\n  [{i}/{len(service_ids)}] [FAIL] {service_id} (HTTP {status})")
            print(f"      URL: {url}")
            if result:
                if "json" in result:
                    print(f"      Error: {json.dumps(result['json'], indent=2)}")
                elif "body" in result:
                    body = result["body"]
                    if len(body) > 200:
                        body = body[:200] + "..."
                    print(f"      Body: {body}")

        # Pause between requests to avoid overwhelming the CDA
        if i < len(service_ids) and args.delay > 0:
            time.sleep(args.delay)

    print("-" * 60)
    print()

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total services: {len(service_ids)}")
    print(f"Successful:     {success_count}")
    print(f"Failed:         {failure_count}")
    print()

    # Show failure details
    if failures:
        print("FAILURE SUMMARY:")
        print("-" * 60)
        for service_id, status, _result, _url in failures:
            print(f"  - {service_id}: HTTP {status}")
        print()
        sys.exit(1)
    else:
        print("All services passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
